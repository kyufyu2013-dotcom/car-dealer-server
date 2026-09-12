import express from 'express';
import cors from 'cors';
import pg from 'pg';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import path from 'path';
import fs from 'fs/promises';
import { gzipSync, gunzipSync } from 'zlib';
import { S3Client, PutObjectCommand, ListObjectsV2Command, DeleteObjectsCommand } from '@aws-sdk/client-s3';
import { fileURLToPath } from 'url';
import os from 'os';
import { monitorEventLoopDelay } from 'perf_hooks';

const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 8787);
const JWT_SECRET = process.env.JWT_SECRET || 'DEV_ONLY_CHANGE_THIS_SECRET_BEFORE_DEPLOYING_0123456789';
const SUPER_ADMIN_USER = process.env.SUPER_ADMIN_USER || 'm200530366';
const SUPER_ADMIN_PASSWORD = process.env.SUPER_ADMIN_PASSWORD || '00000000';
const DATABASE_URL = process.env.DATABASE_URL;
// Production: set OFFLINE_LICENSE_PRIVATE_KEY / OFFLINE_LICENSE_PUBLIC_KEY in the server environment.
// The bundled key is a development fallback so the package works immediately; rotate it before paid rollout.
const OFFLINE_LICENSE_PRIVATE_KEY = (process.env.OFFLINE_LICENSE_PRIVATE_KEY || `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIC7vypfOaya2RQ/Or9GJ39xf4+0BoqDt939beqY0QHYS
-----END PRIVATE KEY-----`).replace(/\\n/g,'\n');
const OFFLINE_LICENSE_PUBLIC_KEY = (process.env.OFFLINE_LICENSE_PUBLIC_KEY || `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA9HcbP6jcb7lfwCpp5gw1Jm5lB6aDGyCy2XbY4/uyXJU=
-----END PUBLIC KEY-----`).replace(/\\n/g,'\n');
const OFFLINE_GRACE_SECONDS = 72*60*60;
// Phase 6A: desktop update policy metadata is signed separately from login/offline authorization.
// Replace UPDATE_SIGNING_PRIVATE_KEY before paid production; the desktop bundles the matching public key.
const UPDATE_SIGNING_PRIVATE_KEY = (process.env.UPDATE_SIGNING_PRIVATE_KEY || `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINJNyM8Z3NP+A+nNSTsGntFeJovtB25kFHjt1DLw9bCV
-----END PRIVATE KEY-----`).replace(/\\n/g,'\n');
const UPDATE_SIGNING_KEY_ID = process.env.UPDATE_SIGNING_KEY_ID || 'desktop-update-ed25519-v1';
// Phase 7A: encrypted central PostgreSQL logical backup. Secrets stay in server environment.
const POSTGRES_BACKUP_DIR = process.env.POSTGRES_BACKUP_DIR || path.join(__dirname,'central-backups');
const BACKUP_ENCRYPTION_KEY = process.env.BACKUP_ENCRYPTION_KEY || 'DEV_ONLY_CHANGE_BACKUP_KEY_BEFORE_PRODUCTION_0123456789';
const BACKUP_S3_BUCKET = process.env.BACKUP_S3_BUCKET || '';
const BACKUP_S3_REGION = process.env.BACKUP_S3_REGION || 'ap-northeast-1';
const BACKUP_S3_ENDPOINT = process.env.BACKUP_S3_ENDPOINT || '';
const BACKUP_S3_PREFIX = String(process.env.BACKUP_S3_PREFIX || 'car-dealer-central').replace(/^\/+|\/+$/g,'');
const BACKUP_S3_ACCESS_KEY_ID = process.env.BACKUP_S3_ACCESS_KEY_ID || '';
const BACKUP_S3_SECRET_ACCESS_KEY = process.env.BACKUP_S3_SECRET_ACCESS_KEY || '';
const BACKUP_S3_FORCE_PATH_STYLE = String(process.env.BACKUP_S3_FORCE_PATH_STYLE||'').toLowerCase()==='true';
// Phase 7C: central Primary / Standby high-availability awareness.
// PostgreSQL streaming replication and promotion are infrastructure responsibilities; the app detects
// pg_is_in_recovery(), keeps a standby read-only, and becomes write-ready automatically after promotion.
const CENTRAL_HA_ENABLED = String(process.env.CENTRAL_HA_ENABLED||'').toLowerCase()==='true';
const CENTRAL_HA_INSTANCE_ID = String(process.env.CENTRAL_HA_INSTANCE_ID||process.env.RENDER_INSTANCE_ID||process.env.HOSTNAME||'central-1').slice(0,120);
const CENTRAL_HA_SITE = String(process.env.CENTRAL_HA_SITE||'primary-site').slice(0,120);
const CENTRAL_HA_EXPECTED_ROLE = ['primary','standby','auto'].includes(String(process.env.CENTRAL_HA_EXPECTED_ROLE||'auto').toLowerCase())?String(process.env.CENTRAL_HA_EXPECTED_ROLE||'auto').toLowerCase():'auto';
const CENTRAL_HA_PEER_URL = String(process.env.CENTRAL_HA_PEER_URL||'').replace(/\/$/,'');
const CENTRAL_HA_PEER_TIMEOUT_MS = Math.max(1000,Math.min(10000,Number(process.env.CENTRAL_HA_PEER_TIMEOUT_MS||3500)));
let haRuntime={enabled:CENTRAL_HA_ENABLED,instanceId:CENTRAL_HA_INSTANCE_ID,site:CENTRAL_HA_SITE,expectedRole:CENTRAL_HA_EXPECTED_ROLE,dbRole:'unknown',schemaReady:false,writeReady:false,lastCheckedAt:null,lastRoleChangeAt:null,lastError:'',wal:{}};
let haMigrationRunning=false;
// Phase 8A: isolated Dealer Node load-test harness. Disabled by default and never writes into real dealership tables.
const LOAD_TEST_ENABLED = String(process.env.LOAD_TEST_ENABLED||'').toLowerCase()==='true';
const LOAD_TEST_TOKEN = String(process.env.LOAD_TEST_TOKEN||'');
const LOAD_TEST_MAX_RPS = Math.max(10,Math.min(10000,Number(process.env.LOAD_TEST_MAX_RPS||2500)));
let loadTestWindowSecond=0,loadTestWindowCount=0;
// v10.2 / Phase 8C hotfix: Super Admin can launch a guarded, server-managed synthetic Dealer Node load test.
// It reuses the isolated load_test_* tables and intentionally requires LOAD_TEST_ENABLED + a configured token.
let managedLoadTest={running:false,stopRequested:false,runId:'',targetNodes:0,durationSeconds:0,heartbeatIntervalMs:15000,startedAt:null,completedAt:null,totalRequests:0,successCount:0,errorCount:0,currentRps:0,p95Ms:0,p99Ms:0,lastError:''};

// Phase 9B: controlled resilience drill guard. Maintenance mode is application-level only:
// it temporarily rejects normal mutating API traffic with HTTP 503 while Super Admin remains available.
let maintenanceRuntime={enabled:false,reason:'',startedAt:null,expiresAt:null,startedBy:'',updatedAt:null};
function maintenanceActive(){
  if(!maintenanceRuntime.enabled)return false;
  if(maintenanceRuntime.expiresAt&&Date.now()>=Date.parse(maintenanceRuntime.expiresAt)){
    maintenanceRuntime.enabled=false;
    pool.query("UPDATE resilience_control_state SET maintenance_enabled=FALSE,updated_at=$1 WHERE id=1",[now()]).catch(()=>{});
    return false;
  }
  return true;
}
async function loadMaintenanceRuntime(){
  try{
    const r=(await pool.query("SELECT * FROM resilience_control_state WHERE id=1")).rows[0];
    if(r)maintenanceRuntime={enabled:!!r.maintenance_enabled,reason:r.reason||'',startedAt:r.started_at||null,expiresAt:r.expires_at||null,startedBy:r.started_by||'',updatedAt:r.updated_at||null};
    maintenanceActive();
  }catch{}
  return maintenanceRuntime;
}



// Phase 9C-9F: Production Resilience Suite（商用韌性驗證中心）.
// Synthetic tests are isolated from dealership tables. Destructive PostgreSQL promotion is intentionally excluded.
const resilienceJobs=new Map();
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
function suitePublic(j){if(!j)return null;const {cancelRequested,...x}=j;return x}
async function createSuiteRun(phase,testType,title,config,actor){
  const suiteId=`rs_${phase.toLowerCase()}_${crypto.randomUUID()}`,startedAt=now();
  await pool.query(`INSERT INTO resilience_suite_runs(suite_id,phase,test_type,status,title,config,result,started_at,actor) VALUES($1,$2,$3,'running',$4,$5::jsonb,'{}'::jsonb,$6,$7)`,[suiteId,phase,testType,title,JSON.stringify(config||{}),startedAt,actor]);
  const j={suiteId,phase,testType,title,status:'running',config:config||{},result:{},startedAt,completedAt:null,actor,progress:0,cancelRequested:false};resilienceJobs.set(suiteId,j);return j;
}
async function finishSuiteRun(j,status,result){j.status=status;j.result=result||{};j.completedAt=now();j.progress=100;await pool.query('UPDATE resilience_suite_runs SET status=$1,result=$2::jsonb,completed_at=$3 WHERE suite_id=$4',[status,JSON.stringify(j.result),j.completedAt,j.suiteId]);return suitePublic(j)}
async function suiteRows(){const rows=(await pool.query('SELECT * FROM resilience_suite_runs ORDER BY id DESC LIMIT 100')).rows;return rows.map(r=>({...r,live:suitePublic(resilienceJobs.get(r.suite_id))}))}
async function phase9cReconnectStorm(j){
  const cfg=j.config,nodes=Math.max(100,Math.min(10000,Number(cfg.nodes||10000))),jitterMs=Math.max(250,Math.min(30000,Number(cfg.jitterMs||10000))),concurrency=Math.max(10,Math.min(500,Number(cfg.concurrency||150))),maxAttempts=3;
  const before=await collectSystemMetrics(),started=Date.now(),lat=[],attempts={};let ok=0,failed=0,idx=0;
  async function worker(){while(idx<nodes&&!j.cancelRequested){const n=++idx;await sleep(Math.floor(Math.random()*jitterMs));let good=false;for(let a=1;a<=maxAttempts&&!good;a++){attempts[a]=(attempts[a]||0)+1;const t=process.hrtime.bigint();try{await pool.query(`INSERT INTO load_test_nodes(node_id,run_id,virtual_company_id,app_version,last_seq,payload_bytes,last_seen_at) VALUES($1,$2,$3,'0.11.0',$4,512,$5) ON CONFLICT(node_id) DO UPDATE SET run_id=EXCLUDED.run_id,last_seq=EXCLUDED.last_seq,last_seen_at=EXCLUDED.last_seen_at`,[`storm_${j.suiteId}_${n}`,j.suiteId,`storm_company_${n}`,a,now()]);good=true;ok++}catch{if(a<maxAttempts)await sleep(Math.min(2000,250*2**(a-1)+Math.random()*250));else failed++}finally{lat.push(Number(process.hrtime.bigint()-t)/1e6)}}j.progress=Math.min(99,Math.round((ok+failed)/nodes*100));}}
  await Promise.all(Array.from({length:Math.min(concurrency,nodes)},worker));const after=await collectSystemMetrics(),elapsed=(Date.now()-started)/1000,rate=nodes?ok/nodes:0;
  const result={nodes,successCount:ok,failedCount:failed,reconnectSuccessRate:rate,recoverySeconds:elapsed,p95Ms:percentile(lat,.95),p99Ms:percentile(lat,.99),attempts,before,after,jitterMs,backoff:'exponential'};
  const status=j.cancelRequested?'cancelled':rate>=.99&&result.p95Ms<1000?'passed':rate>=.95?'warning':'failed';return finishSuiteRun(j,status,result);
}
async function phase9dFaultRecovery(j){
  const samples=[];let failures=0;for(let i=0;i<20&&!j.cancelRequested;i++){const t=process.hrtime.bigint();try{await Promise.race([pool.query('SELECT 1 AS ok'),new Promise((_,rej)=>setTimeout(()=>rej(new Error('timeout')),1500))]);samples.push(Number(process.hrtime.bigint()-t)/1e6)}catch{failures++}await sleep(100)}
  const m=await collectSystemMetrics();const errorRate=failures/20;const result={probeCount:20,failures,errorRate,p95Ms:percentile(samples,.95),pgWaiting:m.pgWaiting,pgQueryMs:m.pgQueryMs,apiP95Ms:m.apiP95Ms,eventLoopP95Ms:m.eventLoopP95Ms,note:'安全故障恢復驗證：不會關閉正式 PostgreSQL，也不會自動 Promote。'};
  const status=j.cancelRequested?'cancelled':errorRate===0&&m.pgWaiting===0?'passed':errorRate<=.05?'warning':'failed';return finishSuiteRun(j,status,result);
}
async function phase9eDisasterRecovery(j){
  let stage='尋找最近備份',b=null,backupSource='latest-existing',freshBackupReason='';
  const start=Date.now();
  try{
    b=(await pool.query("SELECT backup_id,started_at,completed_at,local_path,offsite_status,verification_status,drill_status,row_count,table_count FROM central_backup_events WHERE status IN ('success','partial') ORDER BY id DESC LIMIT 1")).rows[0]||null;
    // Render 的本機磁碟可能在重新部署後被清空；如果 DB 還留著舊備份紀錄、但實體檔已不存在，
    // 9E 會自動建立一份新的隔離驗證備份，避免只因 ephemeral disk 而得到沒有意義的 FAIL。
    if(b?.local_path){
      try{await fs.access(b.local_path)}catch{freshBackupReason='最近備份紀錄存在，但本機備份檔已不存在（常見於 Render 重新部署後的 ephemeral disk）。';b=null}
    }else if(b){freshBackupReason='最近備份紀錄沒有可讀取的本機備份檔。';b=null}
    if(!b){
      stage='建立本次 9E 驗證用中央備份';
      const created=await createCentralBackup('resilience_9e',j.actor);
      b=(await pool.query('SELECT backup_id,started_at,completed_at,local_path,offsite_status,verification_status,drill_status,row_count,table_count FROM central_backup_events WHERE backup_id=$1',[created.backupId])).rows[0];
      backupSource='fresh-created-for-9e';
    }
    stage='驗證備份完整性';
    const verified=await verifyCentralBackup(b.backup_id,j.actor);
    stage='執行隔離 Restore Drill';
    const r=await drillCentralBackup(b.backup_id,j.actor);
    stage='計算 RTO / RPO';
    const rto=(Date.now()-start)/1000;
    const backupAt=Date.parse(verified.createdAt||b.completed_at||b.started_at||'');
    const rpo=Number.isFinite(backupAt)?Math.max(0,(Date.now()-backupAt)/1000):null;
    return finishSuiteRun(j,'passed',{backupId:b.backup_id,restoreId:r.restoreId,rowCount:r.rowCount,tableCount:r.tableCount,rtoSeconds:rto,rpoSeconds:rpo,mode:'transactional-temp-table-drill',productionDataChanged:false,backupSource,freshBackupReason,verification:'passed',detail:`備份驗證與隔離 Restore Drill 通過，共驗證 ${Number(r.rowCount||0).toLocaleString()} 筆資料。`})
  }catch(e){
    const msg=String(e?.message||e);
    let hint='請查看中央備份頁與錯誤診斷中心。';
    if(/ENOENT|no such file|找不到.*檔|本機檔案/i.test(msg))hint='備份紀錄存在，但實體檔案不存在；Render 重新部署可能清除本機 ephemeral disk。重新執行 9E 會嘗試建立新備份。';
    else if(/Schema 不相容/i.test(msg))hint='備份 Schema 與目前資料庫版本不同，請先建立新版中央備份後再測。';
    else if(/SHA-256/i.test(msg))hint='備份檔完整性驗證失敗，請建立新備份並檢查儲存環境。';
    else if(/中央備份正在執行中|另一個 Server Instance/i.test(msg))hint='目前已有備份工作執行中，等待完成後再執行 9E。';
    return finishSuiteRun(j,'failed',{error:msg,failureStage:stage,hint,backupId:b?.backup_id||null,backupSource,freshBackupReason,rtoSeconds:(Date.now()-start)/1000,productionDataChanged:false})
  }
}
async function phase9fSoak(j){
  const hours=Math.max(1,Math.min(72,Number(j.config.hours||1))),startedMs=Date.now(),end=startedMs+hours*3600000;
  let first=null,last=null,maxRss=0,maxP95=0,maxWait=0,maxErrorRate=0,maxEventLoop=0,samples=0;
  while(Date.now()<end&&!j.cancelRequested){
    const m=await collectSystemMetrics();first=first||m;last=m;maxRss=Math.max(maxRss,m.rssBytes);maxP95=Math.max(maxP95,m.apiP95Ms);maxWait=Math.max(maxWait,m.pgWaiting);maxErrorRate=Math.max(maxErrorRate,Number(m.apiErrorRate||0));maxEventLoop=Math.max(maxEventLoop,Number(m.eventLoopP95Ms||0));samples++;
    await pool.query(`INSERT INTO resilience_soak_samples(suite_id,sampled_at,cpu_percent,rss_bytes,api_p95_ms,api_error_rate,pg_waiting,event_loop_p95_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,[j.suiteId,m.sampledAt,m.cpuPercent,m.rssBytes,m.apiP95Ms,m.apiErrorRate,m.pgWaiting,m.eventLoopP95Ms]);
    j.progress=Math.min(99,Math.round((Date.now()-startedMs)/(hours*3600000)*100));
    // 以短間隔等待，讓「提前停止」不必等滿下一個 60 秒採樣週期才生效。
    for(let waited=0;waited<60000&&Date.now()<end&&!j.cancelRequested;waited+=2000)await sleep(Math.min(2000,60000-waited));
  }
  const stoppedMs=Date.now(),actualSeconds=Math.max(0,(stoppedMs-startedMs)/1000),growth=first&&last?last.rssBytes-first.rssBytes:0,growthPct=first?.rssBytes?growth/first.rssBytes*100:0;
  const healthy=samples>0&&growthPct<25&&maxP95<1000&&maxWait<5&&maxErrorRate<0.01&&maxEventLoop<100;
  const earlyStopped=!!j.cancelRequested;
  const result={requestedHours:hours,actualRunSeconds:actualSeconds,actualRunMinutes:actualSeconds/60,earlyStopped,stopMode:earlyStopped?'manual_early_stop':'completed',samples,memoryGrowthBytes:growth,memoryGrowthPercent:growthPct,maxRssBytes:maxRss,maxApiP95Ms:maxP95,maxPgWaiting:maxWait,maxApiErrorRate:maxErrorRate,maxEventLoopP95Ms:maxEventLoop,startedMetric:first,endedMetric:last,note:earlyStopped?'本次由 Super Admin 手動提前停止；PASS/FAIL 僅代表實際運行期間的監測結果，不代表已完成原設定耐久時數。':'已跑滿原設定耐久測試時間。'};
  // 使用者要求：提前停止時也立即結算；停止前全部正常就 PASS，否則 FAIL，並保留 Early Stop 標記與實際運行時間。
  const status=earlyStopped?(healthy?'passed':'failed'):(healthy?'passed':(growthPct<50&&maxP95<2000?'warning':'failed'));
  return finishSuiteRun(j,status,result);
}
async function launchSuite(phase,config,actor){
  const defs={C:{type:'reconnect_storm',title:'Phase 9C｜Node Reconnect Storm（節點重連風暴）',fn:phase9cReconnectStorm},D:{type:'fault_recovery',title:'Phase 9D｜PostgreSQL / API Fault Recovery（故障恢復）',fn:phase9dFaultRecovery},E:{type:'disaster_recovery',title:'Phase 9E｜Disaster Recovery（災難復原驗證）',fn:phase9eDisasterRecovery},F:{type:'soak_test',title:'Phase 9F｜Soak Test（長時間耐久測試）',fn:phase9fSoak}};const d=defs[phase];if(!d)throw new Error('未知 Phase');const j=await createSuiteRun(`9${phase}`,d.type,d.title,config,actor);d.fn(j).catch(e=>finishSuiteRun(j,'failed',{error:String(e?.message||e)}).catch(()=>{}));return suitePublic(j);
}

// Phase 8C: lightweight central performance telemetry. Technical metrics are Super Admin only.
const METRICS_SAMPLE_MS=Math.max(5000,Math.min(60000,Number(process.env.METRICS_SAMPLE_MS||15000)));
const METRICS_RETENTION_HOURS=Math.max(1,Math.min(24*30,Number(process.env.METRICS_RETENTION_HOURS||72)));
// Phase 8D: sustained anomaly + capacity alert engine. An alert opens only after consecutive bad samples.
const ALERT_TRIGGER_SAMPLES=Math.max(2,Math.min(20,Number(process.env.ALERT_TRIGGER_SAMPLES||4)));
const ALERT_RECOVERY_SAMPLES=Math.max(2,Math.min(20,Number(process.env.ALERT_RECOVERY_SAMPLES||3)));
const ALERT_CPU_PERCENT=Math.max(1,Math.min(100,Number(process.env.ALERT_CPU_PERCENT||80)));
const ALERT_RAM_PERCENT=Math.max(1,Math.min(100,Number(process.env.ALERT_RAM_PERCENT||85)));
const ALERT_API_P95_MS=Math.max(50,Number(process.env.ALERT_API_P95_MS||500));
const ALERT_API_5XX_RATE=Math.max(0,Math.min(1,Number(process.env.ALERT_API_5XX_RATE||0.01)));
const ALERT_EVENT_LOOP_P95_MS=Math.max(10,Number(process.env.ALERT_EVENT_LOOP_P95_MS||100));
const ALERT_PG_WAITING=Math.max(1,Number(process.env.ALERT_PG_WAITING||1));
const ALERT_CAPACITY_PERCENT=Math.max(1,Math.min(100,Number(process.env.ALERT_CAPACITY_PERCENT||80)));
const alertRuntime=new Map();
const eventLoopMonitor=monitorEventLoopDelay({resolution:20}); eventLoopMonitor.enable();
let perfLastCpu=process.cpuUsage(),perfLastWall=process.hrtime.bigint();
let apiPerfWindow=[];
function percentile(values,p){if(!values.length)return 0;const a=[...values].sort((x,y)=>x-y);return Number(a[Math.min(a.length-1,Math.max(0,Math.ceil(a.length*p)-1))]||0)}
function recordApiPerf(ms,status){const t=Date.now();apiPerfWindow.push({t,ms:Number(ms||0),status:Number(status||0)});const cutoff=t-60000;if(apiPerfWindow.length>20000||apiPerfWindow[0]?.t<cutoff)apiPerfWindow=apiPerfWindow.filter(x=>x.t>=cutoff)}
function apiPerfSnapshot(){const cutoff=Date.now()-60000;const a=apiPerfWindow.filter(x=>x.t>=cutoff);const lat=a.map(x=>x.ms),errors=a.filter(x=>x.status>=500).length;return {count:a.length,rps:a.length/60,p50Ms:percentile(lat,.50),p95Ms:percentile(lat,.95),p99Ms:percentile(lat,.99),errorRate:a.length?errors/a.length:0}}
function processCpuPercent(){const cur=process.cpuUsage(),wall=process.hrtime.bigint();const cpuUs=(cur.user-perfLastCpu.user)+(cur.system-perfLastCpu.system);const wallUs=Number(wall-perfLastWall)/1000;perfLastCpu=cur;perfLastWall=wall;return wallUs>0?Math.min(100,(cpuUs/wallUs)*100):0}
async function collectSystemMetrics(){
  const mem=process.memoryUsage(),api=apiPerfSnapshot(),cpu=processCpuPercent();
  const elP95=Number(eventLoopMonitor.percentile(95)/1e6||0),elMax=Number(eventLoopMonitor.max/1e6||0); eventLoopMonitor.reset();
  let pgQueryMs=0,pgOk=true;const q0=process.hrtime.bigint();try{await pool.query('SELECT 1')}catch{pgOk=false}finally{pgQueryMs=Number(process.hrtime.bigint()-q0)/1e6}
  return {sampledAt:now(),instanceId:CENTRAL_HA_INSTANCE_ID,site:CENTRAL_HA_SITE,cpuPercent:cpu,rssBytes:mem.rss,heapUsedBytes:mem.heapUsed,heapTotalBytes:mem.heapTotal,systemFreeBytes:os.freemem(),systemTotalBytes:os.totalmem(),eventLoopP95Ms:elP95,eventLoopMaxMs:elMax,apiRps:api.rps,apiP50Ms:api.p50Ms,apiP95Ms:api.p95Ms,apiP99Ms:api.p99Ms,apiErrorRate:api.errorRate,pgTotal:Number(pool.totalCount||0),pgIdle:Number(pool.idleCount||0),pgWaiting:Number(pool.waitingCount||0),pgQueryMs,pgOk,uptimeSeconds:Math.round(process.uptime()),loadAvg1:Number(os.loadavg()[0]||0),cpuCores:os.cpus().length};
}
function assessPerformance(m){const issues=[];let score=100;if(m.cpuPercent>=85){score-=25;issues.push('Node.js CPU 使用率過高')}else if(m.cpuPercent>=70){score-=10;issues.push('CPU 使用率偏高')}const memRatio=m.systemTotalBytes?1-m.systemFreeBytes/m.systemTotalBytes:0;if(memRatio>=.9){score-=20;issues.push('系統記憶體使用率超過 90%')}if(m.eventLoopP95Ms>=100){score-=25;issues.push('Event Loop 延遲嚴重')}else if(m.eventLoopP95Ms>=40){score-=10;issues.push('Event Loop 延遲偏高')}if(m.pgWaiting>0){score-=Math.min(25,m.pgWaiting*5);issues.push(`PostgreSQL 等待連線 ${m.pgWaiting}`)}if(m.pgQueryMs>=200){score-=20;issues.push('PostgreSQL 基礎查詢延遲過高')}else if(m.pgQueryMs>=80){score-=8;issues.push('PostgreSQL 查詢延遲偏高')}if(m.apiErrorRate>=.02){score-=25;issues.push('API 5xx 錯誤率偏高')}if(m.apiP95Ms>=1000){score-=20;issues.push('API P95 延遲過高')}else if(m.apiP95Ms>=500){score-=8;issues.push('API P95 延遲偏高')}score=Math.max(0,score);let bottleneck='none';if(m.pgWaiting>0||m.pgQueryMs>=200)bottleneck='postgres';else if(m.eventLoopP95Ms>=100)bottleneck='event_loop';else if(m.cpuPercent>=85)bottleneck='cpu';else if(memRatio>=.9)bottleneck='memory';else if(m.apiP95Ms>=1000)bottleneck='api_latency';else if(m.apiErrorRate>=.02)bottleneck='api_errors';return {score,grade:score>=90?'A':score>=80?'B':score>=65?'C':score>=50?'D':'F',bottleneck,issues,memoryPercent:memRatio*100};}

function alertDefinitions(m,capacity){
  const ramPct=m.systemTotalBytes?(1-m.systemFreeBytes/m.systemTotalBytes)*100:0;
  const capPct=Number(capacity?.usagePercent||0);
  return [
    {key:'cpu_high',bad:m.cpuPercent>=ALERT_CPU_PERCENT,severity:'warning',title:'CPU 負載偏高',message:`CPU Usage（處理器使用率） ${m.cpuPercent.toFixed(1)}%，已達警戒值 ${ALERT_CPU_PERCENT}%`,impact:'中央 Server 可用運算餘裕下降，API 回應可能逐漸變慢。',advice:'檢查是否正在壓力測試、大量同步或有高 CPU 工作；若持續發生，準備增加 CPU 資源。',value:m.cpuPercent,threshold:ALERT_CPU_PERCENT,unit:'%'},
    {key:'ram_high',bad:ramPct>=ALERT_RAM_PERCENT,severity:'warning',title:'RAM 使用率偏高',message:`RAM Usage（系統記憶體使用率） ${ramPct.toFixed(1)}%，已達警戒值 ${ALERT_RAM_PERCENT}%`,impact:'主機可用記憶體不足時可能增加交換或造成程序不穩定。',advice:'檢查其他程序與 Node.js 記憶體使用；若持續升高，增加 RAM 或排查記憶體異常。',value:ramPct,threshold:ALERT_RAM_PERCENT,unit:'%'},
    {key:'api_p95_high',bad:m.apiP95Ms>=ALERT_API_P95_MS,severity:m.apiP95Ms>=1000?'critical':'warning',title:'API 回應延遲偏高',message:`API P95（95% 請求回應時間） ${m.apiP95Ms.toFixed(1)} ms，警戒值 ${ALERT_API_P95_MS} ms`,impact:'多數使用者操作可能開始感覺變慢。',advice:'對照 CPU、Event Loop 與 PostgreSQL 指標，找出延遲來源。',value:m.apiP95Ms,threshold:ALERT_API_P95_MS,unit:'ms'},
    {key:'api_5xx_high',bad:m.apiErrorRate>=ALERT_API_5XX_RATE,severity:'critical',title:'API 伺服器錯誤率偏高',message:`API 5xx Rate（伺服器錯誤率） ${(m.apiErrorRate*100).toFixed(3)}%，警戒值 ${(ALERT_API_5XX_RATE*100).toFixed(2)}%`,impact:'部分登入、同步或管理操作可能直接失敗。',advice:'立即查看 Phase 5A 錯誤診斷中心與 Server log，確認共同錯誤來源。',value:m.apiErrorRate*100,threshold:ALERT_API_5XX_RATE*100,unit:'%'},
    {key:'event_loop_high',bad:m.eventLoopP95Ms>=ALERT_EVENT_LOOP_P95_MS,severity:'critical',title:'Event Loop 延遲過高',message:`Event Loop P95（事件迴圈延遲） ${m.eventLoopP95Ms.toFixed(1)} ms，警戒值 ${ALERT_EVENT_LOOP_P95_MS} ms`,impact:'Node.js 主執行緒忙碌，API 可能整體卡頓。',advice:'檢查同步 CPU 工作、過大的 JSON 處理或高併發工作。',value:m.eventLoopP95Ms,threshold:ALERT_EVENT_LOOP_P95_MS,unit:'ms'},
    {key:'pg_waiting',bad:m.pgWaiting>=ALERT_PG_WAITING,severity:'critical',title:'PostgreSQL 連線池壅塞',message:`Waiting Connections（等待中的資料庫連線） ${m.pgWaiting}，警戒值 ${ALERT_PG_WAITING}`,impact:'API 正在等待可用資料庫連線，延遲可能快速上升。',advice:'檢查 Connection Pool（資料庫連線池）、慢查詢與 PostgreSQL 負載。',value:m.pgWaiting,threshold:ALERT_PG_WAITING,unit:'connections'},
    {key:'capacity_high',bad:capPct>=ALERT_CAPACITY_PERCENT,severity:capPct>=90?'critical':'capacity',title:'接近安全容量上限',message:`Capacity Usage（安全容量使用率） ${capPct.toFixed(1)}%，警戒值 ${ALERT_CAPACITY_PERCENT}%`,impact:`目前約 ${Number(capacity?.onlineNodes||0).toLocaleString()} 個 Dealer Node；最近壓測安全容量約 ${Number(capacity?.safeNodes||0).toLocaleString()}。`,advice:'準備擴充中央服務資源，並在擴充後重新執行 Phase 8A 壓力測試確認新安全容量。',value:capPct,threshold:ALERT_CAPACITY_PERCENT,unit:'%'}
  ];
}
async function getCapacityAlertSnapshot(){
  let onlineNodes=0,safeNodes=0,sourceRunId='';
  try{onlineNodes=Number((await pool.query('SELECT COUNT(*)::int AS n FROM dealer_nodes WHERE last_seen_at >= $1',[new Date(Date.now()-60000).toISOString()])).rows[0]?.n||0)}catch{}
  try{const r=(await pool.query("SELECT run_id,analysis,estimated_nodes FROM load_test_runs WHERE status IN ('completed','completed_with_errors') ORDER BY capacity_score DESC,started_at DESC LIMIT 1")).rows[0];if(r){safeNodes=Number(r.analysis?.recommendedNodes||r.estimated_nodes||0);sourceRunId=String(r.run_id||'')}}catch{}
  return {onlineNodes,safeNodes,usagePercent:safeNodes>0?onlineNodes/safeNodes*100:0,sourceRunId};
}
async function evaluatePerformanceAlerts(m){
  const capacity=await getCapacityAlertSnapshot(),defs=alertDefinitions(m,capacity),ts=now();
  for(const d of defs){
    const st=alertRuntime.get(d.key)||{bad:0,good:0,active:false};
    if(d.bad){st.bad++;st.good=0}else{st.good++;st.bad=0}
    if(!st.active&&d.bad&&st.bad>=ALERT_TRIGGER_SAMPLES){
      st.active=true;
      await pool.query(`INSERT INTO performance_alert_events(alert_key,severity,status,title,message,impact,advice,value,threshold,unit,opened_at,last_seen_at,occurrence_count,context) VALUES($1,$2,'open',$3,$4,$5,$6,$7,$8,$9,$10,$10,1,$11::jsonb) ON CONFLICT (alert_key) WHERE status='open' DO UPDATE SET severity=excluded.severity,title=excluded.title,message=excluded.message,impact=excluded.impact,advice=excluded.advice,value=excluded.value,threshold=excluded.threshold,unit=excluded.unit,last_seen_at=excluded.last_seen_at,occurrence_count=performance_alert_events.occurrence_count+1,context=excluded.context`,[d.key,d.severity,d.title,d.message,d.impact,d.advice,d.value,d.threshold,d.unit,ts,JSON.stringify({instanceId:m.instanceId,site:m.site,capacity})]);
      await recordDiagnostic('',`PERF_${d.key.toUpperCase()}`,'performance_alert',d.message,{severity:d.severity==='critical'?'critical':'warn',context:{impact:d.impact,advice:d.advice,value:d.value,threshold:d.threshold,unit:d.unit,capacity}});
    }else if(st.active&&d.bad){
      await pool.query(`UPDATE performance_alert_events SET severity=$1,message=$2,impact=$3,advice=$4,value=$5,threshold=$6,unit=$7,last_seen_at=$8,occurrence_count=occurrence_count+1,context=$9::jsonb WHERE alert_key=$10 AND status='open'`,[d.severity,d.message,d.impact,d.advice,d.value,d.threshold,d.unit,ts,JSON.stringify({instanceId:m.instanceId,site:m.site,capacity}),d.key]);
    }else if(st.active&&!d.bad&&st.good>=ALERT_RECOVERY_SAMPLES){
      st.active=false;
      await pool.query(`UPDATE performance_alert_events SET status='recovered',recovered_at=$1,last_seen_at=$1 WHERE alert_key=$2 AND status='open'`,[ts,d.key]);
      try{await pool.query(`UPDATE diagnostic_events SET resolved=TRUE,resolved_at=$1 WHERE company_id='' AND module='performance_alert' AND error_code=$2 AND resolved=FALSE`,[ts,`PERF_${d.key.toUpperCase()}`])}catch{}
    }
    alertRuntime.set(d.key,st);
  }
  return capacity;
}
async function getPerformanceAlertCenter(){
  const capacity=await getCapacityAlertSnapshot();
  let events=[];try{events=(await pool.query(`SELECT * FROM performance_alert_events ORDER BY CASE WHEN status='open' THEN 0 ELSE 1 END, last_seen_at DESC LIMIT 100`)).rows}catch{}
  const open=events.filter(x=>x.status==='open');
  let level='normal';if(open.some(x=>x.severity==='critical'))level='critical';else if(open.some(x=>x.severity==='capacity'))level='capacity';else if(open.length)level='warning';
  return {level,openCount:open.length,events,capacity,thresholds:{triggerSamples:ALERT_TRIGGER_SAMPLES,recoverySamples:ALERT_RECOVERY_SAMPLES,cpuPercent:ALERT_CPU_PERCENT,ramPercent:ALERT_RAM_PERCENT,apiP95Ms:ALERT_API_P95_MS,api5xxPercent:ALERT_API_5XX_RATE*100,eventLoopP95Ms:ALERT_EVENT_LOOP_P95_MS,pgWaiting:ALERT_PG_WAITING,capacityPercent:ALERT_CAPACITY_PERCENT}};
}


function b64url(v){return Buffer.from(v).toString('base64url')}
function offlineVerifier(password){const salt=crypto.randomBytes(16).toString('hex');const hash=crypto.scryptSync(String(password),salt,64,{N:16384,r:8,p:1}).toString('hex');return `${salt}:${hash}`;}
function issueOfflineTicket(company,user,password,seconds=OFFLINE_GRACE_SECONDS){
  const issuedAtMs=Date.now(); const duration=Math.max(5,Math.min(Number(seconds)||OFFLINE_GRACE_SECONDS,OFFLINE_GRACE_SECONDS));
  const payload={v:1,company:companyDto(company),user:userDto(user),companyId:company.id,userId:user.id,username:user.username,role:user.role,tokenVersion:Number(user.token_version||0),issuedAtMs,offlineUntilMs:issuedAtMs+duration*1000,offlineVerifier:offlineVerifier(password)};
  const body=b64url(JSON.stringify(payload)); const sig=crypto.sign(null,Buffer.from(body),OFFLINE_LICENSE_PRIVATE_KEY).toString('base64url'); return `${body}.${sig}`;
}

function issueSalesLanAuthBundle(company,users,seconds=OFFLINE_GRACE_SECONDS){
  const issuedAtMs=Date.now();
  const duration=Math.max(5,Math.min(Number(seconds)||OFFLINE_GRACE_SECONDS,OFFLINE_GRACE_SECONDS));
  const payload={v:1,type:'sales-lan-auth',companyId:company.id,company:companyDto(company),issuedAtMs,offlineUntilMs:issuedAtMs+duration*1000,users:(users||[]).filter(u=>u.role==='sales'&&u.enabled!==false).map(u=>({id:u.id,username:u.username,name:u.name,role:'sales',commissionRate:Number(u.commission_rate||0),baseSalary:Number(u.base_salary||0),tokenVersion:Number(u.token_version||0),passwordHash:String(u.password_hash||''),branchId:String(u.branch_id||'')}))};
  const body=b64url(JSON.stringify(payload));
  const sig=crypto.sign(null,Buffer.from(body),OFFLINE_LICENSE_PRIVATE_KEY).toString('base64url');
  return `${body}.${sig}`;
}

if (!DATABASE_URL) {
  console.error('FATAL: DATABASE_URL is missing.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : false
});

function now(){ return new Date().toISOString(); }
function taiwanDateParts(date=new Date()){
  const parts=new Intl.DateTimeFormat('en-US',{timeZone:'Asia/Taipei',year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(date);
  const get=t=>parts.find(p=>p.type===t)?.value||'';
  return {year:get('year'),month:get('month'),day:get('day')};
}
function today(){ const p=taiwanDateParts(); return `${p.year}-${p.month}-${p.day}`; }
function addDays(n){
  const p=taiwanDateParts();
  const d=new Date(Date.UTC(Number(p.year),Number(p.month)-1,Number(p.day)));
  d.setUTCDate(d.getUTCDate()+Number(n||0));
  return d.toISOString().slice(0,10);
}
function cleanCode(v){ return String(v||'').trim(); }

function hashPassword(password, salt=crypto.randomBytes(16).toString('hex')){
  const hash=crypto.scryptSync(String(password),salt,64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored){
  try{
    const [salt,hash]=String(stored).split(':');
    const calc=crypto.scryptSync(String(password),salt,64);
    return crypto.timingSafeEqual(calc,Buffer.from(hash,'hex'));
  }catch{return false;}
}
function companyStatus(c){
  const t=today();
  if(!c.enabled)return '已停用';
  if(c.start_date&&c.start_date>t)return '尚未啟用';
  if(c.expires_at&&c.expires_at<t)return '已到期';
  return '啟用中';
}
function companyDto(c){
  return {
    id:c.id,
    name:c.name,
    enabled:!!c.enabled,
    startDate:c.start_date||'',
    expiresAt:c.expires_at||'',
    createdAt:c.created_at,
    createdBy:c.created_by,
    contactEmail:c.contact_email||'',
    trial:!!c.trial,
    status:companyStatus(c),
    lastOnlineAt:c.last_auth_at||'',
    trialRemainingSeconds:c.expires_at?Math.max(0,Math.floor((new Date(c.expires_at+'T23:59:59+08:00').getTime()-Date.now())/1000)):null,
    mainUsername:c.main_username||'',
    payrollCostMode:['realtime_estimate','settled_only'].includes(String(c.payroll_cost_mode||''))?String(c.payroll_cost_mode):'realtime_estimate',
    ownerUserId:c.owner_user_id||'',
    systemActivationDate:c.system_activation_date||c.start_date||'',
    systemActivationMonth:String(c.system_activation_date||c.start_date||'').slice(0,7),
    systemActivationSetAt:c.system_activation_set_at||'',
    systemActivationSetBy:c.system_activation_set_by||''
  };
}
function branchDto(b){
  return {
    id:b.id,
    companyId:b.company_id,
    code:b.code||'',
    name:b.name||'',
    isHeadOffice:!!b.is_head_office,
    enabled:!!b.enabled,
    address:b.address||'',
    phone:b.phone||'',
    saleApprovalMode:b.sale_approval_mode||'branch_manager',
    saleApproverUserId:b.sale_approver_user_id||'',
    createdAt:b.created_at||'',
    updatedAt:b.updated_at||''
  };
}
async function getCompanyBranches(companyId,client=pool,{includeDisabled=false}={}){
  const q=await client.query(`SELECT * FROM branches WHERE company_id=$1 ${includeDisabled?'':'AND enabled=TRUE'} ORDER BY is_head_office DESC,name ASC,id ASC`,[companyId]);
  return q.rows.map(branchDto);
}
async function getDefaultBranch(companyId,client=pool){
  const q=await client.query(`SELECT * FROM branches WHERE company_id=$1 ORDER BY is_head_office DESC,created_at ASC LIMIT 1`,[companyId]);
  return q.rows[0]?branchDto(q.rows[0]):null;
}
function userDto(u){
  return {
    id:u.id,
    username:u.username,
    name:u.name,
    role:u.role,
    branchId:u.branch_id||'',
    commissionRate:Number(u.commission_rate||0),
    baseSalary:Number(u.base_salary||0),
    position:u.position||'',
    salaryType:u.salary_type||'fixed',
    loginEnabled:u.login_enabled!==false,
    permissions:(u.permissions&&typeof u.permissions==='object')?u.permissions:{},
    enabled:!!u.enabled,
    passwordChangedAt:u.password_changed_at||'',
    passwordChangedBy:u.password_changed_by||''
  };
}

const ROLE_PERMISSION_DEFAULTS={
  admin:{vehicleView:true,vehicleCreate:true,vehicleEdit:true,vehicleDelete:true,vehicleTransfer:true,saleApprove:true,saleReject:true,saleCancel:true,peopleManage:true,viewCosts:true,viewReports:true,operatingCostManage:true},
  branchManager:{vehicleView:true,vehicleCreate:true,vehicleEdit:true,vehicleDelete:true,vehicleTransfer:true,saleApprove:true,saleReject:true,saleCancel:false,peopleManage:true,viewCosts:true,viewReports:true,operatingCostManage:false},
  sales:{vehicleView:true,vehicleCreate:false,vehicleEdit:false,vehicleDelete:false,vehicleTransfer:false,saleApprove:false,saleReject:false,saleCancel:false,peopleManage:false,viewCosts:false,viewReports:false,operatingCostManage:false},
  staff:{vehicleView:false,vehicleCreate:false,vehicleEdit:false,vehicleDelete:false,vehicleTransfer:false,saleApprove:false,saleReject:false,saleCancel:false,peopleManage:false,viewCosts:false,viewReports:false,operatingCostManage:false}
};
function effectivePermissions(user){return {...(ROLE_PERMISSION_DEFAULTS[user?.role]||{}),...((user?.permissions&&typeof user.permissions==='object')?user.permissions:{})}}
function hasPermission(user,key){return !!effectivePermissions(user)[key]}
async function resolveSaleApprover(companyId,branchId,client=pool){
  const branch=(await client.query('SELECT * FROM branches WHERE id=$1 AND company_id=$2',[branchId,companyId])).rows[0];
  if(!branch)return null;
  const admin=(await client.query("SELECT * FROM users WHERE company_id=$1 AND role='admin' AND enabled=TRUE ORDER BY updated_at ASC LIMIT 1",[companyId])).rows[0]||null;
  const mode=String(branch.sale_approval_mode||'branch_manager');
  if(mode==='specific_user'&&branch.sale_approver_user_id){
    const u=(await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[branch.sale_approver_user_id,companyId])).rows[0];
    if(u&&hasPermission(u,'saleApprove')&&(u.role==='admin'||String(u.branch_id||'')===String(branchId)))return {type:'specific_user',user:u};
  }
  if(mode==='branch_manager'){
    const managers=(await client.query("SELECT * FROM users WHERE company_id=$1 AND branch_id=$2 AND role='branchManager' AND enabled=TRUE ORDER BY updated_at ASC",[companyId,branchId])).rows;
    const u=managers.find(x=>hasPermission(x,'saleApprove'));
    if(u)return {type:'branch_manager',user:u};
  }
  if(admin&&hasPermission(admin,'saleApprove'))return {type:'company_admin',user:admin};
  return admin?{type:'company_admin',user:admin}:null;
}
function stampApprovalTarget(request,target){request.approvalTargetType=target?.type||'company_admin';request.approvalTargetUserId=target?.user?.id||'';request.approvalTargetName=target?.user?.name||target?.user?.username||'公司管理員';return request}
function canActOnSaleRequest(user,request){if(!user||!hasPermission(user,'saleApprove'))return false;if(!request?.approvalTargetUserId)return user.role==='admin';return String(request.approvalTargetUserId)===String(user.id||'')}

function salesSafeSnapshot(snapshot,user){
  const d=snapshot&&typeof snapshot==='object'?snapshot:{};
  const branchId=String(user?.branch_id||'');
  const cars=(Array.isArray(d.cars)?d.cars:[])
    .filter(c=>c&&c.status==='在庫'&&(!branchId||String(c.branchId||'')===branchId))
    .map(c=>({
      id:c.id,branchId:c.branchId||'',plate:c.plate||'',model:c.model||'',year:c.year||'',mileage:Number(c.mileage||0),
      inDate:c.inDate||'',floorPrice:Number(c.floorPrice||0),status:'在庫',salesNote:String(c.salesNote||''),
      commissionMode:c.commissionMode==='fixed'?'fixed':'percentage',fixedCommissionAmount:Math.max(0,Number(c.fixedCommissionAmount||0)),
      inspectionStatus:c.inspectionStatus||'',
      inspectionPhotoCount:Number(c.inspectionPhotoCount??(Array.isArray(c.inspectionCertPhotos)?c.inspectionCertPhotos.length:0)),
      intakePhotoCount:Number(c.intakePhotoCount??(Array.isArray(c.intakePhotos)?c.intakePhotos.length:0)),
      inspectionCertPhotos:Array.isArray(c.inspectionCertPhotos)?c.inspectionCertPhotos:[],
      intakePhotos:Array.isArray(c.intakePhotos)?c.intakePhotos:[]
    }));
  const requests=(Array.isArray(d.saleRequests)?d.saleRequests:[])
    .filter(r=>r&&String(r.salesId)===String(user.id))
    .map(r=>({
      id:r.id,operationId:r.operationId||'',branchId:r.branchId||'',carId:r.carId,plate:r.plate||'',model:r.model||'',floorPrice:Number(r.floorPrice||0),
      sellPrice:Number(r.sellPrice||0),saleDate:r.saleDate||'',requestedAt:r.requestedAt||'',
      salesId:r.salesId,salesName:r.salesName||user.name,commissionRate:Number(r.commissionRate??user.commission_rate??0),
      expectedCommission:Number(r.expectedCommission||0),commissionMode:r.commissionMode==='fixed'?'fixed':'percentage',fixedCommissionAmount:Math.max(0,Number(r.fixedCommissionAmount||0)),status:r.status||'待確認',
      rejectReason:r.rejectReason||'',rejectedAt:r.rejectedAt||'',confirmedAt:r.confirmedAt||'',cancelReason:r.cancelReason||'',canceledAt:r.canceledAt||''
    }));
  return {
    settings:{companyName:d.settings?.companyName||''},
    users:[{...userDto(user),password:''}],
    cars,
    saleRequests:requests
  };
}
function cloudOperationalSnapshot(snapshot){
  const d=JSON.parse(JSON.stringify(snapshot||{}));
  d.cars=(Array.isArray(d.cars)?d.cars:[]).map(c=>{
    const x={...c};
    x.inspectionPhotoCount=Array.isArray(c.inspectionCertPhotos)?c.inspectionCertPhotos.length:Number(c.inspectionPhotoCount||0);
    x.intakePhotoCount=Array.isArray(c.intakePhotos)?c.intakePhotos.length:Number(c.intakePhotoCount||0);
    // Phase 14D.3 hotfix: Central keeps a minimal financial summary for every vehicle
    // so Super Admin can show purchase price / total cost even while the Dealer Node is offline.
    // Detailed cost lines, source notes and photos remain Dealer Node local-only.
    const sold=String(c.status||'')==='已售'||Number(c.sellPrice||0)>0;
    x.purchasePrice=Math.max(0,Number(c.purchasePrice||0));
    x.totalCost=Math.max(0,Number(c.totalCost??((Number(c.purchasePrice)||0)+(Array.isArray(c.costs)?c.costs.reduce((a,b)=>a+Number(b.amount||0),0):0))));
    for(const k of ['costs','source','sourceNote','salesNote','inspectionCertPhotos','intakePhotos']) delete x[k];
    if(!sold){for(const k of ['companyProfit','saleTransferFee','saleFuelFee','saleLicenseTax','saleOtherFee','saleOtherFeeName','saleExtraCost']) delete x[k];}
    else{
      x.companyProfit=Number(c.companyProfit||0);
      x.saleExtraCost=Math.max(0,Number(c.saleExtraCost||0));
    }
    return x;
  });
  // Detailed operation/salary history is authoritative on the Dealer Node.
  delete d.operationLogs;
  delete d.salaryHistory;
  return d;
}
function branchManagerSafeSnapshot(snapshot,user){
  const d=JSON.parse(JSON.stringify(snapshot&&typeof snapshot==='object'?snapshot:{}));
  const branchId=String(user?.branch_id||'');
  const cars=(Array.isArray(d.cars)?d.cars:[]).filter(c=>String(c?.branchId||'')===branchId);
  const carIds=new Set(cars.map(c=>String(c.id)));
  const requests=(Array.isArray(d.saleRequests)?d.saleRequests:[]).filter(r=>(String(r?.branchId||'')===branchId||carIds.has(String(r?.carId||'')))&&(r.status!=='待確認'||String(r.approvalTargetUserId||'')===String(user?.id||'')));
  const users=(Array.isArray(d.users)?d.users:[]).filter(u=>String(u?.id||'')===String(user?.id||'')||(u?.role==='sales'&&String(u?.branchId||'')===branchId));
  const userIds=new Set(users.map(u=>String(u.id)));
  const salaryHistory=(Array.isArray(d.salaryHistory)?d.salaryHistory:[]).filter(x=>userIds.has(String(x?.salesId||'')));
  const operationLogs=(Array.isArray(d.operationLogs)?d.operationLogs:[]).filter(x=>carIds.has(String(x?.carId||'')));
  return {...d,settings:{...(d.settings||{}),activeBranchId:branchId},users,cars,saleRequests:requests,salaryHistory,operationLogs};
}
function staffSafeSnapshot(snapshot,user){
  const d=JSON.parse(JSON.stringify(snapshot&&typeof snapshot==='object'?snapshot:{}));
  const branchId=String(user?.branch_id||'');
  const perms=effectivePermissions(user);
  const cars=perms.vehicleView?(Array.isArray(d.cars)?d.cars:[]).filter(c=>!branchId||String(c?.branchId||'')===branchId):[];
  const carIds=new Set(cars.map(c=>String(c.id)));
  const requests=(perms.saleApprove||perms.saleReject)?(Array.isArray(d.saleRequests)?d.saleRequests:[]).filter(r=>String(r?.approvalTargetUserId||'')===String(user?.id||'')):[];
  const users=perms.peopleManage?(Array.isArray(d.users)?d.users:[]).filter(u=>!branchId||String(u?.branchId||'')===branchId):[{...userDto(user),password:''}];
  const safeCars=perms.viewCosts?cars:cars.map(c=>{const x={...c};for(const k of ['purchasePrice','costs','totalCost','source','sourceNote','companyProfit'])delete x[k];return x});
  return {...d,settings:{...(d.settings||{}),activeBranchId:branchId||d.settings?.activeBranchId},users,cars:safeCars,saleRequests:requests};
}
function snapshotForUser(snapshot,user){
  if(user?.role==='sales')return salesSafeSnapshot(snapshot,user);
  if(user?.role==='branchManager')return branchManagerSafeSnapshot(snapshot,user);
  if(user?.role==='staff')return staffSafeSnapshot(snapshot,user);
  return snapshot;
}

function signUser(u,rememberLogin=false){
  return jwt.sign(
    {sub:u.id,companyId:u.company_id,role:u.role,username:u.username,tokenVersion:Number(u.token_version||0),rememberLogin:!!rememberLogin},
    JWT_SECRET,
    {expiresIn:rememberLogin?'15d':'12h'}
  );
}
function refreshedUserToken(req,u){
  return req?.auth?.rememberLogin?signUser(u,true):null;
}
function signSuper(){
  return jwt.sign({sub:'platform-admin',role:'platformAdmin'},JWT_SECRET,{expiresIn:'12h'});
}

function cleanSemver(v){
  const m=String(v||'').trim().match(/^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/);
  return m?`${Number(m[1])}.${Number(m[2])}.${Number(m[3])}`:'0.0.0';
}
function compareSemver(a,b){
  const aa=cleanSemver(a).split('.').map(Number),bb=cleanSemver(b).split('.').map(Number);
  for(let i=0;i<3;i++){if(aa[i]>bb[i])return 1;if(aa[i]<bb[i])return -1}return 0;
}
async function getDesktopUpdatePolicy(client=pool){
  const {rows}=await client.query('SELECT * FROM desktop_update_policy WHERE id=1');
  const r=rows[0]||{};
  return {enabled:!!r.enabled,channel:String(r.channel||'stable'),latestVersion:cleanSemver(r.latest_version||'0.9.6'),minimumVersion:cleanSemver(r.minimum_version||'0.0.0'),downloadUrl:String(r.download_url||''),releaseNotes:String(r.release_notes||''),packageSha256:String(r.package_sha256||'').toLowerCase(),packageSignature:String(r.package_signature||''),updatedAt:r.updated_at||'',updatedBy:r.updated_by||''};
}
function signUpdateManifestPayload(payload){
  const body=b64url(JSON.stringify(payload));
  const signature=crypto.sign(null,Buffer.from(body),UPDATE_SIGNING_PRIVATE_KEY).toString('base64url');
  return {body,signature,keyId:UPDATE_SIGNING_KEY_ID,algorithm:'Ed25519'};
}

// Phase 3C: lightweight realtime push hub for Sales inventory changes.
// Streams carry only change notifications; actual inventory still comes through Sales-safe Node APIs.
const salesLiveClients=new Map();
function addSalesLiveClient(companyId,res){
  const key=String(companyId);
  if(!salesLiveClients.has(key))salesLiveClients.set(key,new Set());
  salesLiveClients.get(key).add(res);
}
function removeSalesLiveClient(companyId,res){
  const key=String(companyId),set=salesLiveClients.get(key);
  if(!set)return;set.delete(res);if(!set.size)salesLiveClients.delete(key);
}
function notifySalesInventoryChanged(companyId,version,reason='inventoryChanged'){
  const set=salesLiveClients.get(String(companyId));if(!set||!set.size)return;
  const payload=JSON.stringify({companyId:String(companyId),version:Number(version||0),reason,at:now()});
  for(const res of [...set]){try{res.write(`event: inventory\ndata: ${payload}\n\n`)}catch{removeSalesLiveClient(companyId,res)}}
}

async function recordSyncEvent(companyId,eventType,message='',opts={}){
  try{
    await pool.query(`INSERT INTO sync_events(company_id,event_type,status,message,actor,operation_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,[String(companyId),String(eventType),String(opts.status||'ok'),String(message||''),String(opts.actor||''),opts.operationId?String(opts.operationId):null,now()]);
  }catch(e){console.warn('sync event log failed:',e?.message||e)}
}

const DIAG_SEVERITIES=new Set(['info','warn','error','critical']);
const DIAG_SECRET_KEYS=/pass(word)?|token|authorization|cookie|secret|jwt|offlineVerifier|passwordHash/i;
function sanitizeDiagnosticContext(input,depth=0){
  if(depth>3)return '[max-depth]';
  if(input===null||input===undefined)return input;
  if(typeof input==='string')return input.slice(0,500);
  if(typeof input==='number'||typeof input==='boolean')return input;
  if(Array.isArray(input))return input.slice(0,20).map(v=>sanitizeDiagnosticContext(v,depth+1));
  if(typeof input==='object'){
    const out={};let n=0;
    for(const [k,v] of Object.entries(input)){
      if(n++>=30)break;
      out[k]=DIAG_SECRET_KEYS.test(k)?'[redacted]':sanitizeDiagnosticContext(v,depth+1);
    }
    return out;
  }
  return String(input).slice(0,500);
}
function diagnosticFingerprint(code,module,message){return crypto.createHash('sha256').update(`${code}|${module}|${String(message||'').slice(0,500)}`).digest('hex').slice(0,32)}
async function recordDiagnostic(companyId,errorCode,module,message='',opts={}){
  try{
    const code=String(errorCode||'SYSTEM_UNKNOWN').toUpperCase().replace(/[^A-Z0-9_.-]/g,'_').slice(0,64)||'SYSTEM_UNKNOWN';
    const mod=String(module||'system').replace(/[^A-Za-z0-9_.-]/g,'_').slice(0,64)||'system';
    const severity=DIAG_SEVERITIES.has(String(opts.severity||'error'))?String(opts.severity||'error'):'error';
    const msg=String(message||'').slice(0,1000),fp=diagnosticFingerprint(code,mod,msg),ts=now();
    const ctx=sanitizeDiagnosticContext(opts.context||{});
    await pool.query(`INSERT INTO diagnostic_events(company_id,error_code,module,severity,message,fingerprint,app_version,actor,first_seen_at,last_seen_at,occurrence_count,resolved,resolved_at,last_context)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,1,FALSE,NULL,$10::jsonb)
      ON CONFLICT(company_id,error_code,module,fingerprint) DO UPDATE SET severity=excluded.severity,message=excluded.message,app_version=excluded.app_version,actor=excluded.actor,last_seen_at=excluded.last_seen_at,occurrence_count=diagnostic_events.occurrence_count+1,resolved=FALSE,resolved_at=NULL,last_context=excluded.last_context`,
      [companyId?String(companyId):'',code,mod,severity,msg,fp,String(opts.appVersion||'').slice(0,40),String(opts.actor||'').slice(0,80),ts,JSON.stringify(ctx)]);
  }catch(e){console.warn('diagnostic log failed:',e?.message||e)}
}

const SERVER_SCHEMA_TARGET=32;
const SERVER_MIGRATIONS=[
  {
    version:1,
    name:'baseline-commercial-schema',
    sql:`
      CREATE TABLE IF NOT EXISTS companies(
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        start_date TEXT,
        expires_at TEXT,
        created_at TEXT NOT NULL,
        created_by TEXT NOT NULL DEFAULT 'self',
        contact_email TEXT,
        trial BOOLEAN NOT NULL DEFAULT TRUE,
        last_auth_at TEXT
      );

      CREATE TABLE IF NOT EXISTS users(
        id TEXT PRIMARY KEY,
        company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        username TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT NOT NULL,
        role TEXT NOT NULL,
        commission_rate DOUBLE PRECISION NOT NULL DEFAULT 0,
        base_salary DOUBLE PRECISION NOT NULL DEFAULT 0,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        updated_at TEXT NOT NULL,
        UNIQUE(company_id, username)
      );

      CREATE TABLE IF NOT EXISTS snapshots(
        company_id TEXT PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE,
        version INTEGER NOT NULL DEFAULT 0,
        json JSONB NOT NULL,
        updated_at TEXT NOT NULL
      );

      ALTER TABLE companies ADD COLUMN IF NOT EXISTS last_auth_at TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS base_salary DOUBLE PRECISION NOT NULL DEFAULT 0;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_by TEXT;

      CREATE TABLE IF NOT EXISTS dealer_nodes(
        company_id TEXT PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE,
        node_id TEXT NOT NULL,
        device_name TEXT,
        app_version TEXT,
        last_seen_at TEXT NOT NULL,
        local_data_bytes BIGINT NOT NULL DEFAULT 0,
        capabilities JSONB NOT NULL DEFAULT '{}'::jsonb
      );

      CREATE TABLE IF NOT EXISTS offline_license_tests(
        company_id TEXT PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE,
        enabled BOOLEAN NOT NULL DEFAULT FALSE,
        duration_seconds INTEGER NOT NULL DEFAULT 60,
        simulate_outage BOOLEAN NOT NULL DEFAULT FALSE,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS sync_events(
        id BIGSERIAL PRIMARY KEY,
        company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        event_type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ok',
        message TEXT NOT NULL DEFAULT '',
        actor TEXT NOT NULL DEFAULT '',
        operation_id TEXT,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS dealer_node_requests(
        id TEXT PRIMARY KEY,
        company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        node_id TEXT NOT NULL,
        resource TEXT NOT NULL,
        payload JSONB NOT NULL DEFAULT '{}'::jsonb,
        status TEXT NOT NULL DEFAULT 'queued',
        requested_at TEXT NOT NULL,
        claimed_at TEXT,
        completed_at TEXT,
        expires_at TEXT NOT NULL,
        result_json JSONB,
        error_text TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_sync_events_company_time ON sync_events(company_id,created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_sync_events_status ON sync_events(status,created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON dealer_nodes(last_seen_at);
      CREATE INDEX IF NOT EXISTS idx_node_requests_lookup ON dealer_node_requests(company_id,node_id,status,requested_at);
      CREATE INDEX IF NOT EXISTS idx_node_requests_expire ON dealer_node_requests(expires_at);
      CREATE INDEX IF NOT EXISTS idx_users_company ON users(company_id);
      CREATE INDEX IF NOT EXISTS idx_users_company_role ON users(company_id,role);
    `
  },
  {
    version:2,
    name:'phase4b-migration-safety-audit',
    sql:`
      CREATE TABLE IF NOT EXISTS migration_safety_events(
        id BIGSERIAL PRIMARY KEY,
        migration_version INTEGER NOT NULL,
        migration_name TEXT NOT NULL,
        status TEXT NOT NULL,
        detail TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_migration_safety_time ON migration_safety_events(created_at DESC);
    `
  },
  {
    version:3,
    name:'phase5a-diagnostic-events',
    sql:`
      CREATE TABLE IF NOT EXISTS diagnostic_events(
        id BIGSERIAL PRIMARY KEY,
        company_id TEXT NOT NULL DEFAULT '',
        error_code TEXT NOT NULL,
        module TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'error',
        message TEXT NOT NULL DEFAULT '',
        fingerprint TEXT NOT NULL,
        app_version TEXT NOT NULL DEFAULT '',
        actor TEXT NOT NULL DEFAULT '',
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        occurrence_count INTEGER NOT NULL DEFAULT 1,
        resolved BOOLEAN NOT NULL DEFAULT FALSE,
        resolved_at TEXT,
        last_context JSONB NOT NULL DEFAULT '{}'::jsonb
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_diag_dedupe ON diagnostic_events(company_id,error_code,module,fingerprint);
      CREATE INDEX IF NOT EXISTS idx_diag_company_time ON diagnostic_events(company_id,last_seen_at DESC);
      CREATE INDEX IF NOT EXISTS idx_diag_severity_time ON diagnostic_events(severity,last_seen_at DESC);
    `
  },
  {
    version:4,
    name:'phase6a-desktop-update-policy',
    sql:`
      CREATE TABLE IF NOT EXISTS desktop_update_policy(
        id INTEGER PRIMARY KEY CHECK(id=1),
        enabled BOOLEAN NOT NULL DEFAULT FALSE,
        channel TEXT NOT NULL DEFAULT 'stable',
        latest_version TEXT NOT NULL DEFAULT '0.9.6',
        minimum_version TEXT NOT NULL DEFAULT '0.0.0',
        download_url TEXT NOT NULL DEFAULT '',
        release_notes TEXT NOT NULL DEFAULT '',
        package_sha256 TEXT NOT NULL DEFAULT '',
        package_signature TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL,
        updated_by TEXT NOT NULL DEFAULT ''
      );
      INSERT INTO desktop_update_policy(id,enabled,channel,latest_version,minimum_version,download_url,release_notes,package_sha256,package_signature,updated_at,updated_by)
      VALUES(1,FALSE,'stable','0.9.6','0.0.0','','','','',CURRENT_TIMESTAMP::text,'migration')
      ON CONFLICT(id) DO NOTHING;
    `
  },
  {
    version:5,
    name:'phase6c-desktop-update-events',
    sql:`
      CREATE TABLE IF NOT EXISTS desktop_update_events(
        id BIGSERIAL PRIMARY KEY,
        company_id TEXT NOT NULL DEFAULT '',
        attempt_id TEXT NOT NULL,
        from_version TEXT NOT NULL DEFAULT '',
        target_version TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending',
        detail TEXT NOT NULL DEFAULT '',
        started_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        completed_at TEXT
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_update_attempt ON desktop_update_events(company_id,attempt_id);
      CREATE INDEX IF NOT EXISTS idx_update_events_time ON desktop_update_events(updated_at DESC);
      CREATE INDEX IF NOT EXISTS idx_update_events_company ON desktop_update_events(company_id,updated_at DESC);
    `
  },
  {
    version:6,
    name:'phase7a-central-postgresql-backup',
    sql:`
      CREATE TABLE IF NOT EXISTS central_backup_policy(
        id INTEGER PRIMARY KEY CHECK(id=1),
        enabled BOOLEAN NOT NULL DEFAULT FALSE,
        daily_hour_taipei INTEGER NOT NULL DEFAULT 3,
        retention_days INTEGER NOT NULL DEFAULT 14,
        offsite_enabled BOOLEAN NOT NULL DEFAULT FALSE,
        updated_at TEXT NOT NULL,
        updated_by TEXT NOT NULL DEFAULT ''
      );
      INSERT INTO central_backup_policy(id,enabled,daily_hour_taipei,retention_days,offsite_enabled,updated_at,updated_by)
      VALUES(1,FALSE,3,14,FALSE,CURRENT_TIMESTAMP::text,'migration') ON CONFLICT(id) DO NOTHING;
      CREATE TABLE IF NOT EXISTS central_backup_events(
        id BIGSERIAL PRIMARY KEY,
        backup_id TEXT NOT NULL UNIQUE,
        trigger_type TEXT NOT NULL DEFAULT 'manual',
        status TEXT NOT NULL DEFAULT 'running',
        started_at TEXT NOT NULL,
        completed_at TEXT,
        size_bytes BIGINT NOT NULL DEFAULT 0,
        sha256 TEXT NOT NULL DEFAULT '',
        local_path TEXT NOT NULL DEFAULT '',
        offsite_provider TEXT NOT NULL DEFAULT '',
        offsite_key TEXT NOT NULL DEFAULT '',
        offsite_status TEXT NOT NULL DEFAULT 'disabled',
        encryption TEXT NOT NULL DEFAULT 'AES-256-GCM',
        table_count INTEGER NOT NULL DEFAULT 0,
        row_count BIGINT NOT NULL DEFAULT 0,
        error_text TEXT NOT NULL DEFAULT '',
        created_by TEXT NOT NULL DEFAULT ''
      );
      CREATE INDEX IF NOT EXISTS idx_central_backup_time ON central_backup_events(started_at DESC);
      CREATE INDEX IF NOT EXISTS idx_central_backup_status ON central_backup_events(status,started_at DESC);
      UPDATE desktop_update_policy SET latest_version='0.9.6',updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v6' WHERE id=1 AND updated_by='migration' AND latest_version='0.9.5';
    `
  },
  {
    version:7,
    name:'phase7b-backup-verify-restore',
    sql:`
      ALTER TABLE central_backup_events ADD COLUMN IF NOT EXISTS verification_status TEXT NOT NULL DEFAULT 'pending';
      ALTER TABLE central_backup_events ADD COLUMN IF NOT EXISTS verified_at TEXT;
      ALTER TABLE central_backup_events ADD COLUMN IF NOT EXISTS verification_error TEXT NOT NULL DEFAULT '';
      ALTER TABLE central_backup_events ADD COLUMN IF NOT EXISTS drill_status TEXT NOT NULL DEFAULT 'not_run';
      ALTER TABLE central_backup_events ADD COLUMN IF NOT EXISTS drill_at TEXT;
      ALTER TABLE central_backup_events ADD COLUMN IF NOT EXISTS drill_error TEXT NOT NULL DEFAULT '';
      CREATE TABLE IF NOT EXISTS central_restore_events(
        id BIGSERIAL PRIMARY KEY,
        restore_id TEXT NOT NULL UNIQUE,
        backup_id TEXT NOT NULL DEFAULT '',
        safety_backup_id TEXT NOT NULL DEFAULT '',
        mode TEXT NOT NULL DEFAULT 'restore',
        status TEXT NOT NULL DEFAULT 'running',
        started_at TEXT NOT NULL,
        completed_at TEXT,
        actor TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT '',
        error_text TEXT NOT NULL DEFAULT ''
      );
      CREATE INDEX IF NOT EXISTS idx_central_restore_time ON central_restore_events(started_at DESC);
      UPDATE desktop_update_policy SET latest_version='0.9.7',updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v7' WHERE id=1 AND latest_version='0.9.6';
    `
  },
  {
    version:8,
    name:'phase7c-primary-standby-ha',
    sql:`
      CREATE TABLE IF NOT EXISTS central_ha_events(
        id BIGSERIAL PRIMARY KEY,
        instance_id TEXT NOT NULL DEFAULT '',
        site TEXT NOT NULL DEFAULT '',
        event_type TEXT NOT NULL,
        from_role TEXT NOT NULL DEFAULT '',
        to_role TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_central_ha_time ON central_ha_events(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_central_ha_instance ON central_ha_events(instance_id,created_at DESC);
      UPDATE desktop_update_policy SET latest_version='0.9.8',updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v8' WHERE id=1 AND latest_version='0.9.7';
    `
  },
  {
    version:9,
    name:'phase8a-dealer-node-load-simulator',
    sql:`
      CREATE TABLE IF NOT EXISTS load_test_nodes(
        node_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL DEFAULT '',
        virtual_company_id TEXT NOT NULL DEFAULT '',
        app_version TEXT NOT NULL DEFAULT '',
        last_seq BIGINT NOT NULL DEFAULT 0,
        payload_bytes INTEGER NOT NULL DEFAULT 0,
        last_seen_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_load_test_nodes_run ON load_test_nodes(run_id,last_seen_at DESC);
      CREATE TABLE IF NOT EXISTS load_test_runs(
        run_id TEXT PRIMARY KEY,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        status TEXT NOT NULL DEFAULT 'running',
        target_nodes INTEGER NOT NULL DEFAULT 0,
        duration_seconds INTEGER NOT NULL DEFAULT 0,
        heartbeat_interval_ms INTEGER NOT NULL DEFAULT 15000,
        concurrency INTEGER NOT NULL DEFAULT 0,
        total_requests BIGINT NOT NULL DEFAULT 0,
        success_count BIGINT NOT NULL DEFAULT 0,
        error_count BIGINT NOT NULL DEFAULT 0,
        rps DOUBLE PRECISION NOT NULL DEFAULT 0,
        p50_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
        p95_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
        p99_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
        max_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
        detail JSONB NOT NULL DEFAULT '{}'::jsonb
      );
      CREATE INDEX IF NOT EXISTS idx_load_test_runs_time ON load_test_runs(started_at DESC);
      UPDATE desktop_update_policy SET latest_version='0.9.9',updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v9' WHERE id=1 AND latest_version='0.9.8';
    `
  },
  {
    version:10,
    name:'phase8b-load-capacity-analysis',
    sql:`
      ALTER TABLE load_test_runs ADD COLUMN IF NOT EXISTS capacity_score INTEGER NOT NULL DEFAULT 0;
      ALTER TABLE load_test_runs ADD COLUMN IF NOT EXISTS estimated_nodes INTEGER NOT NULL DEFAULT 0;
      ALTER TABLE load_test_runs ADD COLUMN IF NOT EXISTS bottleneck TEXT NOT NULL DEFAULT '';
      ALTER TABLE load_test_runs ADD COLUMN IF NOT EXISTS analysis JSONB NOT NULL DEFAULT '{}'::jsonb;
      CREATE INDEX IF NOT EXISTS idx_load_test_runs_capacity ON load_test_runs(capacity_score DESC,started_at DESC);
      UPDATE desktop_update_policy SET latest_version='0.10.0',updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v10' WHERE id=1 AND latest_version='0.9.9';
    `
  },
  {
    version:11,
    name:'phase8c-system-performance-monitoring',
    sql:`
      CREATE TABLE IF NOT EXISTS system_metric_samples(
        id BIGSERIAL PRIMARY KEY,
        instance_id TEXT NOT NULL DEFAULT '',
        site TEXT NOT NULL DEFAULT '',
        sampled_at TEXT NOT NULL,
        cpu_percent DOUBLE PRECISION NOT NULL DEFAULT 0,
        rss_bytes BIGINT NOT NULL DEFAULT 0,
        heap_used_bytes BIGINT NOT NULL DEFAULT 0,
        heap_total_bytes BIGINT NOT NULL DEFAULT 0,
        system_free_bytes BIGINT NOT NULL DEFAULT 0,
        system_total_bytes BIGINT NOT NULL DEFAULT 0,
        event_loop_p95_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
        event_loop_max_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
        api_rps DOUBLE PRECISION NOT NULL DEFAULT 0,
        api_p95_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
        api_error_rate DOUBLE PRECISION NOT NULL DEFAULT 0,
        pg_total INTEGER NOT NULL DEFAULT 0,
        pg_idle INTEGER NOT NULL DEFAULT 0,
        pg_waiting INTEGER NOT NULL DEFAULT 0,
        pg_query_ms DOUBLE PRECISION NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_system_metric_samples_time ON system_metric_samples(sampled_at DESC);
      UPDATE desktop_update_policy SET latest_version='0.10.1',updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v11' WHERE id=1 AND latest_version='0.10.0';
    `
  },
  {
    version:12,
    name:'phase8d-performance-alert-center',
    sql:`
      CREATE TABLE IF NOT EXISTS performance_alert_events(
        id BIGSERIAL PRIMARY KEY,
        alert_key TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'warning',
        status TEXT NOT NULL DEFAULT 'open',
        title TEXT NOT NULL DEFAULT '',
        message TEXT NOT NULL DEFAULT '',
        impact TEXT NOT NULL DEFAULT '',
        advice TEXT NOT NULL DEFAULT '',
        value DOUBLE PRECISION NOT NULL DEFAULT 0,
        threshold DOUBLE PRECISION NOT NULL DEFAULT 0,
        unit TEXT NOT NULL DEFAULT '',
        opened_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        recovered_at TEXT,
        occurrence_count INTEGER NOT NULL DEFAULT 1,
        context JSONB NOT NULL DEFAULT '{}'::jsonb
      );
      CREATE INDEX IF NOT EXISTS idx_performance_alert_events_status_time ON performance_alert_events(status,last_seen_at DESC);
      CREATE UNIQUE INDEX IF NOT EXISTS idx_performance_alert_one_open ON performance_alert_events(alert_key) WHERE status='open';
      UPDATE desktop_update_policy SET latest_version='0.10.7',updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v12' WHERE id=1 AND latest_version IN ('0.10.1','0.10.2','0.10.3','0.10.4');
    `
  },
  {
    version:13,
    name:'phase9a-resilience-drill-center',
    sql:`
      CREATE TABLE IF NOT EXISTS resilience_drill_events(
        id BIGSERIAL PRIMARY KEY,
        drill_id TEXT NOT NULL UNIQUE,
        drill_type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'running',
        title TEXT NOT NULL DEFAULT '',
        summary TEXT NOT NULL DEFAULT '',
        detail JSONB NOT NULL DEFAULT '{}'::jsonb,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        actor TEXT NOT NULL DEFAULT ''
      );
      CREATE INDEX IF NOT EXISTS idx_resilience_drill_events_time ON resilience_drill_events(started_at DESC);
      CREATE INDEX IF NOT EXISTS idx_resilience_drill_events_type ON resilience_drill_events(drill_type,started_at DESC);
      UPDATE desktop_update_policy SET latest_version='0.10.7',updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v13' WHERE id=1 AND latest_version='0.10.7';
    `
  },
  {
    version:14,
    name:'phase9b-controlled-resilience-maintenance-state',
    sql:`
      CREATE TABLE IF NOT EXISTS resilience_control_state(
        id INTEGER PRIMARY KEY CHECK(id=1),
        maintenance_enabled BOOLEAN NOT NULL DEFAULT FALSE,
        reason TEXT NOT NULL DEFAULT '',
        started_at TEXT,
        expires_at TEXT,
        started_by TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL
      );
      INSERT INTO resilience_control_state(id,maintenance_enabled,reason,started_at,expires_at,started_by,updated_at)
      VALUES(1,FALSE,'',NULL,NULL,'',CURRENT_TIMESTAMP::text)
      ON CONFLICT(id) DO NOTHING;
      UPDATE desktop_update_policy SET latest_version='0.10.7',updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v14' WHERE id=1 AND latest_version='0.10.7';
    `
  },
  {
    version:15,
    name:'phase9c9f-production-resilience-suite',
    sql:`
      CREATE TABLE IF NOT EXISTS resilience_suite_runs(
        id BIGSERIAL PRIMARY KEY,
        suite_id TEXT NOT NULL UNIQUE,
        phase TEXT NOT NULL,
        test_type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'running',
        title TEXT NOT NULL DEFAULT '',
        config JSONB NOT NULL DEFAULT '{}'::jsonb,
        result JSONB NOT NULL DEFAULT '{}'::jsonb,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        actor TEXT NOT NULL DEFAULT ''
      );
      CREATE INDEX IF NOT EXISTS idx_resilience_suite_runs_phase_time ON resilience_suite_runs(phase,started_at DESC);
      CREATE TABLE IF NOT EXISTS resilience_soak_samples(
        id BIGSERIAL PRIMARY KEY,
        suite_id TEXT NOT NULL,
        sampled_at TEXT NOT NULL,
        cpu_percent DOUBLE PRECISION NOT NULL DEFAULT 0,
        rss_bytes BIGINT NOT NULL DEFAULT 0,
        api_p95_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
        api_error_rate DOUBLE PRECISION NOT NULL DEFAULT 0,
        pg_waiting INTEGER NOT NULL DEFAULT 0,
        event_loop_p95_ms DOUBLE PRECISION NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_resilience_soak_samples_suite_time ON resilience_soak_samples(suite_id,sampled_at);
      UPDATE desktop_update_policy SET latest_version='0.11.0',updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v15' WHERE id=1;
    `
  },
  {
    version:16,
    name:'phase10-security-audit-integrity-release-governance',
    sql:`
      CREATE TABLE IF NOT EXISTS security_audit_events(
        id BIGSERIAL PRIMARY KEY,
        actor TEXT NOT NULL DEFAULT '', actor_role TEXT NOT NULL DEFAULT '', company_id TEXT NOT NULL DEFAULT '',
        action TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'api', status TEXT NOT NULL DEFAULT 'success',
        ip TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '', target_type TEXT NOT NULL DEFAULT '', target_id TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT '', metadata JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_security_audit_time ON security_audit_events(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_security_audit_category ON security_audit_events(category,created_at DESC);
      CREATE TABLE IF NOT EXISTS idempotency_keys(
        id BIGSERIAL PRIMARY KEY, company_id TEXT NOT NULL DEFAULT '', actor_id TEXT NOT NULL DEFAULT '', route TEXT NOT NULL,
        idem_key TEXT NOT NULL, request_hash TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'seen', created_at TEXT NOT NULL,
        UNIQUE(company_id,actor_id,route,idem_key)
      );
      CREATE INDEX IF NOT EXISTS idx_idempotency_time ON idempotency_keys(created_at DESC);
      CREATE TABLE IF NOT EXISTS release_control_events(
        id BIGSERIAL PRIMARY KEY, release_id TEXT NOT NULL UNIQUE, server_version TEXT NOT NULL DEFAULT '', api_version TEXT NOT NULL DEFAULT '',
        schema_version INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'attention', readiness JSONB NOT NULL DEFAULT '{}'::jsonb,
        actor TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_release_control_time ON release_control_events(created_at DESC);
      UPDATE desktop_update_policy SET updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v16' WHERE id=1;
    `
  },
  {
    version:17,
    name:'phase11-commercial-acceptance-pilot-production-readiness',
    sql:`
      CREATE TABLE IF NOT EXISTS pilot_dealers(
        id BIGSERIAL PRIMARY KEY, company_id TEXT NOT NULL UNIQUE, status TEXT NOT NULL DEFAULT 'active',
        started_at TEXT NOT NULL, completed_at TEXT, started_by TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
        baseline_server_version TEXT NOT NULL DEFAULT '', baseline_schema_version INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_pilot_dealers_status_time ON pilot_dealers(status,started_at DESC);
      CREATE TABLE IF NOT EXISTS commercial_acceptance_events(
        id BIGSERIAL PRIMARY KEY, acceptance_id TEXT NOT NULL UNIQUE, status TEXT NOT NULL, result JSONB NOT NULL DEFAULT '{}'::jsonb,
        actor TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_commercial_acceptance_time ON commercial_acceptance_events(created_at DESC);
      UPDATE desktop_update_policy SET updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v17' WHERE id=1;
    `
  },
  {
    version:18,
    name:'phase12-subscription-licensing-payment-provider-architecture',
    sql:`
      CREATE TABLE IF NOT EXISTS subscription_plans(
        id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', active BOOLEAN NOT NULL DEFAULT TRUE,
        price_cents BIGINT NOT NULL DEFAULT 0, currency TEXT NOT NULL DEFAULT 'TWD', billing_interval TEXT NOT NULL DEFAULT 'month',
        billing_interval_count INTEGER NOT NULL DEFAULT 1, trial_days INTEGER NOT NULL DEFAULT 0, grace_days INTEGER NOT NULL DEFAULT 7,
        max_nodes INTEGER NOT NULL DEFAULT 1, features JSONB NOT NULL DEFAULT '{}'::jsonb, sort_order INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_subscription_plans_active_sort ON subscription_plans(active,sort_order,name);

      CREATE TABLE IF NOT EXISTS payment_providers(
        id TEXT PRIMARY KEY, provider_type TEXT NOT NULL, display_name TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT FALSE,
        mode TEXT NOT NULL DEFAULT 'test', webhook_enabled BOOLEAN NOT NULL DEFAULT FALSE, adapter_key TEXT NOT NULL DEFAULT '',
        capabilities JSONB NOT NULL DEFAULT '{}'::jsonb, config JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      INSERT INTO payment_providers(id,provider_type,display_name,enabled,mode,webhook_enabled,adapter_key,capabilities,config,created_at,updated_at) VALUES
        ('manual','manual','人工收款 / 銀行轉帳',TRUE,'live',FALSE,'manual','{"manualConfirm":true}'::jsonb,'{}'::jsonb,CURRENT_TIMESTAMP::text,CURRENT_TIMESTAMP::text),
        ('webhook_generic','webhook','Webhook 金流通知（預留）',FALSE,'test',TRUE,'generic_webhook','{"webhook":true,"oneTime":true}'::jsonb,'{}'::jsonb,CURRENT_TIMESTAMP::text,CURRENT_TIMESTAMP::text),
        ('credit_card','card','信用卡 / 定期扣款（預留）',FALSE,'test',TRUE,'card_adapter','{"card":true,"recurring":true,"oneTime":true}'::jsonb,'{}'::jsonb,CURRENT_TIMESTAMP::text,CURRENT_TIMESTAMP::text),
        ('virtual_account','virtual_account','ATM / 虛擬帳號（預留）',FALSE,'test',TRUE,'virtual_account_adapter','{"virtualAccount":true,"webhook":true}'::jsonb,'{}'::jsonb,CURRENT_TIMESTAMP::text,CURRENT_TIMESTAMP::text),
        ('wallet','wallet','第三方支付 / 行動錢包（預留）',FALSE,'test',TRUE,'wallet_adapter','{"wallet":true,"webhook":true}'::jsonb,'{}'::jsonb,CURRENT_TIMESTAMP::text,CURRENT_TIMESTAMP::text)
      ON CONFLICT(id) DO NOTHING;

      CREATE TABLE IF NOT EXISTS dealer_subscriptions(
        company_id TEXT PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE, plan_id TEXT REFERENCES subscription_plans(id) ON DELETE SET NULL,
        status TEXT NOT NULL DEFAULT 'trial', current_period_start TEXT, current_period_end TEXT, grace_until TEXT,
        auto_renew BOOLEAN NOT NULL DEFAULT FALSE, cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
        provider_id TEXT REFERENCES payment_providers(id) ON DELETE SET NULL, external_customer_id TEXT NOT NULL DEFAULT '',
        external_subscription_id TEXT NOT NULL DEFAULT '', payment_method_ref TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_dealer_subscriptions_status_end ON dealer_subscriptions(status,current_period_end);

      CREATE TABLE IF NOT EXISTS payment_transactions(
        id TEXT PRIMARY KEY, company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        provider_id TEXT REFERENCES payment_providers(id) ON DELETE SET NULL, provider_transaction_id TEXT,
        amount_cents BIGINT NOT NULL DEFAULT 0, currency TEXT NOT NULL DEFAULT 'TWD', payment_type TEXT NOT NULL DEFAULT 'manual',
        status TEXT NOT NULL DEFAULT 'pending', description TEXT NOT NULL DEFAULT '', idempotency_key TEXT,
        paid_at TEXT, confirmed_at TEXT, confirmed_by TEXT NOT NULL DEFAULT '', raw_data JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_provider_tx_unique ON payment_transactions(provider_id,provider_transaction_id) WHERE provider_transaction_id IS NOT NULL AND provider_transaction_id<>'';
      CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_idempotency_unique ON payment_transactions(idempotency_key) WHERE idempotency_key IS NOT NULL AND idempotency_key<>'';
      CREATE INDEX IF NOT EXISTS idx_payment_company_time ON payment_transactions(company_id,created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_payment_status_time ON payment_transactions(status,created_at DESC);

      CREATE TABLE IF NOT EXISTS payment_webhook_events(
        id BIGSERIAL PRIMARY KEY, provider_id TEXT NOT NULL, provider_event_id TEXT NOT NULL, event_type TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'received', transaction_id TEXT NOT NULL DEFAULT '', payload JSONB NOT NULL DEFAULT '{}'::jsonb,
        error_text TEXT NOT NULL DEFAULT '', received_at TEXT NOT NULL, processed_at TEXT,
        UNIQUE(provider_id,provider_event_id)
      );
      CREATE INDEX IF NOT EXISTS idx_payment_webhook_time ON payment_webhook_events(received_at DESC);

      CREATE TABLE IF NOT EXISTS subscription_events(
        id BIGSERIAL PRIMARY KEY, company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE, event_type TEXT NOT NULL,
        old_status TEXT NOT NULL DEFAULT '', new_status TEXT NOT NULL DEFAULT '', old_period_end TEXT, new_period_end TEXT,
        source TEXT NOT NULL DEFAULT '', reference_id TEXT NOT NULL DEFAULT '', actor TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_subscription_events_company_time ON subscription_events(company_id,created_at DESC);

      UPDATE desktop_update_policy SET updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v18' WHERE id=1;
    `
  },
  {
    version:19,
    name:'phase12-payment-record-soft-delete-audit',
    sql:`
      ALTER TABLE payment_transactions ADD COLUMN IF NOT EXISTS deleted_at TEXT;
      ALTER TABLE payment_transactions ADD COLUMN IF NOT EXISTS deleted_by TEXT NOT NULL DEFAULT '';
      ALTER TABLE payment_transactions ADD COLUMN IF NOT EXISTS delete_reason TEXT NOT NULL DEFAULT '';
      CREATE INDEX IF NOT EXISTS idx_payment_visible_time ON payment_transactions(deleted_at,created_at DESC);
      UPDATE desktop_update_policy SET updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v19' WHERE id=1;
    `
  }
,
  {
    version:20,
    name:'phase12e-h-webhook-provider-auto-renew-security',
    sql:`
      ALTER TABLE payment_providers ADD COLUMN IF NOT EXISTS webhook_secret TEXT NOT NULL DEFAULT '';
      ALTER TABLE payment_providers ADD COLUMN IF NOT EXISTS last_test_at TEXT;
      ALTER TABLE payment_providers ADD COLUMN IF NOT EXISTS last_test_status TEXT NOT NULL DEFAULT '';
      ALTER TABLE dealer_subscriptions ADD COLUMN IF NOT EXISTS next_renewal_at TEXT;
      ALTER TABLE dealer_subscriptions ADD COLUMN IF NOT EXISTS renewal_failures INTEGER NOT NULL DEFAULT 0;
      ALTER TABLE dealer_subscriptions ADD COLUMN IF NOT EXISTS last_renewal_attempt_at TEXT;
      ALTER TABLE dealer_subscriptions ADD COLUMN IF NOT EXISTS last_renewal_status TEXT NOT NULL DEFAULT '';
      CREATE TABLE IF NOT EXISTS payment_renewal_attempts(
        id BIGSERIAL PRIMARY KEY, company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        provider_id TEXT, attempt_key TEXT NOT NULL UNIQUE, status TEXT NOT NULL DEFAULT 'pending', amount_cents BIGINT NOT NULL DEFAULT 0,
        error_text TEXT NOT NULL DEFAULT '', transaction_id TEXT NOT NULL DEFAULT '', started_at TEXT NOT NULL, completed_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_renewal_attempt_time ON payment_renewal_attempts(started_at DESC);
      CREATE INDEX IF NOT EXISTS idx_renewal_attempt_company ON payment_renewal_attempts(company_id,started_at DESC);
      UPDATE desktop_update_policy SET updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v20' WHERE id=1;
    `
  },
  {
    version:21,
    name:'phase13-dealer-subscription-center-notification-read-state',
    sql:`
      CREATE TABLE IF NOT EXISTS dealer_notification_reads(
        company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        notification_key TEXT NOT NULL,
        read_at TEXT NOT NULL,
        read_by TEXT NOT NULL DEFAULT '',
        PRIMARY KEY(company_id,notification_key)
      );
      CREATE INDEX IF NOT EXISTS idx_dealer_notification_reads_time ON dealer_notification_reads(company_id,read_at DESC);
      UPDATE desktop_update_policy SET updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v21' WHERE id=1;
    `
  },
  {
    version:22,
    name:'phase13-hotfix1-renewal-request-notification-center',
    sql:`
      CREATE TABLE IF NOT EXISTS dealer_renewal_requests(
        id BIGSERIAL PRIMARY KEY,
        company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        plan_id TEXT REFERENCES subscription_plans(id) ON DELETE SET NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        note TEXT NOT NULL DEFAULT '',
        requested_by TEXT NOT NULL DEFAULT '',
        requested_at TEXT NOT NULL,
        contacted_at TEXT,
        contacted_by TEXT NOT NULL DEFAULT '',
        closed_at TEXT,
        closed_by TEXT NOT NULL DEFAULT '',
        close_note TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_dealer_renewal_requests_status_time ON dealer_renewal_requests(status,requested_at DESC);
      CREATE INDEX IF NOT EXISTS idx_dealer_renewal_requests_company_time ON dealer_renewal_requests(company_id,requested_at DESC);
      CREATE UNIQUE INDEX IF NOT EXISTS uq_dealer_renewal_request_open_company ON dealer_renewal_requests(company_id) WHERE status IN ('pending','contacted');
      UPDATE desktop_update_policy SET updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v22' WHERE id=1;
    `
  },
  {
    version:23,
    name:'phase14a-company-branch-core',
    sql:`
      ALTER TABLE companies ADD COLUMN IF NOT EXISTS business_type TEXT NOT NULL DEFAULT 'used_car';
      ALTER TABLE companies ADD COLUMN IF NOT EXISTS enabled_modules JSONB NOT NULL DEFAULT '["vehicle_sales"]'::jsonb;

      CREATE TABLE IF NOT EXISTS branches(
        id TEXT PRIMARY KEY,
        company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        code TEXT NOT NULL,
        name TEXT NOT NULL,
        is_head_office BOOLEAN NOT NULL DEFAULT FALSE,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        address TEXT NOT NULL DEFAULT '',
        phone TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(company_id,code)
      );
      CREATE INDEX IF NOT EXISTS idx_branches_company_enabled ON branches(company_id,enabled,is_head_office DESC);
      CREATE UNIQUE INDEX IF NOT EXISTS uq_branches_one_head_office ON branches(company_id) WHERE is_head_office=TRUE;

      INSERT INTO branches(id,company_id,code,name,is_head_office,enabled,address,phone,created_at,updated_at)
      SELECT c.id || '_main',c.id,'MAIN','總店',TRUE,TRUE,'','',CURRENT_TIMESTAMP::text,CURRENT_TIMESTAMP::text
      FROM companies c
      WHERE NOT EXISTS(SELECT 1 FROM branches b WHERE b.company_id=c.id);

      ALTER TABLE users ADD COLUMN IF NOT EXISTS branch_id TEXT REFERENCES branches(id) ON DELETE SET NULL;
      UPDATE users u SET branch_id=b.id FROM branches b
      WHERE b.company_id=u.company_id AND b.is_head_office=TRUE AND u.branch_id IS NULL;
      CREATE INDEX IF NOT EXISTS idx_users_company_branch ON users(company_id,branch_id);

      UPDATE snapshots s SET json=jsonb_set(COALESCE(s.json,'{}'::jsonb),'{settings,defaultBranchId}',to_jsonb(b.id),true)
      FROM branches b WHERE b.company_id=s.company_id AND b.is_head_office=TRUE;

      UPDATE snapshots s SET json=jsonb_set(s.json,'{cars}',COALESCE((
        SELECT jsonb_agg(CASE WHEN e ? 'branchId' AND COALESCE(e->>'branchId','')<>'' THEN e ELSE e || jsonb_build_object('branchId',b.id) END)
        FROM jsonb_array_elements(COALESCE(s.json->'cars','[]'::jsonb)) e
      ),'[]'::jsonb),true)
      FROM branches b WHERE b.company_id=s.company_id AND b.is_head_office=TRUE;

      UPDATE snapshots s SET json=jsonb_set(s.json,'{saleRequests}',COALESCE((
        SELECT jsonb_agg(CASE WHEN e ? 'branchId' AND COALESCE(e->>'branchId','')<>'' THEN e ELSE e || jsonb_build_object('branchId',b.id) END)
        FROM jsonb_array_elements(COALESCE(s.json->'saleRequests','[]'::jsonb)) e
      ),'[]'::jsonb),true)
      FROM branches b WHERE b.company_id=s.company_id AND b.is_head_office=TRUE;

      UPDATE desktop_update_policy SET updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v23' WHERE id=1;
    `
  },
  {
    version:24,
    name:'phase14b2-configurable-permissions-approval-routing',
    sql:`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS permissions JSONB NOT NULL DEFAULT '{}'::jsonb;
      ALTER TABLE branches ADD COLUMN IF NOT EXISTS sale_approval_mode TEXT NOT NULL DEFAULT 'branch_manager';
      ALTER TABLE branches ADD COLUMN IF NOT EXISTS sale_approver_user_id TEXT;
      CREATE INDEX IF NOT EXISTS idx_users_company_branch_role ON users(company_id,branch_id,role,enabled);
    `
  },
  {
    version:25,
    name:'phase14b3-staff-payroll-cost-notifications',
    sql:`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS position TEXT NOT NULL DEFAULT '';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS salary_type TEXT NOT NULL DEFAULT 'fixed';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS login_enabled BOOLEAN NOT NULL DEFAULT TRUE;
      UPDATE users SET position=CASE WHEN role='branchManager' THEN '分店主管' WHEN role='sales' THEN '業務' WHEN role='admin' THEN '公司管理員' ELSE '一般員工' END WHERE COALESCE(position,'')='';
      UPDATE users SET salary_type='base_plus_commission' WHERE role='sales' AND salary_type='fixed';
      CREATE TABLE IF NOT EXISTS payroll_settlements(
        id TEXT PRIMARY KEY,
        company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        employee_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        branch_id TEXT,
        month TEXT NOT NULL,
        base_salary DOUBLE PRECISION NOT NULL DEFAULT 0,
        commission DOUBLE PRECISION NOT NULL DEFAULT 0,
        allowance DOUBLE PRECISION NOT NULL DEFAULT 0,
        overtime DOUBLE PRECISION NOT NULL DEFAULT 0,
        deductions DOUBLE PRECISION NOT NULL DEFAULT 0,
        total_cost DOUBLE PRECISION NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'confirmed',
        settled_at TEXT NOT NULL,
        settled_by TEXT NOT NULL DEFAULT '',
        note TEXT NOT NULL DEFAULT '',
        UNIQUE(company_id, employee_id, month)
      );
      CREATE INDEX IF NOT EXISTS idx_payroll_company_month ON payroll_settlements(company_id,month,branch_id);
    `
  },
  {
    version:26,
    name:'phase14b3-payroll-realtime-estimate-mode',
    sql:`
      ALTER TABLE companies ADD COLUMN IF NOT EXISTS payroll_cost_mode TEXT NOT NULL DEFAULT 'realtime_estimate';
      UPDATE companies SET payroll_cost_mode='realtime_estimate' WHERE payroll_cost_mode IS NULL OR payroll_cost_mode NOT IN ('realtime_estimate','settled_only');
    `
  },
  {
    version:27,
    name:'phase14b5-monthly-dashboard',
    sql:`
      CREATE TABLE IF NOT EXISTS payroll_month_periods(
        company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        month TEXT NOT NULL,
        employee_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
        locked BOOLEAN NOT NULL DEFAULT FALSE,
        locked_at TEXT,
        locked_by TEXT NOT NULL DEFAULT '',
        unlocked_at TEXT,
        unlocked_by TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY(company_id,month)
      );
      CREATE TABLE IF NOT EXISTS payroll_month_events(
        id BIGSERIAL PRIMARY KEY,
        company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        month TEXT NOT NULL,
        action TEXT NOT NULL,
        actor TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_payroll_month_events_company_month ON payroll_month_events(company_id,month,id DESC);
      INSERT INTO payroll_month_periods(company_id,month,employee_ids,locked,created_at,updated_at)
      SELECT c.id,to_char(CURRENT_DATE,'YYYY-MM'),COALESCE((SELECT jsonb_agg(u.id ORDER BY u.id) FROM users u WHERE u.company_id=c.id AND u.enabled=TRUE AND u.role<>'admin'),'[]'::jsonb),FALSE,CURRENT_TIMESTAMP::text,CURRENT_TIMESTAMP::text
      FROM companies c ON CONFLICT(company_id,month) DO NOTHING;
    `
  },
  {
    version:28,
    name:'phase14b6-company-activation-boundary',
    sql:`
      ALTER TABLE companies ADD COLUMN IF NOT EXISTS system_activation_date TEXT;
      ALTER TABLE companies ADD COLUMN IF NOT EXISTS system_activation_set_at TEXT;
      ALTER TABLE companies ADD COLUMN IF NOT EXISTS system_activation_set_by TEXT NOT NULL DEFAULT '';
      ALTER TABLE companies ADD COLUMN IF NOT EXISTS owner_user_id TEXT;
      UPDATE companies c SET owner_user_id=(
        SELECT u.id FROM users u WHERE u.company_id=c.id AND u.role='admin' ORDER BY u.updated_at ASC,u.id ASC LIMIT 1
      ) WHERE COALESCE(c.owner_user_id,'')='';
      UPDATE companies SET system_activation_date=COALESCE(NULLIF(system_activation_date,''),NULLIF(start_date,''),LEFT(created_at,10),CURRENT_DATE::text)
      WHERE COALESCE(system_activation_date,'')='';
      UPDATE companies SET system_activation_set_at=COALESCE(NULLIF(system_activation_set_at,''),created_at,CURRENT_TIMESTAMP::text)
      WHERE COALESCE(system_activation_set_at,'')='';
      CREATE TABLE IF NOT EXISTS company_setting_events(
        id BIGSERIAL PRIMARY KEY,
        company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        setting_key TEXT NOT NULL,
        old_value TEXT NOT NULL DEFAULT '',
        new_value TEXT NOT NULL DEFAULT '',
        actor_id TEXT NOT NULL DEFAULT '',
        actor TEXT NOT NULL DEFAULT '',
        reason TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_company_setting_events_company ON company_setting_events(company_id,id DESC);
    `
  },
  {
    version:29,
    name:'phase14b7-staff-audit-payroll-undo',
    sql:`
      CREATE TABLE IF NOT EXISTS staff_change_events(
        id BIGSERIAL PRIMARY KEY,
        company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        event_type TEXT NOT NULL,
        employee_id TEXT NOT NULL DEFAULT '',
        employee_name TEXT NOT NULL DEFAULT '',
        position TEXT NOT NULL DEFAULT '',
        branch_id TEXT NOT NULL DEFAULT '',
        actor_id TEXT NOT NULL DEFAULT '',
        actor_name TEXT NOT NULL DEFAULT '',
        actor_role TEXT NOT NULL DEFAULT '',
        reason TEXT NOT NULL DEFAULT '',
        owner_read_at TEXT,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_staff_change_events_company ON staff_change_events(company_id,id DESC);
      CREATE INDEX IF NOT EXISTS idx_staff_change_events_unread ON staff_change_events(company_id,owner_read_at,id DESC);
    `
  },
  {
    version:30,
    name:'phase14c-vehicle-transfer-workflow',
    sql:`
      CREATE TABLE IF NOT EXISTS vehicle_transfers(
        id TEXT PRIMARY KEY,
        company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        car_id TEXT NOT NULL,
        plate TEXT NOT NULL DEFAULT '',
        model TEXT NOT NULL DEFAULT '',
        from_branch_id TEXT NOT NULL REFERENCES branches(id),
        to_branch_id TEXT NOT NULL REFERENCES branches(id),
        status TEXT NOT NULL DEFAULT 'in_transit',
        requested_by_id TEXT NOT NULL DEFAULT '',
        requested_by_name TEXT NOT NULL DEFAULT '',
        requested_by_role TEXT NOT NULL DEFAULT '',
        requested_at TEXT NOT NULL,
        note TEXT NOT NULL DEFAULT '',
        arrived_by_id TEXT NOT NULL DEFAULT '',
        arrived_by_name TEXT NOT NULL DEFAULT '',
        arrived_at TEXT,
        canceled_by_id TEXT NOT NULL DEFAULT '',
        canceled_by_name TEXT NOT NULL DEFAULT '',
        canceled_at TEXT,
        cancel_reason TEXT NOT NULL DEFAULT '',
        owner_read_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_vehicle_transfers_company_time ON vehicle_transfers(company_id,requested_at DESC);
      CREATE INDEX IF NOT EXISTS idx_vehicle_transfers_route_status ON vehicle_transfers(company_id,from_branch_id,to_branch_id,status);
      CREATE UNIQUE INDEX IF NOT EXISTS uq_vehicle_transfer_active_car ON vehicle_transfers(company_id,car_id) WHERE status='in_transit';
      UPDATE users SET permissions=jsonb_set(COALESCE(permissions,'{}'::jsonb),'{vehicleTransfer}','true'::jsonb,true) WHERE role='branchManager';
    `
  },
  {
    version:31,
    name:'phase14d-operating-cost-center',
    sql:`
      CREATE TABLE IF NOT EXISTS operating_cost_rules(
        id TEXT PRIMARY KEY,
        company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'other',
        amount DOUBLE PRECISION NOT NULL DEFAULT 0,
        allocation_mode TEXT NOT NULL DEFAULT 'company',
        branch_id TEXT REFERENCES branches(id) ON DELETE SET NULL,
        start_month TEXT NOT NULL,
        end_month TEXT,
        day_of_month INTEGER NOT NULL DEFAULT 1,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        note TEXT NOT NULL DEFAULT '',
        created_by_id TEXT NOT NULL DEFAULT '',
        created_by_name TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_operating_cost_rules_company ON operating_cost_rules(company_id,enabled,start_month);

      CREATE TABLE IF NOT EXISTS operating_cost_entries(
        id TEXT PRIMARY KEY,
        company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        month TEXT NOT NULL,
        expense_date TEXT NOT NULL,
        name TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'other',
        amount DOUBLE PRECISION NOT NULL DEFAULT 0,
        allocation_mode TEXT NOT NULL DEFAULT 'company',
        branch_id TEXT REFERENCES branches(id) ON DELETE SET NULL,
        allocation_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        source_type TEXT NOT NULL DEFAULT 'manual',
        recurring_rule_id TEXT REFERENCES operating_cost_rules(id) ON DELETE SET NULL,
        note TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'active',
        created_by_id TEXT NOT NULL DEFAULT '',
        created_by_name TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        voided_at TEXT,
        voided_by TEXT NOT NULL DEFAULT '',
        void_reason TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_operating_cost_entries_company_month ON operating_cost_entries(company_id,month,status,expense_date DESC);
      CREATE UNIQUE INDEX IF NOT EXISTS uq_operating_cost_rule_month ON operating_cost_entries(company_id,recurring_rule_id,month) WHERE recurring_rule_id IS NOT NULL;
      UPDATE desktop_update_policy SET updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v31' WHERE id=1;
    `
  },
  {
    version:32,
    name:'phase14d3-superadmin-vehicle-list-simplified',
    sql:`
      CREATE TABLE IF NOT EXISTS super_data_center_settings(
        id INTEGER PRIMARY KEY CHECK(id=1),
        password_salt TEXT NOT NULL DEFAULT '',
        password_hash TEXT NOT NULL DEFAULT '',
        retention_value BIGINT NOT NULL DEFAULT 24,
        retention_unit TEXT NOT NULL DEFAULT 'hour',
        retention_forever BOOLEAN NOT NULL DEFAULT FALSE,
        updated_at TEXT NOT NULL,
        updated_by TEXT NOT NULL DEFAULT 'platform-admin'
      );
      CREATE TABLE IF NOT EXISTS super_data_center_access_logs(
        id BIGSERIAL PRIMARY KEY,
        actor TEXT NOT NULL DEFAULT 'platform-admin',
        company_id TEXT NOT NULL DEFAULT '',
        company_name TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'success',
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_super_dc_access_time ON super_data_center_access_logs(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_super_dc_access_company ON super_data_center_access_logs(company_id,created_at DESC);
      INSERT INTO super_data_center_access_logs(actor,company_id,company_name,status,created_at)
      SELECT actor,COALESCE(target_id,''),COALESCE((SELECT c.name FROM companies c WHERE c.id=security_audit_events.target_id),''),status,created_at
      FROM security_audit_events
      WHERE action='super_remote_data_center_access'
        AND NOT EXISTS (
          SELECT 1 FROM super_data_center_access_logs l
          WHERE l.actor=security_audit_events.actor AND l.company_id=COALESCE(security_audit_events.target_id,'') AND l.created_at=security_audit_events.created_at
        );
      DELETE FROM security_audit_events WHERE action IN ('super_remote_data_center_access','super_remote_live_snapshot_request');
    `
  }];

async function ensureMigrationTable(client=pool){
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations(
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      status TEXT NOT NULL,
      started_at TEXT NOT NULL,
      completed_at TEXT,
      error_text TEXT
    )
  `);
}

async function ensureMigrationSafetyTable(client=pool){
  await client.query(`CREATE TABLE IF NOT EXISTS migration_safety_events(id BIGSERIAL PRIMARY KEY,migration_version INTEGER NOT NULL,migration_name TEXT NOT NULL,status TEXT NOT NULL,detail TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL)`);
}

async function migrationSafetyEvent(client,version,name,status,detail=''){
  try{await ensureMigrationSafetyTable(client);await client.query('INSERT INTO migration_safety_events(migration_version,migration_name,status,detail,created_at) VALUES($1,$2,$3,$4,$5)',[version,name,status,String(detail||'').slice(0,2000),now()]);}catch(e){console.warn('migration safety audit failed:',e?.message||e)}
}

async function getServerSchemaStatus(client=pool){
  await ensureMigrationTable(client);
  const {rows}=await client.query('SELECT version,name,status,started_at,completed_at,error_text FROM schema_migrations ORDER BY version ASC');
  const completed=rows.filter(r=>r.status==='completed').map(r=>Number(r.version||0));
  const currentVersion=completed.length?Math.max(...completed):0;
  const failed=rows.filter(r=>r.status==='failed').slice(-1)[0]||null;
  return {currentVersion,targetVersion:SERVER_SCHEMA_TARGET,status:failed&&Number(failed.version)>currentVersion?'failed':(currentVersion>=SERVER_SCHEMA_TARGET?'ready':'pending'),failedMigration:failed,history:rows};
}

async function runServerMigrations(){
  const lockClient=await pool.connect();
  try{
    await ensureMigrationTable(lockClient);
    await lockClient.query('SELECT pg_advisory_lock($1)',[938501]);
    for(const m of SERVER_MIGRATIONS){
      const prior=(await lockClient.query('SELECT status FROM schema_migrations WHERE version=$1',[m.version])).rows[0];
      if(prior?.status==='completed')continue;
      const started=now();
      await lockClient.query(`INSERT INTO schema_migrations(version,name,status,started_at,completed_at,error_text)
        VALUES($1,$2,'running',$3,NULL,NULL)
        ON CONFLICT(version) DO UPDATE SET name=excluded.name,status='running',started_at=excluded.started_at,completed_at=NULL,error_text=NULL`,[m.version,m.name,started]);
      await migrationSafetyEvent(lockClient,m.version,m.name,'started','PostgreSQL transaction protection active');
      try{
        await lockClient.query('BEGIN');
        await lockClient.query(m.sql);
        await lockClient.query('COMMIT');
        await lockClient.query("UPDATE schema_migrations SET status='completed',completed_at=$1,error_text=NULL WHERE version=$2",[now(),m.version]);
        await migrationSafetyEvent(lockClient,m.version,m.name,'completed','Transaction committed successfully');
        console.log(`PostgreSQL migration v${m.version} completed: ${m.name}`);
      }catch(e){
        try{await lockClient.query('ROLLBACK')}catch{}
        try{await lockClient.query("UPDATE schema_migrations SET status='failed',completed_at=$1,error_text=$2 WHERE version=$3",[now(),String(e?.message||e).slice(0,2000),m.version])}catch{}
        await migrationSafetyEvent(lockClient,m.version,m.name,'rolled_back',String(e?.message||e));
        throw new Error(`PostgreSQL migration v${m.version} failed (${m.name}): ${e?.message||e}`);
      }
    }
  }finally{
    try{await lockClient.query('SELECT pg_advisory_unlock($1)',[938501])}catch{}
    lockClient.release();
  }
}

async function ensurePaymentProviderWebhookSecrets(){
  const {rows}=await pool.query(`SELECT id FROM payment_providers WHERE webhook_enabled=TRUE AND COALESCE(webhook_secret,'')=''`);
  for(const row of rows){
    const secret=crypto.randomBytes(24).toString('hex');
    await pool.query(`UPDATE payment_providers SET webhook_secret=$1,updated_at=$2 WHERE id=$3 AND COALESCE(webhook_secret,'')=''`,[secret,now(),row.id]);
  }
  if(rows.length)console.log(`Payment provider webhook secrets initialized: ${rows.length}`);
}

async function initDb(){
  await runServerMigrations();
  await ensurePaymentProviderWebhookSecrets();
  const schema=await getServerSchemaStatus();
  if(schema.currentVersion!==SERVER_SCHEMA_TARGET||schema.status!=='ready')throw new Error(`PostgreSQL schema not ready: v${schema.currentVersion}/${SERVER_SCHEMA_TARGET}`);
  const r = await pool.query('SELECT NOW() AS now');
  console.log(`PostgreSQL connected: ${r.rows[0].now} | schema v${schema.currentVersion}/${schema.targetVersion}`);
}

async function inspectDatabaseHaRole(){
  const {rows}=await pool.query(`SELECT pg_is_in_recovery() AS in_recovery,
    CASE WHEN pg_is_in_recovery() THEN NULL ELSE pg_current_wal_lsn()::text END AS current_wal_lsn,
    pg_last_wal_receive_lsn()::text AS receive_lsn,
    pg_last_wal_replay_lsn()::text AS replay_lsn,
    pg_last_xact_replay_timestamp() AS replay_timestamp`);
  const r=rows[0]||{};
  const standby=!!r.in_recovery;
  let lagSeconds=null;
  if(standby&&r.replay_timestamp){const n=(Date.now()-new Date(r.replay_timestamp).getTime())/1000;if(Number.isFinite(n))lagSeconds=Math.max(0,Math.round(n*10)/10)}
  return {dbRole:standby?'standby':'primary',wal:{currentLsn:r.current_wal_lsn||'',receiveLsn:r.receive_lsn||'',replayLsn:r.replay_lsn||'',replayTimestamp:r.replay_timestamp?new Date(r.replay_timestamp).toISOString():null,replicationLagSeconds:lagSeconds}};
}
async function recordHaEvent(eventType,fromRole,toRole,detail=''){
  try{
    // Physical standby is read-only, so audit insertion is only attempted on a writable primary.
    if(toRole==='standby'||haRuntime.dbRole==='standby')return;
    await pool.query('INSERT INTO central_ha_events(instance_id,site,event_type,from_role,to_role,detail,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)',[CENTRAL_HA_INSTANCE_ID,CENTRAL_HA_SITE,String(eventType||'role_change'),String(fromRole||''),String(toRole||''),String(detail||'').slice(0,1000),now()]);
  }catch(e){console.warn('HA audit unavailable:',e?.message||e)}
}
async function refreshHaRuntime({allowMigration=false,recordTransition=true}={}){
  const prev=haRuntime.dbRole;
  try{
    const db=await inspectDatabaseHaRole();
    let schemaReady=false;
    if(db.dbRole==='primary'&&allowMigration&&!haMigrationRunning){
      haMigrationRunning=true;
      try{await runServerMigrations()}finally{haMigrationRunning=false}
    }
    try{const schema=await getServerSchemaStatus();schemaReady=schema.status==='ready'&&schema.currentVersion===SERVER_SCHEMA_TARGET}catch{}
    haRuntime={...haRuntime,dbRole:db.dbRole,wal:db.wal,schemaReady,writeReady:(!CENTRAL_HA_ENABLED||db.dbRole==='primary')&&schemaReady,lastCheckedAt:now(),lastError:''};
    if(prev!=='unknown'&&prev!==db.dbRole){
      haRuntime.lastRoleChangeAt=now();
      if(recordTransition)await recordHaEvent('database_role_changed',prev,db.dbRole,`PostgreSQL role ${prev} -> ${db.dbRole}`);
    }
    return haRuntime;
  }catch(e){haRuntime={...haRuntime,writeReady:false,lastCheckedAt:now(),lastError:String(e?.message||e).slice(0,500)};return haRuntime}
}
async function probeHaPeer(){
  if(!CENTRAL_HA_PEER_URL)return {configured:false,ok:false,url:'',detail:'未設定 CENTRAL_HA_PEER_URL'};
  const ctl=new AbortController();const timer=setTimeout(()=>ctl.abort(),CENTRAL_HA_PEER_TIMEOUT_MS);
  try{
    const r=await fetch(`${CENTRAL_HA_PEER_URL}/api/ready`,{signal:ctl.signal,headers:{Accept:'application/json'}});
    let body={};try{body=await r.json()}catch{}
    return {configured:true,ok:r.ok,url:CENTRAL_HA_PEER_URL,httpStatus:r.status,probe:body};
  }catch(e){return {configured:true,ok:false,url:CENTRAL_HA_PEER_URL,detail:e?.name==='AbortError'?'連線逾時':String(e?.message||e)}
  }finally{clearTimeout(timer)}
}

async function getCompany(companyId, client=pool){
  const {rows}=await client.query('SELECT * FROM companies WHERE id=$1',[companyId]);
  return rows[0]||null;
}
async function getUserById(companyId,userId){
  const {rows}=await pool.query(
    'SELECT * FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',
    [userId,companyId]
  );
  return rows[0]||null;
}
async function getSnapshot(companyId, client=pool){
  const {rows}=await client.query('SELECT * FROM snapshots WHERE company_id=$1',[companyId]);
  const row=rows[0];
  if(row){
    return {version:Number(row.version||0),snapshot:row.json,updatedAt:row.updated_at};
  }
  return {version:0,snapshot:{settings:{companyName:'車行',taxRate:0},users:[],cars:[],saleRequests:[],operationLogs:[]},updatedAt:null};
}

async function auth(req,res,next){
  const token=(req.headers.authorization||'').replace(/^Bearer\s+/i,'');
  if(!token)return res.status(401).json({error:'未登入'});
  try{
    req.auth=jwt.verify(token,JWT_SECRET);
    if(req.auth.role!=='platformAdmin'){
      const {rows}=await pool.query('SELECT enabled,token_version FROM users WHERE id=$1 AND company_id=$2',[req.auth.sub,req.auth.companyId]);
      const u=rows[0];
      if(!u||!u.enabled)return res.status(401).json({error:'帳號已停用或不存在'});
      if(Number(u.token_version||0)!==Number(req.auth.tokenVersion||0))return res.status(401).json({error:'密碼已變更，請使用新密碼重新登入'});
    }
    next();
  }catch(e){
    return res.status(401).json({error:'登入已失效，請重新登入'});
  }
}
async function requireActiveCompany(req,res,next){
  try{
    const c=await getCompany(req.auth.companyId);
    if(!c)return res.status(403).json({error:'車行不存在'});
    const st=companyStatus(c);
    const billing=await subscriptionAccess(c.id);
    if(['已停用','尚未啟用'].includes(st))return res.status(403).json({error:`車行授權狀態：${st}`});
    if(!billing.managed&&st!=='啟用中')return res.status(403).json({error:`車行授權狀態：${st}`});
    if(billing.managed&&!billing.allowed)return res.status(403).json({error:`訂閱授權狀態：${billing.status}`,subscriptionStatus:billing.status,billingAccessOnly:true,planName:billing.planName||'',currentPeriodEnd:billing.periodEnd||null,graceUntil:billing.graceUntil||null});
    req.company=c;req.subscription=billing;
    next();
  }catch(e){ next(e); }
}
function superAuth(req,res,next){
  auth(req,res,()=>{
    if(req.auth.role!=='platformAdmin')return res.status(403).json({error:'權限不足'});
    next();
  });
}


// Phase 10A-10D: Production Security & Data Integrity Suite（商用安全與資料完整性中心）
const SECURITY_RATE_WINDOW_MS=60_000;
const SECURITY_API_MAX=Math.max(60,Math.min(3000,Number(process.env.SECURITY_API_MAX_PER_MINUTE||600)));
const SECURITY_LOGIN_MAX=Math.max(3,Math.min(30,Number(process.env.SECURITY_LOGIN_MAX_PER_15MIN||8)));
const SECURITY_LOGIN_WINDOW_MS=15*60_000;
const rateWindows=new Map(),loginWindows=new Map();
function remoteIp(req){return String(req.headers['x-forwarded-for']||req.ip||'').split(',')[0].trim().slice(0,120)}
function bucketCheck(map,key,windowMs,max){const t=Date.now();let x=map.get(key);if(!x||t-x.startedAt>=windowMs){x={startedAt:t,count:0};map.set(key,x)}x.count++;return {allowed:x.count<=max,count:x.count,remaining:Math.max(0,max-x.count),resetAt:new Date(x.startedAt+windowMs).toISOString()}}
function safeAuditPayload(body){if(!body||typeof body!=='object')return {};const out={};for(const [k,v] of Object.entries(body)){if(/pass|token|secret|key|authorization/i.test(k))out[k]='[REDACTED]';else if(typeof v==='string')out[k]=v.slice(0,300);else if(typeof v==='number'||typeof v==='boolean'||v==null)out[k]=v;else out[k]='[OBJECT]'}return out}
async function auditSecurityEvent(req,{action='',category='api',status='success',detail='',targetType='',targetId='',metadata={}}={}){try{await pool.query(`INSERT INTO security_audit_events(actor,actor_role,company_id,action,category,status,ip,user_agent,target_type,target_id,detail,metadata,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13)`,[String(req.auth?.username||req.auth?.sub||req.body?.username||'anonymous').slice(0,150),String(req.auth?.role||'').slice(0,80),String(req.auth?.companyId||'').slice(0,150),String(action||`${req.method} ${req.path}`).slice(0,220),String(category).slice(0,80),String(status).slice(0,40),remoteIp(req),String(req.headers['user-agent']||'').slice(0,400),String(targetType).slice(0,80),String(targetId).slice(0,180),String(detail).slice(0,1000),JSON.stringify(metadata||{}),now()])}catch(e){console.warn('security audit unavailable:',e?.message||e)}}

// Phase 14D.1 security layer for the Super Admin data-center access log.
// The dealership side is not notified. Only the central Super Admin can open this page after a second password check.
function dcPasswordHash(password,salt){return crypto.scryptSync(String(password||''),String(salt||''),64).toString('hex')}
async function ensureSuperDataCenterSettings(){
  const r=(await pool.query('SELECT * FROM super_data_center_settings WHERE id=1')).rows[0];
  if(r&&r.password_salt&&r.password_hash)return r;
  const salt=crypto.randomBytes(18).toString('hex'),hash=dcPasswordHash('1234',salt),ts=now();
  await pool.query(`INSERT INTO super_data_center_settings(id,password_salt,password_hash,retention_value,retention_unit,retention_forever,updated_at,updated_by)
    VALUES(1,$1,$2,24,'hour',FALSE,$3,'system-default')
    ON CONFLICT(id) DO UPDATE SET password_salt=CASE WHEN super_data_center_settings.password_salt='' THEN EXCLUDED.password_salt ELSE super_data_center_settings.password_salt END,
      password_hash=CASE WHEN super_data_center_settings.password_hash='' THEN EXCLUDED.password_hash ELSE super_data_center_settings.password_hash END`,[salt,hash,ts]);
  return (await pool.query('SELECT * FROM super_data_center_settings WHERE id=1')).rows[0];
}
function retentionMs(value,unit){const n=Math.max(1,Number(value||1));if(unit==='minute')return n*60_000;if(unit==='hour')return n*3_600_000;if(unit==='day')return n*86_400_000;if(unit==='month')return n*30*86_400_000;return n*3_600_000}
async function cleanupSuperDataCenterAccessLogs(){
  const st=await ensureSuperDataCenterSettings();if(st.retention_forever)return {deleted:0,forever:true};
  const cutoff=new Date(Date.now()-retentionMs(st.retention_value,st.retention_unit)).toISOString();
  const r=await pool.query('DELETE FROM super_data_center_access_logs WHERE created_at < $1',[cutoff]);return {deleted:r.rowCount||0,forever:false,cutoff};
}
function signDataCenterAuditToken(req){return jwt.sign({sub:req.auth.sub||'platform-admin',role:'platformAdmin',purpose:'superDataCenterAudit'},JWT_SECRET,{expiresIn:'20m'})}
function dataCenterAuditAuth(req,res,next){
  try{const token=String(req.headers['x-data-center-audit-token']||'');if(!token)return res.status(401).json({error:'請輸入超級資料中心紀錄密碼'});const p=jwt.verify(token,JWT_SECRET);if(p.role!=='platformAdmin'||p.purpose!=='superDataCenterAudit')return res.status(403).json({error:'資料中心紀錄驗證失效'});req.dcAudit=p;next()}catch{return res.status(401).json({error:'資料中心紀錄驗證已過期，請重新輸入密碼'})}
}
async function recordSuperDataCenterAccess(req,company,status='success'){
  try{await cleanupSuperDataCenterAccessLogs();await pool.query('INSERT INTO super_data_center_access_logs(actor,company_id,company_name,status,created_at) VALUES($1,$2,$3,$4,$5)',[String(req.auth?.username||req.auth?.sub||'platform-admin').slice(0,150),String(company?.id||'').slice(0,150),String(company?.name||'').slice(0,300),String(status||'success').slice(0,40),now()])}catch(e){console.warn('data center access log unavailable:',e?.message||e)}
}
const superDataCenterLogCleanupTimer=setInterval(()=>cleanupSuperDataCenterAccessLogs().catch(()=>{}),30_000);superDataCenterLogCleanupTimer.unref?.();

function securityHeaders(req,res,next){res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');res.setHeader('Cross-Origin-Opener-Policy','same-origin');res.setHeader('Content-Security-Policy',"default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' https: http:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");next()}
function generalRateLimit(req,res,next){if(req.path.startsWith('/super/')||req.path==='/health'||req.path==='/ready')return next();const b=bucketCheck(rateWindows,remoteIp(req)||'unknown',SECURITY_RATE_WINDOW_MS,SECURITY_API_MAX);res.setHeader('X-RateLimit-Limit',String(SECURITY_API_MAX));res.setHeader('X-RateLimit-Remaining',String(b.remaining));if(!b.allowed){res.setHeader('Retry-After',String(Math.ceil((Date.parse(b.resetAt)-Date.now())/1000)));return res.status(429).json({error:'請求過於頻繁，請稍後再試',errorCode:'RATE_LIMITED'})}next()}
function loginGuard(kind='dealer'){return (req,res,next)=>{const key=`${kind}:${remoteIp(req)}:${String(req.body?.username||'').toLowerCase()}`;const b=bucketCheck(loginWindows,key,SECURITY_LOGIN_WINDOW_MS,SECURITY_LOGIN_MAX);if(!b.allowed){auditSecurityEvent(req,{action:`${kind}_login_blocked`,category:'authentication',status:'blocked',detail:'Too many login attempts'});return res.status(429).json({error:'登入嘗試過於頻繁，請稍後再試',errorCode:'LOGIN_RATE_LIMITED',retryAfterSeconds:Math.max(1,Math.ceil((Date.parse(b.resetAt)-Date.now())/1000))})}req.securityLoginKey=key;next()}}
async function phase10DataIntegritySummary(){const issues=[];let duplicateUsers=0,missingSnapshots=0,saleProblems=0;try{duplicateUsers=Number((await pool.query(`SELECT COUNT(*)::int AS n FROM (SELECT company_id,username,COUNT(*) FROM users GROUP BY company_id,username HAVING COUNT(*)>1)x`)).rows[0]?.n||0);missingSnapshots=Number((await pool.query(`SELECT COUNT(*)::int AS n FROM companies c LEFT JOIN snapshots s ON s.company_id=c.id WHERE s.company_id IS NULL`)).rows[0]?.n||0);const snaps=(await pool.query(`SELECT company_id,json FROM snapshots ORDER BY updated_at DESC LIMIT 500`)).rows;for(const row of snaps){const e=validateSaleIntegrity(row.json||{});if(e){saleProblems++;if(issues.length<10)issues.push({companyId:row.company_id,issue:e})}}}catch(e){issues.push({issue:e.message||String(e)})}return {status:duplicateUsers===0&&missingSnapshots===0&&saleProblems===0?'pass':'warning',duplicateUsers,missingSnapshots,saleProblems,issues,checkedAt:now()}}
async function phase10ReleaseReadiness(){const schema=await getServerSchemaStatus(),backup=await centralBackupSummary();const lastRestore=(backup.restoreEvents||[]).find(x=>x.status==='success')||null;const ready=schema.status==='ready'&&!!backup.lastSuccess&&!!lastRestore;return {status:ready?'ready':'attention',serverVersion:'14.9.10',apiVersion:'6.9.10',schemaCurrent:schema.currentVersion,schemaTarget:schema.targetVersion,schemaReady:schema.status==='ready',backupReady:!!backup.lastSuccess,restoreDrillReady:!!lastRestore,lastBackupAt:backup.lastSuccess?.completed_at||backup.lastSuccess?.started_at||null,lastRestoreAt:lastRestore?.completed_at||lastRestore?.started_at||null,note:ready?'具備程式版本回滾前置條件；真正 Render 回滾仍由部署平台操作。':'回滾前請先補齊 Schema / Backup / Restore Drill 條件。',checkedAt:now()}}

// Phase 11A-11C: Commercial Launch Center（商用上線中心）
async function phase11AcceptanceSummary(){
  const [schema,integrity,release,backup]=await Promise.all([getServerSchemaStatus(),phase10DataIntegritySummary(),phase10ReleaseReadiness(),centralBackupSummary()]);
  const latest={};
  const suite=(await pool.query(`SELECT phase,status,result,started_at,completed_at FROM resilience_suite_runs WHERE phase IN ('9C','9D','9E','9F') ORDER BY id DESC`)).rows;
  for(const r of suite)if(!latest[r.phase])latest[r.phase]=r;
  const checks=[];
  const add=(key,title,status,summary)=>checks.push({key,title,status,summary});
  add('schema','Schema（資料庫結構）',schema.status==='ready'&&schema.currentVersion===SERVER_SCHEMA_TARGET?'pass':'fail',`v${schema.currentVersion}/v${schema.targetVersion}`);
  add('security','Security Hardening（安全強化）','pass','Phase 10A 已啟用：安全標頭、登入保護、Rate Limit、Token 驗證與最高權限隔離。');
  add('integrity','Data Integrity（資料完整性）',integrity.status==='pass'?'pass':'fail',`重複帳號 ${integrity.duplicateUsers}｜缺少快照 ${integrity.missingSnapshots}｜成交異常 ${integrity.saleProblems}`);
  add('backup','Backup（有效備份）',release.backupReady?'pass':'fail',release.backupReady?'存在最近有效中央備份。':'找不到有效中央備份。');
  add('restore','Restore Drill（復原演練）',release.restoreDrillReady?'pass':'fail',release.restoreDrillReady?'最近復原演練已通過。':'尚無通過的復原演練。');
  const normalizePhase9Status=(value)=>{
    const v=String(value||'').trim().toLowerCase();
    if(['pass','passed','success','succeeded','ok'].includes(v))return 'pass';
    if(['warn','warning','attention'].includes(v))return 'warning';
    if(['running','queued','pending'].includes(v))return 'running';
    if(['cancelled','canceled'].includes(v))return 'cancelled';
    return 'fail';
  };
  for(const ph of ['9C','9D','9E']){
    const r=latest[ph],mapped=normalizePhase9Status(r?.status);
    const acceptanceStatus=mapped==='pass'?'pass':mapped==='warning'?'warning':'fail';
    add(ph,`${ph} Resilience（韌性驗證）`,acceptanceStatus,r?`最近結果：${r.status}｜${r.completed_at||r.started_at}`:'尚無測試結果。');
  }
  const sf=latest['9F'];let sfStatus='fail',sfText='尚無 9F 耐久測試結果。';
  if(sf){
    const mapped=normalizePhase9Status(sf.status);
    const early=!!(sf.result?.earlyStopped||sf.result?.earlyStop||sf.result?.stopMode==='manual_early_stop');
    if(mapped==='pass'){
      sfStatus=early?'warning':'pass';
      sfText=`最近結果：PASS${early?'（Early Stop／提前停止，僅代表實際運行區間正常）':''}｜${sf.result?.actualRunSeconds?Math.round(Number(sf.result.actualRunSeconds)/60)+' 分鐘':'已完成'}`;
    }else if(mapped==='warning'){
      sfStatus='warning';sfText=`最近結果：WARNING｜${sf.result?.actualRunSeconds?Math.round(Number(sf.result.actualRunSeconds)/60)+' 分鐘':'-'}`;
    }else if(mapped==='running'){
      sfStatus='warning';sfText='最近耐久測試仍在執行中，尚未完成最終判定。';
    }else{
      sfStatus='fail';sfText=`最近結果：${sf.status||'failed'}`;
    }
  }
  add('9F','9F Soak Test（長時間耐久測試）',sfStatus,sfText);
  const fail=checks.filter(x=>x.status==='fail').length,warning=checks.filter(x=>x.status==='warning').length;
  return {status:fail?'fail':warning?'warning':'pass',checks,pass:checks.filter(x=>x.status==='pass').length,warning,fail,checkedAt:now()};
}
async function phase11PilotSummary(){
  const rows=(await pool.query(`SELECT p.*,c.name,c.enabled,c.expires_at,c.last_auth_at,n.last_seen_at AS node_last_seen_at,n.app_version AS node_app_version,
    (SELECT se.status FROM sync_events se WHERE se.company_id=p.company_id ORDER BY se.id DESC LIMIT 1) AS last_sync_status,
    (SELECT se.created_at FROM sync_events se WHERE se.company_id=p.company_id ORDER BY se.id DESC LIMIT 1) AS last_sync_at,
    (SELECT COUNT(*)::int FROM diagnostic_events de WHERE de.company_id=p.company_id AND de.resolved=FALSE AND de.severity IN ('error','critical')) AS open_errors
    FROM pilot_dealers p LEFT JOIN companies c ON c.id=p.company_id LEFT JOIN dealer_nodes n ON n.company_id=p.company_id ORDER BY p.id DESC LIMIT 100`)).rows;
  const active=rows.filter(x=>x.status==='active').length,completed=rows.filter(x=>x.status==='completed').length;
  return {rows,active,completed,total:rows.length};
}
async function phase11ProductionReadiness(){
  const [acceptance,pilot]=await Promise.all([phase11AcceptanceSummary(),phase11PilotSummary()]);
  let status='ready',note='具備正式商用上線條件。';
  if(acceptance.fail>0){status='not_ready';note=`商用驗收仍有 ${acceptance.fail} 項失敗，請先處理。`}
  else if(pilot.completed<1){status='warning';note='核心驗收已通過，但尚未完成至少 1 間 Dealer 的 Pilot（試營運）驗收。'}
  else if(acceptance.warning>0){status='warning';note=`核心驗收無失敗，但仍有 ${acceptance.warning} 項注意事項。`}
  return {status,note,acceptance,pilot,checkedAt:now()};
}


// Phase 12A-12D: Subscription & Licensing（訂閱、付款與授權中心）
function dateOnly(v){return String(v||'').slice(0,10)}
function addPlanPeriod(base,interval='month',count=1){const d=new Date(`${dateOnly(base)||today()}T12:00:00+08:00`),n=Math.max(1,Number(count)||1);if(interval==='year')d.setFullYear(d.getFullYear()+n);else if(interval==='day')d.setDate(d.getDate()+n);else d.setMonth(d.getMonth()+n);return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`}
function addDateDays(base,days=0){const d=new Date(`${dateOnly(base)||today()}T12:00:00+08:00`);d.setDate(d.getDate()+Number(days||0));return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`}
async function subscriptionAccess(companyId,client=pool){const q=await client.query(`SELECT s.*,p.name AS plan_name,p.grace_days,p.billing_interval,p.billing_interval_count,p.price_cents,p.currency FROM dealer_subscriptions s LEFT JOIN subscription_plans p ON p.id=s.plan_id WHERE s.company_id=$1`,[companyId]);const x=q.rows[0];if(!x)return {managed:false,status:'legacy',allowed:true};const t=today(),end=dateOnly(x.current_period_end),grace=dateOnly(x.grace_until);let status=String(x.status||'active'),allowed=true;if(['suspended','cancelled'].includes(status))allowed=false;else if(x.cancel_at_period_end&&end&&t>end){status='cancelled';allowed=false}else if(end&&t>end){if(grace&&t<=grace){status='grace_period';allowed=true}else{status='past_due';allowed=false}}else if(status==='past_due')status='active';return {managed:true,...x,status,allowed,planName:x.plan_name||'',periodEnd:end,graceUntil:grace}}
async function refreshSubscriptionStatuses(){try{const rows=(await pool.query(`SELECT company_id,status,current_period_end,grace_until,cancel_at_period_end FROM dealer_subscriptions`)).rows,t=today();for(const r of rows){let n=r.status;const end=dateOnly(r.current_period_end),gr=dateOnly(r.grace_until);if(['suspended','cancelled'].includes(n))continue;if(r.cancel_at_period_end&&end&&t>end)n='cancelled';else if(end&&t>end)n=gr&&t<=gr?'grace_period':'past_due';else if(['past_due','grace_period','trial'].includes(n))n='active';if(n!==r.status)await pool.query(`UPDATE dealer_subscriptions SET status=$1,updated_at=$2 WHERE company_id=$3`,[n,now(),r.company_id])}}catch(e){console.warn('subscription status refresh failed:',e?.message||e)}}
async function phase12Summary(options={}){
  await refreshSubscriptionStatuses();
  const pageSize=10;
  const cleanPage=v=>Math.max(1,Number(v||1));
  const cleanSearch=v=>String(v||'').trim();

  const paymentPage=cleanPage(options.paymentPage),paymentSearch=cleanSearch(options.paymentSearch),paymentStatus=cleanSearch(options.paymentStatus);
  const planPage=cleanPage(options.planPage),planSearch=cleanSearch(options.planSearch),planStatus=cleanSearch(options.planStatus);
  const subscriptionPage=cleanPage(options.subscriptionPage),subscriptionSearch=cleanSearch(options.subscriptionSearch),subscriptionStatus=cleanSearch(options.subscriptionStatus);

  const paymentWh=['t.deleted_at IS NULL'],paymentParams=[];
  if(paymentSearch){paymentParams.push(`%${paymentSearch}%`);paymentWh.push(`(c.name ILIKE $${paymentParams.length} OR t.description ILIKE $${paymentParams.length} OR t.id ILIKE $${paymentParams.length})`)}
  if(paymentStatus&&['pending','paid','failed','refunded'].includes(paymentStatus)){paymentParams.push(paymentStatus);paymentWh.push(`t.status=$${paymentParams.length}`)}
  const paymentWhere=paymentWh.length?`WHERE ${paymentWh.join(' AND ')}`:'';
  const paymentTotal=Number((await pool.query(`SELECT COUNT(*)::int AS n FROM payment_transactions t JOIN companies c ON c.id=t.company_id ${paymentWhere}`,paymentParams)).rows[0]?.n||0);
  const paymentTotalPages=Math.max(1,Math.ceil(paymentTotal/pageSize)),paymentSafePage=Math.min(paymentPage,paymentTotalPages),paymentOffset=(paymentSafePage-1)*pageSize;
  const paymentQueryParams=[...paymentParams,pageSize,paymentOffset],paymentLimitIdx=paymentParams.length+1,paymentOffsetIdx=paymentParams.length+2;

  const planWh=[],planParams=[];
  if(planSearch){planParams.push(`%${planSearch}%`);planWh.push(`(p.name ILIKE $${planParams.length} OR COALESCE(p.description,'') ILIKE $${planParams.length})`)}
  if(planStatus==='active'||planStatus==='inactive'){planParams.push(planStatus==='active');planWh.push(`p.active=$${planParams.length}`)}
  const planWhere=planWh.length?`WHERE ${planWh.join(' AND ')}`:'';
  const planTotal=Number((await pool.query(`SELECT COUNT(*)::int AS n FROM subscription_plans p ${planWhere}`,planParams)).rows[0]?.n||0);
  const planTotalPages=Math.max(1,Math.ceil(planTotal/pageSize)),planSafePage=Math.min(planPage,planTotalPages),planOffset=(planSafePage-1)*pageSize;
  const planQueryParams=[...planParams,pageSize,planOffset],planLimitIdx=planParams.length+1,planOffsetIdx=planParams.length+2;

  const subWh=[],subParams=[];
  if(subscriptionSearch){subParams.push(`%${subscriptionSearch}%`);subWh.push(`(c.name ILIKE $${subParams.length} OR c.id ILIKE $${subParams.length} OR COALESCE(p.name,'') ILIKE $${subParams.length})`)}
  if(subscriptionStatus&&['active','trial','grace_period','past_due','suspended','cancelled'].includes(subscriptionStatus)){subParams.push(subscriptionStatus);subWh.push(`s.status=$${subParams.length}`)}
  const subWhere=subWh.length?`WHERE ${subWh.join(' AND ')}`:'';
  const subTotal=Number((await pool.query(`SELECT COUNT(*)::int AS n FROM dealer_subscriptions s JOIN companies c ON c.id=s.company_id LEFT JOIN subscription_plans p ON p.id=s.plan_id ${subWhere}`,subParams)).rows[0]?.n||0);
  const subTotalPages=Math.max(1,Math.ceil(subTotal/pageSize)),subSafePage=Math.min(subscriptionPage,subTotalPages),subOffset=(subSafePage-1)*pageSize;
  const subQueryParams=[...subParams,pageSize,subOffset],subLimitIdx=subParams.length+1,subOffsetIdx=subParams.length+2;

  const [plans,planOptions,providers,subs,pays,events,companies,pendingCount,subCounters]=await Promise.all([
    pool.query(`SELECT p.* FROM subscription_plans p ${planWhere} ORDER BY p.sort_order,p.name LIMIT $${planLimitIdx} OFFSET $${planOffsetIdx}`,planQueryParams),
    pool.query(`SELECT * FROM subscription_plans WHERE active=TRUE ORDER BY sort_order,name`),
    pool.query(`SELECT id,provider_type,display_name,enabled,mode,webhook_enabled,adapter_key,capabilities,created_at,updated_at FROM payment_providers ORDER BY CASE WHEN id='manual' THEN 0 ELSE 1 END,display_name`),
    pool.query(`SELECT s.*,c.name AS company_name,c.enabled,c.expires_at,p.name AS plan_name,p.price_cents,p.currency,p.billing_interval,p.billing_interval_count,p.grace_days, EXISTS(SELECT 1 FROM payment_transactions pt WHERE pt.company_id=s.company_id AND pt.status='paid') AS has_paid_payment, (SELECT MAX(pt.paid_at) FROM payment_transactions pt WHERE pt.company_id=s.company_id AND pt.status='paid') AS last_paid_at FROM dealer_subscriptions s JOIN companies c ON c.id=s.company_id LEFT JOIN subscription_plans p ON p.id=s.plan_id ${subWhere} ORDER BY c.name LIMIT $${subLimitIdx} OFFSET $${subOffsetIdx}`,subQueryParams),
    pool.query(`SELECT t.*,c.name AS company_name,pr.display_name AS provider_name FROM payment_transactions t JOIN companies c ON c.id=t.company_id LEFT JOIN payment_providers pr ON pr.id=t.provider_id ${paymentWhere} ORDER BY t.created_at DESC LIMIT $${paymentLimitIdx} OFFSET $${paymentOffsetIdx}`,paymentQueryParams),
    pool.query(`SELECT e.*,c.name AS company_name FROM subscription_events e JOIN companies c ON c.id=e.company_id ORDER BY e.id DESC LIMIT 100`),
    pool.query(`SELECT id,name,enabled,expires_at,trial FROM companies ORDER BY name`),
    pool.query(`SELECT COUNT(*)::int AS n FROM payment_transactions WHERE status='pending' AND deleted_at IS NULL`),
    pool.query(`SELECT COUNT(*) FILTER (WHERE status='active')::int AS active,COUNT(*) FILTER (WHERE status IN ('grace_period','past_due','suspended'))::int AS attention FROM dealer_subscriptions`)
  ]);
  return {
    serverVersion:'14.9.10',apiVersion:'6.9.10',
    plans:plans.rows,planOptions:planOptions.rows,providers:providers.rows,subscriptions:subs.rows,payments:pays.rows,
    planPagination:{page:planSafePage,pageSize,total:planTotal,totalPages:planTotalPages,search:planSearch,status:planStatus},
    subscriptionPagination:{page:subSafePage,pageSize,total:subTotal,totalPages:subTotalPages,search:subscriptionSearch,status:subscriptionStatus},
    paymentPagination:{page:paymentSafePage,pageSize,total:paymentTotal,totalPages:paymentTotalPages,search:paymentSearch,status:paymentStatus},
    activeSubscriptionCount:Number(subCounters.rows[0]?.active||0),attentionSubscriptionCount:Number(subCounters.rows[0]?.attention||0),
    pendingPaymentCount:Number(pendingCount.rows[0]?.n||0),events:events.rows,companies:companies.rows
  }
}
async function subscriptionEvent(client,companyId,eventType,o={}){await client.query(`INSERT INTO subscription_events(company_id,event_type,old_status,new_status,old_period_end,new_period_end,source,reference_id,actor,detail,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,[companyId,eventType,o.oldStatus||'',o.newStatus||'',o.oldPeriodEnd||null,o.newPeriodEnd||null,o.source||'',o.referenceId||'',o.actor||'',o.detail||'',now()])}
async function syncCompanyLicenseToSubscription(client,companyId,enabled,actor='super_admin'){const sub=(await client.query('SELECT * FROM dealer_subscriptions WHERE company_id=$1 FOR UPDATE',[companyId])).rows[0];if(!sub)return;const newStatus=enabled?'active':'suspended',newCancel=enabled?false:sub.cancel_at_period_end;if(sub.status===newStatus&&sub.cancel_at_period_end===newCancel)return;await client.query('UPDATE dealer_subscriptions SET status=$1,cancel_at_period_end=$2,updated_at=$3 WHERE company_id=$4',[newStatus,newCancel,now(),companyId]);await subscriptionEvent(client,companyId,enabled?'license_enabled_from_overview':'license_disabled_from_overview',{oldStatus:sub.status,newStatus,oldPeriodEnd:sub.current_period_end,newPeriodEnd:sub.current_period_end,source:'company_license',actor,detail:enabled?'由車行總覽手動啟用授權，同步恢復訂閱狀態':'由車行總覽手動停用授權，同步停權訂閱狀態'})}
async function syncCompanyExpiryToSubscription(client,companyId,newEnd,actor='super_admin',source='company_overview'){const sub=(await client.query(`SELECT s.*,COALESCE(p.grace_days,0) AS plan_grace_days FROM dealer_subscriptions s LEFT JOIN subscription_plans p ON p.id=s.plan_id WHERE s.company_id=$1 FOR UPDATE`,[companyId])).rows[0];if(!sub)return {managed:false};const end=dateOnly(newEnd);if(!end)return {managed:true,skipped:true};const oldEnd=dateOnly(sub.current_period_end),grace=addDateDays(end,Number(sub.plan_grace_days||0));if(oldEnd===end&&dateOnly(sub.grace_until)===grace)return {managed:true,changed:false,currentPeriodEnd:end,graceUntil:grace};await client.query(`UPDATE dealer_subscriptions SET current_period_end=$1,grace_until=$2,updated_at=$3 WHERE company_id=$4`,[end,grace,now(),companyId]);await subscriptionEvent(client,companyId,'period_adjusted_manually',{oldStatus:sub.status,newStatus:sub.status,oldPeriodEnd:oldEnd,newPeriodEnd:end,source,actor,detail:`Super Admin 手動調整期限：${oldEnd||'-'} → ${end}；寬限至 ${grace}`});return {managed:true,changed:true,currentPeriodEnd:end,graceUntil:grace}}

const app=express();
app.disable('x-powered-by');
app.use(securityHeaders);
app.use(cors({origin:true,credentials:false}));
app.use(express.json({limit:'30mb'}));
app.use('/api',generalRateLimit);
// Phase 10B Audit Log（稽核紀錄）: mutations and login results are recorded; secrets are redacted.
app.use(['/api/auth/login','/api/super/login'],(req,res,next)=>{const started=Date.now();res.on('finish',()=>auditSecurityEvent(req,{action:req.path.includes('/super/')?'super_login':'dealer_login',category:'authentication',status:res.statusCode<400?'success':(res.statusCode===429?'blocked':'rejected'),detail:`HTTP ${res.statusCode} / ${Date.now()-started}ms`}));next()});
app.use('/api',(req,res,next)=>{if(!['POST','PUT','PATCH','DELETE'].includes(req.method)||req.path==='/auth/login'||req.path==='/super/login')return next();const started=Date.now();res.on('finish',()=>{if(!req.auth)return;const auditPath=String(req.originalUrl||req.url||req.path||'').split('?')[0];let category='dealer';if(auditPath.startsWith('/api/super/security/release-snapshot'))category='release';else if(auditPath.startsWith('/api/super/security/integrity-check'))category='data_integrity';else if(auditPath.startsWith('/api/super/security/'))category='security';else if(auditPath.startsWith('/api/super/'))category='super_admin';else if(auditPath.startsWith('/api/admin/'))category='dealer_admin';auditSecurityEvent(req,{action:`${req.method} ${auditPath}`,category,status:res.statusCode<400?'success':'rejected',detail:`HTTP ${res.statusCode} / ${Date.now()-started}ms`,metadata:{body:safeAuditPayload(req.body)}})});next()});
app.use((req,res,next)=>{const started=process.hrtime.bigint();res.on('finish',()=>{const ms=Number(process.hrtime.bigint()-started)/1e6;recordApiPerf(ms,res.statusCode)});next()});
app.use('/sales', express.static(path.join(__dirname,'public','sales'),{setHeaders:(res)=>{res.setHeader('Cache-Control','no-store, no-cache, must-revalidate, proxy-revalidate');res.setHeader('Pragma','no-cache');res.setHeader('Expires','0');}}));
app.use('/m200530366', express.static(path.join(__dirname,'public','m200530366'),{setHeaders:(res)=>{res.setHeader('Cache-Control','no-store, no-cache, must-revalidate, proxy-revalidate');res.setHeader('Pragma','no-cache');res.setHeader('Expires','0');}}));
app.get('/sales',(req,res)=>res.redirect('/sales/'));
app.get('/m200530366',(req,res)=>res.redirect('/m200530366/'));

// A physical PostgreSQL standby must never accept mutations. After promotion,
// refreshHaRuntime automatically flips writeReady and normal traffic resumes.
app.use('/api',(req,res,next)=>{
  if(CENTRAL_HA_ENABLED&&haRuntime.dbRole==='standby'&&!['GET','HEAD','OPTIONS'].includes(req.method)){
    return res.status(503).json({error:'中央服務目前為備援待命狀態，請稍後重試',errorCode:'HA_STANDBY_READ_ONLY'});
  }
  next();
});

// Phase 9B Maintenance Mode（維護演練模式）: intentionally creates an application-level brownout
// for normal write traffic so Node reconnect/retry behavior can be observed without touching PostgreSQL itself.
app.use('/api',(req,res,next)=>{
  if(!maintenanceActive())return next();
  if(req.path.startsWith('/super/')||req.path==='/health'||req.path==='/ready'||['GET','HEAD','OPTIONS'].includes(req.method))return next();
  res.setHeader('Retry-After','15');
  return res.status(503).json({error:'中央服務正在執行受控維護演練，請稍後自動重試',errorCode:'RESILIENCE_MAINTENANCE',maintenance:{reason:maintenanceRuntime.reason,expiresAt:maintenanceRuntime.expiresAt}});
});

app.get('/api/ready',async(req,res)=>{
  const st=await refreshHaRuntime({allowMigration:false,recordTransition:false});
  const ready=!CENTRAL_HA_ENABLED?st.schemaReady:(st.dbRole==='primary'&&st.schemaReady);
  const body={ok:ready,time:now(),service:'car-dealer-central',version:'6.9.11',haEnabled:CENTRAL_HA_ENABLED,dbRole:st.dbRole,writeReady:ready,schemaReady:st.schemaReady,site:CENTRAL_HA_SITE,instanceId:CENTRAL_HA_INSTANCE_ID};
  res.status(ready?200:503).json(body);
});

app.get('/api/health',async(req,res)=>{
  try{
    await pool.query('SELECT 1');
    res.json({ok:true,time:now(),service:'car-dealer-central',database:'postgres',version:'6.9.11',schemaVersion:SERVER_SCHEMA_TARGET,architecture:'phase14d3-operating-cost-history-pagination'});
  }catch(e){
    res.status(503).json({ok:false,error:'database unavailable'});
  }
});

app.get('/api/public/node-status',async(req,res,next)=>{
  try{
    const companyCode=String(req.query.companyCode||'').trim();
    if(!companyCode)return res.json({ok:true,known:false,online:false});
    const c=await getCompany(companyCode);
    if(!c)return res.json({ok:true,known:false,online:false});
    const n=(await pool.query('SELECT * FROM dealer_nodes WHERE company_id=$1',[companyCode])).rows[0];
    res.json({ok:true,known:true,online:!!(n&&nodeOnline(n)),lastSeenAt:n?.last_seen_at||null});
  }catch(e){next(e)}
});

app.post('/api/company/register',async(req,res,next)=>{
  const client=await pool.connect();
  try{
    const {companyName,companyCode,ownerName,email,username,password}=req.body||{};
    if(!companyName||!companyCode||!ownerName||!username||!password)
      return res.status(400).json({error:'資料不完整'});
    if(!/^[A-Za-z0-9_-]{3,40}$/.test(companyCode))
      return res.status(400).json({error:'車行代碼格式不正確'});

    const exists=await client.query('SELECT 1 FROM companies WHERE id=$1',[companyCode]);
    if(exists.rowCount)return res.status(409).json({error:'車行代碼已被使用'});

    const company={
      id:companyCode,name:companyName,enabled:true,start_date:today(),expires_at:addDays(7),
      created_at:now(),created_by:'self',contact_email:email||'',trial:true
    };
    const user={
      id:`admin_${crypto.randomUUID()}`,company_id:companyCode,username,name:ownerName,
      role:'admin',commission_rate:0,base_salary:0,enabled:true,updated_at:now()
    };
    const snapshot={
      settings:{companyName,taxRate:0,defaultBranchId:companyCode+'_main'},
      users:[{id:user.id,username:user.username,password:'',name:user.name,role:'admin',branchId:companyCode+'_main',commissionRate:0,baseSalary:0}],
      cars:[],saleRequests:[],operationLogs:[]
    };

    await client.query('BEGIN');
    await client.query(`
      INSERT INTO companies(id,name,enabled,start_date,expires_at,created_at,created_by,contact_email,trial,system_activation_date,system_activation_set_at,system_activation_set_by)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$4,$6,$7)
    `,[company.id,company.name,true,company.start_date,company.expires_at,company.created_at,company.created_by,company.contact_email,true]);
    await client.query(`INSERT INTO branches(id,company_id,code,name,is_head_office,enabled,address,phone,created_at,updated_at) VALUES($1,$2,'MAIN','總店',TRUE,TRUE,'','',$3,$3)`,[companyCode+'_main',companyCode,now()]);
    user.branch_id=companyCode+'_main';
    await client.query('UPDATE companies SET owner_user_id=$1 WHERE id=$2',[user.id,companyCode]);
    await client.query(`
      INSERT INTO users(id,company_id,username,password_hash,name,role,commission_rate,base_salary,enabled,updated_at,branch_id)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    `,[user.id,user.company_id,user.username,hashPassword(password),user.name,user.role,0,0,true,user.updated_at,user.branch_id]);
    await client.query(`
      INSERT INTO snapshots(company_id,version,json,updated_at) VALUES($1,$2,$3::jsonb,$4)
    `,[companyCode,1,JSON.stringify(snapshot),now()]);
    await client.query('COMMIT');

    const registeredCompany={...company,main_username:username};
    res.json({token:signUser(user),company:companyDto(registeredCompany),user:userDto(user),branches:[branchDto({id:companyCode+'_main',company_id:companyCode,code:'MAIN',name:'總店',is_head_office:true,enabled:true,address:'',phone:'',created_at:company.created_at,updated_at:company.created_at})],defaultBranchId:companyCode+'_main',snapshot,version:1,offlineTicket:issueOfflineTicket(registeredCompany,user,password,OFFLINE_GRACE_SECONDS),offlinePolicy:{graceSeconds:OFFLINE_GRACE_SECONDS,test:false}});
  }catch(e){
    try{ await client.query('ROLLBACK'); }catch{}
    next(e);
  }finally{ client.release(); }
});

app.post('/api/auth/login',loginGuard('dealer'),async(req,res,next)=>{
  try{
    const {companyCode,username,password,rememberLogin=false}=req.body||{};
    const c=await getCompany(companyCode);
    if(!c)return res.status(401).json({error:'找不到此車行代碼'});
    const st=companyStatus(c);
    const billing=await subscriptionAccess(c.id);
    if(['已停用','尚未啟用'].includes(st))return res.status(403).json({error:`車行目前${st}`});
    if(!billing.managed&&st!=='啟用中')return res.status(403).json({error:`車行目前${st}`});
    if(billing.managed&&!billing.allowed)return res.status(403).json({error:`訂閱授權狀態：${billing.status}`,subscriptionStatus:billing.status,billingAccessOnly:true,planName:billing.planName||'',currentPeriodEnd:billing.periodEnd||null,graceUntil:billing.graceUntil||null});

    const {rows}=await pool.query('SELECT * FROM users WHERE company_id=$1 AND username=$2 AND enabled=TRUE AND login_enabled=TRUE',[companyCode,username]);
    const u=rows[0];
    if(!u||!verifyPassword(password,u.password_hash))return res.status(401).json({error:'帳號或密碼錯誤'});

    const test=(await pool.query('SELECT * FROM offline_license_tests WHERE company_id=$1',[companyCode])).rows[0];
    if(test?.enabled && test?.simulate_outage)return res.status(503).json({error:'授權服務暫時無回應',offlineFaultTest:true});
    const snap=await getSnapshot(companyCode);
    await pool.query('UPDATE companies SET last_auth_at=$1 WHERE id=$2',[now(),companyCode]);
    const fresh=await getCompany(companyCode);
    const branches=await getCompanyBranches(companyCode);
    const defaultBranch=branches.find(b=>b.isHeadOffice)||branches[0]||null;
    const offlineSeconds=test?.enabled?Number(test.duration_seconds||60):OFFLINE_GRACE_SECONDS;
    res.json({token:signUser(u,!!rememberLogin),company:{...companyDto(fresh),subscription:billing.managed?{status:billing.status,planName:billing.planName,currentPeriodEnd:billing.periodEnd,graceUntil:billing.graceUntil,autoRenew:!!billing.auto_renew}:null},user:userDto(u),branches,defaultBranchId:defaultBranch?.id||'',snapshot:snapshotForUser(snap.snapshot,u),version:snap.version,offlineTicket:issueOfflineTicket(fresh,u,password,offlineSeconds),offlinePolicy:{graceSeconds:offlineSeconds,test:!!test?.enabled},rememberLogin:!!rememberLogin});
  }catch(e){ next(e); }
});

app.get('/api/session/restore',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    const u=await getUserById(req.auth.companyId,req.auth.sub);
    if(!u)return res.status(401).json({error:'帳號已失效'});
    const snap=await getSnapshot(req.auth.companyId);
    const branches=await getCompanyBranches(req.auth.companyId);
    const defaultBranch=branches.find(b=>b.isHeadOffice)||branches[0]||null;
    res.json({token:refreshedUserToken(req,u),company:{...companyDto(req.company),subscription:req.subscription?.managed?{status:req.subscription.status,planName:req.subscription.planName,currentPeriodEnd:req.subscription.periodEnd,graceUntil:req.subscription.graceUntil,autoRenew:!!req.subscription.auto_renew}:null},user:userDto(u),branches,defaultBranchId:defaultBranch?.id||'',snapshot:snapshotForUser(snap.snapshot,u),version:snap.version});
  }catch(e){ next(e); }
});



// Phase 13A-13E: Dealer Desktop Subscription Center（車行端方案、付款、通知與授權 UX）
function phase13StatusLabel(x){return ({active:'使用中',trial:'試用中',grace_period:'寬限期',past_due:'已逾期',suspended:'已停權',cancelled:'已取消',legacy:'舊版授權'})[String(x||'')]||String(x||'未知')}
function phase13PaymentLabel(x){return ({pending:'待確認',paid:'已付款',failed:'付款失敗',refunded:'已退款',chargeback:'爭議款',cancelled:'已取消'})[String(x||'')]||String(x||'')}
function phase13DaysUntil(d){const x=dateOnly(d);if(!x)return null;const a=new Date(today()+'T00:00:00Z'),b=new Date(x+'T00:00:00Z');return Math.ceil((b-a)/86400000)}
async function dealerSubscriptionCenter(companyId,{paymentPage=1,paymentSearch='',paymentStatus='',notificationPage=1}={}){
  const c=await getCompany(companyId);if(!c)throw Object.assign(new Error('車行不存在'),{statusCode:404});
  const access=await subscriptionAccess(companyId);
  const pageSize=10,pp=Math.max(1,Number(paymentPage)||1),np=Math.max(1,Number(notificationPage)||1),search=String(paymentSearch||'').trim().slice(0,100),status=String(paymentStatus||'').trim();
  const params=[companyId];const wh=['t.company_id=$1','t.deleted_at IS NULL'];
  if(search){params.push('%'+search+'%');wh.push(`(t.description ILIKE $${params.length} OR t.id ILIKE $${params.length} OR COALESCE(t.provider_transaction_id,'') ILIKE $${params.length})`)}
  if(['pending','paid','failed','refunded','chargeback','cancelled'].includes(status)){params.push(status);wh.push(`t.status=$${params.length}`)}
  const where='WHERE '+wh.join(' AND '),total=Number((await pool.query(`SELECT COUNT(*)::int n FROM payment_transactions t ${where}`,params)).rows[0]?.n||0),pages=Math.max(1,Math.ceil(total/pageSize)),safe=Math.min(pp,pages),off=(safe-1)*pageSize;
  const qp=[...params,pageSize,off],li=params.length+1,oi=params.length+2;
  const payments=(await pool.query(`SELECT t.id,t.provider_id,t.provider_transaction_id,t.amount_cents,t.currency,t.payment_type,t.status,t.description,t.paid_at,t.confirmed_at,t.created_at,t.updated_at,p.display_name provider_name FROM payment_transactions t LEFT JOIN payment_providers p ON p.id=t.provider_id ${where} ORDER BY t.created_at DESC LIMIT $${li} OFFSET $${oi}`,qp)).rows.map(x=>({...x,statusLabel:phase13PaymentLabel(x.status)}));
  let plan=null;if(access.managed&&access.plan_id)plan=(await pool.query(`SELECT id,name,description,price_cents,currency,billing_interval,billing_interval_count,grace_days,max_nodes,features,active FROM subscription_plans WHERE id=$1`,[access.plan_id])).rows[0]||null;
  const events=(await pool.query(`SELECT id,event_type,old_status,new_status,old_period_end,new_period_end,source,reference_id,detail,created_at FROM subscription_events WHERE company_id=$1 ORDER BY id DESC LIMIT 80`,[companyId])).rows;
  const recentPayments=(await pool.query(`SELECT id,status,amount_cents,currency,description,created_at,paid_at FROM payment_transactions WHERE company_id=$1 AND deleted_at IS NULL AND status IN ('paid','failed','refunded','chargeback') ORDER BY created_at DESC LIMIT 50`,[companyId])).rows;
  const notifications=[];const push=(n)=>{if(!notifications.some(x=>x.key===n.key))notifications.push(n)};
  const days=phase13DaysUntil(access.periodEnd||c.expires_at);
  if(access.managed){
    if(access.status==='grace_period')push({key:`state:grace:${access.periodEnd}`,kind:'warning',title:'目前處於寬限期',message:`付費期限已到，寬限至 ${access.graceUntil||'-'}。請儘快完成續費。`,createdAt:now(),priority:100});
    if(['past_due','suspended','cancelled'].includes(access.status))push({key:`state:block:${access.status}:${access.periodEnd}`,kind:'danger',title:`方案${phase13StatusLabel(access.status)}`,message:`目前方案狀態為「${phase13StatusLabel(access.status)}」，部分或全部功能可能無法使用。`,createdAt:now(),priority:110});
    if(days!==null&&days>=0&&days<=7&&access.status==='active')push({key:`state:expiring:${access.periodEnd}`,kind:'warning',title:'方案即將到期',message:`距離付費期限 ${access.periodEnd} 還有 ${days} 天。`,createdAt:now(),priority:90});
  }else if(c.expires_at&&phase13DaysUntil(c.expires_at)<=7)push({key:`legacy:expiring:${c.expires_at}`,kind:'warning',title:'授權即將到期',message:`目前授權到期日為 ${c.expires_at}。`,createdAt:now(),priority:80});
  for(const p of recentPayments){const k=`payment:${p.id}`;if(p.status==='paid')push({key:k,kind:'success',title:'付款成功',message:`${p.description||'付款'} NT$${Math.round(Number(p.amount_cents||0)/100).toLocaleString()} 已完成。`,createdAt:p.paid_at||p.created_at,priority:40});else if(p.status==='failed')push({key:k,kind:'danger',title:'付款失敗',message:`${p.description||'付款'} 未完成，訂閱期限沒有延長。`,createdAt:p.created_at,priority:70});else if(p.status==='refunded')push({key:k,kind:'info',title:'退款紀錄',message:`${p.description||'付款'} 已記錄退款。`,createdAt:p.created_at,priority:50});else if(p.status==='chargeback')push({key:k,kind:'danger',title:'付款爭議',message:`${p.description||'付款'} 已標記為爭議款。`,createdAt:p.created_at,priority:75})}
  for(const e of events){if(['manual_period_adjustment','payment_confirmed','payment_succeeded','license_enabled_from_overview','license_disabled_from_overview','subscription_deleted','renewal_requested'].includes(e.event_type))push({key:`subevt:${e.id}`,kind:e.event_type.includes('disabled')||e.event_type==='subscription_deleted'?'danger':e.event_type==='renewal_requested'?'info':'info',title:e.event_type==='renewal_requested'?'已送出續費需求':'方案異動',message:e.detail||`訂閱狀態已更新為 ${phase13StatusLabel(e.new_status)}`,createdAt:e.created_at,priority:30})}
  notifications.sort((a,b)=>(b.priority-a.priority)||(Date.parse(b.createdAt||0)-Date.parse(a.createdAt||0)));
  const reads=new Set((await pool.query(`SELECT notification_key FROM dealer_notification_reads WHERE company_id=$1`,[companyId])).rows.map(x=>x.notification_key));notifications.forEach(n=>n.read=reads.has(n.key));
  const nTotal=notifications.length,nPages=Math.max(1,Math.ceil(nTotal/pageSize)),nSafe=Math.min(np,nPages),nSlice=notifications.slice((nSafe-1)*pageSize,nSafe*pageSize),unread=notifications.filter(n=>!n.read).length;
  const availablePlans=(await pool.query(`SELECT id,name,description,price_cents,currency,billing_interval,billing_interval_count,grace_days,max_nodes,features,sort_order FROM subscription_plans WHERE active=TRUE ORDER BY sort_order,name`)).rows;
  const enabledProviders=(await pool.query(`SELECT id,provider_type,display_name,mode,capabilities FROM payment_providers WHERE enabled=TRUE ORDER BY CASE WHEN id='manual' THEN 0 ELSE 1 END,display_name`)).rows;
  return {ok:true,serverTime:now(),company:{id:c.id,name:c.name,licenseStatus:companyStatus(c),enabled:!!c.enabled,startDate:dateOnly(c.start_date),expiresAt:dateOnly(c.expires_at)},subscription:access.managed?{managed:true,status:access.status,statusLabel:phase13StatusLabel(access.status),allowed:!!access.allowed,planId:access.plan_id||null,planName:access.planName||plan?.name||'',currentPeriodStart:dateOnly(access.current_period_start),currentPeriodEnd:access.periodEnd,graceUntil:access.graceUntil,remainingDays:days,autoRenew:!!access.auto_renew,cancelAtPeriodEnd:!!access.cancel_at_period_end,nextRenewalAt:access.next_renewal_at||null,lastRenewalStatus:access.last_renewal_status||'',renewalFailures:Number(access.renewal_failures||0),providerId:access.provider_id||null}: {managed:false,status:'legacy',statusLabel:'舊版授權',allowed:companyStatus(c)==='啟用中',remainingDays:phase13DaysUntil(c.expires_at)},plan,payments,paymentPagination:{page:safe,pageSize,total,totalPages:pages,search,status},notifications:nSlice,notificationPagination:{page:nSafe,pageSize,total:nTotal,totalPages:nPages,unread},availablePlans,paymentChannels:enabledProviders,onlinePaymentReady:enabledProviders.some(p=>p.id!=='manual'&&p.mode==='live')};
}
app.get('/api/dealer/subscription-center',auth,async(req,res,next)=>{try{if(req.auth.role!=='admin')return res.status(403).json({error:'僅車行管理員可查看方案與付款資訊'});const q=req.query||{};res.json(await dealerSubscriptionCenter(req.auth.companyId,{paymentPage:q.paymentPage,paymentSearch:q.paymentSearch,paymentStatus:q.paymentStatus,notificationPage:q.notificationPage}))}catch(e){next(e)}});
app.post('/api/dealer/subscription-center/notifications/read',auth,async(req,res,next)=>{try{if(req.auth.role!=='admin')return res.status(403).json({error:'僅車行管理員可操作通知'});const key=String(req.body?.key||'').slice(0,300);if(!key)return res.status(400).json({error:'通知編號不正確'});await pool.query(`INSERT INTO dealer_notification_reads(company_id,notification_key,read_at,read_by) VALUES($1,$2,$3,$4) ON CONFLICT(company_id,notification_key) DO UPDATE SET read_at=EXCLUDED.read_at,read_by=EXCLUDED.read_by`,[req.auth.companyId,key,now(),req.auth.username||req.auth.sub]);res.json({ok:true})}catch(e){next(e)}});
app.post('/api/dealer/subscription-center/notifications/read-all',auth,async(req,res,next)=>{try{if(req.auth.role!=='admin')return res.status(403).json({error:'僅車行管理員可操作通知'});const d=await dealerSubscriptionCenter(req.auth.companyId,{notificationPage:1});for(const n of d.notifications||[])await pool.query(`INSERT INTO dealer_notification_reads(company_id,notification_key,read_at,read_by) VALUES($1,$2,$3,$4) ON CONFLICT(company_id,notification_key) DO UPDATE SET read_at=EXCLUDED.read_at,read_by=EXCLUDED.read_by`,[req.auth.companyId,n.key,now(),req.auth.username||req.auth.sub]);res.json({ok:true})}catch(e){next(e)}});
app.post('/api/dealer/subscription-center/renewal-request',auth,async(req,res,next)=>{const client=await pool.connect();try{if(req.auth.role!=='admin')return res.status(403).json({error:'僅車行管理員可申請方案／續費'});const requestedPlanId=String(req.body?.planId||'').trim();let requestedPlan=null;if(requestedPlanId){requestedPlan=(await client.query(`SELECT id,name,price_cents,currency,billing_interval,billing_interval_count FROM subscription_plans WHERE id=$1 AND active=TRUE`,[requestedPlanId])).rows[0];if(!requestedPlan)return res.status(400).json({error:'選擇的方案不存在或目前已停用'})}const access=await subscriptionAccess(req.auth.companyId,client);const targetPlanId=requestedPlan?.id||access.plan_id||null;if(!targetPlanId)return res.status(400).json({error:'請先從方案商城選擇一個方案'});const actionLabel=requestedPlan&&requestedPlan.id!==access.plan_id?'選擇方案':'續費';const defaultNote=requestedPlan?`車行由 Desktop ${actionLabel}：${requestedPlan.name}`:'車行由 Desktop 送出續費需求';const note=String(req.body?.note||defaultNote).slice(0,500),actor=req.auth.username||req.auth.sub||'dealer_admin',ts=now();await client.query('BEGIN');const open=(await client.query(`SELECT id,status,plan_id,requested_at FROM dealer_renewal_requests WHERE company_id=$1 AND status IN ('pending','contacted') ORDER BY id DESC LIMIT 1 FOR UPDATE`,[req.auth.companyId])).rows[0];if(open){const changed=String(open.plan_id||'')!==String(targetPlanId||'')||!!requestedPlan;await client.query(`UPDATE dealer_renewal_requests SET plan_id=$1,note=$2,requested_by=$3,updated_at=$4 WHERE id=$5`,[targetPlanId,note,actor,ts,open.id]);await subscriptionEvent(client,req.auth.companyId,'renewal_requested',{oldStatus:access.status||'legacy',newStatus:access.status||'legacy',oldPeriodEnd:access.periodEnd||null,newPeriodEnd:access.periodEnd||null,source:'dealer_desktop',referenceId:String(open.id),actor,detail:changed?`更新方案／續費需求：${note}`:note});await client.query('COMMIT');return res.json({ok:true,alreadyPending:true,updated:changed,requestId:open.id,status:open.status,message:changed?'方案／續費需求已更新，Super Admin 會看到你最新選擇的方案。':(open.status==='contacted'?'平台已收到並正在處理你的續費需求。':'續費需求已經送出，平台尚未處理。')})}const row=(await client.query(`INSERT INTO dealer_renewal_requests(company_id,plan_id,status,note,requested_by,requested_at,updated_at) VALUES($1,$2,'pending',$3,$4,$5,$5) RETURNING id`,[req.auth.companyId,targetPlanId,note,actor,ts])).rows[0];await subscriptionEvent(client,req.auth.companyId,'renewal_requested',{oldStatus:access.status||'legacy',newStatus:access.status||'legacy',oldPeriodEnd:access.periodEnd||null,newPeriodEnd:access.periodEnd||null,source:'dealer_desktop',referenceId:String(row.id),actor,detail:note});await client.query('COMMIT');res.json({ok:true,requestId:row.id,status:'pending',message:requestedPlan?`已送出「${requestedPlan.name}」${actionLabel}需求，Super Admin 已收到通知。`:'續費需求已送出，Super Admin 已收到待處理通知。'})}catch(e){try{await client.query('ROLLBACK')}catch{};if(String(e?.code||'')==='23505')return res.json({ok:true,alreadyPending:true,message:'方案／續費需求已經在待處理清單中。'});next(e)}finally{client.release()}});

app.get('/api/node/status',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    const n=(await pool.query('SELECT * FROM dealer_nodes WHERE company_id=$1',[req.auth.companyId])).rows[0];
    res.json({ok:true,online:!!(n&&nodeOnline(n)),lastSeenAt:n?.last_seen_at||null});
  }catch(e){next(e)}
});

// Short-lived ticket avoids putting the normal bearer token in an EventSource URL.
app.post('/api/sales/live-ticket',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    if(req.auth.role!=='sales')return res.status(403).json({error:'僅業務帳號可使用即時更新'});
    const ticket=jwt.sign({sub:req.auth.sub,companyId:req.auth.companyId,role:'sales',tokenVersion:Number(req.auth.tokenVersion||0),purpose:'sales-live'},JWT_SECRET,{expiresIn:'2m'});
    res.json({ok:true,ticket,expiresInSeconds:120});
  }catch(e){next(e)}
});

app.get('/api/sales/live',async(req,res)=>{
  const ticket=String(req.query.ticket||'');
  try{
    const a=jwt.verify(ticket,JWT_SECRET);
    if(a?.purpose!=='sales-live'||a?.role!=='sales')return res.status(401).end();
    const ur=await pool.query('SELECT enabled,token_version FROM users WHERE id=$1 AND company_id=$2',[a.sub,a.companyId]);
    const u=ur.rows[0];
    if(!u||!u.enabled||Number(u.token_version||0)!==Number(a.tokenVersion||0))return res.status(401).end();
    const c=await getCompany(a.companyId);
    if(!c||companyStatus(c)!=='啟用中')return res.status(403).end();
    res.setHeader('Content-Type','text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control','no-cache, no-transform');
    res.setHeader('Connection','keep-alive');
    res.setHeader('X-Accel-Buffering','no');
    res.flushHeaders?.();
    addSalesLiveClient(a.companyId,res);
    res.write(`event: ready\ndata: ${JSON.stringify({ok:true,at:now()})}\n\n`);
    const keep=setInterval(()=>{try{res.write(`: keepalive ${Date.now()}\n\n`)}catch{}},25000);
    req.on('close',()=>{clearInterval(keep);removeSalesLiveClient(a.companyId,res)});
  }catch(e){
    if(!res.headersSent)res.status(401).end();else res.end();
  }
});

app.get('/api/company/snapshot',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    const u=await getUserById(req.auth.companyId,req.auth.sub);
    if(!u)return res.status(401).json({error:'帳號已失效'});
    const snap=await getSnapshot(req.auth.companyId);
    const branches=await getCompanyBranches(req.auth.companyId);
    const defaultBranch=branches.find(b=>b.isHeadOffice)||branches[0]||null;
    res.json({token:refreshedUserToken(req,u),company:{...companyDto(req.company),subscription:req.subscription?.managed?{status:req.subscription.status,planName:req.subscription.planName,currentPeriodEnd:req.subscription.periodEnd,graceUntil:req.subscription.graceUntil,autoRenew:!!req.subscription.auto_renew}:null},user:userDto(u),branches,defaultBranchId:defaultBranch?.id||'',snapshot:snapshotForUser(snap.snapshot,u),version:snap.version,updatedAt:snap.updatedAt});
  }catch(e){ next(e); }
});


function validateSaleIntegrity(snapshot){
  const d=snapshot&&typeof snapshot==='object'?snapshot:{};
  const cars=Array.isArray(d.cars)?d.cars:[];
  const reqs=Array.isArray(d.saleRequests)?d.saleRequests:[];
  const carMap=new Map(cars.map(c=>[String(c.id),c]));
  const pendingCount=new Map();
  const completedCount=new Map();
  for(const r of reqs){
    if(!r?.carId)continue;
    const k=String(r.carId);
    if(r.status==='待確認')pendingCount.set(k,(pendingCount.get(k)||0)+1);
    if(r.status==='已成交')completedCount.set(k,(completedCount.get(k)||0)+1);
  }
  for(const [k,n] of pendingCount){
    if(n>1)return `同一台車不可同時存在 ${n} 筆待確認成交申請`;
    const c=carMap.get(k);
    if(c&&c.status==='已售')return '已售車輛不可仍有待確認成交申請';
  }
  for(const [k,n] of completedCount){
    if(n>1)return `同一台車不可有 ${n} 筆已成交紀錄`;
  }
  return '';
}

app.put('/api/company/snapshot',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    const incoming=req.body?.snapshot;
    const baseVersion=Number(req.body?.baseVersion||0);
    if(!incoming||typeof incoming!=='object')return res.status(400).json({error:'snapshot 不正確'});
    if(!['admin','branchManager','staff'].includes(req.auth.role))return res.status(403).json({error:'此帳號不可直接覆寫整份車行資料'});
    const authUser=(await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId])).rows[0];
    if(!authUser)return res.status(401).json({error:'登入帳號不存在或已停用'});
    const isScopedOperator=req.auth.role!=='admin';
    const managerBranchId=String(authUser.branch_id||'');
    if(isScopedOperator&&!managerBranchId)return res.status(403).json({error:'此帳號尚未指定所屬分店'});
    const authPerms=effectivePermissions(authUser);
    const staffChangeContext=(req.body?.staffChangeContext&&typeof req.body.staffChangeContext==='object')?req.body.staffChangeContext:{};
    const companyOwnerId=String((await client.query('SELECT owner_user_id FROM companies WHERE id=$1',[req.auth.companyId])).rows[0]?.owner_user_id||'');
    const actorName=String(authUser.name||authUser.username||req.auth.username||req.auth.sub||'');

    await client.query('BEGIN');
    const lock=await client.query('SELECT version,json FROM snapshots WHERE company_id=$1 FOR UPDATE',[req.auth.companyId]);
    const existing=lock.rows[0]
      ? {version:Number(lock.rows[0].version),snapshot:lock.rows[0].json}
      : {version:0,snapshot:{settings:{companyName:'車行',taxRate:0},users:[],cars:[],saleRequests:[],operationLogs:[]}};
    if(baseVersion!==existing.version){
      await client.query('ROLLBACK');
      return res.status(409).json({error:'中央資料已有新版本',version:existing.version});
    }

    let clean=JSON.parse(JSON.stringify(incoming));
    const branchRows=(await client.query('SELECT id,is_head_office FROM branches WHERE company_id=$1 AND enabled=TRUE',[req.auth.companyId])).rows;
    const branchIds=new Set(branchRows.map(x=>String(x.id)));
    const defaultBranchId=String(branchRows.find(x=>x.is_head_office)?.id||branchRows[0]?.id||'');
    clean.settings=clean.settings||{};
    if(defaultBranchId)clean.settings.defaultBranchId=defaultBranchId;
    for(const car of (Array.isArray(clean.cars)?clean.cars:[])){
      car.branchId=String(car.branchId||defaultBranchId);
      if(car.branchId&&!branchIds.has(car.branchId)){await client.query('ROLLBACK');return res.status(400).json({error:'車輛所屬分店不存在或已停用'});}
    }
    const activeTransferRows=(await client.query("SELECT car_id,from_branch_id FROM vehicle_transfers WHERE company_id=$1 AND status='in_transit'",[req.auth.companyId])).rows;
    if(activeTransferRows.length){
      const oldCars=new Map((Array.isArray(existing.snapshot?.cars)?existing.snapshot.cars:[]).map(c=>[String(c.id),c]));
      const newCars=new Map((Array.isArray(clean.cars)?clean.cars:[]).map(c=>[String(c.id),c]));
      for(const tr of activeTransferRows){const old=oldCars.get(String(tr.car_id)),next=newCars.get(String(tr.car_id));if(!next){await client.query('ROLLBACK');return res.status(409).json({error:'調撥中的車輛不能刪除'});}if(String(next.branchId||'')!==String(tr.from_branch_id||'')||String(old?.branchId||'')!==String(tr.from_branch_id||'')){await client.query('ROLLBACK');return res.status(409).json({error:'調撥中的車輛不能直接變更分店，請由目的分店主管確認到店'});}}
    }
    for(const sr of (Array.isArray(clean.saleRequests)?clean.saleRequests:[])){
      if(!sr.branchId&&sr.carId){const car=(clean.cars||[]).find(x=>String(x.id)===String(sr.carId));sr.branchId=car?.branchId||defaultBranchId;}
      if(sr.branchId&&!branchIds.has(String(sr.branchId))){await client.query('ROLLBACK');return res.status(400).json({error:'成交資料所屬分店不存在或已停用'});}
    }
    const saleIntegrityError=validateSaleIntegrity(clean);
    if(saleIntegrityError){await client.query('ROLLBACK');return res.status(409).json({error:saleIntegrityError,version:existing.version});}
    const users=Array.isArray(clean.users)?clean.users:[];
    const keep=new Set();

    for(const x of users){
      if(!x?.id||!x?.username)continue;
      keep.add(x.id);
      const byId=await client.query('SELECT * FROM users WHERE company_id=$1 AND id=$2',[req.auth.companyId,x.id]);
      const byName=byId.rowCount?byId:await client.query('SELECT * FROM users WHERE company_id=$1 AND username=$2',[req.auth.companyId,x.username]);
      const old=byName.rows[0];
      const ph=x.password?hashPassword(x.password):(old?.password_hash||'');
      const userBranchId=String(x.branchId||old?.branch_id||defaultBranchId);
      if(userBranchId&&!branchIds.has(userBranchId)){await client.query('ROLLBACK');return res.status(400).json({error:`職員 ${x.name||x.username} 的所屬分店不存在或已停用`});}
      let nextRole=['admin','branchManager','sales','staff'].includes(String(x.role||''))?String(x.role):'staff';
      if(isScopedOperator){
        if(!authPerms.peopleManage&&String(x.id)!==String(authUser.id)){await client.query('ROLLBACK');return res.status(403).json({error:'你的帳號沒有管理人員權限'});}
        if(String(x.id)===String(authUser.id)){nextRole=authUser.role;x.branchId=managerBranchId;}
        else if(!['sales','staff'].includes(nextRole)||userBranchId!==managerBranchId){await client.query('ROLLBACK');return res.status(403).json({error:'此帳號只能管理自己分店的業務或一般員工'});}
      }
      x.role=nextRole;
      if(old){
        await client.query(`
          UPDATE users SET username=$1,password_hash=$2,name=$3,role=$4,commission_rate=$5,base_salary=$6,enabled=TRUE,updated_at=$7,branch_id=$8,permissions=$9::jsonb,position=$10,salary_type=$11,login_enabled=$12
          WHERE id=$13 AND company_id=$14
        `,[x.username,ph||old.password_hash,x.name||x.username,x.role||'staff',Number(x.commissionRate||0),Number(x.baseSalary||0),now(),userBranchId||null,JSON.stringify(x.permissions||old.permissions||{}),String(x.position||''),['fixed','base_plus_commission','commission_only'].includes(String(x.salaryType||''))?String(x.salaryType):'fixed',x.loginEnabled!==false,old.id,req.auth.companyId]);
        if(old.id!==x.id){ x.id=old.id; keep.add(old.id); }
      }else{
        if(!ph&&x.loginEnabled!==false)return res.status(400).json({error:`新帳號 ${x.username} 必須設定密碼`});
        await client.query(`
          INSERT INTO users(id,company_id,username,password_hash,name,role,commission_rate,base_salary,enabled,updated_at,branch_id,permissions,position,salary_type,login_enabled)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,TRUE,$9,$10,$11::jsonb,$12,$13,$14)
        `,[x.id,req.auth.companyId,x.username,ph||hashPassword(crypto.randomBytes(18).toString('hex')),x.name||x.username,x.role||'staff',Number(x.commissionRate||0),Number(x.baseSalary||0),now(),userBranchId||null,JSON.stringify(x.permissions||{}),String(x.position||''),['fixed','base_plus_commission','commission_only'].includes(String(x.salaryType||''))?String(x.salaryType):'fixed',x.loginEnabled!==false]);
        await client.query(`INSERT INTO staff_change_events(company_id,event_type,employee_id,employee_name,position,branch_id,actor_id,actor_name,actor_role,reason,owner_read_at,created_at) VALUES($1,'created',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,[req.auth.companyId,x.id,String(x.name||x.username||''),String(x.position||''),userBranchId||'',String(authUser.id),actorName,String(authUser.role||''),String(staffChangeContext?.reason||'新增人員'),String(authUser.id)===companyOwnerId?now():null,now()]);
      }
      x.branchId=userBranchId||'';x.password='';
    }

    const all=await client.query('SELECT id,role,branch_id,name,position,enabled FROM users WHERE company_id=$1',[req.auth.companyId]);
    const deletions=all.rows.filter(u=>u.enabled&&['sales','branchManager','staff'].includes(u.role)&&!keep.has(u.id)&&(!isScopedOperator||(['sales','staff'].includes(u.role)&&String(u.branch_id||'')===managerBranchId)));
    if(deletions.length){
      const deletionReason=String(staffChangeContext?.type==='delete'?staffChangeContext?.reason||'':'').trim();
      if(!deletionReason){await client.query('ROLLBACK');return res.status(400).json({error:'刪除／離職人員必須填寫原因'});}
      const targetId=String(staffChangeContext?.employeeId||'');
      if(deletions.length===1&&targetId&&String(deletions[0].id)!==targetId){await client.query('ROLLBACK');return res.status(409).json({error:'人員異動資料已變更，請重新操作'});}
      for(const u of deletions){
        await client.query('UPDATE users SET enabled=FALSE,token_version=token_version+1,updated_at=$1 WHERE id=$2',[now(),u.id]);
        await client.query(`INSERT INTO staff_change_events(company_id,event_type,employee_id,employee_name,position,branch_id,actor_id,actor_name,actor_role,reason,owner_read_at,created_at) VALUES($1,'removed',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,[req.auth.companyId,String(u.id),String(u.name||''),String(u.position||''),String(u.branch_id||''),String(authUser.id),actorName,String(authUser.role||''),deletionReason,String(authUser.id)===companyOwnerId?now():null,now()]);
      }
    }

    if(isScopedOperator){
      const base=JSON.parse(JSON.stringify(existing.snapshot||{}));
      const incomingUsers=Array.isArray(clean.users)?clean.users:[];
      const incomingCars=Array.isArray(clean.cars)?clean.cars:[];
      const baseCars=Array.isArray(base.cars)?base.cars:[];
      const baseRequests=Array.isArray(base.saleRequests)?base.saleRequests:[];
      const baseCarMap=new Map(baseCars.map(c=>[String(c.id),c]));

      // Phase 14B.2: role is a template; per-user permissions decide actual actions, while branch scope remains enforced.
      const existingIds=new Set(baseCars.filter(c=>String(c.branchId||'')===managerBranchId).map(c=>String(c.id)));
      const incomingIds0=new Set(incomingCars.map(c=>String(c.id)));
      if([...incomingIds0].some(id=>!existingIds.has(id))&&!authPerms.vehicleCreate){await client.query('ROLLBACK');return res.status(403).json({error:'你的帳號沒有新增車輛權限'});}
      if([...existingIds].some(id=>!incomingIds0.has(id))&&!authPerms.vehicleDelete){await client.query('ROLLBACK');return res.status(403).json({error:'你的帳號沒有刪除車輛權限'});}
      if(!authPerms.vehicleEdit&&incomingCars.some(car=>existingIds.has(String(car.id)))){await client.query('ROLLBACK');return res.status(403).json({error:'你的帳號沒有編輯車輛權限'});}
      // Phase 14B.1: branch managers may CRUD inventory only inside their own branch.
      // They still cannot move vehicles across branches or alter final sale state via snapshot upload.
      for(const car of incomingCars){
        const id=String(car?.id||'');
        const old=baseCarMap.get(id);
        if(String(car?.branchId||managerBranchId)!==managerBranchId){await client.query('ROLLBACK');return res.status(403).json({error:'此帳號只能管理自己分店的車輛'});}
        if(old&&String(old.branchId||'')!==managerBranchId){await client.query('ROLLBACK');return res.status(403).json({error:'不可修改其他分店的車輛'});}
        car.branchId=managerBranchId;
        if(old){
          // 成交狀態與成交結果仍由公司管理員／成交 API 控制。
          for(const k of ['status','outDate','sellPrice','saleDate','salesId','salesName','commissionAmount','companyProfit']){
            if(old[k]!==undefined)car[k]=old[k]; else delete car[k];
          }
        }else{
          car.status='在庫';
          delete car.outDate;delete car.sellPrice;delete car.saleDate;delete car.salesId;delete car.salesName;delete car.commissionAmount;delete car.companyProfit;
        }
      }
      const incomingIds=new Set(incomingCars.map(c=>String(c.id)));
      for(const old of baseCars.filter(c=>String(c.branchId||'')===managerBranchId&&!incomingIds.has(String(c.id)))){
        if(old.status==='已售'){await client.query('ROLLBACK');return res.status(403).json({error:'此帳號不可刪除已售車輛'});}
        if(baseRequests.some(r=>String(r.carId||'')===String(old.id)&&r.status==='待確認')){await client.query('ROLLBACK');return res.status(409).json({error:'此車有待確認成交申請，不能刪除'});}
      }
      base.cars=[...baseCars.filter(c=>String(c.branchId||'')!==managerBranchId),...incomingCars];
      base.saleRequests=baseRequests;

      base.users=[...(Array.isArray(base.users)?base.users:[]).filter(u=>!(['sales','staff'].includes(u.role)&&String(u.branchId||'')===managerBranchId)),...incomingUsers.filter(u=>['sales','staff'].includes(u.role))];
      base.settings={...(base.settings||{})};
      base.operationLogs=Array.isArray(base.operationLogs)?base.operationLogs:[];
      const existingSalary=Array.isArray(base.salaryHistory)?base.salaryHistory:[];
      const incomingSalary=Array.isArray(clean.salaryHistory)?clean.salaryHistory:[];
      const scopedSalesIds=new Set(incomingUsers.filter(u=>u.role==='sales').map(u=>String(u.id)));
      base.salaryHistory=[...existingSalary.filter(x=>!scopedSalesIds.has(String(x.salesId||''))),...incomingSalary];
      clean=base;
    }

    if(req.auth.role==='admin'){
      clean.saleRequests=Array.isArray(clean.saleRequests)?clean.saleRequests:[];
      for(const sr of clean.saleRequests){if(sr.status==='待確認'&&!sr.directByAdmin){const target=await resolveSaleApprover(req.auth.companyId,String(sr.branchId||defaultBranchId),client);stampApprovalTarget(sr,target);}}
    }
    const ver=existing.version+1;
    await client.query(`
      INSERT INTO snapshots(company_id,version,json,updated_at)
      VALUES($1,$2,$3::jsonb,$4)
      ON CONFLICT(company_id) DO UPDATE SET version=EXCLUDED.version,json=EXCLUDED.json,updated_at=EXCLUDED.updated_at
    `,[req.auth.companyId,ver,JSON.stringify(cloudOperationalSnapshot(clean)),now()]);
    await client.query('COMMIT');
    notifySalesInventoryChanged(req.auth.companyId,ver,'snapshot');
    res.json({ok:true,version:ver});
  }catch(e){
    try{ await client.query('ROLLBACK'); }catch{}
    if(e?.code==='23505')return res.status(409).json({error:'同一車行內帳號名稱不可重複'});
    next(e);
  }finally{ client.release(); }
});


// Phase 14D.3 hotfix: Dealer Node pushes the final closed-deal financial summary back to Central.
// This is intentionally a narrow patch endpoint: it cannot alter sale status, sale price, branch, or identity.
app.put('/api/company/sale-financial-summaries',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    if(!['admin','branchManager'].includes(String(req.auth.role||'')))return res.status(403).json({error:'此帳號不可同步成交財務摘要'});
    const summaries=Array.isArray(req.body?.summaries)?req.body.summaries.slice(0,1000):[];
    if(!summaries.length)return res.json({ok:true,updated:0,version:Number((await getSnapshot(req.auth.companyId,client)).version||0)});
    const actor=(await client.query('SELECT id,role,branch_id FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId])).rows[0];
    if(!actor)return res.status(401).json({error:'登入帳號不存在或已停用'});
    await client.query('BEGIN');
    const lock=await client.query('SELECT version,json FROM snapshots WHERE company_id=$1 FOR UPDATE',[req.auth.companyId]);
    if(!lock.rows[0]){await client.query('ROLLBACK');return res.status(404).json({error:'車行資料不存在'});}
    const d=lock.rows[0].json||{};d.cars=Array.isArray(d.cars)?d.cars:[];
    const byId=new Map(d.cars.map(c=>[String(c.id),c]));
    let updated=0;
    for(const x of summaries){
      const id=String(x?.carId||x?.id||'');if(!id)continue;
      const c=byId.get(id);if(!c)continue;
      const sold=String(c.status||'')==='已售'||Number(c.sellPrice||0)>0;
      if(actor.role==='branchManager'&&String(c.branchId||'')!==String(actor.branch_id||''))continue;
      const purchasePrice=Number(x.purchasePrice),totalCost=Number(x.totalCost);
      if(!Number.isFinite(purchasePrice)||purchasePrice<0||!Number.isFinite(totalCost)||totalCost<0)continue;
      const next={purchasePrice:Math.max(0,purchasePrice),totalCost:Math.max(0,totalCost)};
      if(sold){
        const saleExtraCost=Number(x.saleExtraCost),companyProfit=Number(x.companyProfit);
        if(Number.isFinite(saleExtraCost)&&saleExtraCost>=0)next.saleExtraCost=Math.max(0,saleExtraCost);
        if(Number.isFinite(companyProfit))next.companyProfit=companyProfit;
        // Keep fee breakdown when supplied so Super Admin detail remains explainable.
        for(const k of ['saleTransferFee','saleFuelFee','saleLicenseTax','saleOtherFee']){
          const n=Number(x[k]);if(Number.isFinite(n)&&n>=0)next[k]=n;
        }
        if(x.saleOtherFeeName!==undefined)next.saleOtherFeeName=String(x.saleOtherFeeName||'').slice(0,200);
      }
      let changed=false;for(const [k,v] of Object.entries(next)){if(c[k]!==v){c[k]=v;changed=true;}}
      if(changed)updated++;
    }
    let ver=Number(lock.rows[0].version||0);
    if(updated){ver+=1;await client.query('UPDATE snapshots SET version=$1,json=$2::jsonb,updated_at=$3 WHERE company_id=$4',[ver,JSON.stringify(cloudOperationalSnapshot(d)),now(),req.auth.companyId]);}
    await client.query('COMMIT');
    if(updated)recordSyncEvent(req.auth.companyId,'vehicle_financial_summary_sync',`車輛財務摘要同步 ${updated} 筆`,{actor:req.auth.username||req.auth.sub});
    res.json({ok:true,updated,version:ver});
  }catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}
});


async function enforceManagerBranch(req,branchId,client=pool){
  if(req.auth.role!=='branchManager')return true;
  const me=(await client.query('SELECT branch_id FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId])).rows[0];
  return !!me?.branch_id&&String(me.branch_id)===String(branchId||'');
}

// Phase 14A: Company / Branch core（公司／分店核心）
app.get('/api/company/branches',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    const branches=await getCompanyBranches(req.auth.companyId,pool,{includeDisabled:req.auth.role==='admin'});
    const defaultBranch=branches.find(b=>b.isHeadOffice)||branches[0]||null;
    res.json({ok:true,branches,defaultBranchId:defaultBranch?.id||''});
  }catch(e){next(e)}
});
app.post('/api/admin/branches',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    if(req.auth.role!=='admin')return res.status(403).json({error:'僅總公司管理員可新增分店'});
    const name=String(req.body?.name||'').trim(),code=String(req.body?.code||'').trim().toUpperCase(),address=String(req.body?.address||'').trim().slice(0,300),phone=String(req.body?.phone||'').trim().slice(0,80);
    if(!name)return res.status(400).json({error:'分店名稱不能空白'});
    if(name.length>80)return res.status(400).json({error:'分店名稱過長'});
    if(!/^[A-Z0-9_-]{2,20}$/.test(code))return res.status(400).json({error:'分店代碼請使用 2-20 碼英數、底線或減號'});
    const id=`br_${crypto.randomUUID()}`,ts=now();
    const q=await pool.query(`INSERT INTO branches(id,company_id,code,name,is_head_office,enabled,address,phone,created_at,updated_at) VALUES($1,$2,$3,$4,FALSE,TRUE,$5,$6,$7,$7) RETURNING *`,[id,req.auth.companyId,code,name,address,phone,ts]);
    res.json({ok:true,branch:branchDto(q.rows[0])});
  }catch(e){if(e?.code==='23505')return res.status(409).json({error:'這個分店代碼已存在'});next(e)}
});
app.patch('/api/admin/branches/:id',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    if(req.auth.role!=='admin')return res.status(403).json({error:'僅總公司管理員可修改分店'});
    const old=(await pool.query('SELECT * FROM branches WHERE id=$1 AND company_id=$2',[req.params.id,req.auth.companyId])).rows[0];
    if(!old)return res.status(404).json({error:'找不到分店'});
    const name=req.body?.name===undefined?old.name:String(req.body.name||'').trim(),address=req.body?.address===undefined?old.address:String(req.body.address||'').trim().slice(0,300),phone=req.body?.phone===undefined?old.phone:String(req.body.phone||'').trim().slice(0,80),enabled=req.body?.enabled===undefined?old.enabled:!!req.body.enabled;
    const saleApprovalMode=req.body?.saleApprovalMode===undefined?String(old.sale_approval_mode||'branch_manager'):String(req.body.saleApprovalMode||'branch_manager');
    const saleApproverUserId=req.body?.saleApproverUserId===undefined?String(old.sale_approver_user_id||''):String(req.body.saleApproverUserId||'');
    if(!['branch_manager','company_admin','specific_user'].includes(saleApprovalMode))return res.status(400).json({error:'成交審核方式不正確'});
    if(saleApprovalMode==='specific_user'&&!saleApproverUserId)return res.status(400).json({error:'請選擇指定審核人'});
    if(!name)return res.status(400).json({error:'分店名稱不能空白'});
    if(old.is_head_office&&!enabled)return res.status(400).json({error:'總店不能停用'});
    const q=await pool.query(`UPDATE branches SET name=$1,address=$2,phone=$3,enabled=$4,sale_approval_mode=$5,sale_approver_user_id=$6,updated_at=$7 WHERE id=$8 AND company_id=$9 RETURNING *`,[name,address,phone,enabled,saleApprovalMode,saleApprovalMode==='specific_user'?saleApproverUserId:null,now(),old.id,req.auth.companyId]);
    if(req.body?.saleApprovalMode!==undefined||req.body?.saleApproverUserId!==undefined){const snap=(await pool.query('SELECT json FROM snapshots WHERE company_id=$1',[req.auth.companyId])).rows[0];if(snap){const d=JSON.parse(JSON.stringify(snap.json||{}));d.saleRequests=Array.isArray(d.saleRequests)?d.saleRequests:[];const target=await resolveSaleApprover(req.auth.companyId,old.id,pool);let changed=false;for(const r of d.saleRequests){if(r.status==='待確認'&&String(r.branchId||'')===String(old.id)){stampApprovalTarget(r,target);changed=true}}if(changed)await pool.query('UPDATE snapshots SET version=version+1,json=$1::jsonb,updated_at=$2 WHERE company_id=$3',[JSON.stringify(d),now(),req.auth.companyId]);}}
    res.json({ok:true,branch:branchDto(q.rows[0])});
  }catch(e){next(e)}
});
app.post('/api/admin/branches/:id/set-head-office',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    if(req.auth.role!=='admin')return res.status(403).json({error:'僅總公司管理員可設定總店'});
    await client.query('BEGIN');
    const b=(await client.query('SELECT * FROM branches WHERE id=$1 AND company_id=$2 FOR UPDATE',[req.params.id,req.auth.companyId])).rows[0];
    if(!b){await client.query('ROLLBACK');return res.status(404).json({error:'找不到分店'});}
    if(!b.enabled){await client.query('ROLLBACK');return res.status(400).json({error:'停用中的分店不能設為總店'});}
    await client.query('UPDATE branches SET is_head_office=FALSE,updated_at=$1 WHERE company_id=$2 AND is_head_office=TRUE',[now(),req.auth.companyId]);
    const q=await client.query('UPDATE branches SET is_head_office=TRUE,updated_at=$1 WHERE id=$2 RETURNING *',[now(),b.id]);
    const snap=(await client.query('SELECT json FROM snapshots WHERE company_id=$1 FOR UPDATE',[req.auth.companyId])).rows[0];
    if(snap){const d=JSON.parse(JSON.stringify(snap.json||{}));d.settings=d.settings||{};d.settings.defaultBranchId=b.id;await client.query('UPDATE snapshots SET json=$1::jsonb,updated_at=$2 WHERE company_id=$3',[JSON.stringify(d),now(),req.auth.companyId]);}
    await client.query('COMMIT');
    res.json({ok:true,branch:branchDto(q.rows[0])});
  }catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}
});


// Phase 14D: Operating cost center（公司／分店營運成本中心）
const OPERATING_COST_CATEGORIES=new Set(['rent','utilities','internet','advertising','insurance','interest','cleaning','equipment','outsourcing','tax','transport','other']);
function validCostMonth(v){return /^\d{4}-\d{2}$/.test(String(v||''))}
function safeCostCategory(v){v=String(v||'other');return OPERATING_COST_CATEGORIES.has(v)?v:'other'}
function costEntryDto(r){return {id:r.id,month:r.month,expenseDate:r.expense_date,name:r.name,category:r.category,amount:Number(r.amount||0),allocationMode:r.allocation_mode,branchId:r.branch_id||'',allocations:Array.isArray(r.allocation_json)?r.allocation_json:(r.allocation_json||[]),sourceType:r.source_type,recurringRuleId:r.recurring_rule_id||'',note:r.note||'',status:r.status,createdById:r.created_by_id||'',createdByName:r.created_by_name||'',createdAt:r.created_at||'',voidedAt:r.voided_at||'',voidedBy:r.voided_by||'',voidReason:r.void_reason||''}}
function costRuleDto(r){return {id:r.id,name:r.name,category:r.category,amount:Number(r.amount||0),allocationMode:r.allocation_mode,branchId:r.branch_id||'',startMonth:r.start_month,endMonth:r.end_month||'',dayOfMonth:Number(r.day_of_month||1),enabled:!!r.enabled,note:r.note||'',createdByName:r.created_by_name||'',createdAt:r.created_at||'',updatedAt:r.updated_at||''}}
async function operatingCostActor(req,client=pool){return (await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId])).rows[0]||null}
function canViewOperatingCosts(u){return !!u&&(u.role==='admin'||hasPermission(u,'viewCosts'))}
function canManageOperatingCosts(u){return !!u&&(u.role==='admin'||hasPermission(u,'operatingCostManage'))}
async function costAllocations(companyId,mode,branchId,amount,client=pool){
  amount=Math.max(0,Number(amount||0));
  if(mode==='company')return [];
  if(mode==='branch'){
    const b=(await client.query('SELECT id FROM branches WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[branchId,companyId])).rows[0];
    if(!b)throw new Error('找不到可用的成本歸屬分店');return [{branchId:b.id,amount}];
  }
  if(mode==='all_branches'){
    const rows=(await client.query('SELECT id FROM branches WHERE company_id=$1 AND enabled=TRUE ORDER BY is_head_office DESC,name,id',[companyId])).rows;
    if(!rows.length)return [];
    const share=Math.floor((amount/rows.length)*100)/100, out=rows.map((b,i)=>({branchId:b.id,amount:share}));
    const assigned=share*rows.length;out[out.length-1].amount=Number((share+(amount-assigned)).toFixed(2));return out;
  }
  throw new Error('成本歸屬方式不正確');
}
function costDateForMonth(month,day){const [y,m]=String(month).split('-').map(Number);const max=new Date(Date.UTC(y,m,0)).getUTCDate();return `${month}-${String(Math.max(1,Math.min(max,Number(day)||1))).padStart(2,'0')}`}
async function ensureRecurringOperatingCosts(companyId,month,client=pool){
  if(!validCostMonth(month))return;
  const rules=(await client.query(`SELECT * FROM operating_cost_rules WHERE company_id=$1 AND enabled=TRUE AND start_month<=$2 AND (end_month IS NULL OR end_month='' OR end_month>=$2) ORDER BY created_at`,[companyId,month])).rows;
  for(const r of rules){
    const exists=(await client.query('SELECT id FROM operating_cost_entries WHERE company_id=$1 AND recurring_rule_id=$2 AND month=$3',[companyId,r.id,month])).rows[0];if(exists)continue;
    const allocations=await costAllocations(companyId,r.allocation_mode,r.branch_id,r.amount,client),id=`oc_${crypto.randomUUID()}`,ts=now();
    await client.query(`INSERT INTO operating_cost_entries(id,company_id,month,expense_date,name,category,amount,allocation_mode,branch_id,allocation_json,source_type,recurring_rule_id,note,status,created_by_id,created_by_name,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,'recurring',$11,$12,'active',$13,$14,$15,$15) ON CONFLICT DO NOTHING`,[id,companyId,month,costDateForMonth(month,r.day_of_month),r.name,r.category,r.amount,r.allocation_mode,r.branch_id||null,JSON.stringify(allocations),r.id,r.note,r.created_by_id,r.created_by_name,ts]);
  }
}
function summarizeOperatingCosts(entries,branchId=''){
  const active=entries.filter(x=>x.status==='active');
  let total=0;const byCategory={};
  for(const e of active){let amt=Number(e.amount||0);if(branchId){if(e.allocationMode==='branch')amt=String(e.branchId)===String(branchId)?amt:0;else if(e.allocationMode==='all_branches')amt=Number((e.allocations||[]).find(a=>String(a.branchId)===String(branchId))?.amount||0);else amt=0;}total+=amt;byCategory[e.category]=(byCategory[e.category]||0)+amt}
  return {total:Number(total.toFixed(2)),byCategory};
}
app.get('/api/operating-costs',auth,requireActiveCompany,async(req,res,next)=>{try{
  const actor=await operatingCostActor(req);if(!canViewOperatingCosts(actor))return res.status(403).json({error:'你的帳號沒有查看營運成本權限'});
  const month=validCostMonth(req.query.month)?String(req.query.month):today().slice(0,7);await ensureRecurringOperatingCosts(req.auth.companyId,month);
  let rows=(await pool.query(`SELECT * FROM operating_cost_entries WHERE company_id=$1 AND month=$2 ORDER BY expense_date DESC,created_at DESC`,[req.auth.companyId,month])).rows.map(costEntryDto);
  let rules=(await pool.query(`SELECT * FROM operating_cost_rules WHERE company_id=$1 ORDER BY enabled DESC,name,created_at DESC`,[req.auth.companyId])).rows.map(costRuleDto);
  if(actor.role!=='admin'){
    const bid=String(actor.branch_id||'');rows=rows.filter(e=>e.allocationMode==='branch'?String(e.branchId)===bid:e.allocationMode==='all_branches'?(e.allocations||[]).some(a=>String(a.branchId)===bid):false);
    rules=rules.filter(r=>r.allocationMode==='branch'&&String(r.branchId)===bid);
  }
  const branchId=actor.role==='admin'?String(req.query.branchId||''):String(actor.branch_id||'');res.json({ok:true,month,entries:rows,rules,summary:summarizeOperatingCosts(rows,branchId),canManage:canManageOperatingCosts(actor)});
}catch(e){next(e)}});
app.post('/api/operating-costs/entries',auth,requireActiveCompany,async(req,res,next)=>{const client=await pool.connect();try{
  const actor=await operatingCostActor(req,client);if(!canManageOperatingCosts(actor))return res.status(403).json({error:'你的帳號沒有管理營運成本權限'});
  const b=req.body||{},name=String(b.name||'').trim(),amount=Math.max(0,Number(b.amount||0)),expenseDate=String(b.expenseDate||today()),month=expenseDate.slice(0,7),mode=String(b.allocationMode||'company'),branchId=String(b.branchId||'');
  if(!name)return res.status(400).json({error:'請輸入成本名稱'});if(!(amount>0))return res.status(400).json({error:'成本金額必須大於 0'});if(!/^\d{4}-\d{2}-\d{2}$/.test(expenseDate))return res.status(400).json({error:'支出日期格式不正確'});
  if(actor.role!=='admin'&&(mode!=='branch'||String(actor.branch_id||'')!==branchId))return res.status(403).json({error:'非公司管理員只能新增自己分店的成本'});
  const allocations=await costAllocations(req.auth.companyId,mode,branchId,amount,client),id=`oc_${crypto.randomUUID()}`,ts=now();
  await client.query(`INSERT INTO operating_cost_entries(id,company_id,month,expense_date,name,category,amount,allocation_mode,branch_id,allocation_json,source_type,note,status,created_by_id,created_by_name,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,'manual',$11,'active',$12,$13,$14,$14)`,[id,req.auth.companyId,month,expenseDate,name,safeCostCategory(b.category),amount,mode,branchId||null,JSON.stringify(allocations),String(b.note||'').slice(0,1000),String(actor.id),String(actor.name||actor.username||''),ts]);
  res.json({ok:true,id});
}catch(e){next(e)}finally{client.release()}});
app.delete('/api/operating-costs/entries/:id',auth,requireActiveCompany,async(req,res,next)=>{const client=await pool.connect();try{
  const actor=await operatingCostActor(req,client);if(!canManageOperatingCosts(actor))return res.status(403).json({error:'你的帳號沒有管理營運成本權限'});const reason=String(req.body?.reason||'').trim();if(!reason)return res.status(400).json({error:'作廢原因不能空白'});
  const row=(await client.query('SELECT * FROM operating_cost_entries WHERE id=$1 AND company_id=$2',[req.params.id,req.auth.companyId])).rows[0];if(!row)return res.status(404).json({error:'找不到成本紀錄'});if(actor.role!=='admin'&&!(row.allocation_mode==='branch'&&String(row.branch_id)===String(actor.branch_id||'')))return res.status(403).json({error:'不能作廢其他分店的成本'});
  const ts=now();
  await client.query('BEGIN');
  await client.query(`UPDATE operating_cost_entries SET status='voided',voided_at=$1,voided_by=$2,void_reason=$3,updated_at=$1 WHERE id=$4`,[ts,String(actor.name||actor.username||''),reason.slice(0,500),row.id]);
  if(row.source_type==='recurring'&&row.recurring_rule_id){
    await client.query(`UPDATE operating_cost_rules SET enabled=FALSE,end_month=COALESCE(end_month,$1),updated_at=$2 WHERE id=$3 AND company_id=$4`,[row.month,ts,row.recurring_rule_id,req.auth.companyId]);
  }
  await client.query('COMMIT');res.json({ok:true,recurringRuleStopped:row.source_type==='recurring'&&!!row.recurring_rule_id});
}catch(e){next(e)}finally{client.release()}});
app.post('/api/operating-costs/rules',auth,requireActiveCompany,async(req,res,next)=>{const client=await pool.connect();try{
  const actor=await operatingCostActor(req,client);if(!canManageOperatingCosts(actor))return res.status(403).json({error:'你的帳號沒有管理營運成本權限'});const b=req.body||{},name=String(b.name||'').trim(),amount=Math.max(0,Number(b.amount||0)),mode=String(b.allocationMode||'company'),branchId=String(b.branchId||''),startMonth=String(b.startMonth||today().slice(0,7)),endMonth=String(b.endMonth||''),day=Math.max(1,Math.min(28,Number(b.dayOfMonth)||1));
  if(!name||!(amount>0)||!validCostMonth(startMonth)||endMonth&&!validCostMonth(endMonth))return res.status(400).json({error:'固定成本資料不完整'});if(endMonth&&endMonth<startMonth)return res.status(400).json({error:'結束月份不能早於開始月份'});if(actor.role!=='admin'&&(mode!=='branch'||String(actor.branch_id||'')!==branchId))return res.status(403).json({error:'非公司管理員只能建立自己分店固定成本'});await costAllocations(req.auth.companyId,mode,branchId,amount,client);
  const id=`ocr_${crypto.randomUUID()}`,ts=now();await client.query(`INSERT INTO operating_cost_rules(id,company_id,name,category,amount,allocation_mode,branch_id,start_month,end_month,day_of_month,enabled,note,created_by_id,created_by_name,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,TRUE,$11,$12,$13,$14,$14)`,[id,req.auth.companyId,name,safeCostCategory(b.category),amount,mode,branchId||null,startMonth,endMonth||null,day,String(b.note||'').slice(0,1000),String(actor.id),String(actor.name||actor.username||''),ts]);await ensureRecurringOperatingCosts(req.auth.companyId,startMonth,client);res.json({ok:true,id});
}catch(e){next(e)}finally{client.release()}});
app.patch('/api/operating-costs/rules/:id',auth,requireActiveCompany,async(req,res,next)=>{const client=await pool.connect();try{
  const actor=await operatingCostActor(req,client);if(!canManageOperatingCosts(actor))return res.status(403).json({error:'你的帳號沒有管理營運成本權限'});const old=(await client.query('SELECT * FROM operating_cost_rules WHERE id=$1 AND company_id=$2',[req.params.id,req.auth.companyId])).rows[0];if(!old)return res.status(404).json({error:'找不到固定成本規則'});if(actor.role!=='admin'&&!(old.allocation_mode==='branch'&&String(old.branch_id)===String(actor.branch_id||'')))return res.status(403).json({error:'不能修改其他分店固定成本'});
  const enabled=req.body?.enabled===undefined?old.enabled:!!req.body.enabled,endMonth=req.body?.endMonth===undefined?(old.end_month||''):String(req.body.endMonth||'');if(endMonth&&!validCostMonth(endMonth))return res.status(400).json({error:'結束月份格式不正確'});await client.query('UPDATE operating_cost_rules SET enabled=$1,end_month=$2,note=$3,updated_at=$4 WHERE id=$5',[enabled,endMonth||null,req.body?.note===undefined?old.note:String(req.body.note||'').slice(0,1000),now(),old.id]);res.json({ok:true});
}catch(e){next(e)}finally{client.release()}});

// ---- Password management v8.3 ----
// Dealership admin settings: company display name is canonical in companies + snapshot settings.
app.put('/api/admin/company/settings',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    if(req.auth.role!=='admin')return res.status(403).json({error:'僅總公司管理員可修改公司設定'});
    const companyName=String(req.body?.companyName||'').trim();
    if(!companyName)return res.status(400).json({error:'車行名稱不能空白'});
    if(companyName.length>80)return res.status(400).json({error:'車行名稱過長'});
    await client.query('BEGIN');
    await client.query('UPDATE companies SET name=$1 WHERE id=$2',[companyName,req.auth.companyId]);
    const lock=await client.query('SELECT version,json FROM snapshots WHERE company_id=$1 FOR UPDATE',[req.auth.companyId]);
    if(lock.rowCount){
      const d=JSON.parse(JSON.stringify(lock.rows[0].json||{}));d.settings=d.settings||{};d.settings.companyName=companyName;
      await client.query('UPDATE snapshots SET json=$1::jsonb,updated_at=$2 WHERE company_id=$3',[JSON.stringify(d),now(),req.auth.companyId]);
    }
    await client.query('COMMIT');
    const c=(await pool.query('SELECT * FROM companies WHERE id=$1',[req.auth.companyId])).rows[0];
    res.json({ok:true,company:companyDto(c)});
  }catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}
});


app.put('/api/admin/company/activation',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    const actor=(await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId])).rows[0];
    const company=(await client.query('SELECT * FROM companies WHERE id=$1',[req.auth.companyId])).rows[0];
    if(!actor||!company)return res.status(404).json({error:'公司或帳號不存在'});
    const ownerId=String(company.owner_user_id||'');
    if(!ownerId||String(actor.id)!==ownerId)return res.status(403).json({error:'只有公司老闆帳號可以修改系統正式啟用日'});
    const activationDate=String(req.body?.systemActivationDate||'').trim();
    const currentPassword=String(req.body?.currentPassword||'');
    const reason=String(req.body?.reason||'').trim().slice(0,500);
    if(!/^\d{4}-\d{2}-\d{2}$/.test(activationDate))return res.status(400).json({error:'正式啟用日格式不正確'});
    if(activationDate>today())return res.status(400).json({error:'正式啟用日不能晚於今天'});
    if(!verifyPassword(currentPassword,actor.password_hash))return res.status(401).json({error:'目前密碼錯誤'});
    const oldDate=String(company.system_activation_date||company.start_date||today()).slice(0,10);
    if(activationDate===oldDate)return res.json({ok:true,company:companyDto(company),unchanged:true});
    if(!reason)return res.status(400).json({error:'修改正式啟用日必須填寫原因'});
    const newMonth=activationDate.slice(0,7);
    const earliestSettled=(await client.query('SELECT MIN(month) AS month FROM payroll_settlements WHERE company_id=$1',[req.auth.companyId])).rows[0]?.month||'';
    const earliestLocked=(await client.query('SELECT MIN(month) AS month FROM payroll_month_periods WHERE company_id=$1 AND locked=TRUE',[req.auth.companyId])).rows[0]?.month||'';
    const protectedMonths=[earliestSettled,earliestLocked].filter(Boolean).sort();
    if(protectedMonths.length&&newMonth>protectedMonths[0])return res.status(409).json({error:`${protectedMonths[0]} 已有正式薪資結算或封帳資料，正式啟用日不能改到該月份之後`});
    await client.query('BEGIN');
    const at=now(),who=actor.name||actor.username;
    await client.query('UPDATE companies SET system_activation_date=$1,system_activation_set_at=$2,system_activation_set_by=$3 WHERE id=$4',[activationDate,at,who,req.auth.companyId]);
    await client.query(`INSERT INTO company_setting_events(company_id,setting_key,old_value,new_value,actor_id,actor,reason,created_at) VALUES($1,'system_activation_date',$2,$3,$4,$5,$6,$7)`,[req.auth.companyId,oldDate,activationDate,actor.id,who,reason,at]);
    await client.query('COMMIT');
    const updated=(await pool.query('SELECT * FROM companies WHERE id=$1',[req.auth.companyId])).rows[0];
    res.json({ok:true,company:companyDto(updated)});
  }catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}
});

app.post('/api/account/change-password',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    const {currentPassword,newPassword}=req.body||{};
    if(!currentPassword||!newPassword)return res.status(400).json({error:'請輸入目前密碼與新密碼'});
    if(String(newPassword).length<6)return res.status(400).json({error:'新密碼至少 6 碼'});
    const {rows}=await pool.query('SELECT * FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId]);
    const u=rows[0];
    if(!u||!verifyPassword(currentPassword,u.password_hash))return res.status(401).json({error:'目前密碼錯誤'});
    const changedAt=now();
    await pool.query('UPDATE users SET password_hash=$1,token_version=token_version+1,password_changed_at=$2,password_changed_by=$3,updated_at=$2 WHERE id=$4 AND company_id=$5',[hashPassword(newPassword),changedAt,u.username,u.id,req.auth.companyId]);
    res.json({ok:true,message:'密碼修改成功，請重新登入'});
  }catch(e){next(e)}
});

app.post('/api/admin/users/:userId/reset-password',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    if(!['admin','branchManager'].includes(req.auth.role))return res.status(403).json({error:'僅公司管理員或分店主管可重設人員密碼'});
    const actor=(await pool.query('SELECT * FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId])).rows[0];
    if(!actor||!hasPermission(actor,'peopleManage'))return res.status(403).json({error:'你的帳號沒有管理人員權限'});
    const newPassword=String(req.body?.newPassword||'');
    if(newPassword.length<6)return res.status(400).json({error:'新密碼至少 6 碼'});
    const {rows}=await pool.query("SELECT * FROM users WHERE id=$1 AND company_id=$2 AND role IN ('sales','staff') AND enabled=TRUE AND login_enabled=TRUE",[req.params.userId,req.auth.companyId]);
    const target=rows[0]; if(!target)return res.status(404).json({error:'找不到可登入的人員帳號'});
    if(req.auth.role==='branchManager'){
      const me=(await pool.query('SELECT branch_id FROM users WHERE id=$1 AND company_id=$2',[req.auth.sub,req.auth.companyId])).rows[0];
      if(!me?.branch_id||String(target.branch_id||'')!==String(me.branch_id))return res.status(403).json({error:'不可管理其他分店的人員帳號'});
    }
    const changedAt=now();
    await pool.query('UPDATE users SET password_hash=$1,token_version=token_version+1,password_changed_at=$2,password_changed_by=$3,updated_at=$2 WHERE id=$4',[hashPassword(newPassword),changedAt,req.auth.username,target.id]);
    res.json({ok:true,passwordChangedAt:changedAt,passwordChangedBy:req.auth.username});
  }catch(e){next(e)}
});

app.post('/api/sales/request',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    if(req.auth.role!=='sales')return res.status(403).json({error:'僅業務帳號可使用'});
    const body=req.body||{};
    await client.query('BEGIN');
    const lock=await client.query('SELECT version,json FROM snapshots WHERE company_id=$1 FOR UPDATE',[req.auth.companyId]);
    if(!lock.rows[0]){await client.query('ROLLBACK');return res.status(404).json({error:'車行資料不存在'});}
    const existing={version:Number(lock.rows[0].version),snapshot:lock.rows[0].json};
    const d=existing.snapshot;
    d.saleRequests=Array.isArray(d.saleRequests)?d.saleRequests:[];
    d.cars=Array.isArray(d.cars)?d.cars:[];
    const operationId=String(body.operationId||'').trim();
    if(operationId&&!/^[A-Za-z0-9._:-]{8,120}$/.test(operationId)){await client.query('ROLLBACK');return res.status(400).json({error:'同步識別碼格式錯誤'});}
    const {rows}=await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId]);
    const u=rows[0];
    if(!u){await client.query('ROLLBACK');return res.status(401).json({error:'帳號不存在'});}
    if(operationId){
      const dup=d.saleRequests.find(r=>String(r.operationId||'')===operationId&&String(r.salesId)===String(u.id));
      if(dup){await client.query('COMMIT');return res.json({ok:true,duplicate:true,ackOperationId:operationId,version:existing.version,snapshot:salesSafeSnapshot(d,u),requestId:dup.id});}
    }
    const c=d.cars.find(x=>x.id===body.carId);
    if(!c||c.status!=='在庫'){await client.query('ROLLBACK');return res.status(400).json({error:'車輛不存在或已售'});}
    if(u.branch_id&&String(c.branchId||'')!==String(u.branch_id)){await client.query('ROLLBACK');return res.status(403).json({error:'業務只能操作自己分店的車輛'});}
    if(d.saleRequests.some(r=>r.carId===c.id&&r.status==='待確認')){await client.query('ROLLBACK');return res.status(409).json({error:'此車已有待確認成交申請'});}
    if((await client.query("SELECT 1 FROM vehicle_transfers WHERE company_id=$1 AND car_id=$2 AND status='in_transit' LIMIT 1",[req.auth.companyId,String(c.id)])).rowCount){await client.query('ROLLBACK');return res.status(409).json({error:'此車正在跨分店調撥中，暫時不能提出成交申請'});}
    const sell=Number(body.sellPrice||0);
    if(sell<=0){await client.query('ROLLBACK');return res.status(400).json({error:'售價錯誤'});}
    const rate=Number(u.commission_rate||0),floor=Number(c.floorPrice||0);
    const commissionMode=c.commissionMode==='fixed'?'fixed':'percentage',fixedCommissionAmount=Math.max(0,Number(c.fixedCommissionAmount||0));
    const expectedCommission=commissionMode==='fixed'?fixedCommissionAmount:Math.max(0,sell-floor)*rate/100;
    const saleRequest={
      id:`req_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,operationId:operationId||`legacy_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,branchId:c.branchId||'',carId:c.id,plate:c.plate,model:c.model,
      floorPrice:floor,sellPrice:sell,saleDate:body.saleDate||today(),requestedAt:today(),salesId:u.id,salesName:u.name,
      commissionRate:rate,commissionMode,fixedCommissionAmount,expectedCommission,status:'待確認'
    };
    stampApprovalTarget(saleRequest,await resolveSaleApprover(req.auth.companyId,c.branchId,client));
    d.saleRequests.push(saleRequest);
    const ver=existing.version+1;
    await client.query('UPDATE snapshots SET version=$1,json=$2::jsonb,updated_at=$3 WHERE company_id=$4',[ver,JSON.stringify(cloudOperationalSnapshot(d)),now(),req.auth.companyId]);
    await client.query('COMMIT');
    recordSyncEvent(req.auth.companyId,'sale_request',`成交申請已送達：${c.plate||c.model||c.id}`,{actor:u.username||u.name,operationId:operationId||null});
    notifySalesInventoryChanged(req.auth.companyId,ver,'saleRequest');
    res.json({ok:true,ackOperationId:operationId||null,version:ver,snapshot:salesSafeSnapshot(d,u),approvalTargetName:saleRequest.approvalTargetName||'公司管理員',approvalTargetType:saleRequest.approvalTargetType||'company_admin'});
  }catch(e){
    try{ await client.query('ROLLBACK'); }catch{}
    next(e);
  }finally{ client.release(); }
});


// -------------------- Dealership admin sale workflow --------------------
app.post('/api/admin/sale/direct-request',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    if(req.auth.role!=='admin')return res.status(403).json({error:'僅公司管理員可操作成交流程'});
    const {carId,salesId,sellPrice,saleDate}=req.body||{};
    await client.query('BEGIN');
    const lock=await client.query('SELECT version,json FROM snapshots WHERE company_id=$1 FOR UPDATE',[req.auth.companyId]);
    if(!lock.rows[0]){await client.query('ROLLBACK');return res.status(404).json({error:'車行資料不存在'});}
    const d=lock.rows[0].json||{};d.cars=Array.isArray(d.cars)?d.cars:[];d.saleRequests=Array.isArray(d.saleRequests)?d.saleRequests:[];
    const c=d.cars.find(x=>String(x.id)===String(carId));
    if(!c||c.status!=='在庫'){await client.query('ROLLBACK');return res.status(409).json({error:'此車已售或不存在，不能再次建立成交'});}
    if(!(await enforceManagerBranch(req,c.branchId,client))){await client.query('ROLLBACK');return res.status(403).json({error:'分店主管只能操作自己分店的車輛'});}
    if(d.saleRequests.some(r=>String(r.carId)===String(c.id)&&r.status==='待確認')){await client.query('ROLLBACK');return res.status(409).json({error:'此車已有待確認成交申請，請直接處理原申請'});}
    if((await client.query("SELECT 1 FROM vehicle_transfers WHERE company_id=$1 AND car_id=$2 AND status='in_transit' LIMIT 1",[req.auth.companyId,String(c.id)])).rowCount){await client.query('ROLLBACK');return res.status(409).json({error:'此車正在跨分店調撥中，不能建立成交申請'});}
    if(d.saleRequests.some(r=>String(r.carId)===String(c.id)&&r.status==='已成交')){await client.query('ROLLBACK');return res.status(409).json({error:'此車已有成交紀錄'});}
    const ur=await client.query("SELECT * FROM users WHERE id=$1 AND company_id=$2 AND role='sales' AND enabled=TRUE",[salesId,req.auth.companyId]);
    const u=ur.rows[0];if(!u){await client.query('ROLLBACK');return res.status(400).json({error:'業務帳號不存在或已停用'});}
    if(String(u.branch_id||'')!==String(c.branchId||'')){await client.query('ROLLBACK');return res.status(403).json({error:'成交業務必須屬於車輛所在分店'});}
    const sell=Number(sellPrice||0);if(sell<=0){await client.query('ROLLBACK');return res.status(400).json({error:'售價錯誤'});}
    const floor=Number(c.floorPrice||0),rate=Number(u.commission_rate||0);
    const commissionMode=c.commissionMode==='fixed'?'fixed':'percentage',fixedCommissionAmount=Math.max(0,Number(c.fixedCommissionAmount||0));
    const expectedCommission=commissionMode==='fixed'?fixedCommissionAmount:Math.max(0,sell-floor)*rate/100;
    const r={id:`req_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,branchId:c.branchId||'',carId:c.id,plate:c.plate,model:c.model,floorPrice:floor,sellPrice:sell,saleDate:saleDate||today(),requestedAt:today(),salesId:u.id,salesName:u.name,commissionRate:rate,commissionMode,fixedCommissionAmount,expectedCommission,status:'待確認',directByAdmin:true};
    stampApprovalTarget(r,{type:'company_admin',user:(await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2',[req.auth.sub,req.auth.companyId])).rows[0]});
    d.saleRequests.push(r);
    const ver=Number(lock.rows[0].version||0)+1;
    await client.query('UPDATE snapshots SET version=$1,json=$2::jsonb,updated_at=$3 WHERE company_id=$4',[ver,JSON.stringify(cloudOperationalSnapshot(d)),now(),req.auth.companyId]);
    await client.query('COMMIT');recordSyncEvent(req.auth.companyId,'sale_request','後台建立成交申請',{actor:req.auth.username||req.auth.sub});notifySalesInventoryChanged(req.auth.companyId,ver,'saleConfirmed');const authU=(await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2',[req.auth.sub,req.auth.companyId])).rows[0];res.json({ok:true,version:ver,snapshot:snapshotForUser(d,authU),request:r});
  }catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}
});

app.post('/api/admin/sale/confirm',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    const actingUser=(await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId])).rows[0];
    if(!actingUser||!hasPermission(actingUser,'saleApprove'))return res.status(403).json({error:'你的帳號沒有確認成交權限'});
    const {requestId,transfer=0,fuel=0,license=0,other=0,otherName='',localTotalCost=0}=req.body||{};
    await client.query('BEGIN');
    const lock=await client.query('SELECT version,json FROM snapshots WHERE company_id=$1 FOR UPDATE',[req.auth.companyId]);
    if(!lock.rows[0]){await client.query('ROLLBACK');return res.status(404).json({error:'車行資料不存在'});}
    const d=lock.rows[0].json||{};d.cars=Array.isArray(d.cars)?d.cars:[];d.saleRequests=Array.isArray(d.saleRequests)?d.saleRequests:[];
    const r=d.saleRequests.find(x=>String(x.id)===String(requestId));
    if(!r){await client.query('ROLLBACK');return res.status(404).json({error:'找不到成交申請'});}
    if(!canActOnSaleRequest(actingUser,r)){await client.query('ROLLBACK');return res.status(403).json({error:`此成交申請目前由 ${r.approvalTargetName||'其他人員'} 負責審核`});}
    if(!(await enforceManagerBranch(req,r.branchId,client))){await client.query('ROLLBACK');return res.status(403).json({error:'分店主管只能處理自己分店的成交申請'});}
    if(r.status!=='待確認'){await client.query('ROLLBACK');return res.status(409).json({error:`此申請目前為「${r.status}」，不可重複確認`});}
    const c=d.cars.find(x=>String(x.id)===String(r.carId));
    if(!c){await client.query('ROLLBACK');return res.status(404).json({error:'找不到車輛'});}
    if(c.status!=='在庫'){await client.query('ROLLBACK');return res.status(409).json({error:'此車已完成成交，不可再次確認'});}
    if(d.saleRequests.some(x=>String(x.carId)===String(c.id)&&x.status==='已成交')){await client.query('ROLLBACK');return res.status(409).json({error:'此車已有成交紀錄，不可重複成交'});}
    const tr=Number(transfer||0),fu=Number(fuel||0),li=Number(license||0),ot=Number(other||0);
    const commission=r.commissionMode==='fixed'?Math.max(0,Number(r.fixedCommissionAmount||r.expectedCommission||0)):Math.max(0,Number(r.sellPrice||0)-Number(r.floorPrice||0))*Number(r.commissionRate||0)/100;
    const extra=tr+fu+li+ot,totalCost=Math.max(0,Number(localTotalCost||0));
    Object.assign(c,{status:'已售',outDate:r.saleDate,sellPrice:Number(r.sellPrice||0),salesId:r.salesId,salesName:r.salesName,commissionRate:Number(r.commissionRate||0),commissionMode:r.commissionMode==='fixed'?'fixed':'percentage',fixedCommissionAmount:Math.max(0,Number(r.fixedCommissionAmount||0)),commissionAmount:commission,totalCost,saleTransferFee:tr,saleFuelFee:fu,saleLicenseTax:li,saleOtherFee:ot,saleOtherFeeName:String(otherName||''),saleExtraCost:extra,companyProfit:Number(r.sellPrice||0)-totalCost-extra-commission});
    Object.assign(r,{status:'已成交',finalCommission:commission,confirmedAt:now()});
    d.operationLogs=Array.isArray(d.operationLogs)?d.operationLogs:[];
    d.operationLogs.push({id:`log_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,action:'確認成交',carId:c.id,plate:c.plate||'',requestId:r.id,reason:'',operatedAt:now(),operatedBy:req.auth.username||req.auth.sub});
    // Defense in depth: there must never be another pending request for this sold car.
    for(const x of d.saleRequests){
      if(x.id!==r.id&&String(x.carId)===String(c.id)&&x.status==='待確認'){
        x.status='已駁回';x.rejectReason='此車已由其他成交申請完成成交';x.rejectedAt=now();
      }
    }
    const ver=Number(lock.rows[0].version||0)+1;
    await client.query('UPDATE snapshots SET version=$1,json=$2::jsonb,updated_at=$3 WHERE company_id=$4',[ver,JSON.stringify(cloudOperationalSnapshot(d)),now(),req.auth.companyId]);
    await client.query('COMMIT');recordSyncEvent(req.auth.companyId,'sale_confirm',`確認成交：${c.plate||c.model||c.id}`,{actor:req.auth.username||req.auth.sub,operationId:r.operationId||null});notifySalesInventoryChanged(req.auth.companyId,ver,'saleStatusChanged');const authU=(await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2',[req.auth.sub,req.auth.companyId])).rows[0];res.json({ok:true,version:ver,snapshot:snapshotForUser(d,authU)});
  }catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}
});

app.post('/api/admin/sale/cancel',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    const actingUser=(await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId])).rows[0];
    if(!actingUser||!hasPermission(actingUser,'saleCancel'))return res.status(403).json({error:'你的帳號沒有取消成交權限'});
    const {carId,reason}=req.body||{};
    const why=String(reason||'').trim();
    if(!why)return res.status(400).json({error:'取消成交原因不可空白'});
    await client.query('BEGIN');
    const lock=await client.query('SELECT version,json FROM snapshots WHERE company_id=$1 FOR UPDATE',[req.auth.companyId]);
    if(!lock.rows[0]){await client.query('ROLLBACK');return res.status(404).json({error:'車行資料不存在'});}
    const d=lock.rows[0].json||{};
    d.cars=Array.isArray(d.cars)?d.cars:[];
    d.saleRequests=Array.isArray(d.saleRequests)?d.saleRequests:[];
    const c=d.cars.find(x=>String(x.id)===String(carId));
    if(!c){await client.query('ROLLBACK');return res.status(404).json({error:'找不到車輛'});}
    if(!(await enforceManagerBranch(req,c.branchId,client))){await client.query('ROLLBACK');return res.status(403).json({error:'分店主管只能操作自己分店的車輛'});}
    if(c.status!=='已售'){await client.query('ROLLBACK');return res.status(409).json({error:'此車目前不是已售狀態，無法取消成交'});}
    const completed=d.saleRequests
      .filter(r=>String(r.carId)===String(c.id)&&r.status==='已成交')
      .sort((a,b)=>String(b.confirmedAt||'').localeCompare(String(a.confirmedAt||'')));
    if(completed.length!==1){
      await client.query('ROLLBACK');
      return res.status(409).json({error:completed.length===0?'找不到此車的已成交申請紀錄':'此車存在多筆已成交紀錄，請先由系統管理員處理資料'});
    }
    const r=completed[0];
    Object.assign(r,{
      status:'成交已取消',
      cancelReason:why,
      canceledAt:now(),
      canceledBy:req.auth.username||req.auth.sub,
      previousConfirmedAt:r.confirmedAt||''
    });
    d.operationLogs=Array.isArray(d.operationLogs)?d.operationLogs:[];
    d.operationLogs.push({id:`log_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,action:'取消成交／恢復在庫',carId:c.id,plate:c.plate||'',requestId:r.id,reason:why,operatedAt:r.canceledAt,operatedBy:req.auth.username||req.auth.sub,previousConfirmedAt:r.previousConfirmedAt||''});
    // 只清除「成交結果」欄位；進貨成本、底價、來源、照片、整備資料全部保留。
    Object.assign(c,{
      status:'在庫',outDate:'',sellPrice:0,salesId:'',salesName:'',commissionRate:0,commissionAmount:0,
      saleTransferFee:0,saleFuelFee:0,saleLicenseTax:0,saleOtherFee:0,saleOtherFeeName:'',saleExtraCost:0,companyProfit:0
    });
    const ver=Number(lock.rows[0].version||0)+1;
    const integrity=validateSaleIntegrity(d);
    if(integrity){await client.query('ROLLBACK');return res.status(409).json({error:integrity});}
    await client.query('UPDATE snapshots SET version=$1,json=$2::jsonb,updated_at=$3 WHERE company_id=$4',[ver,JSON.stringify(cloudOperationalSnapshot(d)),now(),req.auth.companyId]);
    await client.query('COMMIT');
    recordSyncEvent(req.auth.companyId,'sale_cancel',`取消成交：${c.plate||c.model||c.id}`,{actor:req.auth.username||req.auth.sub,operationId:r.operationId||null});
    notifySalesInventoryChanged(req.auth.companyId,ver,'saleCanceled');
    const authU=(await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2',[req.auth.sub,req.auth.companyId])).rows[0];
    res.json({ok:true,version:ver,snapshot:snapshotForUser(d,authU),canceledRequestId:r.id});
  }catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}
});

app.post('/api/admin/sale/reject',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    const actingUser=(await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId])).rows[0];
    if(!actingUser||!hasPermission(actingUser,'saleReject'))return res.status(403).json({error:'你的帳號沒有駁回成交權限'});
    const {requestId,reason}=req.body||{};if(!String(reason||'').trim())return res.status(400).json({error:'駁回原因不可空白'});
    await client.query('BEGIN');
    const lock=await client.query('SELECT version,json FROM snapshots WHERE company_id=$1 FOR UPDATE',[req.auth.companyId]);
    if(!lock.rows[0]){await client.query('ROLLBACK');return res.status(404).json({error:'車行資料不存在'});}
    const d=lock.rows[0].json||{};d.saleRequests=Array.isArray(d.saleRequests)?d.saleRequests:[];
    const r=d.saleRequests.find(x=>String(x.id)===String(requestId));
    if(!r){await client.query('ROLLBACK');return res.status(404).json({error:'找不到成交申請'});}
    if(!canActOnSaleRequest(actingUser,r)){await client.query('ROLLBACK');return res.status(403).json({error:`此成交申請目前由 ${r.approvalTargetName||'其他人員'} 負責審核`});}
    if(!(await enforceManagerBranch(req,r.branchId,client))){await client.query('ROLLBACK');return res.status(403).json({error:'分店主管只能處理自己分店的成交申請'});}
    if(r.status!=='待確認'){await client.query('ROLLBACK');return res.status(409).json({error:`此申請目前為「${r.status}」，不可再次處理`});}
    r.status='已駁回';r.rejectReason=String(reason).trim();r.rejectedAt=now();
    d.operationLogs=Array.isArray(d.operationLogs)?d.operationLogs:[];
    d.operationLogs.push({id:`log_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,action:'駁回成交申請',carId:r.carId,plate:r.plate||'',requestId:r.id,reason:r.rejectReason,operatedAt:r.rejectedAt,operatedBy:req.auth.username||req.auth.sub});
    const ver=Number(lock.rows[0].version||0)+1;
    await client.query('UPDATE snapshots SET version=$1,json=$2::jsonb,updated_at=$3 WHERE company_id=$4',[ver,JSON.stringify(cloudOperationalSnapshot(d)),now(),req.auth.companyId]);
    await client.query('COMMIT');recordSyncEvent(req.auth.companyId,'sale_reject',`駁回成交申請：${r.plate||r.carId}`,{actor:req.auth.username||req.auth.sub,operationId:r.operationId||null});notifySalesInventoryChanged(req.auth.companyId,ver,'saleStatusChanged');const authU=(await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2',[req.auth.sub,req.auth.companyId])).rows[0];res.json({ok:true,version:ver,snapshot:snapshotForUser(d,authU)});
  }catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}
});



// -------------------- Phase 14C vehicle transfer workflow --------------------
function transferDto(x){return {id:x.id,carId:x.car_id,plate:x.plate||'',model:x.model||'',fromBranchId:x.from_branch_id,toBranchId:x.to_branch_id,status:x.status,requestedById:x.requested_by_id||'',requestedByName:x.requested_by_name||'',requestedByRole:x.requested_by_role||'',requestedAt:x.requested_at,note:x.note||'',arrivedById:x.arrived_by_id||'',arrivedByName:x.arrived_by_name||'',arrivedAt:x.arrived_at||null,canceledById:x.canceled_by_id||'',canceledByName:x.canceled_by_name||'',canceledAt:x.canceled_at||null,cancelReason:x.cancel_reason||'',ownerRead:!!x.owner_read_at,updatedAt:x.updated_at||x.requested_at};}
async function transferActor(req,client=pool){return (await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId])).rows[0]||null}
app.get('/api/transfers',auth,requireActiveCompany,async(req,res,next)=>{try{
  const actor=await transferActor(req);if(!actor||!['admin','branchManager'].includes(actor.role))return res.status(403).json({error:'僅公司管理員或分店主管可查看車輛調撥'});
  const limit=Math.min(5000,Math.max(1,Number(req.query.limit||100)));let params=[req.auth.companyId],scope='';
  if(actor.role==='branchManager'){scope=' AND (t.from_branch_id=$2 OR t.to_branch_id=$2)';params.push(String(actor.branch_id||''));}
  params.push(limit);const q=await pool.query(`SELECT t.*,fb.name from_branch_name,tb.name to_branch_name FROM vehicle_transfers t LEFT JOIN branches fb ON fb.id=t.from_branch_id LEFT JOIN branches tb ON tb.id=t.to_branch_id WHERE t.company_id=$1${scope} ORDER BY t.requested_at DESC LIMIT $${params.length}`,params);
  const owner=(await pool.query('SELECT owner_user_id FROM companies WHERE id=$1',[req.auth.companyId])).rows[0]?.owner_user_id||'';
  const ownerUnread=String(actor.id)===String(owner)?Number((await pool.query("SELECT COUNT(*)::int n FROM vehicle_transfers WHERE company_id=$1 AND owner_read_at IS NULL AND requested_by_role='branchManager'",[req.auth.companyId])).rows[0]?.n||0):0;
  const pendingArrival=actor.role==='branchManager'?Number((await pool.query("SELECT COUNT(*)::int n FROM vehicle_transfers WHERE company_id=$1 AND to_branch_id=$2 AND status='in_transit'",[req.auth.companyId,String(actor.branch_id||'')])).rows[0]?.n||0):0;
  res.json({transfers:q.rows.map(x=>({...transferDto(x),fromBranchName:x.from_branch_name||'',toBranchName:x.to_branch_name||''})),ownerUnreadCount:ownerUnread,pendingArrivalCount:pendingArrival});
}catch(e){next(e)}});
app.post('/api/transfers',auth,requireActiveCompany,async(req,res,next)=>{const client=await pool.connect();try{
  const actor=await transferActor(req,client);if(!actor||!['admin','branchManager'].includes(actor.role)||!hasPermission(actor,'vehicleTransfer'))return res.status(403).json({error:'你的帳號沒有車輛調撥權限'});
  const carId=String(req.body?.carId||''),toBranchId=String(req.body?.toBranchId||''),note=String(req.body?.note||'').trim().slice(0,500);if(!carId||!toBranchId)return res.status(400).json({error:'請選擇車輛與目的分店'});
  await client.query('BEGIN');const lock=await client.query('SELECT version,json FROM snapshots WHERE company_id=$1 FOR UPDATE',[req.auth.companyId]);if(!lock.rows[0]){await client.query('ROLLBACK');return res.status(404).json({error:'車行資料不存在'});}const d=lock.rows[0].json||{};d.cars=Array.isArray(d.cars)?d.cars:[];d.saleRequests=Array.isArray(d.saleRequests)?d.saleRequests:[];
  const c=d.cars.find(x=>String(x.id)===carId);if(!c||c.status!=='在庫'){await client.query('ROLLBACK');return res.status(409).json({error:'只有在庫車輛可以調撥'});}const fromBranchId=String(c.branchId||'');
  if(actor.role==='branchManager'&&String(actor.branch_id||'')!==fromBranchId){await client.query('ROLLBACK');return res.status(403).json({error:'分店主管只能調撥自己分店的車輛'});}if(fromBranchId===toBranchId){await client.query('ROLLBACK');return res.status(400).json({error:'目的分店不能與目前分店相同'});}
  const dest=(await client.query('SELECT * FROM branches WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[toBranchId,req.auth.companyId])).rows[0];if(!dest){await client.query('ROLLBACK');return res.status(404).json({error:'目的分店不存在或已停用'});}if(d.saleRequests.some(r=>String(r.carId)===carId&&r.status==='待確認')){await client.query('ROLLBACK');return res.status(409).json({error:'此車有待確認成交申請，不能調撥'});}if((await client.query("SELECT 1 FROM vehicle_transfers WHERE company_id=$1 AND car_id=$2 AND status='in_transit' LIMIT 1",[req.auth.companyId,carId])).rowCount){await client.query('ROLLBACK');return res.status(409).json({error:'此車已有進行中的調撥'});}
  const company=(await client.query('SELECT owner_user_id FROM companies WHERE id=$1',[req.auth.companyId])).rows[0]||{},ts=now(),id='tr_'+crypto.randomUUID(),direct=actor.role==='admin';
  await client.query(`INSERT INTO vehicle_transfers(id,company_id,car_id,plate,model,from_branch_id,to_branch_id,status,requested_by_id,requested_by_name,requested_by_role,requested_at,note,arrived_by_id,arrived_by_name,arrived_at,owner_read_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$12,$12)`,[id,req.auth.companyId,carId,String(c.plate||''),String(c.model||''),fromBranchId,toBranchId,direct?'completed':'in_transit',String(actor.id),String(actor.name||actor.username||''),String(actor.role),ts,note,direct?String(actor.id):'',direct?String(actor.name||actor.username||''):'',direct?ts:null,String(actor.id)===String(company.owner_user_id||'')?ts:null]);
  let ver=Number(lock.rows[0].version||0);if(direct){c.branchId=toBranchId;d.operationLogs=Array.isArray(d.operationLogs)?d.operationLogs:[];d.operationLogs.push({id:`log_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,action:'車輛直接調撥',carId:c.id,plate:c.plate||'',reason:`${fromBranchId} → ${toBranchId}${note?'｜'+note:''}`,operatedAt:ts,operatedBy:actor.username||actor.name});ver+=1;await client.query('UPDATE snapshots SET version=$1,json=$2::jsonb,updated_at=$3 WHERE company_id=$4',[ver,JSON.stringify(cloudOperationalSnapshot(d)),ts,req.auth.companyId]);}
  await client.query('COMMIT');if(direct)notifySalesInventoryChanged(req.auth.companyId,ver,'vehicleTransfer');res.json({ok:true,id,status:direct?'completed':'in_transit',version:ver,snapshot:snapshotForUser(d,actor)});
}catch(e){try{await client.query('ROLLBACK')}catch{};if(e?.code==='23505')return res.status(409).json({error:'此車已有進行中的調撥'});next(e)}finally{client.release()}});
app.post('/api/transfers/:id/arrive',auth,requireActiveCompany,async(req,res,next)=>{const client=await pool.connect();try{
  const actor=await transferActor(req,client);if(!actor||!['admin','branchManager'].includes(actor.role)||!hasPermission(actor,'vehicleTransfer'))return res.status(403).json({error:'你的帳號沒有確認調撥到店權限'});await client.query('BEGIN');const tr=(await client.query('SELECT * FROM vehicle_transfers WHERE id=$1 AND company_id=$2 FOR UPDATE',[req.params.id,req.auth.companyId])).rows[0];if(!tr){await client.query('ROLLBACK');return res.status(404).json({error:'找不到調撥紀錄'});}if(tr.status!=='in_transit'){await client.query('ROLLBACK');return res.status(409).json({error:'此調撥已經處理完成'});}if(actor.role==='branchManager'&&String(actor.branch_id||'')!==String(tr.to_branch_id)){await client.query('ROLLBACK');return res.status(403).json({error:'只有目的分店主管可以確認到店'});}
  const lock=await client.query('SELECT version,json FROM snapshots WHERE company_id=$1 FOR UPDATE',[req.auth.companyId]);const d=lock.rows[0]?.json||{};d.cars=Array.isArray(d.cars)?d.cars:[];const c=d.cars.find(x=>String(x.id)===String(tr.car_id));if(!c||c.status!=='在庫'){await client.query('ROLLBACK');return res.status(409).json({error:'車輛目前不是可到店的在庫狀態'});}if(String(c.branchId||'')!==String(tr.from_branch_id)){await client.query('ROLLBACK');return res.status(409).json({error:'車輛目前分店已變更，請由公司管理員檢查'});}c.branchId=tr.to_branch_id;const ts=now();d.operationLogs=Array.isArray(d.operationLogs)?d.operationLogs:[];d.operationLogs.push({id:`log_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,action:'車輛調撥確認到店',carId:c.id,plate:c.plate||'',reason:`${tr.from_branch_id} → ${tr.to_branch_id}`,operatedAt:ts,operatedBy:actor.username||actor.name});const ver=Number(lock.rows[0].version||0)+1;await client.query('UPDATE snapshots SET version=$1,json=$2::jsonb,updated_at=$3 WHERE company_id=$4',[ver,JSON.stringify(cloudOperationalSnapshot(d)),ts,req.auth.companyId]);await client.query("UPDATE vehicle_transfers SET status='completed',arrived_by_id=$1,arrived_by_name=$2,arrived_at=$3,updated_at=$3 WHERE id=$4",[String(actor.id),String(actor.name||actor.username||''),ts,tr.id]);await client.query('COMMIT');notifySalesInventoryChanged(req.auth.companyId,ver,'vehicleTransferArrived');res.json({ok:true,version:ver,snapshot:snapshotForUser(d,actor)});
}catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}});
app.post('/api/transfers/:id/cancel',auth,requireActiveCompany,async(req,res,next)=>{const client=await pool.connect();try{
  const actor=await transferActor(req,client);if(!actor||!['admin','branchManager'].includes(actor.role)||!hasPermission(actor,'vehicleTransfer'))return res.status(403).json({error:'你的帳號沒有取消調撥權限'});const reason=String(req.body?.reason||'').trim();if(!reason)return res.status(400).json({error:'取消調撥原因不能空白'});await client.query('BEGIN');const tr=(await client.query('SELECT * FROM vehicle_transfers WHERE id=$1 AND company_id=$2 FOR UPDATE',[req.params.id,req.auth.companyId])).rows[0];if(!tr){await client.query('ROLLBACK');return res.status(404).json({error:'找不到調撥紀錄'});}if(tr.status!=='in_transit'){await client.query('ROLLBACK');return res.status(409).json({error:'只有調撥中的紀錄可以取消'});}if(actor.role==='branchManager'&&String(actor.branch_id||'')!==String(tr.from_branch_id)){await client.query('ROLLBACK');return res.status(403).json({error:'只有提出調撥的來源分店主管可以取消'});}const ts=now();await client.query("UPDATE vehicle_transfers SET status='canceled',canceled_by_id=$1,canceled_by_name=$2,canceled_at=$3,cancel_reason=$4,updated_at=$3 WHERE id=$5",[String(actor.id),String(actor.name||actor.username||''),ts,reason,tr.id]);await client.query('COMMIT');res.json({ok:true});
}catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}});
app.post('/api/transfers/read-all',auth,requireActiveCompany,async(req,res,next)=>{try{const c=(await pool.query('SELECT owner_user_id FROM companies WHERE id=$1',[req.auth.companyId])).rows[0]||{};if(String(c.owner_user_id||'')!==String(req.auth.sub||''))return res.status(403).json({error:'僅公司老闆可操作調撥通知'});await pool.query('UPDATE vehicle_transfers SET owner_read_at=$1 WHERE company_id=$2 AND owner_read_at IS NULL',[now(),req.auth.companyId]);res.json({ok:true});}catch(e){next(e)}});

// -------------------- Phase 14B.7 staff change audit / owner notifications --------------------
app.get('/api/admin/staff-events',auth,requireActiveCompany,async(req,res,next)=>{try{
  const c=(await pool.query('SELECT owner_user_id FROM companies WHERE id=$1',[req.auth.companyId])).rows[0]||{};
  if(String(c.owner_user_id||'')!==String(req.auth.sub||''))return res.status(403).json({error:'僅公司老闆可查看全公司人員異動通知'});
  const limit=Math.min(5000,Math.max(1,Number(req.query.limit||50)));
  const q=await pool.query(`SELECT e.*,b.name branch_name FROM staff_change_events e LEFT JOIN branches b ON b.id=e.branch_id AND b.company_id=e.company_id WHERE e.company_id=$1 ORDER BY e.id DESC LIMIT $2`,[req.auth.companyId,limit]);
  const unread=Number((await pool.query('SELECT COUNT(*)::int AS n FROM staff_change_events WHERE company_id=$1 AND owner_read_at IS NULL',[req.auth.companyId])).rows[0]?.n||0);
  res.json({events:q.rows.map(x=>({id:Number(x.id),type:x.event_type,employeeId:x.employee_id,employeeName:x.employee_name,position:x.position,branchId:x.branch_id,branchName:x.branch_name||'',actorId:x.actor_id,actorName:x.actor_name,actorRole:x.actor_role,reason:x.reason,createdAt:x.created_at,read:!!x.owner_read_at})),unreadCount:unread});
}catch(e){next(e)}});
app.post('/api/admin/staff-events/read-all',auth,requireActiveCompany,async(req,res,next)=>{try{
  const c=(await pool.query('SELECT owner_user_id FROM companies WHERE id=$1',[req.auth.companyId])).rows[0]||{};
  if(String(c.owner_user_id||'')!==String(req.auth.sub||''))return res.status(403).json({error:'僅公司老闆可操作人員異動通知'});
  await pool.query('UPDATE staff_change_events SET owner_read_at=$1 WHERE company_id=$2 AND owner_read_at IS NULL',[now(),req.auth.companyId]);res.json({ok:true});
}catch(e){next(e)}});

// -------------------- Phase 14B.4 payroll month period / close --------------------
function payrollCurrentMonth(){return today().slice(0,7)}
async function companyPayrollActivation(client,companyId){
  const c=(await client.query('SELECT system_activation_date,start_date FROM companies WHERE id=$1',[companyId])).rows[0]||{};
  const date=String(c.system_activation_date||c.start_date||today()).slice(0,10),month=date.slice(0,7);
  return {date,month};
}
async function isPayrollBeforeActivation(client,companyId,month){const a=await companyPayrollActivation(client,companyId);return {before:String(month)<a.month,activation:a};}

function payrollMonthStatus(period,month,expectedCount,settledCount){
  if(period?.preActivation)return 'pre_activation';
  if(period?.locked)return 'closed';
  if(String(month)===payrollCurrentMonth())return 'in_progress';
  if(String(month)>payrollCurrentMonth())return 'in_progress';
  if(expectedCount<=0)return 'all_settled';
  if(settledCount<=0)return 'pending';
  if(settledCount<expectedCount)return 'partial';
  return 'all_settled';
}
async function ensurePayrollPeriod(client,companyId,month,{refreshCurrent=true,addEmployeeId=''}={}){
  if(!/^\d{4}-\d{2}$/.test(String(month||'')))throw new Error('INVALID_PAYROLL_MONTH');
  const boundary=await isPayrollBeforeActivation(client,companyId,month);
  if(boundary.before)return {company_id:companyId,month,employee_ids:[],locked:false,preActivation:true,activationDate:boundary.activation.date,activationMonth:boundary.activation.month};
  let row=(await client.query('SELECT * FROM payroll_month_periods WHERE company_id=$1 AND month=$2',[companyId,month])).rows[0];
  if(!row){
    const users=(await client.query("SELECT id FROM users WHERE company_id=$1 AND enabled=TRUE AND role<>'admin' ORDER BY id",[companyId])).rows.map(x=>String(x.id));
    row=(await client.query(`INSERT INTO payroll_month_periods(company_id,month,employee_ids,locked,created_at,updated_at) VALUES($1,$2,$3::jsonb,FALSE,$4,$4) ON CONFLICT(company_id,month) DO UPDATE SET updated_at=payroll_month_periods.updated_at RETURNING *`,[companyId,month,JSON.stringify(users),now()])).rows[0];
  }
  let ids=Array.isArray(row.employee_ids)?row.employee_ids.map(String):[];
  if(!row.locked && refreshCurrent && String(month)===payrollCurrentMonth()){
    const current=(await client.query("SELECT id FROM users WHERE company_id=$1 AND enabled=TRUE AND role<>'admin' ORDER BY id",[companyId])).rows.map(x=>String(x.id));
    ids=[...new Set([...ids,...current])];
  }
  if(!row.locked && addEmployeeId)ids=[...new Set([...ids,String(addEmployeeId)])];
  const oldIds=Array.isArray(row.employee_ids)?row.employee_ids.map(String):[];
  if(JSON.stringify(ids)!==JSON.stringify(oldIds)){
    row=(await client.query('UPDATE payroll_month_periods SET employee_ids=$1::jsonb,updated_at=$2 WHERE company_id=$3 AND month=$4 RETURNING *',[JSON.stringify(ids),now(),companyId,month])).rows[0];
  }
  return row;
}
async function payrollPeriodSummary(client,companyId,month,period=null){
  period=period||await ensurePayrollPeriod(client,companyId,month,{refreshCurrent:false});
  if(period?.preActivation)return {month,status:'pre_activation',expectedCount:0,settledCount:0,remainingCount:0,locked:false,systemActivationDate:period.activationDate||'',systemActivationMonth:period.activationMonth||String(period.activationDate||'').slice(0,7),beforeActivation:true};
  const ids=Array.isArray(period.employee_ids)?period.employee_ids.map(String):[];
  const q=await client.query('SELECT employee_id FROM payroll_settlements WHERE company_id=$1 AND month=$2',[companyId,month]);
  const settledSet=new Set(q.rows.map(x=>String(x.employee_id)));
  const settledCount=ids.filter(id=>settledSet.has(id)).length;
  const expectedCount=ids.length;
  return {month,status:payrollMonthStatus(period,month,expectedCount,settledCount),expectedCount,settledCount,remainingCount:Math.max(0,expectedCount-settledCount),locked:!!period.locked,lockedAt:period.locked_at||null,lockedBy:period.locked_by||'',unlockedAt:period.unlocked_at||null,unlockedBy:period.unlocked_by||''};
}
async function recentPayrollMonthStates(client,companyId,focusMonth){
  const activation=await companyPayrollActivation(client,companyId);
  const rows=(await client.query('SELECT * FROM payroll_month_periods WHERE company_id=$1 AND month >= $2 ORDER BY month DESC LIMIT 12',[companyId,activation.month])).rows;
  const map=new Map(rows.map(r=>[String(r.month),r]));
  for(const m of [payrollCurrentMonth(),String(focusMonth)])if(m&&m>=activation.month&&!map.has(m)){const p=await ensurePayrollPeriod(client,companyId,m,{refreshCurrent:m===payrollCurrentMonth()});if(!p.preActivation)map.set(m,p)}
  const months=[...map.keys()].filter(m=>m>=activation.month).sort().reverse().slice(0,12),out=[];
  for(const m of months)out.push(await payrollPeriodSummary(client,companyId,m,map.get(m)));
  return out;
}

// -------------------- Phase 14B.3 payroll / company cost --------------------
app.get('/api/admin/payroll',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    const u=await getUserById(req.auth.companyId,req.auth.sub);if(!u)return res.status(401).json({error:'帳號已失效'});
    if(!(u.role==='admin'||hasPermission(u,'viewReports')||hasPermission(u,'peopleManage')))return res.status(403).json({error:'沒有薪資／人事成本查看權限'});
    const month=String(req.query.month||payrollCurrentMonth());if(!/^\d{4}-\d{2}$/.test(month))return res.status(400).json({error:'月份格式不正確'});
    const period=await ensurePayrollPeriod(pool,req.auth.companyId,month,{refreshCurrent:true});
    const activation=await companyPayrollActivation(pool,req.auth.companyId);
    if(period.preActivation){
      const company=(await pool.query('SELECT payroll_cost_mode FROM companies WHERE id=$1',[req.auth.companyId])).rows[0]||{};
      const costMode=['realtime_estimate','settled_only'].includes(String(company.payroll_cost_mode||''))?String(company.payroll_cost_mode):'realtime_estimate';
      const monthState=await payrollPeriodSummary(pool,req.auth.companyId,month,period),monthStates=await recentPayrollMonthStates(pool,req.auth.companyId,activation.month);
      return res.json({month,costMode,monthState,monthStates,events:[],settlements:[],employees:[],systemActivationDate:activation.date,systemActivationMonth:activation.month,beforeActivation:true});
    }
    const params=[req.auth.companyId,month];let branchClause='';
    if(u.role!=='admin'){params.push(String(u.branch_id||''));branchClause=` AND p.branch_id=$${params.length}`;}
    const q=await pool.query(`SELECT p.*,u.name employee_name,u.position,u.salary_type FROM payroll_settlements p JOIN users u ON u.id=p.employee_id WHERE p.company_id=$1 AND p.month=$2${branchClause} ORDER BY u.name,p.employee_id`,params);
    const periodIds=Array.isArray(period.employee_ids)?period.employee_ids.map(String):[];
    let usersQ;
    if(periodIds.length){
      usersQ=await pool.query(`SELECT * FROM users WHERE company_id=$1 AND id = ANY($2::text[]) ${u.role==='admin'?'':'AND branch_id=$3'} ORDER BY name`,u.role==='admin'?[req.auth.companyId,periodIds]:[req.auth.companyId,periodIds,String(u.branch_id||'')]);
    }else usersQ={rows:[]};
    const company=(await pool.query('SELECT payroll_cost_mode FROM companies WHERE id=$1',[req.auth.companyId])).rows[0]||{};
    const costMode=['realtime_estimate','settled_only'].includes(String(company.payroll_cost_mode||''))?String(company.payroll_cost_mode):'realtime_estimate';
    const monthState=await payrollPeriodSummary(pool,req.auth.companyId,month,period),monthStates=await recentPayrollMonthStates(pool,req.auth.companyId,month);
    const events=(await pool.query('SELECT action,actor,detail,created_at FROM payroll_month_events WHERE company_id=$1 AND month=$2 ORDER BY id DESC LIMIT 20',[req.auth.companyId,month])).rows;
    res.json({month,costMode,monthState,monthStates,events,settlements:q.rows.map(x=>({id:x.id,employeeId:x.employee_id,employeeName:x.employee_name,position:x.position||'',salaryType:x.salary_type||'fixed',branchId:x.branch_id||'',baseSalary:Number(x.base_salary||0),commission:Number(x.commission||0),allowance:Number(x.allowance||0),overtime:Number(x.overtime||0),deductions:Number(x.deductions||0),totalCost:Number(x.total_cost||0),status:x.status,settledAt:x.settled_at,settledBy:x.settled_by,note:x.note||''})),employees:usersQ.rows.map(userDto),systemActivationDate:activation.date,systemActivationMonth:activation.month,beforeActivation:false});
  }catch(e){if(e?.message==='INVALID_PAYROLL_MONTH')return res.status(400).json({error:'月份格式不正確'});next(e)}
});

app.put('/api/admin/payroll/settings',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    const u=await getUserById(req.auth.companyId,req.auth.sub);if(!u)return res.status(401).json({error:'帳號已失效'});
    if(u.role!=='admin')return res.status(403).json({error:'僅公司管理員可修改薪資成本計算模式'});
    const mode=String(req.body?.costMode||'');
    if(!['realtime_estimate','settled_only'].includes(mode))return res.status(400).json({error:'薪資成本計算模式不正確'});
    await pool.query('UPDATE companies SET payroll_cost_mode=$1 WHERE id=$2',[mode,req.auth.companyId]);
    res.json({ok:true,costMode:mode});
  }catch(e){next(e)}
});

app.post('/api/admin/payroll/month/lock',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    const actor=(await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId])).rows[0];
    if(!actor||actor.role!=='admin')return res.status(403).json({error:'僅公司管理員可以封帳'});
    const month=String(req.body?.month||'');if(!/^\d{4}-\d{2}$/.test(month))return res.status(400).json({error:'月份格式不正確'});
    if(month>=payrollCurrentMonth())return res.status(409).json({error:'目前月份尚未結束，不能封帳'});
    await client.query('BEGIN');
    const period=await ensurePayrollPeriod(client,req.auth.companyId,month,{refreshCurrent:false});
    if(period.preActivation){await client.query('ROLLBACK');return res.status(409).json({error:`${period.activationDate||''} 為系統正式啟用日，啟用前月份不納入薪資月結`});}
    const summary=await payrollPeriodSummary(client,req.auth.companyId,month,period);
    if(summary.locked){await client.query('ROLLBACK');return res.json({ok:true,monthState:summary});}
    if(summary.remainingCount>0){await client.query('ROLLBACK');return res.status(409).json({error:`尚有 ${summary.remainingCount} 位員工未結算，不能封帳`});}
    const at=now(),who=actor.name||actor.username;
    await client.query('UPDATE payroll_month_periods SET locked=TRUE,locked_at=$1,locked_by=$2,updated_at=$1 WHERE company_id=$3 AND month=$4',[at,who,req.auth.companyId,month]);
    await client.query('INSERT INTO payroll_month_events(company_id,month,action,actor,detail,created_at) VALUES($1,$2,$3,$4,$5,$6)',[req.auth.companyId,month,'lock',who,'薪資月份封帳',at]);
    await client.query('COMMIT');
    res.json({ok:true,monthState:await payrollPeriodSummary(client,req.auth.companyId,month)});
  }catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}
});
app.post('/api/admin/payroll/month/unlock',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    const actor=(await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId])).rows[0];
    if(!actor||actor.role!=='admin')return res.status(403).json({error:'僅公司管理員可以解除封帳'});
    const month=String(req.body?.month||'');if(!/^\d{4}-\d{2}$/.test(month))return res.status(400).json({error:'月份格式不正確'});
    const reason=String(req.body?.reason||'').trim().slice(0,500);if(!reason)return res.status(400).json({error:'解除封帳必須填寫原因'});
    await client.query('BEGIN');const period=await ensurePayrollPeriod(client,req.auth.companyId,month,{refreshCurrent:false});
    if(period.preActivation){await client.query('ROLLBACK');return res.status(409).json({error:`${period.activationDate||''} 為系統正式啟用日，啟用前月份不納入薪資月結`});}
    if(!period.locked){await client.query('ROLLBACK');return res.json({ok:true,monthState:await payrollPeriodSummary(client,req.auth.companyId,month,period)});}
    const at=now(),who=actor.name||actor.username;
    await client.query('UPDATE payroll_month_periods SET locked=FALSE,unlocked_at=$1,unlocked_by=$2,updated_at=$1 WHERE company_id=$3 AND month=$4',[at,who,req.auth.companyId,month]);
    await client.query('INSERT INTO payroll_month_events(company_id,month,action,actor,detail,created_at) VALUES($1,$2,$3,$4,$5,$6)',[req.auth.companyId,month,'unlock',who,reason,at]);
    await client.query('COMMIT');res.json({ok:true,monthState:await payrollPeriodSummary(client,req.auth.companyId,month)});
  }catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}
});

app.post('/api/admin/payroll/unsettle',auth,requireActiveCompany,async(req,res,next)=>{const client=await pool.connect();try{
  const month=String(req.body?.month||''),employeeId=String(req.body?.employeeId||''),reason=String(req.body?.reason||'').trim();
  if(!/^\d{4}-\d{2}$/.test(month)||!employeeId)return res.status(400).json({error:'月份或人員資料不正確'});if(!reason)return res.status(400).json({error:'請填寫撤銷結算原因'});
  const actor=(await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId])).rows[0];if(!actor||!hasPermission(actor,'peopleManage'))return res.status(403).json({error:'你的帳號沒有薪資管理權限'});
  await client.query('BEGIN');const period=await ensurePayrollPeriod(client,req.auth.companyId,month,{refreshCurrent:false});if(period.locked){await client.query('ROLLBACK');return res.status(409).json({error:'此月份已封帳，請先解除封帳再撤銷結算'});}
  const emp=(await client.query('SELECT id,name,branch_id FROM users WHERE id=$1 AND company_id=$2',[employeeId,req.auth.companyId])).rows[0];if(!emp){await client.query('ROLLBACK');return res.status(404).json({error:'找不到人員'});}if(actor.role!=='admin'&&String(emp.branch_id||'')!==String(actor.branch_id||'')){await client.query('ROLLBACK');return res.status(403).json({error:'只能處理自己分店的人員'});}
  const old=(await client.query('DELETE FROM payroll_settlements WHERE company_id=$1 AND employee_id=$2 AND month=$3 RETURNING total_cost',[req.auth.companyId,employeeId,month])).rows[0];if(!old){await client.query('ROLLBACK');return res.status(404).json({error:'此人員目前沒有已結算資料'});}
  const who=actor.name||actor.username||req.auth.sub,detail=`撤銷 ${emp.name} 薪資結算；原已結算成本 NT$ ${Number(old.total_cost||0).toLocaleString()}；原因：${reason}`;
  await client.query('INSERT INTO payroll_month_events(company_id,month,action,actor,detail,created_at) VALUES($1,$2,$3,$4,$5,$6)',[req.auth.companyId,month,'unsettle',who,detail,now()]);await client.query('COMMIT');res.json({ok:true,monthState:await payrollPeriodSummary(client,req.auth.companyId,month)});
}catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}});

app.post('/api/admin/payroll/settle',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    const actor=(await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId])).rows[0];
    if(!actor||(actor.role!=='admin'&&!hasPermission(actor,'peopleManage')))return res.status(403).json({error:'沒有薪資結算權限'});
    const employeeId=String(req.body?.employeeId||''),month=String(req.body?.month||today().slice(0,7));
    if(!/^\d{4}-\d{2}$/.test(month))return res.status(400).json({error:'月份格式不正確'});
    const period=await ensurePayrollPeriod(client,req.auth.companyId,month,{refreshCurrent:true,addEmployeeId:employeeId});
    if(period.preActivation)return res.status(409).json({error:`${period.activationDate||''} 為系統正式啟用日，啟用前月份不納入薪資結算`});
    if(period.locked)return res.status(409).json({error:'此月份已封帳，如需修改請先由公司管理員解除封帳'});
    const emp=(await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[employeeId,req.auth.companyId])).rows[0];
    if(!emp)return res.status(404).json({error:'找不到員工'});
    if(actor.role!=='admin'&&String(emp.branch_id||'')!==String(actor.branch_id||''))return res.status(403).json({error:'只能結算自己分店的人員'});
    const snap=await getSnapshot(req.auth.companyId);const d=snap.snapshot||{};
    const commission=(Array.isArray(d.cars)?d.cars:[]).filter(c=>c.status==='已售'&&String(c.salesId||'')===employeeId&&String(c.outDate||'').slice(0,7)===month).reduce((a,c)=>a+Number(c.commissionAmount||0),0);
    const salaryType=['fixed','base_plus_commission','commission_only'].includes(String(emp.salary_type||''))?String(emp.salary_type):'fixed';
    const baseSalary=salaryType==='commission_only'?0:Math.max(0,Number(req.body?.baseSalary??emp.base_salary??0));
    const commissionCost=salaryType==='fixed'?0:Math.max(0,commission);
    const allowance=Math.max(0,Number(req.body?.allowance||0)),overtime=Math.max(0,Number(req.body?.overtime||0)),deductions=Math.max(0,Number(req.body?.deductions||0));
    const totalCost=Math.max(0,baseSalary+commissionCost+allowance+overtime-deductions),id=`pay_${req.auth.companyId}_${employeeId}_${month}`;
    const settledAt=now(),note=String(req.body?.note||'').slice(0,500);
    await client.query(`INSERT INTO payroll_settlements(id,company_id,employee_id,branch_id,month,base_salary,commission,allowance,overtime,deductions,total_cost,status,settled_at,settled_by,note)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'confirmed',$12,$13,$14)
      ON CONFLICT(company_id,employee_id,month) DO UPDATE SET branch_id=excluded.branch_id,base_salary=excluded.base_salary,commission=excluded.commission,allowance=excluded.allowance,overtime=excluded.overtime,deductions=excluded.deductions,total_cost=excluded.total_cost,status='confirmed',settled_at=excluded.settled_at,settled_by=excluded.settled_by,note=excluded.note`,
      [id,req.auth.companyId,employeeId,emp.branch_id||null,month,baseSalary,commissionCost,allowance,overtime,deductions,totalCost,settledAt,actor.name||actor.username,note]);
    res.json({ok:true,settlement:{id,employeeId,employeeName:emp.name,branchId:emp.branch_id||'',month,baseSalary,commission:commissionCost,allowance,overtime,deductions,totalCost,status:'confirmed',settledAt,settledBy:actor.name||actor.username,note}});
  }catch(e){next(e)}finally{client.release()}
});

// -------------------- Super Admin cloud API --------------------
app.post('/api/super/login',loginGuard('super'),(req,res)=>{
  const {username,password}=req.body||{};
  if(username!==SUPER_ADMIN_USER||password!==SUPER_ADMIN_PASSWORD)return res.status(401).json({error:'Super Admin 帳號或密碼錯誤'});
  res.json({token:signSuper(),user:{username:SUPER_ADMIN_USER,role:'platformAdmin'}});
});

app.get('/api/update/desktop-manifest',async(req,res,next)=>{
  try{
    const policy=await getDesktopUpdatePolicy();
    const payload={v:1,product:'used-car-dealer-desktop',enabled:policy.enabled,channel:policy.channel,latestVersion:policy.latestVersion,minimumVersion:policy.minimumVersion,downloadUrl:policy.downloadUrl,releaseNotes:policy.releaseNotes,packageSha256:policy.packageSha256,packageSignature:policy.packageSignature,issuedAt:now(),policyUpdatedAt:policy.updatedAt};
    res.json(signUpdateManifestPayload(payload));
  }catch(e){next(e)}
});
app.get('/api/super/update-policy',superAuth,async(req,res,next)=>{
  try{res.json({policy:await getDesktopUpdatePolicy(),keyId:UPDATE_SIGNING_KEY_ID});}catch(e){next(e)}
});
app.patch('/api/super/update-policy',superAuth,async(req,res,next)=>{
  try{
    const old=await getDesktopUpdatePolicy(),b=req.body||{};
    const latest=cleanSemver(b.latestVersion===undefined?old.latestVersion:b.latestVersion);
    const minimum=cleanSemver(b.minimumVersion===undefined?old.minimumVersion:b.minimumVersion);
    if(compareSemver(minimum,latest)>0)return res.status(400).json({error:'最低允許版本不能高於最新版本'});
    const channel=String(b.channel===undefined?old.channel:b.channel||'stable').trim().slice(0,30)||'stable';
    const downloadUrl=String(b.downloadUrl===undefined?old.downloadUrl:b.downloadUrl||'').trim().slice(0,2000);
    const releaseNotes=String(b.releaseNotes===undefined?old.releaseNotes:b.releaseNotes||'').slice(0,12000);
    const packageSha256=String(b.packageSha256===undefined?old.packageSha256:b.packageSha256||'').trim().toLowerCase();
    if(packageSha256 && !/^[a-f0-9]{64}$/.test(packageSha256))return res.status(400).json({error:'SHA-256 必須是 64 位十六進位字串'});
    const packageSignature=packageSha256?crypto.sign(null,Buffer.from(packageSha256),UPDATE_SIGNING_PRIVATE_KEY).toString('base64url'):'';
    await pool.query(`UPDATE desktop_update_policy SET enabled=$1,channel=$2,latest_version=$3,minimum_version=$4,download_url=$5,release_notes=$6,package_sha256=$7,package_signature=$8,updated_at=$9,updated_by=$10 WHERE id=1`,
      [b.enabled===undefined?old.enabled:!!b.enabled,channel,latest,minimum,downloadUrl,releaseNotes,packageSha256,packageSignature,now(),SUPER_ADMIN_USER]);
    res.json({ok:true,policy:await getDesktopUpdatePolicy()});
  }catch(e){next(e)}
});

function loadTestAuth(req,res,next){
  if(!LOAD_TEST_ENABLED)return res.status(404).json({error:'Load test endpoint disabled'});
  if(!LOAD_TEST_TOKEN||LOAD_TEST_TOKEN.length<16)return res.status(503).json({error:'LOAD_TEST_TOKEN not configured'});
  const supplied=String(req.headers['x-loadtest-token']||req.headers.authorization||'').replace(/^Bearer\s+/i,'');
  const a=Buffer.from(supplied),b=Buffer.from(LOAD_TEST_TOKEN);
  if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return res.status(401).json({error:'Invalid load-test token'});
  const sec=Math.floor(Date.now()/1000);if(sec!==loadTestWindowSecond){loadTestWindowSecond=sec;loadTestWindowCount=0}
  if(++loadTestWindowCount>LOAD_TEST_MAX_RPS)return res.status(429).json({error:'Load-test server safety RPS limit reached',limit:LOAD_TEST_MAX_RPS});
  next();
}

app.post('/api/load-test/run/start',loadTestAuth,async(req,res,next)=>{
  try{
    const b=req.body||{},runId=String(b.runId||`lt_${crypto.randomUUID()}`).slice(0,100);
    const targetNodes=Math.max(1,Math.min(100000,Number(b.targetNodes||10000)));
    const durationSeconds=Math.max(1,Math.min(86400,Number(b.durationSeconds||60)));
    const heartbeatIntervalMs=Math.max(1000,Math.min(300000,Number(b.heartbeatIntervalMs||15000)));
    const concurrency=Math.max(1,Math.min(5000,Number(b.concurrency||200)));
    await pool.query('DELETE FROM load_test_nodes WHERE last_seen_at < $1',[new Date(Date.now()-24*3600*1000).toISOString()]);
    await pool.query(`INSERT INTO load_test_runs(run_id,started_at,status,target_nodes,duration_seconds,heartbeat_interval_ms,concurrency,detail)
      VALUES($1,$2,'running',$3,$4,$5,$6,$7::jsonb)
      ON CONFLICT(run_id) DO UPDATE SET started_at=EXCLUDED.started_at,completed_at=NULL,status='running',target_nodes=EXCLUDED.target_nodes,duration_seconds=EXCLUDED.duration_seconds,heartbeat_interval_ms=EXCLUDED.heartbeat_interval_ms,concurrency=EXCLUDED.concurrency,total_requests=0,success_count=0,error_count=0,rps=0,p50_ms=0,p95_ms=0,p99_ms=0,max_ms=0,detail=EXCLUDED.detail`,
      [runId,now(),targetNodes,durationSeconds,heartbeatIntervalMs,concurrency,JSON.stringify({source:'phase8a-simulator',serverInstance:CENTRAL_HA_INSTANCE_ID})]);
    res.json({ok:true,runId,serverTime:now(),maxRps:LOAD_TEST_MAX_RPS});
  }catch(e){next(e)}
});

app.post('/api/load-test/heartbeat',loadTestAuth,async(req,res,next)=>{
  const started=process.hrtime.bigint();
  try{
    const b=req.body||{},runId=String(b.runId||'').slice(0,100),nodeId=String(b.nodeId||'').slice(0,120),virtualCompanyId=String(b.companyId||'').slice(0,120);
    if(!runId||!nodeId||!virtualCompanyId)return res.status(400).json({error:'runId/nodeId/companyId required'});
    const seq=Math.max(0,Number(b.seq||0)),appVersion=String(b.appVersion||'0.10.7').slice(0,40),payloadBytes=Math.max(0,Math.min(1000000,Number(b.payloadBytes||0)));
    await pool.query(`INSERT INTO load_test_nodes(node_id,run_id,virtual_company_id,app_version,last_seq,payload_bytes,last_seen_at)
      VALUES($1,$2,$3,$4,$5,$6,$7)
      ON CONFLICT(node_id) DO UPDATE SET run_id=EXCLUDED.run_id,virtual_company_id=EXCLUDED.virtual_company_id,app_version=EXCLUDED.app_version,last_seq=EXCLUDED.last_seq,payload_bytes=EXCLUDED.payload_bytes,last_seen_at=EXCLUDED.last_seen_at`,
      [nodeId,runId,virtualCompanyId,appVersion,seq,payloadBytes,now()]);
    const ms=Number(process.hrtime.bigint()-started)/1e6;
    res.json({ok:true,serverTime:now(),dbMs:Number(ms.toFixed(3))});
  }catch(e){next(e)}
});


function analyzeLoadTestRun(row){
  const targetNodes=Math.max(0,Number(row.target_nodes||row.targetNodes||0));
  const intervalMs=Math.max(1000,Number(row.heartbeat_interval_ms||row.heartbeatIntervalMs||15000));
  const expectedRps=targetNodes/(intervalMs/1000);
  const actualRps=Math.max(0,Number(row.rps||0));
  const total=Math.max(0,Number(row.total_requests||row.totalRequests||0));
  const errors=Math.max(0,Number(row.error_count||row.errorCount||0));
  const errorRate=total?errors/total:1;
  const p95=Math.max(0,Number(row.p95_ms||row.p95Ms||0));
  const p99=Math.max(0,Number(row.p99_ms||row.p99Ms||0));
  const throughputRatio=expectedRps>0?actualRps/expectedRps:0;
  let score=100;
  if(errorRate>0.05)score-=55; else if(errorRate>0.01)score-=35; else if(errorRate>0.001)score-=18; else if(errorRate>0)score-=8;
  if(throughputRatio<0.75)score-=35; else if(throughputRatio<0.9)score-=20; else if(throughputRatio<0.98)score-=8;
  if(p99>3000)score-=30; else if(p99>1500)score-=20; else if(p99>800)score-=12; else if(p99>400)score-=5;
  if(p95>1000)score-=12; else if(p95>500)score-=6;
  score=Math.max(0,Math.min(100,Math.round(score)));
  let bottleneck='none',summary='目前測試範圍內未看到明顯瓶頸';
  if(errorRate>=0.01){bottleneck='errors';summary='錯誤率偏高，先檢查 Server / PostgreSQL 錯誤與連線上限';}
  else if(throughputRatio<0.9){bottleneck='throughput';summary='實際吞吐低於理論目標，可能受 CPU、DB connections 或網路限制';}
  else if(p99>800||p95>500){bottleneck='latency';summary='尾端延遲偏高，優先檢查 PostgreSQL 查詢、connection pool 與 CPU';}
  const sustainableRps=Math.max(0,actualRps*(errorRate===0?0.85:errorRate<0.001?0.75:0.6));
  const estimatedNodes=Math.max(0,Math.floor(sustainableRps*(intervalMs/1000)));
  const grade=score>=90?'A':score>=80?'B':score>=65?'C':score>=50?'D':'F';
  const recommendedNodes=score>=80?Math.max(targetNodes,estimatedNodes):Math.min(targetNodes,estimatedNodes);
  return {score,grade,bottleneck,summary,errorRate,expectedRps,actualRps,throughputRatio,p95Ms:p95,p99Ms:p99,sustainableRps,estimatedNodes,recommendedNodes,heartbeatIntervalMs:intervalMs};
}

async function persistLoadTestAnalysis(runId){
  const q=await pool.query('SELECT * FROM load_test_runs WHERE run_id=$1',[runId]);
  if(!q.rows[0])return null;
  const a=analyzeLoadTestRun(q.rows[0]);
  await pool.query('UPDATE load_test_runs SET capacity_score=$1,estimated_nodes=$2,bottleneck=$3,analysis=$4::jsonb WHERE run_id=$5',[a.score,a.estimatedNodes,a.bottleneck,JSON.stringify(a),runId]);
  return a;
}

app.post('/api/load-test/run/finish',loadTestAuth,async(req,res,next)=>{
  try{
    const b=req.body||{},runId=String(b.runId||'').slice(0,100);if(!runId)return res.status(400).json({error:'runId required'});
    const nums=k=>Math.max(0,Number(b[k]||0));
    const detail=sanitizeDiagnosticContext(b.detail||{});
    await pool.query(`UPDATE load_test_runs SET completed_at=$1,status=$2,total_requests=$3,success_count=$4,error_count=$5,rps=$6,p50_ms=$7,p95_ms=$8,p99_ms=$9,max_ms=$10,detail=COALESCE(detail,'{}'::jsonb)||$11::jsonb WHERE run_id=$12`,
      [now(),String(b.status||'completed').slice(0,30),nums('totalRequests'),nums('successCount'),nums('errorCount'),nums('rps'),nums('p50Ms'),nums('p95Ms'),nums('p99Ms'),nums('maxMs'),JSON.stringify(detail),runId]);
    const active=Number((await pool.query('SELECT COUNT(*)::int AS n FROM load_test_nodes WHERE run_id=$1',[runId])).rows[0]?.n||0);
    const analysis=await persistLoadTestAnalysis(runId);
    res.json({ok:true,runId,virtualNodesSeen:active,analysis});
  }catch(e){next(e)}
});


async function runManagedLoadTest({runId,targetNodes,durationSeconds,heartbeatIntervalMs}){
  const rt=managedLoadTest;
  const latencies=[]; const startedMs=Date.now(); let seq=0;
  // 250 ms pacing keeps the load smooth instead of creating a single burst every 15 seconds.
  const tickMs=250; let carry=0;
  try{
    while(!rt.stopRequested && Date.now()-startedMs < durationSeconds*1000){
      const tickStart=Date.now();
      carry += targetNodes * tickMs / heartbeatIntervalMs;
      let batch=Math.floor(carry); carry-=batch;
      // Extra safety: never schedule more synthetic heartbeats per second than LOAD_TEST_MAX_RPS.
      batch=Math.min(batch,Math.max(1,Math.floor(LOAD_TEST_MAX_RPS*tickMs/1000)));
      const jobs=[];
      for(let i=0;i<batch;i++){
        const n=(seq++%targetNodes)+1;
        jobs.push((async()=>{
          const t0=process.hrtime.bigint();
          try{
            await pool.query(`INSERT INTO load_test_nodes(node_id,run_id,virtual_company_id,app_version,last_seq,payload_bytes,last_seen_at)
              VALUES($1,$2,$3,$4,$5,$6,$7)
              ON CONFLICT(node_id) DO UPDATE SET run_id=EXCLUDED.run_id,virtual_company_id=EXCLUDED.virtual_company_id,app_version=EXCLUDED.app_version,last_seq=EXCLUDED.last_seq,payload_bytes=EXCLUDED.payload_bytes,last_seen_at=EXCLUDED.last_seen_at`,
              [`managed_${runId}_${n}`,runId,`managed_company_${n}`,'0.10.7',seq,512,now()]);
            rt.successCount++;
          }catch(e){rt.errorCount++;rt.lastError=String(e?.message||e).slice(0,500)}
          finally{const ms=Number(process.hrtime.bigint()-t0)/1e6;latencies.push(ms);if(latencies.length>200000)latencies.splice(0,latencies.length-100000);rt.totalRequests++;}
        })());
      }
      await Promise.all(jobs);
      const elapsed=Math.max(.001,(Date.now()-startedMs)/1000);rt.currentRps=rt.totalRequests/elapsed;
      rt.p95Ms=percentile(latencies,.95);rt.p99Ms=percentile(latencies,.99);
      const wait=Math.max(0,tickMs-(Date.now()-tickStart)); if(wait)await new Promise(r=>setTimeout(r,wait));
    }
    const elapsed=Math.max(.001,(Date.now()-startedMs)/1000);
    const status=rt.stopRequested?'completed-stopped':'completed';
    const p50=percentile(latencies,.50),p95=percentile(latencies,.95),p99=percentile(latencies,.99),mx=latencies.reduce((m,v)=>v>m?v:m,0);
    await pool.query(`UPDATE load_test_runs SET completed_at=$1,status=$2,total_requests=$3,success_count=$4,error_count=$5,rps=$6,p50_ms=$7,p95_ms=$8,p99_ms=$9,max_ms=$10,detail=COALESCE(detail,'{}'::jsonb)||$11::jsonb WHERE run_id=$12`,
      [now(),status,rt.totalRequests,rt.successCount,rt.errorCount,rt.totalRequests/elapsed,p50,p95,p99,mx,JSON.stringify({source:'super-admin-managed',stopped:rt.stopRequested,lastError:rt.lastError||''}),runId]);
    await persistLoadTestAnalysis(runId);
  }catch(e){
    rt.lastError=String(e?.message||e).slice(0,1000);
    try{await pool.query(`UPDATE load_test_runs SET completed_at=$1,status='failed',total_requests=$2,success_count=$3,error_count=$4,detail=COALESCE(detail,'{}'::jsonb)||$5::jsonb WHERE run_id=$6`,[now(),rt.totalRequests,rt.successCount,rt.errorCount+1,JSON.stringify({source:'super-admin-managed',error:rt.lastError}),runId])}catch{}
  }finally{
    rt.running=false;rt.completedAt=now();rt.currentRps=0;
  }
}

app.post('/api/super/load-tests/start',superAuth,async(req,res,next)=>{
  try{
    if(managedLoadTest.running)return res.status(409).json({error:'目前已有壓力測試正在執行。'});
    const b=req.body||{};
    const allowedNodes=[100,1000,5000,10000],allowedDurations=[30,60,300];
    const targetNodes=Number(b.targetNodes||100),durationSeconds=Number(b.durationSeconds||30),heartbeatIntervalMs=15000;
    if(!allowedNodes.includes(targetNodes))return res.status(400).json({error:'測試節點只允許 100 / 1,000 / 5,000 / 10,000。'});
    if(!allowedDurations.includes(durationSeconds))return res.status(400).json({error:'測試時間只允許 30 / 60 / 300 秒。'});
    const expectedRps=targetNodes/(heartbeatIntervalMs/1000);
    if(expectedRps>LOAD_TEST_MAX_RPS)return res.status(400).json({error:`此測試理論 ${expectedRps.toFixed(1)} RPS，超過 Server 安全上限 ${LOAD_TEST_MAX_RPS} RPS。`});
    const runId=`ui_${crypto.randomUUID()}`;
    await pool.query('DELETE FROM load_test_nodes WHERE last_seen_at < $1',[new Date(Date.now()-24*3600*1000).toISOString()]);
    await pool.query(`INSERT INTO load_test_runs(run_id,started_at,status,target_nodes,duration_seconds,heartbeat_interval_ms,concurrency,detail) VALUES($1,$2,'running',$3,$4,$5,$6,$7::jsonb)`,[runId,now(),targetNodes,durationSeconds,heartbeatIntervalMs,Math.min(targetNodes,500),JSON.stringify({source:'super-admin-managed',actor:req.user?.username||SUPER_ADMIN_USER,warningConfirmed:true,serverInstance:CENTRAL_HA_INSTANCE_ID})]);
    managedLoadTest={running:true,stopRequested:false,runId,targetNodes,durationSeconds,heartbeatIntervalMs,startedAt:now(),completedAt:null,totalRequests:0,successCount:0,errorCount:0,currentRps:0,p95Ms:0,p99Ms:0,lastError:''};
    void runManagedLoadTest({runId,targetNodes,durationSeconds,heartbeatIntervalMs});
    res.json({ok:true,runId,targetNodes,durationSeconds,expectedRps,maxRps:LOAD_TEST_MAX_RPS});
  }catch(e){next(e)}
});

app.post('/api/super/load-tests/stop',superAuth,async(req,res,next)=>{
  try{
    if(!managedLoadTest.running)return res.status(409).json({error:'目前沒有正在執行的壓力測試。'});
    managedLoadTest.stopRequested=true;
    res.json({ok:true,runId:managedLoadTest.runId,message:'已送出停止要求，系統會在目前批次完成後停止。'});
  }catch(e){next(e)}
});

app.get('/api/super/load-tests',superAuth,async(req,res,next)=>{
  try{
    const {rows}=await pool.query('SELECT * FROM load_test_runs ORDER BY started_at DESC LIMIT 50');
    const active=Number((await pool.query("SELECT COUNT(*)::int AS n FROM load_test_nodes WHERE last_seen_at >= $1",[new Date(Date.now()-60000).toISOString()])).rows[0]?.n||0);
    const completed=rows.filter(r=>String(r.status||'').startsWith('completed'));
    const analyzed=completed.map(r=>{const a=(r.analysis&&Object.keys(r.analysis).length)?r.analysis:analyzeLoadTestRun(r);return {...r,analysis:a,capacity_score:Number(r.capacity_score||a.score||0),estimated_nodes:Number(r.estimated_nodes||a.estimatedNodes||0),bottleneck:r.bottleneck||a.bottleneck};});
    const best=analyzed.slice().sort((a,b)=>Number(b.estimated_nodes||0)-Number(a.estimated_nodes||0))[0]||null;
    const latest=analyzed[0]||null;
    const capacity={latest:latest?latest.analysis:null,best:best?best.analysis:null,bestRunId:best?.run_id||'',testedMaxNodes:analyzed.reduce((m,r)=>Math.max(m,Number(r.target_nodes||0)),0),recommendation:!analyzed.length?'尚無測試資料':(best?.analysis?.score>=80?`目前證據支持約 ${Number(best.analysis.recommendedNodes||0).toLocaleString()} 個節點等級；正式容量仍應保留至少 20% 餘裕。`:'目前測試尚未達到穩定商用門檻，先處理瓶頸再提高節點數。')};
    res.json({managedReady:true,maxRps:LOAD_TEST_MAX_RPS,activeVirtualNodes:active,runs:analyzed,capacity,managed:{...managedLoadTest,expectedRps:managedLoadTest.targetNodes?managedLoadTest.targetNodes/(managedLoadTest.heartbeatIntervalMs/1000):0}});
  }catch(e){next(e)}
});

app.get('/api/super/companies',superAuth,async(req,res,next)=>{
  try{
    const {rows}=await pool.query(`
      SELECT c.*,
        (SELECT u.username FROM users u WHERE u.company_id=c.id AND u.role='admin' AND u.enabled=TRUE ORDER BY u.updated_at ASC LIMIT 1) AS main_username
      FROM companies c ORDER BY c.created_at DESC
    `);
    res.json({companies:rows.map(companyDto)});
  }catch(e){ next(e); }
});


// Dealer Node heartbeat: the desktop identifies itself as the dealership's local data node.
// Phase 3: after a v5.3 Local-first node proves its local SQLite exists, the cloud snapshot is reduced to an operational shadow.
app.post('/api/node/heartbeat',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    if(req.auth.role!=='admin')return res.status(403).json({error:'僅車行管理端可註冊節點'});
    const b=req.body||{};
    const nodeId=String(b.nodeId||'').trim();
    if(!nodeId)return res.status(400).json({error:'缺少 nodeId'});
    await pool.query(`INSERT INTO dealer_nodes(company_id,node_id,device_name,app_version,last_seen_at,local_data_bytes,capabilities)
      VALUES($1,$2,$3,$4,$5,$6,$7::jsonb)
      ON CONFLICT(company_id) DO UPDATE SET node_id=EXCLUDED.node_id,device_name=EXCLUDED.device_name,app_version=EXCLUDED.app_version,last_seen_at=EXCLUDED.last_seen_at,local_data_bytes=EXCLUDED.local_data_bytes,capabilities=EXCLUDED.capabilities`,
      [req.auth.companyId,nodeId,String(b.deviceName||''),String(b.appVersion||''),now(),Math.max(0,Number(b.localDataBytes||0)),JSON.stringify({...b.capabilities,online:true})]);
    let localFirstActivated=false;
    if(b.capabilities?.localFirst===true && Number(b.localDataBytes||0)>0){
      const sr=await pool.query('SELECT json FROM snapshots WHERE company_id=$1',[req.auth.companyId]);
      if(sr.rows[0]){
        const reduced=cloudOperationalSnapshot(sr.rows[0].json||{});
        await pool.query('UPDATE snapshots SET json=$1::jsonb,updated_at=$2 WHERE company_id=$3',[JSON.stringify(reduced),now(),req.auth.companyId]);
        localFirstActivated=true;
      }
    }
    const salesUsers=(await pool.query("SELECT id,company_id,username,password_hash,name,role,commission_rate,base_salary,enabled,token_version,branch_id FROM users WHERE company_id=$1 AND role='sales' AND enabled=TRUE ORDER BY updated_at ASC",[req.auth.companyId])).rows;
    const offlineTest=(await pool.query('SELECT * FROM offline_license_tests WHERE company_id=$1',[req.auth.companyId])).rows[0];
    const lanSeconds=offlineTest?.enabled?Number(offlineTest.duration_seconds||60):OFFLINE_GRACE_SECONDS;
    const companyRow=await getCompany(req.auth.companyId);
    const salesLanAuthBundle=offlineTest?.enabled&&offlineTest?.simulate_outage?null:issueSalesLanAuthBundle(companyRow,salesUsers,lanSeconds);
    const updatePolicy=await getDesktopUpdatePolicy();
    res.json({ok:true,nodeId,serverTime:now(),localFirstActivated,salesLanAuthBundle,lanAuthExpiresInSeconds:salesLanAuthBundle?Math.max(5,Math.min(lanSeconds,OFFLINE_GRACE_SECONDS)):0,updatePolicy:{enabled:updatePolicy.enabled,latestVersion:updatePolicy.latestVersion,minimumVersion:updatePolicy.minimumVersion,channel:updatePolicy.channel}});
  }catch(e){next(e)}
});

// Dealer Node explicit offline signal.
app.post('/api/node/offline',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    if(req.auth.role!=='admin')return res.status(403).json({error:'僅車行管理端可變更節點狀態'});
    const nodeId=String(req.body?.nodeId||'').trim();
    if(!nodeId)return res.status(400).json({error:'缺少 nodeId'});
    const offlineAt=now();
    const r=await pool.query(`UPDATE dealer_nodes SET last_seen_at=$1, capabilities=COALESCE(capabilities,'{}'::jsonb) || '{\"online\":false}'::jsonb WHERE company_id=$2 AND node_id=$3 RETURNING company_id,node_id`,[offlineAt,req.auth.companyId,nodeId]);
    await pool.query(`UPDATE dealer_node_requests SET status='failed',error_text='Dealer Node 已登出或離線',completed_at=$1 WHERE company_id=$2 AND node_id=$3 AND status IN ('queued','claimed')`,[now(),req.auth.companyId,nodeId]);
    recordSyncEvent(req.auth.companyId,'node_offline','車行主機已離線',{actor:req.auth.username||req.auth.sub,status:'warn'});
    res.json({ok:true,offline:true,nodeId,updated:r.rowCount>0});
  }catch(e){next(e)}
});

app.get('/api/super/nodes',superAuth,async(req,res,next)=>{
  try{const {rows}=await pool.query('SELECT * FROM dealer_nodes ORDER BY last_seen_at DESC');res.json({nodes:rows});}catch(e){next(e)}
});

// Phase 2: Super Admin requests data from a live Dealer Node only when it is viewed.
// The desktop polls for commands over its authenticated outbound connection; no inbound port is exposed.
const NODE_RESOURCES=new Set(['companyData','fullCompanyData','vehicleDetail','vehiclePhoto','vehiclePhotoBundle','salesInventory','backupStatus','createBackup']);
function nodeOnline(row,maxAgeMs=45000){
  if(row?.capabilities?.online===false)return false;
  const t=Date.parse(row?.last_seen_at||'');
  return Number.isFinite(t)&&(Date.now()-t)<=maxAgeMs;
}
async function cleanupNodeRequests(){
  try{await pool.query("DELETE FROM dealer_node_requests WHERE expires_at < $1 OR (completed_at IS NOT NULL AND completed_at < $2)",[now(),new Date(Date.now()-5*60*1000).toISOString()]);}catch{}
}

app.post('/api/super/nodes/:companyId/request',superAuth,async(req,res,next)=>{
  try{
    await cleanupNodeRequests();
    const companyId=String(req.params.companyId||'');
    const resource=String(req.body?.resource||'');
    const payload=(req.body?.payload&&typeof req.body.payload==='object')?req.body.payload:{};
    if(!NODE_RESOURCES.has(resource))return res.status(400).json({error:'不支援的 Node 資料類型'});
    const {rows}=await pool.query('SELECT * FROM dealer_nodes WHERE company_id=$1',[companyId]);
    const n=rows[0];
    if(!n)return res.status(409).json({error:'此車行尚未建立 Dealer Node'});
    if(!nodeOnline(n))return res.status(409).json({error:'Dealer Node 目前離線，無法即時讀取'});
    const id=`nreq_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`;
    const requestedAt=now(),expiresAt=new Date(Date.now()+60000).toISOString();
    await pool.query(`INSERT INTO dealer_node_requests(id,company_id,node_id,resource,payload,status,requested_at,expires_at)
      VALUES($1,$2,$3,$4,$5::jsonb,'queued',$6,$7)`,[id,companyId,n.node_id,resource,JSON.stringify(payload),requestedAt,expiresAt]);
    res.json({ok:true,requestId:id,nodeId:n.node_id,status:'queued',expiresAt});
  }catch(e){next(e)}
});


// Phase 14D.1: Super Admin live remote data center metadata. Access is allowed only while the dealership Dealer Node is online.
// The detailed local snapshot itself is relayed on-demand through fullCompanyData and is not persisted as a second permanent copy here.
app.get('/api/super/companies/:id/data-center',superAuth,async(req,res,next)=>{
  try{
    const companyId=String(req.params.id||'').trim();
    const c=await getCompany(companyId);
    if(!c)return res.status(404).json({error:'找不到此車行'});
    const node=(await pool.query('SELECT * FROM dealer_nodes WHERE company_id=$1',[companyId])).rows[0];
    if(!node||!nodeOnline(node))return res.status(409).json({error:'Dealer Node 目前離線，無法開啟線上資料中心'});
    const [branches,users,payroll,periods,payrollEvents,staffEvents,transfers,costRules,costEntries,settingEvents]=await Promise.all([
      pool.query('SELECT id,company_id,code,name,is_head_office,enabled,address,phone,sale_approval_mode,sale_approver_user_id,created_at,updated_at FROM branches WHERE company_id=$1 ORDER BY is_head_office DESC,created_at ASC',[companyId]),
      pool.query(`SELECT id,company_id,username,name,role,commission_rate,base_salary,enabled,updated_at,branch_id,position,salary_type,login_enabled,permissions FROM users WHERE company_id=$1 ORDER BY enabled DESC,updated_at DESC`,[companyId]),
      pool.query('SELECT * FROM payroll_settlements WHERE company_id=$1 ORDER BY month DESC,settled_at DESC LIMIT 3000',[companyId]),
      pool.query('SELECT * FROM payroll_month_periods WHERE company_id=$1 ORDER BY month DESC LIMIT 240',[companyId]),
      pool.query('SELECT * FROM payroll_month_events WHERE company_id=$1 ORDER BY id DESC LIMIT 3000',[companyId]),
      pool.query('SELECT * FROM staff_change_events WHERE company_id=$1 ORDER BY id DESC LIMIT 3000',[companyId]),
      pool.query('SELECT * FROM vehicle_transfers WHERE company_id=$1 ORDER BY requested_at DESC LIMIT 3000',[companyId]),
      pool.query('SELECT * FROM operating_cost_rules WHERE company_id=$1 ORDER BY enabled DESC,created_at DESC LIMIT 3000',[companyId]),
      pool.query('SELECT * FROM operating_cost_entries WHERE company_id=$1 ORDER BY expense_date DESC,created_at DESC LIMIT 5000',[companyId]),
      pool.query('SELECT * FROM company_setting_events WHERE company_id=$1 ORDER BY id DESC LIMIT 3000',[companyId])
    ]);
    await recordSuperDataCenterAccess(req,c,'success');
    res.json({ok:true,company:companyDto(c),node:{nodeId:node.node_id,deviceName:node.device_name,appVersion:node.app_version,lastSeenAt:node.last_seen_at},branches:branches.rows,users:users.rows,payroll:payroll.rows,payrollPeriods:periods.rows,payrollEvents:payrollEvents.rows,staffEvents:staffEvents.rows,transfers:transfers.rows,costRules:costRules.rows,costEntries:costEntries.rows,settingEvents:settingEvents.rows,generatedAt:now()});
  }catch(e){next(e)}
});


// Super Admin data-center access-log controls. Default second-layer password is 1234 and should be changed after deployment.
app.post('/api/super/data-center-audit/unlock',superAuth,async(req,res,next)=>{try{
  const st=await ensureSuperDataCenterSettings(),password=String(req.body?.password||'');
  const got=Buffer.from(dcPasswordHash(password,st.password_salt),'hex'),want=Buffer.from(String(st.password_hash||''),'hex');
  if(got.length!==want.length||!crypto.timingSafeEqual(got,want))return res.status(403).json({error:'資料中心紀錄密碼錯誤'});
  await cleanupSuperDataCenterAccessLogs();res.json({ok:true,token:signDataCenterAuditToken(req),expiresInSeconds:1200});
}catch(e){next(e)}});

app.get('/api/super/data-center-audit/settings',superAuth,dataCenterAuditAuth,async(req,res,next)=>{try{
  const st=await ensureSuperDataCenterSettings();await cleanupSuperDataCenterAccessLogs();res.json({retentionValue:Number(st.retention_value||24),retentionUnit:String(st.retention_unit||'hour'),retentionForever:!!st.retention_forever,updatedAt:st.updated_at,updatedBy:st.updated_by});
}catch(e){next(e)}});

app.patch('/api/super/data-center-audit/settings',superAuth,dataCenterAuditAuth,async(req,res,next)=>{try{
  const forever=!!req.body?.retentionForever,unit=String(req.body?.retentionUnit||'hour'),value=Math.floor(Number(req.body?.retentionValue||1));
  if(!['minute','hour','day','month'].includes(unit))return res.status(400).json({error:'保存時間單位不正確'});
  if(!forever&&(!Number.isFinite(value)||value<1||value>1000000))return res.status(400).json({error:'保存時間請輸入 1～1,000,000'});
  await ensureSuperDataCenterSettings();await pool.query('UPDATE super_data_center_settings SET retention_value=$1,retention_unit=$2,retention_forever=$3,updated_at=$4,updated_by=$5 WHERE id=1',[Math.max(1,value||1),unit,forever,now(),String(req.auth.username||req.auth.sub||'platform-admin')]);
  const cleanup=await cleanupSuperDataCenterAccessLogs();res.json({ok:true,cleanup});
}catch(e){next(e)}});

app.post('/api/super/data-center-audit/change-password',superAuth,dataCenterAuditAuth,async(req,res,next)=>{try{
  const st=await ensureSuperDataCenterSettings(),currentPassword=String(req.body?.currentPassword||''),newPassword=String(req.body?.newPassword||''),confirmPassword=String(req.body?.confirmPassword||'');
  if(newPassword!==confirmPassword)return res.status(400).json({error:'兩次新密碼不一致'});if(newPassword.length<4)return res.status(400).json({error:'新密碼至少 4 碼'});
  const got=Buffer.from(dcPasswordHash(currentPassword,st.password_salt),'hex'),want=Buffer.from(String(st.password_hash||''),'hex');if(got.length!==want.length||!crypto.timingSafeEqual(got,want))return res.status(403).json({error:'原密碼錯誤'});
  const salt=crypto.randomBytes(18).toString('hex'),hash=dcPasswordHash(newPassword,salt);await pool.query('UPDATE super_data_center_settings SET password_salt=$1,password_hash=$2,updated_at=$3,updated_by=$4 WHERE id=1',[salt,hash,now(),String(req.auth.username||req.auth.sub||'platform-admin')]);res.json({ok:true});
}catch(e){next(e)}});

app.get('/api/super/data-center-audit/logs',superAuth,dataCenterAuditAuth,async(req,res,next)=>{try{
  await cleanupSuperDataCenterAccessLogs();const page=Math.max(1,Number(req.query.page||1)),pageSize=Math.max(10,Math.min(50,Number(req.query.pageSize||10))),offset=(page-1)*pageSize,q=String(req.query.q||'').trim().toLowerCase();
  const params=[],where=[];if(q){params.push(`%${q}%`);where.push(`(LOWER(company_name) LIKE $${params.length} OR LOWER(company_id) LIKE $${params.length} OR LOWER(actor) LIKE $${params.length})`)}const ws=where.length?'WHERE '+where.join(' AND '):'';
  const total=Number((await pool.query(`SELECT COUNT(*)::int AS n FROM super_data_center_access_logs ${ws}`,params)).rows[0]?.n||0);params.push(pageSize,offset);const rows=(await pool.query(`SELECT id,actor,company_id,company_name,status,created_at FROM super_data_center_access_logs ${ws} ORDER BY id DESC LIMIT $${params.length-1} OFFSET $${params.length}`,params)).rows;
  res.json({rows,page,pageSize,total,totalPages:Math.max(1,Math.ceil(total/pageSize))});
}catch(e){next(e)}});

app.get('/api/super/node-requests/:id',superAuth,async(req,res,next)=>{
  try{
    const {rows}=await pool.query('SELECT * FROM dealer_node_requests WHERE id=$1',[req.params.id]);
    const r=rows[0];
    if(!r)return res.status(404).json({error:'Node 請求不存在或已結束'});
    if(Date.parse(r.expires_at)<Date.now() && !['completed','failed'].includes(r.status)){
      await pool.query("UPDATE dealer_node_requests SET status='expired',error_text='Node request timeout' WHERE id=$1",[r.id]);
      return res.json({requestId:r.id,status:'expired',error:'Dealer Node 回應逾時'});
    }
    if(r.status==='completed'){
      const result=r.result_json;
      // Result is a relay payload, not permanent business storage. Consume and erase it after Super Admin receives it.
      await pool.query('DELETE FROM dealer_node_requests WHERE id=$1',[r.id]);
      return res.json({requestId:r.id,status:'completed',resource:r.resource,result,completedAt:r.completed_at});
    }
    if(r.status==='failed'){
      const err=r.error_text||'Dealer Node 讀取失敗';
      await pool.query('DELETE FROM dealer_node_requests WHERE id=$1',[r.id]);
      return res.json({requestId:r.id,status:'failed',error:err});
    }
    res.json({requestId:r.id,status:r.status,resource:r.resource,requestedAt:r.requested_at,claimedAt:r.claimed_at,expiresAt:r.expires_at});
  }catch(e){next(e)}
});


// Sales-safe on-demand photo relay: Sales can read only photos of in-stock cars in their own company.
// Sales automatic photo strip: one Node command returns up to 8 photos for one in-stock vehicle.
app.post('/api/sales/node-photos/request',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    await cleanupNodeRequests();
    if(req.auth.role!=='sales')return res.status(403).json({error:'僅業務帳號可使用此入口'});
    const carId=String(req.body?.carId||'').trim();
    if(!carId)return res.status(400).json({error:'缺少車輛資料'});
    const snapRow=(await pool.query('SELECT json FROM snapshots WHERE company_id=$1',[req.auth.companyId])).rows[0];
    const snap=snapRow?.json||{};
    const car=(Array.isArray(snap.cars)?snap.cars:[]).find(c=>String(c?.id)===carId && c?.status==='在庫');
    if(!car)return res.status(404).json({error:'找不到可供業務查看的在庫車輛'});
    const me=(await pool.query('SELECT branch_id FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId])).rows[0];
    if(!me?.branch_id||String(car.branchId||'')!==String(me.branch_id))return res.status(403).json({error:'業務只能查看自己分店的車輛照片'});
    const n=(await pool.query('SELECT * FROM dealer_nodes WHERE company_id=$1',[req.auth.companyId])).rows[0];
    if(!n||!nodeOnline(n))return res.status(409).json({error:'車行主機目前離線，暫時無法讀取照片'});
    const id=`sphotos_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
    const requestedAt=now(),expiresAt=new Date(Date.now()+60000).toISOString();
    const payload={carId,max:8,requesterSalesId:String(req.auth.sub),requesterBranchId:String(me.branch_id)};
    await pool.query(`INSERT INTO dealer_node_requests(id,company_id,node_id,resource,payload,status,requested_at,expires_at)
      VALUES($1,$2,$3,'vehiclePhotoBundle',$4::jsonb,'queued',$5,$6)`,
      [id,req.auth.companyId,n.node_id,JSON.stringify(payload),requestedAt,expiresAt]);
    res.json({ok:true,requestId:id,status:'queued',expiresAt});
  }catch(e){next(e)}
});

app.get('/api/sales/node-photo-bundles/:id',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    if(req.auth.role!=='sales')return res.status(403).json({error:'僅業務帳號可使用此入口'});
    const {rows}=await pool.query('SELECT * FROM dealer_node_requests WHERE id=$1 AND company_id=$2',[req.params.id,req.auth.companyId]);
    const r=rows[0];
    if(!r||r.resource!=='vehiclePhotoBundle'||String(r.payload?.requesterSalesId||'')!==String(req.auth.sub))return res.status(404).json({error:'照片請求不存在'});
    if(Date.parse(r.expires_at)<Date.now()&&!['completed','failed'].includes(r.status)){
      await pool.query("UPDATE dealer_node_requests SET status='expired',error_text='Node request timeout' WHERE id=$1",[r.id]);
      return res.json({requestId:r.id,status:'expired',error:'車行主機回應逾時'});
    }
    if(r.status==='completed'){const result=r.result_json;await pool.query('DELETE FROM dealer_node_requests WHERE id=$1',[r.id]);return res.json({requestId:r.id,status:'completed',result});}
    if(r.status==='failed'){const err=r.error_text||'車行主機讀取照片失敗';await pool.query('DELETE FROM dealer_node_requests WHERE id=$1',[r.id]);return res.json({requestId:r.id,status:'failed',error:err});}
    res.json({requestId:r.id,status:r.status,expiresAt:r.expires_at});
  }catch(e){next(e)}
});

app.post('/api/sales/node-photo/request',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    await cleanupNodeRequests();
    if(req.auth.role!=='sales')return res.status(403).json({error:'僅業務帳號可使用此入口'});
    const carId=String(req.body?.carId||'').trim();
    const kind=req.body?.kind==='inspection'?'inspection':'intake';
    const index=Number(req.body?.index);
    if(!carId||!Number.isInteger(index)||index<0)return res.status(400).json({error:'照片參數不正確'});

    const snapRow=(await pool.query('SELECT json FROM snapshots WHERE company_id=$1',[req.auth.companyId])).rows[0];
    const snap=snapRow?.json||{};
    const car=(Array.isArray(snap.cars)?snap.cars:[]).find(c=>String(c?.id)===carId && c?.status==='在庫');
    if(!car)return res.status(404).json({error:'找不到可供業務查看的在庫車輛'});
    const me=(await pool.query('SELECT branch_id FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId])).rows[0];
    if(!me?.branch_id||String(car.branchId||'')!==String(me.branch_id))return res.status(403).json({error:'業務只能查看自己分店的車輛照片'});
    const count=kind==='inspection'?Number(car.inspectionPhotoCount||0):Number(car.intakePhotoCount||0);
    if(index>=count)return res.status(404).json({error:'此照片不存在'});

    const n=(await pool.query('SELECT * FROM dealer_nodes WHERE company_id=$1',[req.auth.companyId])).rows[0];
    if(!n||!nodeOnline(n))return res.status(409).json({error:'車行主機目前離線，暫時無法讀取照片'});

    const id=`sphoto_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
    const requestedAt=now(),expiresAt=new Date(Date.now()+60000).toISOString();
    const payload={carId,kind,index,requesterSalesId:String(req.auth.sub),requesterBranchId:String(me.branch_id)};
    await pool.query(`INSERT INTO dealer_node_requests(id,company_id,node_id,resource,payload,status,requested_at,expires_at)
      VALUES($1,$2,$3,'vehiclePhoto',$4::jsonb,'queued',$5,$6)`,
      [id,req.auth.companyId,n.node_id,JSON.stringify(payload),requestedAt,expiresAt]);
    res.json({ok:true,requestId:id,status:'queued',expiresAt});
  }catch(e){next(e)}
});

app.get('/api/sales/node-photo-requests/:id',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    if(req.auth.role!=='sales')return res.status(403).json({error:'僅業務帳號可使用此入口'});
    const {rows}=await pool.query('SELECT * FROM dealer_node_requests WHERE id=$1 AND company_id=$2',[req.params.id,req.auth.companyId]);
    const r=rows[0];
    if(!r||r.resource!=='vehiclePhoto'||String(r.payload?.requesterSalesId||'')!==String(req.auth.sub))
      return res.status(404).json({error:'照片請求不存在'});
    if(Date.parse(r.expires_at)<Date.now() && !['completed','failed'].includes(r.status)){
      await pool.query("UPDATE dealer_node_requests SET status='expired',error_text='Node request timeout' WHERE id=$1",[r.id]);
      return res.json({requestId:r.id,status:'expired',error:'車行主機回應逾時'});
    }
    if(r.status==='completed'){
      const result=r.result_json;
      await pool.query('DELETE FROM dealer_node_requests WHERE id=$1',[r.id]);
      return res.json({requestId:r.id,status:'completed',result});
    }
    if(r.status==='failed'){
      const err=r.error_text||'車行主機讀取照片失敗';
      await pool.query('DELETE FROM dealer_node_requests WHERE id=$1',[r.id]);
      return res.json({requestId:r.id,status:'failed',error:err});
    }
    res.json({requestId:r.id,status:r.status,expiresAt:r.expires_at});
  }catch(e){next(e)}
});


app.post('/api/sales/node-inventory/request',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    await cleanupNodeRequests();
    if(req.auth.role!=='sales')return res.status(403).json({error:'僅業務帳號可使用此入口'});
    const me=(await pool.query('SELECT branch_id FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId])).rows[0];
    if(!me?.branch_id)return res.status(403).json({error:'業務帳號尚未指定所屬分店'});
    const n=(await pool.query('SELECT * FROM dealer_nodes WHERE company_id=$1',[req.auth.companyId])).rows[0];
    if(!n||!nodeOnline(n))return res.status(409).json({error:'車行主機目前離線'});
    const id=`sinv_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
    const requestedAt=now(),expiresAt=new Date(Date.now()+60000).toISOString();
    const payload={requesterSalesId:String(req.auth.sub),requesterBranchId:String(me.branch_id)};
    await pool.query(`INSERT INTO dealer_node_requests(id,company_id,node_id,resource,payload,status,requested_at,expires_at)
      VALUES($1,$2,$3,'salesInventory',$4::jsonb,'queued',$5,$6)`,
      [id,req.auth.companyId,n.node_id,JSON.stringify(payload),requestedAt,expiresAt]);
    res.json({ok:true,requestId:id,status:'queued',expiresAt});
  }catch(e){next(e)}
});

app.get('/api/sales/node-inventory-requests/:id',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    if(req.auth.role!=='sales')return res.status(403).json({error:'僅業務帳號可使用此入口'});
    const {rows}=await pool.query('SELECT * FROM dealer_node_requests WHERE id=$1 AND company_id=$2',[req.params.id,req.auth.companyId]);
    const r=rows[0];
    if(!r||r.resource!=='salesInventory'||String(r.payload?.requesterSalesId||'')!==String(req.auth.sub))
      return res.status(404).json({error:'庫存請求不存在'});
    if(Date.parse(r.expires_at)<Date.now() && !['completed','failed'].includes(r.status)){
      await pool.query("UPDATE dealer_node_requests SET status='expired',error_text='Node request timeout' WHERE id=$1",[r.id]);
      return res.json({requestId:r.id,status:'expired',error:'車行主機回應逾時'});
    }
    if(r.status==='completed'){
      const result=r.result_json;
      await pool.query('DELETE FROM dealer_node_requests WHERE id=$1',[r.id]);
      return res.json({requestId:r.id,status:'completed',result});
    }
    if(r.status==='failed'){
      const err=r.error_text||'車行主機讀取庫存失敗';
      await pool.query('DELETE FROM dealer_node_requests WHERE id=$1',[r.id]);
      return res.json({requestId:r.id,status:'failed',error:err});
    }
    res.json({requestId:r.id,status:r.status,expiresAt:r.expires_at});
  }catch(e){next(e)}
});

app.get('/api/node/commands',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    if(req.auth.role!=='admin')return res.status(403).json({error:'僅車行管理端 Dealer Node 可接收命令'});
    const nodeId=String(req.query.nodeId||'').trim();
    if(!nodeId)return res.status(400).json({error:'缺少 nodeId'});
    const n=(await client.query('SELECT * FROM dealer_nodes WHERE company_id=$1',[req.auth.companyId])).rows[0];
    if(!n||n.node_id!==nodeId)return res.status(403).json({error:'Dealer Node 身分不符'});
    await client.query('BEGIN');
    await client.query("UPDATE dealer_node_requests SET status='expired',error_text='Node request timeout' WHERE company_id=$1 AND node_id=$2 AND status IN ('queued','claimed') AND expires_at < $3",[req.auth.companyId,nodeId,now()]);
    await client.query("UPDATE dealer_node_requests SET status='queued',claimed_at=NULL WHERE company_id=$1 AND node_id=$2 AND status='claimed' AND claimed_at < $3",[req.auth.companyId,nodeId,new Date(Date.now()-10000).toISOString()]);
    const q=await client.query(`SELECT * FROM dealer_node_requests
      WHERE company_id=$1 AND node_id=$2 AND status='queued' AND expires_at >= $3
      ORDER BY requested_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED`,[req.auth.companyId,nodeId,now()]);
    if(!q.rows[0]){await client.query('COMMIT');return res.json({command:null});}
    const r=q.rows[0];
    const claimedAt=now();
    await client.query("UPDATE dealer_node_requests SET status='claimed',claimed_at=$1 WHERE id=$2",[claimedAt,r.id]);
    await client.query('COMMIT');
    res.json({command:{id:r.id,resource:r.resource,payload:r.payload||{},requestedAt:r.requested_at,expiresAt:r.expires_at}});
  }catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}
});

app.post('/api/node/commands/:id/result',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    if(req.auth.role!=='admin')return res.status(403).json({error:'僅車行管理端 Dealer Node 可回傳資料'});
    const nodeId=String(req.body?.nodeId||'').trim();
    const ok=req.body?.ok!==false;
    const {rows}=await pool.query('SELECT * FROM dealer_node_requests WHERE id=$1 AND company_id=$2',[req.params.id,req.auth.companyId]);
    const r=rows[0];
    if(!r)return res.status(404).json({error:'Node 請求不存在'});
    if(r.node_id!==nodeId)return res.status(403).json({error:'Dealer Node 身分不符'});
    if(!['queued','claimed'].includes(r.status))return res.status(409).json({error:'Node 請求已處理'});
    if(ok){
      await pool.query("UPDATE dealer_node_requests SET status='completed',completed_at=$1,result_json=$2::jsonb,error_text=NULL WHERE id=$3",[now(),JSON.stringify(req.body?.result??null),r.id]);
    }else{
      const nodeError=String(req.body?.error||'Dealer Node 讀取失敗').slice(0,1000);
      await pool.query("UPDATE dealer_node_requests SET status='failed',completed_at=$1,error_text=$2,result_json=NULL WHERE id=$3",[now(),nodeError,r.id]);
      const isPhoto=String(r.resource||'').toLowerCase().includes('photo');
      await recordDiagnostic(req.auth.companyId,isPhoto?'PHOTO_FETCH_002':'NODE_COMMAND_001',isPhoto?'photo_fetch':'dealer_node',nodeError,{severity:'error',actor:req.auth.username||'',context:{resource:r.resource,requestId:r.id}});
    }
    res.json({ok:true});
  }catch(e){next(e)}
});


app.get('/api/super/companies/:id/offline-test',superAuth,async(req,res,next)=>{try{const r=(await pool.query('SELECT * FROM offline_license_tests WHERE company_id=$1',[req.params.id])).rows[0];res.json({enabled:!!r?.enabled,durationSeconds:Number(r?.duration_seconds||60),simulateOutage:!!r?.simulate_outage,updatedAt:r?.updated_at||null});}catch(e){next(e)}});
app.put('/api/super/companies/:id/offline-test',superAuth,async(req,res,next)=>{try{const b=req.body||{};const sec=Math.max(5,Math.min(259200,Number(b.durationSeconds||60)));await pool.query(`INSERT INTO offline_license_tests(company_id,enabled,duration_seconds,simulate_outage,updated_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(company_id) DO UPDATE SET enabled=excluded.enabled,duration_seconds=excluded.duration_seconds,simulate_outage=excluded.simulate_outage,updated_at=excluded.updated_at`,[req.params.id,!!b.enabled,sec,!!b.simulateOutage,now()]);res.json({ok:true,enabled:!!b.enabled,durationSeconds:sec,simulateOutage:!!b.simulateOutage});}catch(e){next(e)}});

app.get('/api/super/companies/:id/sync-events',superAuth,async(req,res,next)=>{
  try{
    const limit=Math.max(1,Math.min(200,Number(req.query.limit||100)));
    const {rows}=await pool.query('SELECT id,event_type,status,message,actor,operation_id,created_at FROM sync_events WHERE company_id=$1 ORDER BY id DESC LIMIT $2',[req.params.id,limit]);
    res.json({events:rows});
  }catch(e){next(e)}
});

app.post('/api/node/update-report',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    if(req.auth.role!=='admin')return res.status(403).json({error:'僅車行管理端可回報更新狀態'});
    const b=req.body||{},attemptId=String(b.attemptId||'').trim().slice(0,120);
    if(!attemptId)return res.status(400).json({error:'缺少更新識別碼'});
    const allowed=new Set(['download_started','install_launched','success','failed']);
    const status=allowed.has(String(b.status||''))?String(b.status):'failed';
    const detail=String(b.detail||'').slice(0,1000),ts=now();
    const completed=['success','failed'].includes(status)?ts:null;
    await pool.query(`INSERT INTO desktop_update_events(company_id,attempt_id,from_version,target_version,status,detail,started_at,updated_at,completed_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$7,$8)
      ON CONFLICT(company_id,attempt_id) DO UPDATE SET from_version=excluded.from_version,target_version=excluded.target_version,status=excluded.status,detail=excluded.detail,updated_at=excluded.updated_at,completed_at=COALESCE(excluded.completed_at,desktop_update_events.completed_at)`,
      [req.auth.companyId,attemptId,cleanSemver(b.fromVersion||'0.0.0'),cleanSemver(b.targetVersion||'0.0.0'),status,detail,ts,completed]);
    if(status==='failed')await recordDiagnostic(req.auth.companyId,'UPDATE_INSTALL_001','desktop_update',detail||'Desktop 更新失敗',{severity:'error',appVersion:b.fromVersion||'',actor:req.auth.username||'',context:{attemptId,targetVersion:b.targetVersion||''}});
    res.json({ok:true,status});
  }catch(e){next(e)}
});

app.get('/api/super/update-events',superAuth,async(req,res,next)=>{
  try{
    const limit=Math.max(1,Math.min(500,Number(req.query.limit||200)));
    const rows=(await pool.query(`SELECT e.*,c.name AS company_name FROM desktop_update_events e LEFT JOIN companies c ON c.id=e.company_id ORDER BY e.updated_at DESC LIMIT $1`,[limit])).rows;
    res.json({events:rows,generatedAt:now()});
  }catch(e){next(e)}
});

app.post('/api/node/diagnostics',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    if(req.auth.role!=='admin')return res.status(403).json({error:'僅車行管理端可回報診斷事件'});
    const b=req.body||{};
    await recordDiagnostic(req.auth.companyId,b.errorCode||'NODE_UNKNOWN',b.module||'dealer_node',b.message||'',{severity:b.severity||'error',appVersion:b.appVersion||'',actor:req.auth.username||'',context:b.context||{}});
    res.json({ok:true});
  }catch(e){next(e)}
});


const CENTRAL_BACKUP_TABLES=['companies','branches','users','snapshots','dealer_nodes','offline_license_tests','sync_events','dealer_node_requests','schema_migrations','migration_safety_events','diagnostic_events','desktop_update_policy','desktop_update_events','central_backup_policy','central_ha_events','load_test_runs','security_audit_events','idempotency_keys','release_control_events','subscription_plans','payment_providers','dealer_subscriptions','payment_transactions','payment_webhook_events','subscription_events','payment_renewal_attempts','dealer_notification_reads','dealer_renewal_requests','payroll_settlements','payroll_month_periods','payroll_month_events','company_setting_events','staff_change_events','vehicle_transfers','operating_cost_rules','operating_cost_entries','super_data_center_settings'];
let centralBackupRunning=false;
function backupKeyBytes(){return crypto.createHash('sha256').update(String(BACKUP_ENCRYPTION_KEY)).digest()}
function backupStorageStatus(){return {localDir:POSTGRES_BACKUP_DIR,encryption:'AES-256-GCM',productionKeyConfigured:!BACKUP_ENCRYPTION_KEY.startsWith('DEV_ONLY_'),s3Configured:!!BACKUP_S3_BUCKET,s3Bucket:BACKUP_S3_BUCKET||'',s3Region:BACKUP_S3_REGION,s3Endpoint:BACKUP_S3_ENDPOINT||'',s3Prefix:BACKUP_S3_PREFIX}}
async function getCentralBackupPolicy(client=pool){
  const {rows}=await client.query('SELECT * FROM central_backup_policy WHERE id=1');const p=rows[0]||{};
  return {enabled:!!p.enabled,dailyHourTaipei:Math.max(0,Math.min(23,Number(p.daily_hour_taipei??3))),retentionDays:Math.max(1,Math.min(365,Number(p.retention_days||14))),offsiteEnabled:!!p.offsite_enabled,updatedAt:p.updated_at||'',updatedBy:p.updated_by||''};
}
function encryptBackupBuffer(plain){const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',backupKeyBytes(),iv);const enc=Buffer.concat([cipher.update(plain),cipher.final()]),tag=cipher.getAuthTag();const header=Buffer.from(JSON.stringify({format:'CDBAK',version:1,compression:'gzip',encryption:'AES-256-GCM',iv:iv.toString('base64'),tag:tag.toString('base64')})+'\n');return Buffer.concat([Buffer.from('CDBAK1\n'),header,enc])}
function makeS3(){const cfg={region:BACKUP_S3_REGION,forcePathStyle:BACKUP_S3_FORCE_PATH_STYLE};if(BACKUP_S3_ENDPOINT)cfg.endpoint=BACKUP_S3_ENDPOINT;if(BACKUP_S3_ACCESS_KEY_ID&&BACKUP_S3_SECRET_ACCESS_KEY)cfg.credentials={accessKeyId:BACKUP_S3_ACCESS_KEY_ID,secretAccessKey:BACKUP_S3_SECRET_ACCESS_KEY};return new S3Client(cfg)}
async function pruneLocalBackups(retentionDays){try{const files=await fs.readdir(POSTGRES_BACKUP_DIR,{withFileTypes:true});const cutoff=Date.now()-retentionDays*86400000;for(const f of files){if(!f.isFile()||!f.name.endsWith('.cdbak'))continue;const full=path.join(POSTGRES_BACKUP_DIR,f.name),st=await fs.stat(full);if(st.mtimeMs<cutoff)await fs.unlink(full)}}catch(e){console.warn('backup local retention:',e?.message||e)}}
async function uploadOffsiteBackup(fileBuffer,fileName,retentionDays){if(!BACKUP_S3_BUCKET)throw new Error('尚未設定 BACKUP_S3_BUCKET');const s3=makeS3(),key=`${BACKUP_S3_PREFIX}/${fileName}`;await s3.send(new PutObjectCommand({Bucket:BACKUP_S3_BUCKET,Key:key,Body:fileBuffer,ContentType:'application/octet-stream',Metadata:{encrypted:'aes-256-gcm'}}));try{const listed=await s3.send(new ListObjectsV2Command({Bucket:BACKUP_S3_BUCKET,Prefix:`${BACKUP_S3_PREFIX}/`}));const cutoff=Date.now()-retentionDays*86400000,old=(listed.Contents||[]).filter(x=>x.Key&&x.LastModified&&x.LastModified.getTime()<cutoff).map(x=>({Key:x.Key}));if(old.length)await s3.send(new DeleteObjectsCommand({Bucket:BACKUP_S3_BUCKET,Delete:{Objects:old,Quiet:true}}))}catch(e){console.warn('backup s3 retention:',e?.message||e)}return key}
async function createCentralBackup(triggerType='manual',actor='system'){
  if(centralBackupRunning)throw new Error('中央備份正在執行中');centralBackupRunning=true;
  const backupId=crypto.randomUUID(),started=now();let eventCreated=false,lockClient=null,hasDbLock=false;
  try{
    lockClient=await pool.connect();const lock=(await lockClient.query('SELECT pg_try_advisory_lock(73919001) AS locked')).rows[0];hasDbLock=!!lock?.locked;if(!hasDbLock)throw Object.assign(new Error('另一個 Server Instance 正在執行中央備份'),{skipDiagnostic:true});
    await pool.query(`INSERT INTO central_backup_events(backup_id,trigger_type,status,started_at,created_by) VALUES($1,$2,'running',$3,$4)`,[backupId,triggerType,started,String(actor||'').slice(0,80)]);eventCreated=true;
    const policy=await getCentralBackupPolicy(),client=await pool.connect();let data={};
    try{await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');for(const table of CENTRAL_BACKUP_TABLES){const {rows}=await client.query(`SELECT * FROM ${table}`);data[table]=rows}await client.query('COMMIT')}catch(e){try{await client.query('ROLLBACK')}catch{}throw e}finally{client.release()}
    const rowCount=Object.values(data).reduce((n,a)=>n+(Array.isArray(a)?a.length:0),0);const schema=await getServerSchemaStatus();
    const payload={format:'car-dealer-central-logical-backup',formatVersion:1,createdAt:now(),serverVersion:'14.9.10',apiVersion:'6.9.10',schemaVersion:schema.currentVersion,tables:data};
    const compressed=gzipSync(Buffer.from(JSON.stringify(payload))),encrypted=encryptBackupBuffer(compressed);const hash=crypto.createHash('sha256').update(encrypted).digest('hex');
    await fs.mkdir(POSTGRES_BACKUP_DIR,{recursive:true});const stamp=new Date().toISOString().replace(/[:.]/g,'-'),fileName=`central-${stamp}-${backupId.slice(0,8)}.cdbak`,localPath=path.join(POSTGRES_BACKUP_DIR,fileName);await fs.writeFile(localPath,encrypted,{mode:0o600});
    let offsiteStatus='disabled',offsiteKey='',offsiteProvider='';
    if(policy.offsiteEnabled){offsiteProvider='s3';try{offsiteKey=await uploadOffsiteBackup(encrypted,fileName,policy.retentionDays);offsiteStatus='uploaded'}catch(e){offsiteStatus='failed';await recordDiagnostic('','BACKUP_OFFSITE_002','central_backup',e?.message||'異地備份上傳失敗',{severity:'error',actor,context:{backupId}})}}
    await pruneLocalBackups(policy.retentionDays);
    const finalStatus=policy.offsiteEnabled&&offsiteStatus==='failed'?'partial':'success';
    await pool.query(`UPDATE central_backup_events SET status=$1,completed_at=$2,size_bytes=$3,sha256=$4,local_path=$5,offsite_provider=$6,offsite_key=$7,offsite_status=$8,table_count=$9,row_count=$10 WHERE backup_id=$11`,[finalStatus,now(),encrypted.length,hash,localPath,offsiteProvider,offsiteKey,offsiteStatus,CENTRAL_BACKUP_TABLES.length,rowCount,backupId]);
    let verificationStatus='verified';try{await verifyCentralBackup(backupId,actor)}catch{verificationStatus='failed'}
    return {ok:true,backupId,status:finalStatus,verificationStatus,sizeBytes:encrypted.length,sha256:hash,offsiteStatus,offsiteKey,tableCount:CENTRAL_BACKUP_TABLES.length,rowCount};
  }catch(e){if(eventCreated)try{await pool.query(`UPDATE central_backup_events SET status='failed',completed_at=$1,error_text=$2 WHERE backup_id=$3`,[now(),String(e?.message||e).slice(0,2000),backupId])}catch{};if(!e?.skipDiagnostic)await recordDiagnostic('','BACKUP_CREATE_001','central_backup',e?.message||'中央備份失敗',{severity:'error',actor,context:{backupId}});throw e}finally{if(lockClient){if(hasDbLock)try{await lockClient.query('SELECT pg_advisory_unlock(73919001)')}catch{};lockClient.release()}centralBackupRunning=false}
}

const CENTRAL_RESTORE_TABLES=['companies','branches','users','snapshots','dealer_nodes','offline_license_tests','sync_events','dealer_node_requests','diagnostic_events','desktop_update_policy','desktop_update_events','central_backup_policy','central_ha_events','load_test_runs','security_audit_events','idempotency_keys','release_control_events','subscription_plans','payment_providers','dealer_subscriptions','payment_transactions','payment_webhook_events','subscription_events','payment_renewal_attempts','dealer_notification_reads','dealer_renewal_requests','payroll_settlements','payroll_month_periods','payroll_month_events','company_setting_events','staff_change_events','vehicle_transfers','operating_cost_rules','operating_cost_entries','super_data_center_settings'];
function qIdent(v){return '"'+String(v).replaceAll('"','""')+'"'}
function decryptBackupBuffer(buf){
  const magic=Buffer.from('CDBAK1\n');if(!Buffer.isBuffer(buf)||buf.length<magic.length+10||!buf.subarray(0,magic.length).equals(magic))throw new Error('備份格式錯誤');
  const rest=buf.subarray(magic.length),nl=rest.indexOf(10);if(nl<1)throw new Error('備份標頭損壞');
  const h=JSON.parse(rest.subarray(0,nl).toString('utf8'));if(h.format!=='CDBAK'||h.version!==1||h.encryption!=='AES-256-GCM')throw new Error('不支援的備份格式');
  const decipher=crypto.createDecipheriv('aes-256-gcm',backupKeyBytes(),Buffer.from(h.iv,'base64'));decipher.setAuthTag(Buffer.from(h.tag,'base64'));
  const compressed=Buffer.concat([decipher.update(rest.subarray(nl+1)),decipher.final()]);return gunzipSync(compressed);
}
async function loadBackupPayload(backupId){
  const {rows}=await pool.query('SELECT * FROM central_backup_events WHERE backup_id=$1',[backupId]);const ev=rows[0];if(!ev)throw new Error('找不到此備份紀錄');if(!ev.local_path)throw new Error('此備份沒有本機檔案');
  const encrypted=await fs.readFile(ev.local_path);const hash=crypto.createHash('sha256').update(encrypted).digest('hex');if(ev.sha256&&hash!==ev.sha256)throw new Error('SHA-256 不一致，備份檔可能已損壞');
  const payload=JSON.parse(decryptBackupBuffer(encrypted).toString('utf8'));return {ev,payload,hash,sizeBytes:encrypted.length};
}
function validateBackupPayload(payload){
  if(!payload||payload.format!=='car-dealer-central-logical-backup'||payload.formatVersion!==1)throw new Error('備份內容格式不正確');
  if(!payload.tables||typeof payload.tables!=='object')throw new Error('備份缺少資料表內容');
  for(const t of CENTRAL_RESTORE_TABLES)if(!Array.isArray(payload.tables[t]))throw new Error(`備份缺少必要資料表：${t}`);
  return {schemaVersion:Number(payload.schemaVersion||0),tableCount:Object.keys(payload.tables).length,rowCount:Object.values(payload.tables).reduce((n,a)=>n+(Array.isArray(a)?a.length:0),0),createdAt:payload.createdAt||''};
}
async function verifyCentralBackup(backupId,actor=SUPER_ADMIN_USER){
  try{const {payload,hash,sizeBytes}=await loadBackupPayload(backupId),v=validateBackupPayload(payload),schema=await getServerSchemaStatus();if(v.schemaVersion!==schema.currentVersion)throw new Error(`Schema 不相容：備份 v${v.schemaVersion} / 目前 v${schema.currentVersion}`);await pool.query("UPDATE central_backup_events SET verification_status='verified',verified_at=$1,verification_error='' WHERE backup_id=$2",[now(),backupId]);return {ok:true,backupId,sha256:hash,sizeBytes,...v};}
  catch(e){await pool.query("UPDATE central_backup_events SET verification_status='failed',verified_at=$1,verification_error=$2 WHERE backup_id=$3",[now(),String(e?.message||e).slice(0,2000),backupId]).catch(()=>{});await recordDiagnostic('','BACKUP_VERIFY_003','central_backup',e?.message||'備份驗證失敗',{severity:'error',actor,context:{backupId}});throw e}
}
async function insertRows(client,table,rows){for(const row of rows){const cols=Object.keys(row);if(!cols.length)continue;const vals=cols.map(c=>row[c]);await client.query(`INSERT INTO ${qIdent(table)} (${cols.map(qIdent).join(',')}) VALUES (${cols.map((_,i)=>'$'+(i+1)).join(',')})`,vals)}}
async function drillCentralBackup(backupId,actor=SUPER_ADMIN_USER){
  const restoreId=crypto.randomUUID();await pool.query("INSERT INTO central_restore_events(restore_id,backup_id,mode,status,started_at,actor) VALUES($1,$2,'drill','running',$3,$4)",[restoreId,backupId,now(),actor]);
  const client=await pool.connect();try{const {payload}=await loadBackupPayload(backupId),v=validateBackupPayload(payload),schema=await getServerSchemaStatus();if(v.schemaVersion!==schema.currentVersion)throw new Error(`Schema 不相容：備份 v${v.schemaVersion} / 目前 v${schema.currentVersion}`);await client.query('BEGIN');for(const t of CENTRAL_RESTORE_TABLES){const temp=`drill_${t}_${restoreId.replaceAll('-','').slice(0,8)}`;await client.query(`CREATE TEMP TABLE ${qIdent(temp)} (LIKE ${qIdent(t)} INCLUDING DEFAULTS) ON COMMIT DROP`);await insertRows(client,temp,payload.tables[t]);const c=Number((await client.query(`SELECT COUNT(*)::bigint AS n FROM ${qIdent(temp)}`)).rows[0].n);if(c!==payload.tables[t].length)throw new Error(`演練筆數不一致：${t}`)}await client.query('ROLLBACK');await pool.query("UPDATE central_backup_events SET drill_status='passed',drill_at=$1,drill_error='' WHERE backup_id=$2",[now(),backupId]);await pool.query("UPDATE central_restore_events SET status='success',completed_at=$1,detail=$2 WHERE restore_id=$3",[now(),`驗證 ${v.tableCount} tables / ${v.rowCount} rows`,restoreId]);return {ok:true,restoreId,backupId,...v};}
  catch(e){try{await client.query('ROLLBACK')}catch{};await pool.query("UPDATE central_backup_events SET drill_status='failed',drill_at=$1,drill_error=$2 WHERE backup_id=$3",[now(),String(e?.message||e).slice(0,2000),backupId]).catch(()=>{});await pool.query("UPDATE central_restore_events SET status='failed',completed_at=$1,error_text=$2 WHERE restore_id=$3",[now(),String(e?.message||e).slice(0,2000),restoreId]).catch(()=>{});await recordDiagnostic('','BACKUP_DRILL_004','central_backup',e?.message||'復原演練失敗',{severity:'error',actor,context:{backupId,restoreId}});throw e}finally{client.release()}
}
async function restoreCentralBackup(backupId,actor=SUPER_ADMIN_USER){
  const verified=await verifyCentralBackup(backupId,actor);const safety=await createCentralBackup('pre_restore_safety',actor);await verifyCentralBackup(safety.backupId,actor);
  const restoreId=crypto.randomUUID();await pool.query("INSERT INTO central_restore_events(restore_id,backup_id,safety_backup_id,mode,status,started_at,actor) VALUES($1,$2,$3,'restore','running',$4,$5)",[restoreId,backupId,safety.backupId,now(),actor]);
  const {payload}=await loadBackupPayload(backupId),client=await pool.connect();try{await client.query('BEGIN');for(const t of [...CENTRAL_RESTORE_TABLES].reverse())await client.query(`DELETE FROM ${qIdent(t)}`);for(const t of CENTRAL_RESTORE_TABLES){await insertRows(client,t,payload.tables[t]);try{const seq=(await client.query(`SELECT pg_get_serial_sequence($1,'id') AS s`,[t])).rows[0]?.s;if(seq){const mx=Number((await client.query(`SELECT COALESCE(MAX(id),0) AS m FROM ${qIdent(t)}`)).rows[0]?.m||0);if(mx>0)await client.query('SELECT setval($1,$2,true)',[seq,mx])}}catch{}}await client.query('COMMIT');await pool.query("UPDATE central_restore_events SET status='success',completed_at=$1,detail=$2 WHERE restore_id=$3",[now(),`Safety backup: ${safety.backupId}`,restoreId]);return {ok:true,restoreId,backupId,safetyBackupId:safety.backupId,verified};}
  catch(e){try{await client.query('ROLLBACK')}catch{};await pool.query("UPDATE central_restore_events SET status='failed',completed_at=$1,error_text=$2 WHERE restore_id=$3",[now(),String(e?.message||e).slice(0,2000),restoreId]).catch(()=>{});await recordDiagnostic('','BACKUP_RESTORE_005','central_backup',e?.message||'正式復原失敗',{severity:'critical',actor,context:{backupId,restoreId,safetyBackupId:safety.backupId}});throw e}finally{client.release()}
}
async function centralBackupSummary(){const policy=await getCentralBackupPolicy(),events=(await pool.query('SELECT * FROM central_backup_events ORDER BY id DESC LIMIT 100')).rows,restoreEvents=(await pool.query('SELECT * FROM central_restore_events ORDER BY id DESC LIMIT 50')).rows,last=events[0]||null,lastSuccess=events.find(x=>x.status==='success'||x.status==='partial')||null;return {policy,events,restoreEvents,last,lastSuccess,running:centralBackupRunning,storage:backupStorageStatus(),generatedAt:now()}}
async function maybeRunScheduledCentralBackup(){try{const policy=await getCentralBackupPolicy();if(!policy.enabled||centralBackupRunning)return;const d=new Date(),parts=new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Taipei',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',hourCycle:'h23'}).formatToParts(d),get=t=>parts.find(x=>x.type===t)?.value||'';if(Number(get('hour'))!==policy.dailyHourTaipei)return;const day=`${get('year')}-${get('month')}-${get('day')}`,dayStart=new Date(`${day}T00:00:00+08:00`).toISOString();const {rows}=await pool.query("SELECT id FROM central_backup_events WHERE trigger_type='scheduled' AND started_at >= $1 AND status IN ('running','success','partial') LIMIT 1",[dayStart]);if(rows.length)return;await createCentralBackup('scheduled','scheduler')}catch(e){console.warn('scheduled central backup:',e?.message||e)}}

app.get('/api/super/backups',superAuth,async(req,res,next)=>{try{res.json(await centralBackupSummary())}catch(e){next(e)}});
app.patch('/api/super/backups/policy',superAuth,async(req,res,next)=>{try{const b=req.body||{},hour=Math.max(0,Math.min(23,Number(b.dailyHourTaipei??3))),days=Math.max(1,Math.min(365,Number(b.retentionDays||14)));await pool.query(`UPDATE central_backup_policy SET enabled=$1,daily_hour_taipei=$2,retention_days=$3,offsite_enabled=$4,updated_at=$5,updated_by=$6 WHERE id=1`,[!!b.enabled,hour,days,!!b.offsiteEnabled,now(),SUPER_ADMIN_USER]);res.json({ok:true,...await centralBackupSummary()})}catch(e){next(e)}});
app.post('/api/super/backups/run',superAuth,async(req,res,next)=>{try{const result=await createCentralBackup('manual',SUPER_ADMIN_USER);res.json(result)}catch(e){next(e)}});
app.post('/api/super/backups/:backupId/verify',superAuth,async(req,res,next)=>{try{res.json(await verifyCentralBackup(req.params.backupId,SUPER_ADMIN_USER))}catch(e){next(e)}});
app.post('/api/super/backups/:backupId/drill',superAuth,async(req,res,next)=>{try{res.json(await drillCentralBackup(req.params.backupId,SUPER_ADMIN_USER))}catch(e){next(e)}});
app.post('/api/super/backups/:backupId/restore',superAuth,async(req,res,next)=>{try{const phrase=String(req.body?.confirmPhrase||'');if(phrase!==`RESTORE ${req.params.backupId}`)return res.status(400).json({error:'復原確認文字不正確'});res.json(await restoreCentralBackup(req.params.backupId,SUPER_ADMIN_USER))}catch(e){next(e)}});


// Phase 9A: non-destructive commercial readiness / failure drill center.
// This intentionally verifies recovery evidence without stopping PostgreSQL, cutting network, or promoting a standby.
async function resilienceChecks(){
  const checks=[];
  const push=(key,title,status,summary,detail={})=>checks.push({key,title,status,summary,detail});
  try{
    const t0=process.hrtime.bigint();
    const q=await pool.query('SELECT NOW() AS now, pg_is_in_recovery() AS in_recovery');
    const ms=Number(process.hrtime.bigint()-t0)/1e6;
    push('postgres_roundtrip','PostgreSQL Round Trip（資料庫往返）',ms<1000?'pass':'warn',`查詢成功，往返 ${ms.toFixed(1)} ms。`,{latencyMs:ms,inRecovery:!!q.rows[0]?.in_recovery});
  }catch(e){push('postgres_roundtrip','PostgreSQL Round Trip（資料庫往返）','fail','資料庫查詢失敗。',{error:String(e?.message||e)})}

  try{
    const st=await refreshHaRuntime({allowMigration:false,recordTransition:false});
    const peer=await probeHaPeer();
    if(!CENTRAL_HA_ENABLED) push('ha_failover','HA Failover（主備切換準備）','warn','目前未啟用 CENTRAL_HA_ENABLED，尚未具備正式 Primary / Standby 切換條件。',{runtime:st,peer});
    else if(!peer.configured) push('ha_failover','HA Failover（主備切換準備）','warn','HA 已啟用，但尚未設定 Standby / Peer 健康檢查位置。',{runtime:st,peer});
    else if(!peer.ok) push('ha_failover','HA Failover（主備切換準備）','fail','Peer 健康檢查失敗，主機故障時可能無法確認備援端狀態。',{runtime:st,peer});
    else push('ha_failover','HA Failover（主備切換準備）','pass','HA 已啟用，而且 Peer /api/ready 可正常回應。',{runtime:st,peer});
  }catch(e){push('ha_failover','HA Failover（主備切換準備）','fail','HA 檢查失敗。',{error:String(e?.message||e)})}

  try{
    const b=(await pool.query("SELECT backup_id,started_at,verification_status,drill_status,status FROM central_backup_events WHERE status IN ('success','partial') ORDER BY id DESC LIMIT 1")).rows[0];
    if(!b) push('backup_restore','Backup / Restore Drill（備份復原演練）','fail','尚無成功的中央備份。');
    else if(b.verification_status!=='verified') push('backup_restore','Backup / Restore Drill（備份復原演練）','warn','最近備份尚未通過可復原驗證。',{backup:b});
    else if(b.drill_status!=='passed') push('backup_restore','Backup / Restore Drill（備份復原演練）','warn','最近備份已驗證，但尚未完成 Restore Drill（復原演練）。',{backup:b});
    else push('backup_restore','Backup / Restore Drill（備份復原演練）','pass','最近中央備份已驗證，且復原演練通過。',{backup:b});
  }catch(e){push('backup_restore','Backup / Restore Drill（備份復原演練）','fail','無法讀取備份演練紀錄。',{error:String(e?.message||e)})}

  try{
    const r=(await pool.query("SELECT run_id,target_nodes,capacity_score,estimated_nodes,p95_ms,error_count,total_requests,started_at,status FROM load_test_runs WHERE target_nodes>=10000 AND status IN ('completed','completed_with_errors') ORDER BY started_at DESC LIMIT 1")).rows[0];
    if(!r) push('reconnect_storm','10,000 Node Reconnect Evidence（萬節點重連證據）','warn','尚未找到 10,000 Node 等級壓力測試紀錄；正式商用前仍需做重連風暴演練。');
    else if(Number(r.capacity_score||0)<80) push('reconnect_storm','10,000 Node Reconnect Evidence（萬節點重連證據）','warn',`已有 10,000 Node 測試，但容量評分只有 ${Number(r.capacity_score||0)}。`,{run:r});
    else push('reconnect_storm','10,000 Node Reconnect Evidence（萬節點重連證據）','pass',`已找到 ${Number(r.target_nodes||0).toLocaleString()} Node 測試證據，容量評分 ${Number(r.capacity_score||0)}。`,{run:r});
  }catch(e){push('reconnect_storm','10,000 Node Reconnect Evidence（萬節點重連證據）','fail','無法讀取壓力測試證據。',{error:String(e?.message||e)})}

  try{
    const open=(await pool.query("SELECT COUNT(*)::int AS n FROM performance_alert_events WHERE status='open'")).rows[0]?.n||0;
    push('alert_pipeline','Alert Pipeline（異常警報鏈路）',Number(open)>0?'warn':'pass',Number(open)>0?`目前仍有 ${open} 個效能警報尚未恢復。`:'目前沒有未恢復的效能警報。',{openAlerts:Number(open)});
  }catch(e){push('alert_pipeline','Alert Pipeline（異常警報鏈路）','fail','無法讀取 Phase 8D 警報狀態。',{error:String(e?.message||e)})}

  const fail=checks.filter(x=>x.status==='fail').length,warn=checks.filter(x=>x.status==='warn').length,pass=checks.filter(x=>x.status==='pass').length;
  const overall=fail?'fail':warn?'warn':'pass';
  return {overall,pass,warn,fail,checks,generatedAt:now()};
}
async function runResilienceDrill(actor=SUPER_ADMIN_USER){
  const drillId=crypto.randomUUID(),started=now();
  await pool.query("INSERT INTO resilience_drill_events(drill_id,drill_type,status,title,summary,detail,started_at,actor) VALUES($1,'preflight','running',$2,'',$3::jsonb,$4,$5)",[drillId,'Phase 9A 商用前故障準備檢查','{}',started,actor]);
  try{
    const result=await resilienceChecks();
    const status=result.overall==='fail'?'failed':result.overall==='warn'?'warning':'passed';
    const summary=`通過 ${result.pass}｜注意 ${result.warn}｜失敗 ${result.fail}`;
    await pool.query('UPDATE resilience_drill_events SET status=$1,summary=$2,detail=$3::jsonb,completed_at=$4 WHERE drill_id=$5',[status,summary,JSON.stringify(result),now(),drillId]);
    if(result.fail) await recordDiagnostic('','RESILIENCE_PREFLIGHT_001','resilience_drill','商用前故障準備檢查存在失敗項目',{severity:'error',actor,context:{drillId,summary}});
    return {ok:result.fail===0,drillId,status,summary,...result};
  }catch(e){
    await pool.query("UPDATE resilience_drill_events SET status='failed',summary=$1,detail=$2::jsonb,completed_at=$3 WHERE drill_id=$4",[String(e?.message||e).slice(0,1000),JSON.stringify({error:String(e?.message||e)}),now(),drillId]).catch(()=>{});
    throw e;
  }
}
async function resilienceSummary(){
  const current=await resilienceChecks();
  const events=(await pool.query('SELECT * FROM resilience_drill_events ORDER BY id DESC LIMIT 50')).rows;
  const control=await controlledDrillCapabilities(); return {current,events,control,destructiveDrillsEnabled:true,note:'Phase 9B 已加入受控維護中斷、DB 重新連線、Backup/Restore、警報鏈路與 HA Peer 探測。真正的 PostgreSQL Promote 仍由基礎設施層負責，不由應用程式直接執行。',generatedAt:now()};
}
app.get('/api/super/resilience',superAuth,async(req,res,next)=>{try{res.json(await resilienceSummary())}catch(e){next(e)}});
app.post('/api/super/resilience/run',superAuth,async(req,res,next)=>{try{res.json(await runResilienceDrill(req.auth?.username||SUPER_ADMIN_USER))}catch(e){next(e)}});

// Phase 9C-9F API routes. These routes are consumed by the Super Admin resilience page.
app.get('/api/super/resilience/suite',superAuth,async(req,res,next)=>{
  try{
    const runs=await suiteRows();
    const active=[...resilienceJobs.values()].filter(x=>x&&x.status==='running').map(suitePublic);
    res.json({runs,active,generatedAt:now()});
  }catch(e){next(e)}
});

app.post('/api/super/resilience/suite/start',superAuth,async(req,res,next)=>{
  try{
    const raw=String(req.body?.phase||'').trim().toUpperCase();
    const m=raw.match(/^9?([C-F])$/);
    if(!m)return res.status(400).json({error:'Phase 只允許 9C / 9D / 9E / 9F。'});
    const phase=m[1],config=(req.body?.config&&typeof req.body.config==='object')?req.body.config:{};
    if(phase==='C'){
      const nodes=Number(config.nodes||1000);
      if(![100,1000,5000,10000].includes(nodes))return res.status(400).json({error:'9C Node 數量只允許 100 / 1000 / 5000 / 10000。'});
      config.nodes=nodes;
      config.jitterMs=Math.max(250,Math.min(30000,Number(config.jitterMs||10000)));
      config.concurrency=Math.max(10,Math.min(500,Number(config.concurrency||150)));
    }
    if(phase==='F'){
      const hours=Number(config.hours||1);
      if(![1,6,24,72].includes(hours))return res.status(400).json({error:'9F 時間只允許 1 / 6 / 24 / 72 小時。'});
      config.hours=hours;
    }
    const actor=req.auth?.username||SUPER_ADMIN_USER;
    const run=await launchSuite(phase,config,actor);
    res.status(202).json({ok:true,run});
  }catch(e){next(e)}
});


app.post('/api/super/resilience/suite/stop',superAuth,async(req,res,next)=>{
  try{
    const suiteId=String(req.body?.suiteId||'').trim();
    if(!suiteId)return res.status(400).json({error:'缺少測試 ID。'});
    const j=resilienceJobs.get(suiteId);
    if(!j)return res.status(404).json({error:'找不到正在執行的測試；可能已完成或 Server 曾重新啟動。'});
    if(j.phase!=='9F')return res.status(400).json({error:'目前只允許提前停止 9F Soak Test（長時間耐久測試）。'});
    if(j.status!=='running')return res.status(409).json({error:'這個 9F 已經不是執行中狀態。'});
    j.cancelRequested=true;j.stopRequestedAt=now();j.stopRequestedBy=req.auth?.username||SUPER_ADMIN_USER;
    res.status(202).json({ok:true,message:'已送出提前停止要求，系統會立即以停止前資料結算 PASS / FAIL。',run:suitePublic(j)});
  }catch(e){next(e)}
});


// Phase 9B: controlled, auditable drills. No shell commands and no automatic PostgreSQL promotion are executed here.
async function recordControlledDrill(type,title,actor,runner){
  const drillId=crypto.randomUUID(),started=now();
  await pool.query("INSERT INTO resilience_drill_events(drill_id,drill_type,status,title,summary,detail,started_at,actor) VALUES($1,$2,'running',$3,'',$4::jsonb,$5,$6)",[drillId,type,title,'{}',started,actor]);
  try{
    const detail=await runner();
    const status=detail?.status==='warning'?'warning':'passed';
    const summary=String(detail?.summary||'演練完成').slice(0,1000);
    await pool.query('UPDATE resilience_drill_events SET status=$1,summary=$2,detail=$3::jsonb,completed_at=$4 WHERE drill_id=$5',[status,summary,JSON.stringify(detail||{}),now(),drillId]);
    return {ok:true,drillId,status,summary,detail};
  }catch(e){
    const msg=String(e?.message||e).slice(0,1000);
    await pool.query("UPDATE resilience_drill_events SET status='failed',summary=$1,detail=$2::jsonb,completed_at=$3 WHERE drill_id=$4",[msg,JSON.stringify({error:msg}),now(),drillId]).catch(()=>{});
    await recordDiagnostic('','RESILIENCE_CONTROLLED_001','resilience_drill',msg,{severity:'error',actor,context:{drillId,type}});
    throw e;
  }
}
async function controlledDrillCapabilities(){
  const m=await loadMaintenanceRuntime();
  const peer=await probeHaPeer().catch(e=>({configured:!!CENTRAL_HA_PEER_URL,ok:false,error:String(e?.message||e)}));
  return {maintenance:m,types:[
    {key:'db_reconnect',title:'DB Reconnect（資料庫重新連線）',safe:true,description:'建立並釋放專用測試連線，再重新連線驗證；不會關閉正式 PostgreSQL。'},
    {key:'backup_restore',title:'Backup / Restore（備份復原）',safe:true,description:'重新執行最近一份中央備份的暫存 Restore Drill，不修改正式資料。'},
    {key:'alert_pipeline',title:'Alert Pipeline（警報鏈路）',safe:true,description:'建立一筆測試警報並立即 Recovery，驗證 Phase 8D 警報資料鏈。'},
    {key:'ha_peer',title:'HA Peer Probe（備援主機探測）',safe:true,description:'即時檢查 Peer /api/ready；應用程式不會自行 Promote Standby。'},
    {key:'maintenance_brownout',title:'Maintenance Brownout（維護中斷）',safe:false,description:'需先開啟維護模式；正常寫入/Heartbeat 暫時回 503，用來觀察 Node 自動重試與重連。'}
  ],ha:{enabled:CENTRAL_HA_ENABLED,peerConfigured:peer.configured,peerOk:peer.ok,peer},generatedAt:now()};
}
app.get('/api/super/resilience/control',superAuth,async(req,res,next)=>{try{res.json(await controlledDrillCapabilities())}catch(e){next(e)}});
app.post('/api/super/resilience/maintenance/start',superAuth,async(req,res,next)=>{
  try{
    const b=req.body||{},minutes=Number(b.minutes||5),confirmText=String(b.confirmText||'');
    if(confirmText!=='MAINTENANCE')return res.status(400).json({error:'二次確認失敗，請輸入 MAINTENANCE。'});
    if(![1,5,10,15].includes(minutes))return res.status(400).json({error:'維護演練時間只允許 1 / 5 / 10 / 15 分鐘。'});
    const startedAt=now(),expiresAt=new Date(Date.now()+minutes*60000).toISOString(),reason=String(b.reason||'Phase 9B 受控故障演練').slice(0,300),actor=req.auth?.username||SUPER_ADMIN_USER;
    maintenanceRuntime={enabled:true,reason,startedAt,expiresAt,startedBy:actor,updatedAt:startedAt};
    await pool.query('UPDATE resilience_control_state SET maintenance_enabled=TRUE,reason=$1,started_at=$2,expires_at=$3,started_by=$4,updated_at=$2 WHERE id=1',[reason,startedAt,expiresAt,actor]);
    await recordControlledDrill('maintenance_start','Maintenance Mode（維護演練模式）',actor,async()=>({summary:`維護演練模式已開啟 ${minutes} 分鐘。`,minutes,expiresAt,reason,status:'warning'}));
    res.json({ok:true,maintenance:maintenanceRuntime});
  }catch(e){next(e)}
});
app.post('/api/super/resilience/maintenance/stop',superAuth,async(req,res,next)=>{
  try{
    const actor=req.auth?.username||SUPER_ADMIN_USER,stoppedAt=now();
    maintenanceRuntime={enabled:false,reason:'',startedAt:null,expiresAt:null,startedBy:'',updatedAt:stoppedAt};
    await pool.query("UPDATE resilience_control_state SET maintenance_enabled=FALSE,reason='',started_at=NULL,expires_at=NULL,started_by='',updated_at=$1 WHERE id=1",[stoppedAt]);
    await recordControlledDrill('maintenance_stop','Maintenance Recovery（維護恢復）',actor,async()=>({summary:'維護演練模式已手動解除，正常寫入流量恢復。'}));
    res.json({ok:true,maintenance:maintenanceRuntime});
  }catch(e){next(e)}
});
app.post('/api/super/resilience/controlled',superAuth,async(req,res,next)=>{
  try{
    const type=String(req.body?.type||''),actor=req.auth?.username||SUPER_ADMIN_USER;
    const allowed=new Set(['db_reconnect','backup_restore','alert_pipeline','ha_peer','maintenance_brownout']);
    if(!allowed.has(type))return res.status(400).json({error:'不支援的演練類型'});
    if(type==='maintenance_brownout'){
      if(!maintenanceActive())return res.status(409).json({error:'請先開啟 Maintenance Mode（維護演練模式）再進行中斷觀察。'});
      return res.json(await recordControlledDrill(type,'Maintenance Brownout（維護中斷）',actor,async()=>({status:'warning',summary:'維護中斷目前生效中；一般寫入、Heartbeat、同步會收到 HTTP 503，請觀察 Dealer Node 自動重試/重連。',expiresAt:maintenanceRuntime.expiresAt})));
    }
    if(type==='db_reconnect')return res.json(await recordControlledDrill(type,'DB Reconnect（資料庫重新連線）',actor,async()=>{
      const t0=Date.now();const c=await pool.connect();try{await c.query('SELECT 1 AS ok')}finally{c.release()};const q=await pool.query('SELECT NOW() AS now');return {summary:`專用連線釋放後已重新取得 PostgreSQL 連線，總耗時 ${Date.now()-t0} ms。`,roundTripMs:Date.now()-t0,databaseTime:q.rows[0]?.now};
    }));
    if(type==='backup_restore')return res.json(await recordControlledDrill(type,'Backup / Restore（備份復原）',actor,async()=>{
      const b=(await pool.query("SELECT backup_id FROM central_backup_events WHERE status IN ('success','partial') ORDER BY id DESC LIMIT 1")).rows[0];if(!b)throw new Error('尚無可用中央備份。');const r=await drillCentralBackup(b.backup_id,actor);return {summary:`Restore Drill 通過，可重建 ${Number(r.rowCount||0).toLocaleString()} 筆資料。`,backupId:b.backup_id,rowCount:r.rowCount,tableCount:r.tableCount};
    }));
    if(type==='alert_pipeline')return res.json(await recordControlledDrill(type,'Alert Pipeline（警報鏈路）',actor,async()=>{
      const key=`phase9b_test_${crypto.randomUUID()}`,ts=now();await pool.query(`INSERT INTO performance_alert_events(alert_key,severity,status,title,message,impact,advice,value,threshold,unit,opened_at,last_seen_at,context) VALUES($1,'warning','open',$2,$3,$4,$5,1,1,'test',$6,$6,$7::jsonb)`,[key,'Phase 9B 測試警報','這是一筆受控測試警報。','不影響正式服務。','系統將立即自動標記 Recovery。',ts,JSON.stringify({phase:'9B',actor})]);await pool.query("UPDATE performance_alert_events SET status='recovered',recovered_at=$1,last_seen_at=$1 WHERE alert_key=$2 AND status='open'",[now(),key]);return {summary:'Phase 8D 測試警報已成功建立並 Recovery，警報資料鏈正常。',alertKey:key};
    }));
    if(type==='ha_peer')return res.json(await recordControlledDrill(type,'HA Peer Probe（備援主機探測）',actor,async()=>{
      const st=await refreshHaRuntime({allowMigration:false,recordTransition:false}),peer=await probeHaPeer();if(!CENTRAL_HA_ENABLED)return {status:'warning',summary:'CENTRAL_HA_ENABLED 尚未開啟；目前只能完成本機角色檢查。',runtime:st,peer};if(!peer.configured)return {status:'warning',summary:'HA 已啟用，但尚未設定 CENTRAL_HA_PEER_URL。',runtime:st,peer};if(!peer.ok)throw new Error('HA Peer 健康檢查失敗。');return {summary:'HA Peer /api/ready 回應正常；自動 Promote 仍由 PostgreSQL / 基礎設施負責。',runtime:st,peer};
    }));
  }catch(e){next(e)}
});

app.get('/api/super/migrations',superAuth,async(req,res,next)=>{
  try{const schema=await getServerSchemaStatus();await ensureMigrationSafetyTable();const safety=(await pool.query('SELECT id,migration_version,migration_name,status,detail,created_at FROM migration_safety_events ORDER BY id DESC LIMIT 100')).rows;res.json({...schema,safetyEvents:safety});}catch(e){next(e)}
});

app.get('/api/super/diagnostics',superAuth,async(req,res,next)=>{
  try{
    const companyId=String(req.query.companyId||'').trim();
    const limit=Math.max(1,Math.min(500,Number(req.query.limit||200)));
    const onlyOpen=String(req.query.open||'')==='1';
    const where=[],args=[];
    if(companyId){args.push(companyId);where.push(`d.company_id=$${args.length}`)}
    if(onlyOpen)where.push('d.resolved=FALSE');
    args.push(limit);
    const q=`SELECT d.*,c.name AS company_name FROM diagnostic_events d LEFT JOIN companies c ON c.id=d.company_id ${where.length?'WHERE '+where.join(' AND '):''} ORDER BY d.last_seen_at DESC LIMIT $${args.length}`;
    const rows=(await pool.query(q,args)).rows;
    res.json({events:rows,generatedAt:now()});
  }catch(e){next(e)}
});
app.post('/api/super/diagnostics/:id/resolve',superAuth,async(req,res,next)=>{
  try{await pool.query('UPDATE diagnostic_events SET resolved=TRUE,resolved_at=$1 WHERE id=$2',[now(),req.params.id]);res.json({ok:true});}catch(e){next(e)}
});

app.get('/api/super/performance',superAuth,async(req,res,next)=>{
  try{
    const current=await collectSystemMetrics(),assessment=assessPerformance(current);
    const since=new Date(Date.now()-6*3600*1000).toISOString();
    let history=[];try{history=(await pool.query('SELECT * FROM system_metric_samples WHERE sampled_at>=$1 ORDER BY sampled_at DESC LIMIT 1440',[since])).rows.reverse()}catch{}
    const alertCenter=await getPerformanceAlertCenter();
    res.json({current,assessment,alertCenter,history,config:{sampleMs:METRICS_SAMPLE_MS,retentionHours:METRICS_RETENTION_HOURS},generatedAt:now()});
  }catch(e){next(e)}
});

app.get('/api/super/health',superAuth,async(req,res,next)=>{
  try{
    const schema=await getServerSchemaStatus();
    const updatePolicy=await getDesktopUpdatePolicy();
    const companies=(await pool.query('SELECT * FROM companies ORDER BY created_at DESC')).rows;
    const nodes=(await pool.query('SELECT * FROM dealer_nodes')).rows;
    const snaps=(await pool.query('SELECT company_id,updated_at FROM snapshots')).rows;
    const since24=new Date(Date.now()-24*3600*1000).toISOString();
    const failed=(await pool.query("SELECT company_id,COUNT(*)::int n FROM sync_events WHERE status<>'ok' AND event_type<>'node_offline' AND created_at>$1 GROUP BY company_id",[since24])).rows;
    const diagFailed=(await pool.query("SELECT company_id,COUNT(*)::int n FROM diagnostic_events WHERE resolved=FALSE AND severity IN ('error','critical') AND last_seen_at>$1 GROUP BY company_id",[since24])).rows;
    const nb=new Map(nodes.map(x=>[x.company_id,x])),sb=new Map(snaps.map(x=>[x.company_id,x])),fb=new Map(failed.map(x=>[x.company_id,Number(x.n||0)])),db=new Map(diagFailed.map(x=>[x.company_id,Number(x.n||0)]));
    const rows=companies.map(c=>{
      const n=nb.get(c.id),st=sb.get(c.id);let score=40;const issues=[];
      // Node 在線/離線屬於營業主機使用狀態，只保留狀態與事件紀錄，不納入健康度扣分。
      if(c.enabled){score+=20}else issues.push('車行已停用');
      const authAge=Date.now()-Date.parse(c.last_auth_at||'');if(Number.isFinite(authAge)&&authAge<7*86400000)score+=20;else issues.push('最近 7 天無授權登入');
      const snapAge=Date.now()-Date.parse(st?.updated_at||'');if(Number.isFinite(snapAge)&&snapAge<2*86400000)score+=20;else if(Number.isFinite(snapAge)&&snapAge<7*86400000){score+=10;issues.push('資料同步超過 2 天')}else issues.push('資料同步超過 7 天');
      const syncFailures=fb.get(c.id)||0,diagnosticFailures=db.get(c.id)||0,failures=syncFailures+diagnosticFailures;
      if(syncFailures){score=Math.max(0,score-Math.min(15,syncFailures*5));issues.push(`24 小時同步異常 ${syncFailures} 筆`)}
      if(diagnosticFailures){score=Math.max(0,score-Math.min(20,diagnosticFailures*5));issues.push(`24 小時系統錯誤 ${diagnosticFailures} 類`)}
      const caps=n?.capabilities||{};
      const localSchemaVersion=Number(caps.localSchemaVersion||0),localSchemaTarget=Number(caps.localSchemaTarget||0);
      const localSchemaStatus=String(caps.localSchemaStatus||'unknown');
      const migrationSafetyStatus=String(caps.migrationSafetyStatus||'none');
      if(n&&localSchemaTarget>0&&(localSchemaStatus!=='ready'||localSchemaVersion<localSchemaTarget)){score=Math.max(0,score-15);issues.push(`SQLite Schema ${localSchemaStatus} v${localSchemaVersion}/${localSchemaTarget}`)}
      return {companyId:c.id,companyName:c.name,score,issues,nodeOnline:nodeOnline(n),lastSeenAt:n?.last_seen_at||null,appVersion:n?.app_version||'',lastAuthAt:c.last_auth_at||null,snapshotUpdatedAt:st?.updated_at||null,failures24h:failures,postgresSchemaVersion:schema.currentVersion,postgresSchemaTarget:schema.targetVersion,postgresSchemaStatus:schema.status,localSchemaVersion,localSchemaTarget,localSchemaStatus,migrationSafetyStatus,migrationSafetyFromVersion:Number(caps.migrationSafetyFromVersion||0),migrationSafetyTargetVersion:Number(caps.migrationSafetyTargetVersion||0),agentAutoRecovery:!!caps.agentAutoRecovery,agentWatchdog:!!caps.agentWatchdog,agentRecoveryCount:Number(caps.agentRecoveryCount||0),agentLastRecoveryAt:caps.agentLastRecoveryAt||null,agentHeartbeatFailures:Number(caps.agentHeartbeatFailures||0),agentCommandFailures:Number(caps.agentCommandFailures||0),latestDesktopVersion:updatePolicy.latestVersion,minimumDesktopVersion:updatePolicy.minimumVersion,updatePolicyEnabled:updatePolicy.enabled,desktopVersionState:!updatePolicy.enabled?'unmanaged':(compareSemver(n?.app_version||'0.0.0',updatePolicy.minimumVersion)<0?'blocked':(compareSemver(n?.app_version||'0.0.0',updatePolicy.latestVersion)<0?'update_available':'current'))};
    });
    res.json({health:rows,generatedAt:now(),schema,updatePolicy});
  }catch(e){next(e)}
});

app.get('/api/super/ha',superAuth,async(req,res,next)=>{
  try{
    const runtime=await refreshHaRuntime({allowMigration:false,recordTransition:false});
    const peer=await probeHaPeer();
    let events=[];try{events=(await pool.query('SELECT * FROM central_ha_events ORDER BY id DESC LIMIT 100')).rows}catch{}
    const schema=await getServerSchemaStatus();
    res.json({
      enabled:CENTRAL_HA_ENABLED,
      runtime,
      peer,
      schema,
      config:{instanceId:CENTRAL_HA_INSTANCE_ID,site:CENTRAL_HA_SITE,expectedRole:CENTRAL_HA_EXPECTED_ROLE,peerUrl:CENTRAL_HA_PEER_URL||'',peerTimeoutMs:CENTRAL_HA_PEER_TIMEOUT_MS},
      events,
      guidance:{promotionManagedExternally:true,standbyWriteGuard:true,automaticRoleDetection:true,readinessEndpoint:'/api/ready'}
    });
  }catch(e){next(e)}
});

app.get('/api/super/data',superAuth,async(req,res,next)=>{
  try{
    const companies=(await pool.query(`
      SELECT c.*,
        (SELECT u.username FROM users u WHERE u.company_id=c.id AND u.role='admin' AND u.enabled=TRUE ORDER BY u.updated_at ASC LIMIT 1) AS main_username
      FROM companies c ORDER BY c.created_at DESC
    `)).rows;
    const users=(await pool.query('SELECT * FROM users ORDER BY company_id,role,name')).rows;
    const snaps=(await pool.query('SELECT * FROM snapshots')).rows;
    const branches=(await pool.query('SELECT * FROM branches ORDER BY company_id,is_head_office DESC,name ASC,id ASC')).rows;
    const nodes=(await pool.query('SELECT * FROM dealer_nodes')).rows;
    const nodeBy=new Map(nodes.map(n=>[n.company_id,n]));
    const usersBy=new Map(),snapBy=new Map(),branchesBy=new Map();
    for(const u of users){if(!usersBy.has(u.company_id))usersBy.set(u.company_id,[]);usersBy.get(u.company_id).push(userDto(u));}
    for(const b of branches){if(!branchesBy.has(b.company_id))branchesBy.set(b.company_id,[]);branchesBy.get(b.company_id).push(branchDto(b));}
    for(const s of snaps)snapBy.set(s.company_id,{snapshot:s.json,version:Number(s.version||0),updatedAt:s.updated_at});
    res.json({
      companies:companies.map(c=>{
        const s=snapBy.get(c.id)||{snapshot:{settings:{companyName:c.name,taxRate:0},users:[],cars:[],saleRequests:[]},version:0,updatedAt:null};
        const companyBranches=branchesBy.get(c.id)||[];
        return {company:{...companyDto(c),branchCount:companyBranches.filter(b=>b.enabled).length},branches:companyBranches,users:usersBy.get(c.id)||[],snapshot:s.snapshot,version:s.version,updatedAt:s.updatedAt,node:nodeBy.get(c.id)||null};
      })
    });
  }catch(e){ next(e); }
});

app.get('/api/super/companies/:id',superAuth,async(req,res,next)=>{
  try{
    const c=await getCompany(req.params.id);
    if(!c)return res.status(404).json({error:'找不到車行'});
    const {rows}=await pool.query('SELECT * FROM users WHERE company_id=$1 ORDER BY role,name',[c.id]);
    const snap=await getSnapshot(c.id);
    const branches=await getCompanyBranches(c.id,pool,{includeDisabled:true});
    const main=rows.find(x=>x.role==='admin'&&x.enabled)?.username||'';
    res.json({company:{...companyDto({...c,main_username:main}),branchCount:branches.filter(b=>b.enabled).length},branches,users:rows.map(userDto),snapshot:snap.snapshot,version:snap.version,updatedAt:snap.updatedAt});
  }catch(e){ next(e); }
});

// Phase 14A UX revision: Super Admin can manage the company -> head office -> branch hierarchy directly.
app.get('/api/super/companies/:id/branches',superAuth,async(req,res,next)=>{
  try{
    const c=await getCompany(req.params.id);if(!c)return res.status(404).json({error:'找不到車行'});
    const branches=await getCompanyBranches(c.id,pool,{includeDisabled:true});
    const headOffice=branches.find(b=>b.isHeadOffice)||branches[0]||null;
    res.json({ok:true,company:companyDto(c),branches,defaultBranchId:headOffice?.id||''});
  }catch(e){next(e)}
});
app.post('/api/super/companies/:id/branches',superAuth,async(req,res,next)=>{
  try{
    const c=await getCompany(req.params.id);if(!c)return res.status(404).json({error:'找不到車行'});
    const name=String(req.body?.name||'').trim(),code=String(req.body?.code||'').trim().toUpperCase(),address=String(req.body?.address||'').trim().slice(0,300),phone=String(req.body?.phone||'').trim().slice(0,80);
    if(!name)return res.status(400).json({error:'分店名稱不能空白'});if(name.length>80)return res.status(400).json({error:'分店名稱過長'});
    if(!/^[A-Z0-9_-]{2,20}$/.test(code))return res.status(400).json({error:'分店代碼請使用 2-20 碼英數、底線或減號'});
    const id=`br_${crypto.randomUUID()}`,ts=now();
    const q=await pool.query(`INSERT INTO branches(id,company_id,code,name,is_head_office,enabled,address,phone,created_at,updated_at) VALUES($1,$2,$3,$4,FALSE,TRUE,$5,$6,$7,$7) RETURNING *`,[id,c.id,code,name,address,phone,ts]);
    res.json({ok:true,branch:branchDto(q.rows[0])});
  }catch(e){if(e?.code==='23505')return res.status(409).json({error:'這個分店代碼已存在'});next(e)}
});
app.patch('/api/super/companies/:id/branches/:branchId',superAuth,async(req,res,next)=>{
  try{
    const old=(await pool.query('SELECT * FROM branches WHERE id=$1 AND company_id=$2',[req.params.branchId,req.params.id])).rows[0];
    if(!old)return res.status(404).json({error:'找不到分店'});
    const name=req.body?.name===undefined?old.name:String(req.body.name||'').trim(),address=req.body?.address===undefined?old.address:String(req.body.address||'').trim().slice(0,300),phone=req.body?.phone===undefined?old.phone:String(req.body.phone||'').trim().slice(0,80),enabled=req.body?.enabled===undefined?old.enabled:!!req.body.enabled;
    const saleApprovalMode=req.body?.saleApprovalMode===undefined?String(old.sale_approval_mode||'branch_manager'):String(req.body.saleApprovalMode||'branch_manager');
    const saleApproverUserId=req.body?.saleApproverUserId===undefined?String(old.sale_approver_user_id||''):String(req.body.saleApproverUserId||'');
    if(!['branch_manager','company_admin','specific_user'].includes(saleApprovalMode))return res.status(400).json({error:'成交審核方式不正確'});
    if(saleApprovalMode==='specific_user'&&!saleApproverUserId)return res.status(400).json({error:'請選擇指定審核人'});
    if(!name)return res.status(400).json({error:'分店名稱不能空白'});if(name.length>80)return res.status(400).json({error:'分店名稱過長'});
    if(old.is_head_office&&!enabled)return res.status(400).json({error:'總店不能停用'});
    const q=await pool.query(`UPDATE branches SET name=$1,address=$2,phone=$3,enabled=$4,sale_approval_mode=$5,sale_approver_user_id=$6,updated_at=$7 WHERE id=$8 AND company_id=$9 RETURNING *`,[name,address,phone,enabled,saleApprovalMode,saleApprovalMode==='specific_user'?saleApproverUserId:null,now(),old.id,req.params.id]);
    res.json({ok:true,branch:branchDto(q.rows[0])});
  }catch(e){next(e)}
});
app.post('/api/super/companies/:id/branches/:branchId/set-head-office',superAuth,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const b=(await client.query('SELECT * FROM branches WHERE id=$1 AND company_id=$2 FOR UPDATE',[req.params.branchId,req.params.id])).rows[0];
    if(!b){await client.query('ROLLBACK');return res.status(404).json({error:'找不到分店'});}if(!b.enabled){await client.query('ROLLBACK');return res.status(400).json({error:'停用中的分店不能設為總店'});}
    await client.query('UPDATE branches SET is_head_office=FALSE,updated_at=$1 WHERE company_id=$2 AND is_head_office=TRUE',[now(),req.params.id]);
    const q=await client.query('UPDATE branches SET is_head_office=TRUE,updated_at=$1 WHERE id=$2 AND company_id=$3 RETURNING *',[now(),b.id,req.params.id]);
    const snap=(await client.query('SELECT json FROM snapshots WHERE company_id=$1 FOR UPDATE',[req.params.id])).rows[0];
    if(snap){const d=JSON.parse(JSON.stringify(snap.json||{}));d.settings=d.settings||{};d.settings.defaultBranchId=b.id;await client.query('UPDATE snapshots SET json=$1::jsonb,updated_at=$2 WHERE company_id=$3',[JSON.stringify(d),now(),req.params.id]);}
    await client.query('COMMIT');res.json({ok:true,branch:branchDto(q.rows[0])});
  }catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}
});

app.post('/api/super/companies',superAuth,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    const b=req.body||{};
    const companyCode=cleanCode(b.companyCode);
    const companyName=String(b.companyName||'').trim();
    const username=String(b.username||'').trim();
    const password=String(b.password||'');
    const ownerName=String(b.ownerName||'後台管理員').trim()||'後台管理員';
    if(!companyName||!companyCode||!username||!password)return res.status(400).json({error:'車行名稱、車行代碼、主帳號、密碼不可空白'});
    if(!/^[A-Za-z0-9_-]{3,40}$/.test(companyCode))return res.status(400).json({error:'車行代碼只能使用英數、底線、減號，長度 3-40'});
    const startDate=b.startDate||today();
    const expiresAt=b.expiresAt||'';
    if(startDate&&expiresAt&&expiresAt<startDate)return res.status(400).json({error:'到期日不能早於啟用日'});
    const enabled=b.enabled!==false;
    const trial=!!b.trial;
    const id=`admin_${crypto.randomUUID()}`;
    const defaultBranchId=companyCode+'_main';const snapshot={settings:{companyName,taxRate:0,defaultBranchId},users:[{id,username,password:'',name:ownerName,role:'admin',branchId:defaultBranchId,commissionRate:0,baseSalary:0}],cars:[],saleRequests:[],operationLogs:[]};
    await client.query('BEGIN');
    await client.query(`INSERT INTO companies(id,name,enabled,start_date,expires_at,created_at,created_by,contact_email,trial,system_activation_date,system_activation_set_at,system_activation_set_by,owner_user_id) VALUES($1,$2,$3,$4,$5,$6,'manual',$7,$8,$4,$6,'Super Admin',$9)`,[companyCode,companyName,enabled,startDate,expiresAt,now(),String(b.email||''),trial,id]);
    await client.query(`INSERT INTO branches(id,company_id,code,name,is_head_office,enabled,address,phone,created_at,updated_at) VALUES($1,$2,'MAIN','總店',TRUE,TRUE,'','',$3,$3)`,[defaultBranchId,companyCode,now()]);
    await client.query(`INSERT INTO users(id,company_id,username,password_hash,name,role,commission_rate,base_salary,enabled,updated_at,branch_id) VALUES($1,$2,$3,$4,$5,'admin',0,0,TRUE,$6,$7)`,[id,companyCode,username,hashPassword(password),ownerName,now(),defaultBranchId]);
    await client.query(`INSERT INTO snapshots(company_id,version,json,updated_at) VALUES($1,1,$2::jsonb,$3)`,[companyCode,JSON.stringify(snapshot),now()]);
    await client.query('COMMIT');
    const c=await getCompany(companyCode);
    res.json({ok:true,company:companyDto({...c,main_username:username})});
  }catch(e){
    try{await client.query('ROLLBACK');}catch{}
    if(e?.code==='23505')return res.status(409).json({error:'車行代碼或帳號已存在'});
    next(e);
  }finally{client.release();}
});

app.patch('/api/super/companies/:id',superAuth,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const c=await getCompany(req.params.id,client);
    if(!c){await client.query('ROLLBACK');return res.status(404).json({error:'找不到車行'});}
    const b=req.body||{};
    const name=b.name===undefined?c.name:String(b.name||'').trim();
    const enabled=b.enabled===undefined?c.enabled:!!b.enabled;
    const start=b.startDate===undefined?c.start_date:(b.startDate||'');
    const exp=b.expiresAt===undefined?c.expires_at:(b.expiresAt||'');
    const trial=b.trial===undefined?c.trial:!!b.trial;
    const email=b.contactEmail===undefined?c.contact_email:String(b.contactEmail||'');
    if(!name){await client.query('ROLLBACK');return res.status(400).json({error:'車行名稱不可空白'});}
    if(start&&exp&&exp<start){await client.query('ROLLBACK');return res.status(400).json({error:'到期日不能早於啟用日'});}
    await client.query('UPDATE companies SET name=$1,enabled=$2,start_date=$3,expires_at=$4,trial=$5,contact_email=$6 WHERE id=$7',[name,enabled,start,exp,trial,email,c.id]);
    if(enabled!==c.enabled)await syncCompanyLicenseToSubscription(client,c.id,enabled,req.auth.username||req.auth.sub);
    if(exp!==c.expires_at&&exp)await syncCompanyExpiryToSubscription(client,c.id,exp,req.auth.username||req.auth.sub,'company_overview');
    if(exp!==c.expires_at&&exp)await syncCompanyExpiryToSubscription(client,c.id,exp,req.auth.username||req.auth.sub,'company_overview');

    const adminQ=await client.query("SELECT * FROM users WHERE company_id=$1 AND role='admin' ORDER BY updated_at ASC LIMIT 1",[c.id]);
    const admin=adminQ.rows[0];
    if(admin){
      const newUsername=b.mainUsername===undefined?admin.username:String(b.mainUsername||'').trim();
      const newOwnerName=b.ownerName===undefined?admin.name:String(b.ownerName||'').trim();
      if(!newUsername){await client.query('ROLLBACK');return res.status(400).json({error:'主帳號不可空白'});}
      const newHash=b.password?hashPassword(String(b.password)):admin.password_hash;
      await client.query('UPDATE users SET username=$1,password_hash=$2,name=$3,updated_at=$4 WHERE id=$5',[newUsername,newHash,newOwnerName||admin.name,now(),admin.id]);

      const snap=await getSnapshot(c.id,client);
      const d=JSON.parse(JSON.stringify(snap.snapshot||{}));
      d.settings=d.settings||{}; d.settings.companyName=name;
      d.users=Array.isArray(d.users)?d.users:[];
      const su=d.users.find(x=>x.id===admin.id)||d.users.find(x=>x.role==='admin');
      if(su){su.username=newUsername;su.name=newOwnerName||admin.name;su.password='';}
      const ver=snap.version+1;
      await client.query('UPDATE snapshots SET version=$1,json=$2::jsonb,updated_at=$3 WHERE company_id=$4',[ver,JSON.stringify(d),now(),c.id]);
    }
    await client.query('COMMIT');
    const updated=await getCompany(c.id);
    const uq=await pool.query("SELECT username FROM users WHERE company_id=$1 AND role='admin' AND enabled=TRUE ORDER BY updated_at ASC LIMIT 1",[c.id]);
    res.json({ok:true,company:companyDto({...updated,main_username:uq.rows[0]?.username||''})});
  }catch(e){
    try{await client.query('ROLLBACK');}catch{}
    if(e?.code==='23505')return res.status(409).json({error:'此車行內已有相同帳號'});
    next(e);
  }finally{client.release();}
});


app.post('/api/super/companies/:companyId/users/:userId/reset-password',superAuth,async(req,res,next)=>{
  try{
    const newPassword=String(req.body?.newPassword||'');
    if(newPassword.length<6)return res.status(400).json({error:'新密碼至少 6 碼'});
    const {rows}=await pool.query('SELECT * FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.params.userId,req.params.companyId]);
    const target=rows[0]; if(!target)return res.status(404).json({error:'找不到此帳號'});
    const changedAt=now();
    await pool.query('UPDATE users SET password_hash=$1,token_version=token_version+1,password_changed_at=$2,password_changed_by=$3,updated_at=$2 WHERE id=$4',[hashPassword(newPassword),changedAt,SUPER_ADMIN_USER,target.id]);
    res.json({ok:true,passwordChangedAt:changedAt,passwordChangedBy:SUPER_ADMIN_USER});
  }catch(e){next(e)}
});

app.patch('/api/super/companies/:id/license',superAuth,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const c=await getCompany(req.params.id,client);
    if(!c){await client.query('ROLLBACK');return res.status(404).json({error:'找不到車行'});}
    const enabled=req.body.enabled===undefined?c.enabled:!!req.body.enabled;
    const start=req.body.startDate===undefined?c.start_date:req.body.startDate;
    const exp=req.body.expiresAt===undefined?c.expires_at:req.body.expiresAt;
    const trial=req.body.trial===undefined?c.trial:!!req.body.trial;
    if(start&&exp&&exp<start){await client.query('ROLLBACK');return res.status(400).json({error:'到期日不能早於啟用日'});}
    await client.query('UPDATE companies SET enabled=$1,start_date=$2,expires_at=$3,trial=$4 WHERE id=$5',[enabled,start||'',exp||'',trial,c.id]);
    if(enabled!==c.enabled)await syncCompanyLicenseToSubscription(client,c.id,enabled,req.auth.username||req.auth.sub);
    await client.query('COMMIT');
    const updated=await getCompany(c.id);
    res.json({ok:true,company:companyDto(updated),subscriptionSynced:enabled!==c.enabled});
  }catch(e){ try{await client.query('ROLLBACK')}catch{} next(e); }
  finally{client.release();}
});

app.delete('/api/super/companies/:id',superAuth,async(req,res,next)=>{
  try{
    const c=await getCompany(req.params.id);
    if(!c)return res.status(404).json({error:'找不到車行'});
    await pool.query('DELETE FROM companies WHERE id=$1',[c.id]);
    res.json({ok:true,deleted:{id:c.id,name:c.name}});
  }catch(e){ next(e); }
});


// -------------------- Phase 10A-10D Security / Audit / Integrity / Rollback readiness --------------------
app.get('/api/super/security-center',superAuth,async(req,res,next)=>{try{const [integrity,release,auditCount]=await Promise.all([phase10DataIntegritySummary(),phase10ReleaseReadiness(),pool.query(`SELECT COUNT(*)::int AS n FROM security_audit_events`)]);res.json({security:{status:'enabled',securityHeaders:true,loginProtection:true,rateLimit:{apiPerMinute:SECURITY_API_MAX,loginAttemptsPer15Min:SECURITY_LOGIN_MAX},tokenVerification:true,superAdminIsolation:true,sensitiveErrorMasking:true},integrity,release,auditCount:Number(auditCount.rows[0]?.n||0),generatedAt:now()})}catch(e){next(e)}});
app.get('/api/super/security/audit',superAuth,async(req,res,next)=>{try{const page=Math.max(1,Number(req.query.page||1)),limit=10,offset=(page-1)*limit,filter=String(req.query.category||'').trim();const where=filter?'WHERE category=$1':'';const params=filter?[filter]:[];const total=Number((await pool.query(`SELECT COUNT(*)::int AS n FROM security_audit_events ${where}`,params)).rows[0]?.n||0);const rows=(await pool.query(`SELECT id,actor,actor_role,company_id,action,category,status,ip,target_type,target_id,detail,metadata,created_at FROM security_audit_events ${where} ORDER BY id DESC LIMIT 10 OFFSET ${offset}`,params)).rows;res.json({rows,page,pageSize:limit,total,totalPages:Math.max(1,Math.ceil(total/limit))})}catch(e){next(e)}});
app.post('/api/super/security/integrity-check',superAuth,async(req,res,next)=>{try{const result=await phase10DataIntegritySummary();await auditSecurityEvent(req,{action:'phase10c_integrity_check',category:'data_integrity',status:result.status,detail:`duplicateUsers=${result.duplicateUsers}, missingSnapshots=${result.missingSnapshots}, saleProblems=${result.saleProblems}`});res.json(result)}catch(e){next(e)}});
app.get('/api/super/security/release-readiness',superAuth,async(req,res,next)=>{try{res.json(await phase10ReleaseReadiness())}catch(e){next(e)}});
app.post('/api/super/security/release-snapshot',superAuth,async(req,res,next)=>{try{const readiness=await phase10ReleaseReadiness(),releaseId=`rel_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;await pool.query(`INSERT INTO release_control_events(release_id,server_version,api_version,schema_version,status,readiness,actor,created_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8)`,[releaseId,'14.9.10','6.9.10',readiness.schemaCurrent,readiness.status,JSON.stringify(readiness),req.auth.username||req.auth.sub,now()]);await auditSecurityEvent(req,{action:'release_readiness_snapshot',category:'release',status:'success',targetType:'release',targetId:releaseId,detail:'Rollback readiness snapshot created'});res.json({ok:true,releaseId,readiness})}catch(e){next(e)}});
app.get('/api/super/security/releases',superAuth,async(req,res,next)=>{try{const rows=(await pool.query(`SELECT * FROM release_control_events ORDER BY id DESC LIMIT 50`)).rows;res.json({rows})}catch(e){next(e)}});


// -------------------- Phase 11A-11C Commercial Launch Center --------------------
app.get('/api/super/commercial-launch',superAuth,async(req,res,next)=>{try{const [readiness,companies,events]=await Promise.all([phase11ProductionReadiness(),pool.query(`SELECT id,name,enabled,start_date,expires_at,last_auth_at FROM companies ORDER BY name ASC`),pool.query(`SELECT acceptance_id,status,result,actor,created_at FROM commercial_acceptance_events ORDER BY id DESC LIMIT 50`)]);res.json({serverVersion:'14.9.10',apiVersion:'6.9.10',...readiness,companies:companies.rows,acceptanceEvents:events.rows})}catch(e){next(e)}});
app.post('/api/super/commercial-launch/acceptance',superAuth,async(req,res,next)=>{try{const result=await phase11AcceptanceSummary(),acceptanceId=`acc_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;await pool.query(`INSERT INTO commercial_acceptance_events(acceptance_id,status,result,actor,created_at) VALUES($1,$2,$3::jsonb,$4,$5)`,[acceptanceId,result.status,JSON.stringify(result),req.auth.username||req.auth.sub,now()]);await auditSecurityEvent(req,{action:'phase11a_commercial_acceptance',category:'commercial_launch',status:result.status==='fail'?'rejected':'success',targetType:'acceptance',targetId:acceptanceId,detail:`pass=${result.pass}, warning=${result.warning}, fail=${result.fail}`});res.json({acceptanceId,...result})}catch(e){next(e)}});
app.post('/api/super/commercial-launch/pilot/start',superAuth,async(req,res,next)=>{try{const companyId=String(req.body?.companyId||'').trim(),notes=String(req.body?.notes||'').slice(0,1000);if(!companyId)return res.status(400).json({error:'請選擇 Dealer（車行）'});const c=await getCompany(companyId);if(!c)return res.status(404).json({error:'找不到車行'});await pool.query(`INSERT INTO pilot_dealers(company_id,status,started_at,completed_at,started_by,notes,baseline_server_version,baseline_schema_version,updated_at) VALUES($1,'active',$2,NULL,$3,$4,'14.9.10',$5,$2) ON CONFLICT(company_id) DO UPDATE SET status='active',started_at=EXCLUDED.started_at,completed_at=NULL,started_by=EXCLUDED.started_by,notes=EXCLUDED.notes,baseline_server_version=EXCLUDED.baseline_server_version,baseline_schema_version=EXCLUDED.baseline_schema_version,updated_at=EXCLUDED.updated_at`,[companyId,now(),req.auth.username||req.auth.sub,notes,SERVER_SCHEMA_TARGET]);await auditSecurityEvent(req,{action:'phase11b_pilot_start',category:'commercial_launch',targetType:'company',targetId:companyId,detail:`Pilot started: ${c.name}`});res.json({ok:true})}catch(e){next(e)}});
app.post('/api/super/commercial-launch/pilot/complete',superAuth,async(req,res,next)=>{try{const companyId=String(req.body?.companyId||'').trim();const r=await pool.query(`UPDATE pilot_dealers SET status='completed',completed_at=$1,updated_at=$1 WHERE company_id=$2 RETURNING *`,[now(),companyId]);if(!r.rows[0])return res.status(404).json({error:'找不到此 Pilot 紀錄'});await auditSecurityEvent(req,{action:'phase11b_pilot_complete',category:'commercial_launch',targetType:'company',targetId:companyId,detail:'Pilot completed'});res.json({ok:true,row:r.rows[0]})}catch(e){next(e)}});
app.post('/api/super/commercial-launch/pilot/cancel',superAuth,async(req,res,next)=>{try{const companyId=String(req.body?.companyId||'').trim();const r=await pool.query(`UPDATE pilot_dealers SET status='cancelled',completed_at=$1,updated_at=$1 WHERE company_id=$2 RETURNING *`,[now(),companyId]);if(!r.rows[0])return res.status(404).json({error:'找不到此 Pilot 紀錄'});await auditSecurityEvent(req,{action:'phase11b_pilot_cancel',category:'commercial_launch',status:'success',targetType:'company',targetId:companyId,detail:'Pilot cancelled'});res.json({ok:true})}catch(e){next(e)}});


// -------------------- Phase 12A-12D Subscription & Licensing Center --------------------

function safeEqualHex(a,b){try{const A=Buffer.from(String(a||''),'hex'),B=Buffer.from(String(b||''),'hex');return A.length===B.length&&A.length>0&&crypto.timingSafeEqual(A,B)}catch{return false}}
function webhookSignature(secret,payload){return crypto.createHmac('sha256',String(secret||'')).update(JSON.stringify(payload||{})).digest('hex')}
const PAYMENT_TECH_LOG_RETENTION_DAYS=15;
function paymentTechLogCutoff(){return new Date(Date.now()-PAYMENT_TECH_LOG_RETENTION_DAYS*24*60*60*1000).toISOString()}
async function cleanupPaymentTechLogs(client=pool){const cutoff=paymentTechLogCutoff();const [w,r]=await Promise.all([client.query(`DELETE FROM payment_webhook_events WHERE received_at < $1`,[cutoff]),client.query(`DELETE FROM payment_renewal_attempts WHERE started_at < $1`,[cutoff])]);return {cutoff,webhooksDeleted:Number(w.rowCount||0),renewalsDeleted:Number(r.rowCount||0)}}
async function applyProviderPayment(client,{provider,eventId,eventType,companyId,providerTransactionId,amountCents,currency='TWD',payload={},actor='webhook'}){
  const eventKey=String(eventId||'').trim(); if(!eventKey)throw Object.assign(new Error('缺少 providerEventId'),{statusCode:400});
  const existed=(await client.query('SELECT * FROM payment_webhook_events WHERE provider_id=$1 AND provider_event_id=$2',[provider.id,eventKey])).rows[0];
  if(existed)return {ok:true,duplicate:true,event:existed};
  const ts=now();
  await client.query(`INSERT INTO payment_webhook_events(provider_id,provider_event_id,event_type,status,transaction_id,payload,received_at) VALUES($1,$2,$3,'received',$4,$5::jsonb,$6)`,[provider.id,eventKey,eventType||'',providerTransactionId||'',JSON.stringify({...payload,companyId:companyId||payload?.companyId||''}),ts]);
  try{
    if(!companyId)throw new Error('Webhook 缺少 companyId');
    const sub=(await client.query(`SELECT s.*,p.billing_interval,p.billing_interval_count,p.grace_days,p.price_cents,p.currency FROM dealer_subscriptions s JOIN subscription_plans p ON p.id=s.plan_id WHERE s.company_id=$1 FOR UPDATE`,[companyId])).rows[0];
    if(!sub)throw new Error('找不到有效訂閱');
    if(['payment_succeeded','renewal_succeeded'].includes(eventType)){
      const txid=String(providerTransactionId||`${provider.id}_${eventKey}`), payId=`pay_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
      const oldTx=(await client.query(`SELECT id,status FROM payment_transactions WHERE provider_id=$1 AND provider_transaction_id=$2`,[provider.id,txid])).rows[0];
      if(oldTx){await client.query(`UPDATE payment_webhook_events SET status='duplicate_payment',processed_at=$1 WHERE provider_id=$2 AND provider_event_id=$3`,[ts,provider.id,eventKey]);return {ok:true,duplicatePayment:true,paymentId:oldTx.id}}
      const base=sub.current_period_end&&sub.current_period_end>=today()?sub.current_period_end:today(),newEnd=addPlanPeriod(base,sub.billing_interval,sub.billing_interval_count),grace=addDateDays(newEnd,sub.grace_days);
      await client.query(`INSERT INTO payment_transactions(id,company_id,provider_id,provider_transaction_id,amount_cents,currency,payment_type,status,description,idempotency_key,paid_at,confirmed_at,confirmed_by,raw_data,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'provider','paid',$7,$8,$9,$9,$10,$11::jsonb,$9,$9)`,[payId,companyId,provider.id,txid,Number(amountCents||sub.price_cents||0),currency||sub.currency||'TWD',eventType==='renewal_succeeded'?'自動續費成功':'Webhook 付款成功',`${provider.id}:${eventKey}`,ts,actor,JSON.stringify(payload||{})]);
      await client.query(`UPDATE dealer_subscriptions SET status='active',current_period_start=COALESCE(current_period_start,$1),current_period_end=$2,grace_until=$3,provider_id=$4,renewal_failures=0,last_renewal_attempt_at=$5,last_renewal_status='success',next_renewal_at=$2,updated_at=$5 WHERE company_id=$6`,[today(),newEnd,grace,provider.id,ts,companyId]);
      await client.query(`UPDATE companies SET enabled=TRUE,expires_at=$1,trial=FALSE WHERE id=$2`,[newEnd,companyId]);
      await subscriptionEvent(client,companyId,eventType,{oldStatus:sub.status,newStatus:'active',oldPeriodEnd:sub.current_period_end,newPeriodEnd:newEnd,source:`provider:${provider.id}`,referenceId:payId,actor,detail:`${eventType==='renewal_succeeded'?'自動續費':'Webhook 付款'}成功，續期至 ${newEnd}`});
      await client.query(`UPDATE payment_webhook_events SET status='processed',transaction_id=$1,processed_at=$2 WHERE provider_id=$3 AND provider_event_id=$4`,[txid,ts,provider.id,eventKey]);
      return {ok:true,paymentId:payId,newPeriodEnd:newEnd,graceUntil:grace};
    }
    if(['payment_failed','renewal_failed'].includes(eventType)){
      const failures=Number(sub.renewal_failures||0)+1, end=dateOnly(sub.current_period_end),gr=dateOnly(sub.grace_until),status=(end&&today()>end)?((gr&&today()<=gr)?'grace_period':'past_due'):sub.status;
      const payId=`pay_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
      await client.query(`INSERT INTO payment_transactions(id,company_id,provider_id,provider_transaction_id,amount_cents,currency,payment_type,status,description,idempotency_key,raw_data,created_at,updated_at) VALUES($1,$2,$3,'',$4,$5,'provider','failed',$6,$7,$8::jsonb,$9,$9)`,[payId,companyId,provider.id,Number(amountCents||sub.price_cents||0),currency||sub.currency||'TWD',eventType==='renewal_failed'?'自動續費失敗':'Webhook 付款失敗',`${provider.id}:${eventKey}:failed`,JSON.stringify({...payload,providerTransactionId:providerTransactionId||''}),ts]);
      await client.query(`UPDATE dealer_subscriptions SET status=$1,renewal_failures=$2,last_renewal_attempt_at=$3,last_renewal_status='failed',updated_at=$3 WHERE company_id=$4`,[status,failures,ts,companyId]);
      if(status==='past_due')await client.query('UPDATE companies SET enabled=FALSE WHERE id=$1',[companyId]);
      await subscriptionEvent(client,companyId,eventType,{oldStatus:sub.status,newStatus:status,oldPeriodEnd:sub.current_period_end,newPeriodEnd:sub.current_period_end,source:`provider:${provider.id}`,referenceId:eventKey,actor,detail:`${eventType==='renewal_failed'?'自動續費':'Webhook 付款'}失敗，第 ${failures} 次；訂閱期限未延長`});
      await client.query(`UPDATE payment_webhook_events SET status='processed_failed_payment',processed_at=$1 WHERE provider_id=$2 AND provider_event_id=$3`,[ts,provider.id,eventKey]);
      return {ok:true,paymentFailed:true,paymentId:payId,status,renewalFailures:failures};
    }
    if(eventType==='refund'){
      const txid=String(providerTransactionId||''); if(!txid)throw new Error('退款事件缺少 providerTransactionId');
      await client.query(`UPDATE payment_transactions SET status='refunded',updated_at=$1 WHERE provider_id=$2 AND provider_transaction_id=$3`,[ts,provider.id,txid]);
      await subscriptionEvent(client,companyId,'payment_refunded',{oldStatus:sub.status,newStatus:sub.status,oldPeriodEnd:sub.current_period_end,newPeriodEnd:sub.current_period_end,source:`provider:${provider.id}`,referenceId:txid,actor,detail:'收到退款通知；不自動回退已使用的訂閱期限，需管理員人工判斷'});
      await client.query(`UPDATE payment_webhook_events SET status='processed',processed_at=$1 WHERE provider_id=$2 AND provider_event_id=$3`,[ts,provider.id,eventKey]);return {ok:true,refunded:true,subscriptionPeriodUnchanged:true};
    }
    throw new Error(`不支援的 Webhook eventType: ${eventType}`);
  }catch(e){await client.query(`UPDATE payment_webhook_events SET status='failed',error_text=$1,processed_at=$2 WHERE provider_id=$3 AND provider_event_id=$4`,[String(e.message||e).slice(0,1000),now(),provider.id,eventKey]);throw e}
}
async function runAutoRenewalSweep(){
  const rows=(await pool.query(`SELECT s.company_id,s.provider_id,s.current_period_end,s.auto_renew,s.status,p.price_cents,p.currency FROM dealer_subscriptions s JOIN subscription_plans p ON p.id=s.plan_id WHERE s.auto_renew=TRUE AND s.provider_id IS NOT NULL AND s.provider_id<>'manual' AND s.status NOT IN ('suspended','cancelled') AND s.current_period_end IS NOT NULL AND s.current_period_end<=$1`,[today()])).rows;
  let attempted=0,skipped=0;
  for(const r of rows){const provider=(await pool.query('SELECT * FROM payment_providers WHERE id=$1',[r.provider_id])).rows[0];if(!provider||!provider.enabled){skipped++;continue}const key=`renew:${r.company_id}:${r.current_period_end}:${provider.id}`;try{await pool.query(`INSERT INTO payment_renewal_attempts(company_id,provider_id,attempt_key,status,amount_cents,started_at) VALUES($1,$2,$3,'awaiting_provider',$4,$5) ON CONFLICT(attempt_key) DO NOTHING`,[r.company_id,provider.id,key,r.price_cents,now()]);attempted++}catch{skipped++}}
  return {ok:true,scanned:rows.length,attempted,skipped,note:'真實扣款需安裝 Provider Adapter；目前建立唯一續費嘗試，等待 Provider/Webhook 回報，避免重複扣款。'}
}
app.get('/api/super/subscriptions',superAuth,async(req,res,next)=>{try{res.json(await phase12Summary({paymentPage:req.query.paymentPage,paymentSearch:req.query.paymentSearch,paymentStatus:req.query.paymentStatus,planPage:req.query.planPage,planSearch:req.query.planSearch,planStatus:req.query.planStatus,subscriptionPage:req.query.subscriptionPage,subscriptionSearch:req.query.subscriptionSearch,subscriptionStatus:req.query.subscriptionStatus}))}catch(e){next(e)}});
app.post('/api/super/subscriptions/plans',superAuth,async(req,res,next)=>{try{const b=req.body||{},name=String(b.name||'').trim();if(!name)return res.status(400).json({error:'請輸入方案名稱'});const id=String(b.id||`plan_${crypto.randomBytes(5).toString('hex')}`).replace(/[^A-Za-z0-9_-]/g,'').slice(0,60),interval=['month','year','day'].includes(b.billingInterval)?b.billingInterval:'month',ts=now();await pool.query(`INSERT INTO subscription_plans(id,name,description,active,price_cents,currency,billing_interval,billing_interval_count,trial_days,grace_days,max_nodes,features,sort_order,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$14) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,active=EXCLUDED.active,price_cents=EXCLUDED.price_cents,currency=EXCLUDED.currency,billing_interval=EXCLUDED.billing_interval,billing_interval_count=EXCLUDED.billing_interval_count,trial_days=EXCLUDED.trial_days,grace_days=EXCLUDED.grace_days,max_nodes=EXCLUDED.max_nodes,features=EXCLUDED.features,sort_order=EXCLUDED.sort_order,updated_at=EXCLUDED.updated_at`,[id,name,String(b.description||'').slice(0,500),b.active!==false,Math.max(0,Math.round(Number(b.price||0)*100)),String(b.currency||'TWD').slice(0,10),interval,Math.max(1,Number(b.billingIntervalCount)||1),Math.max(0,Number(b.trialDays)||0),Math.max(0,Number(b.graceDays)||0),2147483647,JSON.stringify(b.features&&typeof b.features==='object'?b.features:{}),Number(b.sortOrder)||0,ts]);res.json({ok:true,id})}catch(e){next(e)}});
app.patch('/api/super/subscriptions/plans/:id',superAuth,async(req,res,next)=>{try{const id=String(req.params.id||'').trim(),b=req.body||{};const old=(await pool.query('SELECT * FROM subscription_plans WHERE id=$1',[id])).rows[0];if(!old)return res.status(404).json({error:'找不到方案'});const name=b.name!==undefined?String(b.name||'').trim():old.name;if(!name)return res.status(400).json({error:'方案名稱不能空白'});const interval=b.billingInterval!==undefined?String(b.billingInterval):old.billing_interval;if(!['month','year','day'].includes(interval))return res.status(400).json({error:'不支援的計費週期'});await pool.query(`UPDATE subscription_plans SET name=$1,description=$2,active=$3,price_cents=$4,currency=$5,billing_interval=$6,billing_interval_count=$7,trial_days=$8,grace_days=$9,max_nodes=$10,sort_order=$11,updated_at=$12 WHERE id=$13`,[name,b.description!==undefined?String(b.description||'').slice(0,500):old.description,b.active!==undefined?!!b.active:old.active,b.price!==undefined?Math.max(0,Math.round(Number(b.price||0)*100)):old.price_cents,b.currency!==undefined?String(b.currency||'TWD').slice(0,10):old.currency,interval,b.billingIntervalCount!==undefined?Math.max(1,Number(b.billingIntervalCount)||1):old.billing_interval_count,b.trialDays!==undefined?Math.max(0,Number(b.trialDays)||0):old.trial_days,b.graceDays!==undefined?Math.max(0,Number(b.graceDays)||0):old.grace_days,2147483647,b.sortOrder!==undefined?Number(b.sortOrder)||0:old.sort_order,now(),id]);res.json({ok:true})}catch(e){next(e)}});
app.delete('/api/super/subscriptions/plans/:id',superAuth,async(req,res,next)=>{try{const id=String(req.params.id||'').trim();const plan=(await pool.query('SELECT * FROM subscription_plans WHERE id=$1',[id])).rows[0];if(!plan)return res.status(404).json({error:'找不到方案'});const useCount=Number((await pool.query('SELECT COUNT(*)::int AS n FROM dealer_subscriptions WHERE plan_id=$1',[id])).rows[0]?.n||0);if(useCount>0)return res.status(409).json({error:`「${plan.name}」目前仍有 ${useCount} 間車行使用，為避免破壞既有訂閱不能直接刪除。請先替這些車行更換方案，或將此方案停用。`,inUse:true,useCount});await pool.query('DELETE FROM subscription_plans WHERE id=$1',[id]);res.json({ok:true,deleted:true})}catch(e){next(e)}});
app.post('/api/super/subscriptions/assign',superAuth,async(req,res,next)=>{const client=await pool.connect();try{const companyId=String(req.body?.companyId||''),planId=String(req.body?.planId||'');if(!companyId||!planId)return res.status(400).json({error:'請選擇車行與方案'});await client.query('BEGIN');const plan=(await client.query('SELECT * FROM subscription_plans WHERE id=$1 AND active=TRUE',[planId])).rows[0],company=(await client.query('SELECT * FROM companies WHERE id=$1 FOR UPDATE',[companyId])).rows[0];if(!plan||!company){await client.query('ROLLBACK');return res.status(404).json({error:'找不到車行或方案'})}const old=(await client.query('SELECT * FROM dealer_subscriptions WHERE company_id=$1 FOR UPDATE',[companyId])).rows[0],start=today(),end=old?.current_period_end||company.expires_at||addPlanPeriod(start,plan.billing_interval,plan.billing_interval_count),grace=addDateDays(end,plan.grace_days),ts=now();await client.query(`INSERT INTO dealer_subscriptions(company_id,plan_id,status,current_period_start,current_period_end,grace_until,auto_renew,cancel_at_period_end,provider_id,created_at,updated_at) VALUES($1,$2,'active',$3,$4,$5,FALSE,FALSE,'manual',$6,$6) ON CONFLICT(company_id) DO UPDATE SET plan_id=EXCLUDED.plan_id,status='active',grace_until=EXCLUDED.grace_until,updated_at=EXCLUDED.updated_at`,[companyId,planId,start,end,grace,ts]);await client.query(`UPDATE companies SET enabled=TRUE WHERE id=$1`,[companyId]);await subscriptionEvent(client,companyId,'plan_assigned',{oldStatus:old?.status||'',newStatus:'active',oldPeriodEnd:old?.current_period_end,newPeriodEnd:end,source:'super_admin',actor:req.auth.username||req.auth.sub,detail:`指定方案：${plan.name}`});await client.query('COMMIT');res.json({ok:true})}catch(e){try{await client.query('ROLLBACK')}catch{}next(e)}finally{try{client.release()}catch{}}});
app.post('/api/super/subscriptions/manual-payment',superAuth,async(req,res,next)=>{try{const companyId=String(req.body?.companyId||''),amount=Math.max(0,Number(req.body?.amount||0));if(!companyId)return res.status(400).json({error:'請選擇車行'});const sub=(await pool.query(`SELECT s.*,p.price_cents,p.currency,p.name plan_name FROM dealer_subscriptions s LEFT JOIN subscription_plans p ON p.id=s.plan_id WHERE s.company_id=$1`,[companyId])).rows[0];if(!sub)return res.status(400).json({error:'請先替車行指定訂閱方案'});const id=`pay_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,ts=now();await pool.query(`INSERT INTO payment_transactions(id,company_id,provider_id,amount_cents,currency,payment_type,status,description,created_at,updated_at) VALUES($1,$2,'manual',$3,$4,'manual','pending',$5,$6,$6)`,[id,companyId,Math.round((amount||Number(sub.price_cents||0)/100)*100),sub.currency||'TWD',String(req.body?.description||`人工收款：${sub.plan_name||''}`).slice(0,500),ts]);res.json({ok:true,paymentId:id})}catch(e){next(e)}});
app.post('/api/super/subscriptions/payments/:id/confirm',superAuth,async(req,res,next)=>{const client=await pool.connect();try{await client.query('BEGIN');const pay=(await client.query(`SELECT * FROM payment_transactions WHERE id=$1 FOR UPDATE`,[req.params.id])).rows[0];if(!pay){await client.query('ROLLBACK');return res.status(404).json({error:'找不到付款紀錄'})}if(pay.status==='paid'){await client.query('ROLLBACK');return res.json({ok:true,alreadyProcessed:true})}if(pay.status!=='pending'){await client.query('ROLLBACK');return res.status(400).json({error:`此付款目前為 ${pay.status}，無法確認`})}const sub=(await client.query(`SELECT s.*,p.billing_interval,p.billing_interval_count,p.grace_days,p.name plan_name FROM dealer_subscriptions s JOIN subscription_plans p ON p.id=s.plan_id WHERE s.company_id=$1 FOR UPDATE`,[pay.company_id])).rows[0];if(!sub){await client.query('ROLLBACK');return res.status(400).json({error:'找不到有效訂閱方案'})}const base=sub.current_period_end&&sub.current_period_end>=today()?sub.current_period_end:today(),newEnd=addPlanPeriod(base,sub.billing_interval,sub.billing_interval_count),grace=addDateDays(newEnd,sub.grace_days),ts=now();await client.query(`UPDATE payment_transactions SET status='paid',paid_at=$1,confirmed_at=$1,confirmed_by=$2,updated_at=$1 WHERE id=$3`,[ts,req.auth.username||req.auth.sub,pay.id]);await client.query(`UPDATE dealer_subscriptions SET status='active',current_period_start=COALESCE(current_period_start,$1),current_period_end=$2,grace_until=$3,cancel_at_period_end=FALSE,provider_id='manual',updated_at=$4 WHERE company_id=$5`,[today(),newEnd,grace,ts,pay.company_id]);await client.query(`UPDATE companies SET enabled=TRUE,expires_at=$1,trial=FALSE WHERE id=$2`,[newEnd,pay.company_id]);await subscriptionEvent(client,pay.company_id,'payment_confirmed',{oldStatus:sub.status,newStatus:'active',oldPeriodEnd:sub.current_period_end,newPeriodEnd:newEnd,source:'manual_payment',referenceId:pay.id,actor:req.auth.username||req.auth.sub,detail:`人工確認付款，自動續期至 ${newEnd}`});await client.query(`UPDATE dealer_renewal_requests SET status='closed',closed_at=$1,closed_by=$2,close_note='付款已確認，自動結案',updated_at=$1 WHERE company_id=$3 AND status IN ('pending','contacted')`,[ts,req.auth.username||req.auth.sub||'super_admin',pay.company_id]);await client.query('COMMIT');res.json({ok:true,newPeriodEnd:newEnd,graceUntil:grace})}catch(e){try{await client.query('ROLLBACK')}catch{}next(e)}finally{client.release()}});
app.delete('/api/super/subscriptions/payments/:id',superAuth,async(req,res,next)=>{const client=await pool.connect();try{const id=String(req.params.id||'').trim(),confirmed=req.body?.confirmDelete===true,ackPaid=req.body?.acknowledgePaid===true,reason=String(req.body?.reason||'Super Admin 手動刪除付款紀錄').slice(0,500);if(!confirmed)return res.status(400).json({error:'請完成刪除確認'});await client.query('BEGIN');const pay=(await client.query(`SELECT t.*,c.name AS company_name FROM payment_transactions t JOIN companies c ON c.id=t.company_id WHERE t.id=$1 FOR UPDATE OF t`,[id])).rows[0];if(!pay){await client.query('ROLLBACK');return res.status(404).json({error:'找不到付款紀錄'})}if(pay.deleted_at){await client.query('ROLLBACK');return res.json({ok:true,alreadyDeleted:true})}if(pay.status==='paid'&&!ackPaid){await client.query('ROLLBACK');return res.status(409).json({error:`此筆為已付款紀錄（${pay.company_name}）。刪除只會從付款清單隱藏，不會退款，也不會縮短已延長的訂閱期限。若仍要刪除，請再次確認。`,requiresPaidAck:true})}const actor=req.auth.username||req.auth.sub||'super_admin',ts=now();await client.query(`UPDATE payment_transactions SET deleted_at=$1,deleted_by=$2,delete_reason=$3,updated_at=$1 WHERE id=$4`,[ts,actor,reason,id]);await client.query('COMMIT');await auditSecurityEvent(req,{action:'payment_record_deleted',category:'subscription',status:'success',targetType:'payment_transaction',targetId:id,companyId:pay.company_id,detail:`付款紀錄已由 Super Admin 隱藏刪除｜車行：${pay.company_name}｜狀態：${pay.status}｜金額：${pay.amount_cents} cents｜原因：${reason}`});res.json({ok:true,softDeleted:true,paymentId:id,paidRecord:pay.status==='paid',subscriptionUnaffected:true,refundPerformed:false})}catch(e){try{await client.query('ROLLBACK')}catch{}next(e)}finally{client.release()}});
app.post('/api/super/subscriptions/:companyId/adjust-period',superAuth,async(req,res,next)=>{const client=await pool.connect();try{const companyId=String(req.params.companyId||'').trim(),newEnd=dateOnly(req.body?.currentPeriodEnd);if(!newEnd)return res.status(400).json({error:'請選擇新的付費期限'});await client.query('BEGIN');const sub=(await client.query(`SELECT s.*,c.name AS company_name,COALESCE(p.grace_days,0) AS plan_grace_days FROM dealer_subscriptions s JOIN companies c ON c.id=s.company_id LEFT JOIN subscription_plans p ON p.id=s.plan_id WHERE s.company_id=$1 FOR UPDATE OF s,c`,[companyId])).rows[0];if(!sub){await client.query('ROLLBACK');return res.status(404).json({error:'此車行目前沒有訂閱資料'})}const oldEnd=dateOnly(sub.current_period_end),grace=addDateDays(newEnd,Number(sub.plan_grace_days||0)),actor=req.auth.username||req.auth.sub||'super_admin';await client.query(`UPDATE dealer_subscriptions SET current_period_end=$1,grace_until=$2,updated_at=$3 WHERE company_id=$4`,[newEnd,grace,now(),companyId]);await client.query(`UPDATE companies SET expires_at=$1 WHERE id=$2`,[newEnd,companyId]);await subscriptionEvent(client,companyId,'period_adjusted_manually',{oldStatus:sub.status,newStatus:sub.status,oldPeriodEnd:oldEnd,newPeriodEnd:newEnd,source:'subscription_center',actor,detail:`訂閱中心手動調整期限：${oldEnd||'-'} → ${newEnd}；寬限至 ${grace}`});await client.query('COMMIT');res.json({ok:true,companyName:sub.company_name,oldPeriodEnd:oldEnd,newPeriodEnd:newEnd,graceUntil:grace})}catch(e){try{await client.query('ROLLBACK')}catch{}next(e)}finally{try{client.release()}catch{}}});
app.post('/api/super/subscriptions/:companyId/remove',superAuth,async(req,res,next)=>{const client=await pool.connect();try{const companyId=String(req.params.companyId||'').trim(),confirmed=req.body?.confirmRemove===true,ackPaid=req.body?.acknowledgePaidActive===true;if(!confirmed)return res.status(400).json({error:'請完成刪除訂閱確認'});await client.query('BEGIN');const sub=(await client.query(`SELECT s.*,c.name AS company_name,p.name AS plan_name FROM dealer_subscriptions s JOIN companies c ON c.id=s.company_id LEFT JOIN subscription_plans p ON p.id=s.plan_id WHERE s.company_id=$1 FOR UPDATE OF s,c`,[companyId])).rows[0];if(!sub){await client.query('ROLLBACK');return res.status(404).json({error:'此車行目前沒有訂閱資料'})}const paidInfo=(await client.query(`SELECT COUNT(*)::int AS paid_count,MAX(paid_at) AS last_paid_at FROM payment_transactions WHERE company_id=$1 AND status='paid'`,[companyId])).rows[0]||{};const paidCount=Number(paidInfo.paid_count||0),periodEnd=dateOnly(sub.current_period_end),paidActive=paidCount>0&&!!periodEnd&&periodEnd>=today();if(paidActive&&!ackPaid){await client.query('ROLLBACK');return res.status(409).json({error:`${sub.company_name} 已有付款紀錄，且目前方案尚未到期（${periodEnd}）。若仍要刪除，請再次確認。`,requiresPaidActiveAck:true,companyName:sub.company_name,planName:sub.plan_name||'',periodEnd,paidCount})}const actor=req.auth.username||req.auth.sub||'super_admin';await subscriptionEvent(client,companyId,'subscription_removed',{oldStatus:sub.status,newStatus:'removed',oldPeriodEnd:sub.current_period_end,newPeriodEnd:null,source:'super_admin',actor,detail:`解除車行訂閱｜方案：${sub.plan_name||sub.plan_id||'-'}｜原方案ID：${sub.plan_id||'-'}｜原期限：${periodEnd||'-'}｜已付款紀錄：${paidCount} 筆${paidActive?'｜未到期付費方案已由管理員二次確認刪除':''}`});await client.query(`DELETE FROM dealer_subscriptions WHERE company_id=$1`,[companyId]);await client.query(`UPDATE companies SET enabled=FALSE WHERE id=$1`,[companyId]);await client.query('COMMIT');res.json({ok:true,removed:true,companyId,companyName:sub.company_name,planName:sub.plan_name||'',paidActive,periodEnd,historyPreserved:true,licenseDisabled:true})}catch(e){try{await client.query('ROLLBACK')}catch{}next(e)}finally{try{client.release()}catch{}}});
app.post('/api/super/subscriptions/:companyId/action',superAuth,async(req,res,next)=>{const client=await pool.connect();try{const companyId=req.params.companyId,action=String(req.body?.action||'');await client.query('BEGIN');const sub=(await client.query('SELECT * FROM dealer_subscriptions WHERE company_id=$1 FOR UPDATE',[companyId])).rows[0];if(!sub){await client.query('ROLLBACK');return res.status(404).json({error:'尚未建立訂閱'})}let status=sub.status,cancel=sub.cancel_at_period_end,enabled=true;if(action==='suspend'){status='suspended';enabled=false}else if(action==='resume'){status='active';cancel=false}else if(action==='cancel_at_period_end'){cancel=true}else if(action==='cancel_now'){status='cancelled';enabled=false}else{await client.query('ROLLBACK');return res.status(400).json({error:'未知操作'})}await client.query(`UPDATE dealer_subscriptions SET status=$1,cancel_at_period_end=$2,updated_at=$3 WHERE company_id=$4`,[status,cancel,now(),companyId]);await client.query(`UPDATE companies SET enabled=$1 WHERE id=$2`,[enabled,companyId]);await subscriptionEvent(client,companyId,action,{oldStatus:sub.status,newStatus:status,oldPeriodEnd:sub.current_period_end,newPeriodEnd:sub.current_period_end,source:'super_admin',actor:req.auth.username||req.auth.sub});await client.query('COMMIT');res.json({ok:true})}catch(e){try{await client.query('ROLLBACK')}catch{}next(e)}finally{client.release()}});
app.get('/api/super/subscriptions/renewal-requests/count',superAuth,async(req,res,next)=>{try{const q=await pool.query(`SELECT COUNT(*) FILTER (WHERE status='pending')::int AS pending,COUNT(*) FILTER (WHERE status='contacted')::int AS contacted FROM dealer_renewal_requests WHERE status IN ('pending','contacted')`);res.json({pending:Number(q.rows[0]?.pending||0),contacted:Number(q.rows[0]?.contacted||0),open:Number(q.rows[0]?.pending||0)+Number(q.rows[0]?.contacted||0)})}catch(e){next(e)}});
app.get('/api/super/subscriptions/renewal-requests',superAuth,async(req,res,next)=>{try{const pageSize=10,p=Math.max(1,Number(req.query.page||1)),search=String(req.query.search||'').trim().slice(0,100),status=String(req.query.status||'').trim();const params=[],wh=[];if(search){params.push('%'+search+'%');wh.push(`(c.name ILIKE $${params.length} OR c.id ILIKE $${params.length} OR COALESCE(sp.name,'') ILIKE $${params.length} OR COALESCE(r.note,'') ILIKE $${params.length})`)}if(['pending','contacted','closed'].includes(status)){params.push(status);wh.push(`r.status=$${params.length}`)}const where=wh.length?'WHERE '+wh.join(' AND '):'';const total=Number((await pool.query(`SELECT COUNT(*)::int n FROM dealer_renewal_requests r JOIN companies c ON c.id=r.company_id LEFT JOIN subscription_plans sp ON sp.id=r.plan_id ${where}`,params)).rows[0]?.n||0),pages=Math.max(1,Math.ceil(total/pageSize)),safe=Math.min(p,pages),off=(safe-1)*pageSize;const qp=[...params,pageSize,off],li=params.length+1,oi=params.length+2;const rows=(await pool.query(`SELECT r.*,c.name AS company_name,c.enabled,c.expires_at,sp.name AS plan_name,sp.price_cents,sp.currency,ds.current_period_end,ds.grace_until,ds.status AS subscription_status FROM dealer_renewal_requests r JOIN companies c ON c.id=r.company_id LEFT JOIN subscription_plans sp ON sp.id=r.plan_id LEFT JOIN dealer_subscriptions ds ON ds.company_id=r.company_id ${where} ORDER BY CASE r.status WHEN 'pending' THEN 0 WHEN 'contacted' THEN 1 ELSE 2 END,r.requested_at DESC LIMIT $${li} OFFSET $${oi}`,qp)).rows;const c=await pool.query(`SELECT COUNT(*) FILTER (WHERE status='pending')::int AS pending,COUNT(*) FILTER (WHERE status='contacted')::int AS contacted FROM dealer_renewal_requests WHERE status IN ('pending','contacted')`);res.json({requests:rows,pagination:{page:safe,pageSize,total,totalPages:pages,search,status},counts:{pending:Number(c.rows[0]?.pending||0),contacted:Number(c.rows[0]?.contacted||0),open:Number(c.rows[0]?.pending||0)+Number(c.rows[0]?.contacted||0)}})}catch(e){next(e)}});
app.patch('/api/super/subscriptions/renewal-requests/:id',superAuth,async(req,res,next)=>{try{const id=Number(req.params.id),action=String(req.body?.action||''),note=String(req.body?.note||'').slice(0,500),actor=req.auth.username||req.auth.sub||'super_admin',ts=now();if(!Number.isFinite(id))return res.status(400).json({error:'無效續費申請編號'});const old=(await pool.query(`SELECT r.*,c.name AS company_name FROM dealer_renewal_requests r JOIN companies c ON c.id=r.company_id WHERE r.id=$1`,[id])).rows[0];if(!old)return res.status(404).json({error:'找不到續費申請'});let row;if(action==='contact'){row=(await pool.query(`UPDATE dealer_renewal_requests SET status='contacted',contacted_at=COALESCE(contacted_at,$1),contacted_by=$2,updated_at=$1 WHERE id=$3 RETURNING *`,[ts,actor,id])).rows[0]}else if(action==='close'){row=(await pool.query(`UPDATE dealer_renewal_requests SET status='closed',closed_at=$1,closed_by=$2,close_note=$3,updated_at=$1 WHERE id=$4 RETURNING *`,[ts,actor,note||'Super Admin 手動結案',id])).rows[0]}else if(action==='reopen'){const exists=(await pool.query(`SELECT id FROM dealer_renewal_requests WHERE company_id=$1 AND status IN ('pending','contacted') AND id<>$2 LIMIT 1`,[old.company_id,id])).rows[0];if(exists)return res.status(409).json({error:'此車行已有另一筆待處理續費申請'});row=(await pool.query(`UPDATE dealer_renewal_requests SET status='pending',closed_at=NULL,closed_by='',close_note='',updated_at=$1 WHERE id=$2 RETURNING *`,[ts,id])).rows[0]}else return res.status(400).json({error:'未知操作'});await auditSecurityEvent(req,{action:'renewal_request_'+action,category:'subscription',targetType:'dealer_renewal_request',targetId:String(id),companyId:old.company_id,detail:`續費申請 ${action}｜${old.company_name}`});res.json({ok:true,request:row})}catch(e){next(e)}});
app.delete('/api/super/subscriptions/renewal-requests/:id',superAuth,async(req,res,next)=>{try{const id=Number(req.params.id);if(!Number.isFinite(id))return res.status(400).json({error:'無效續費申請編號'});const row=(await pool.query(`DELETE FROM dealer_renewal_requests WHERE id=$1 RETURNING *`,[id])).rows[0];if(!row)return res.status(404).json({error:'找不到續費申請'});await auditSecurityEvent(req,{action:'renewal_request_deleted',category:'subscription',targetType:'dealer_renewal_request',targetId:String(id),companyId:row.company_id,detail:`Super Admin 刪除續費申請，原狀態：${row.status}`});res.json({ok:true})}catch(e){next(e)}});
app.get('/api/super/subscriptions/webhooks',superAuth,async(req,res,next)=>{try{
  const cleanup=await cleanupPaymentTechLogs();
  const pageSize=10,wp=Math.max(1,Number(req.query.webhookPage||1)),rp=Math.max(1,Number(req.query.renewalPage||1));
  const ws=String(req.query.webhookSearch||'').trim(),wst=String(req.query.webhookStatus||'').trim(),rs=String(req.query.renewalSearch||'').trim(),rst=String(req.query.renewalStatus||'').trim();
  const ww=[],wparams=[];if(ws){wparams.push(`%${ws}%`);ww.push(`(COALESCE(c.name,'') ILIKE $${wparams.length} OR w.provider_event_id ILIKE $${wparams.length} OR w.transaction_id ILIKE $${wparams.length} OR w.event_type ILIKE $${wparams.length} OR COALESCE(w.error_text,'') ILIKE $${wparams.length})`)}if(wst){wparams.push(wst);ww.push(`w.status=$${wparams.length}`)}const wwhere=ww.length?`WHERE ${ww.join(' AND ')}`:'';
  const wtotal=Number((await pool.query(`SELECT COUNT(*)::int n FROM payment_webhook_events w LEFT JOIN companies c ON c.id=(w.payload->>'companyId') ${wwhere}`,wparams)).rows[0]?.n||0),wpages=Math.max(1,Math.ceil(wtotal/pageSize)),wpage=Math.min(wp,wpages),woff=(wpage-1)*pageSize;
  const wq=[...wparams,pageSize,woff],wli=wparams.length+1,woi=wparams.length+2;const webhooks=(await pool.query(`SELECT w.*,p.display_name,c.name company_name,(w.payload->>'companyId') company_id FROM payment_webhook_events w LEFT JOIN payment_providers p ON p.id=w.provider_id LEFT JOIN companies c ON c.id=(w.payload->>'companyId') ${wwhere} ORDER BY w.id DESC LIMIT $${wli} OFFSET $${woi}`,wq)).rows;
  const rw=[],rparams=[];if(rs){rparams.push(`%${rs}%`);rw.push(`(c.name ILIKE $${rparams.length} OR r.attempt_key ILIKE $${rparams.length} OR COALESCE(r.transaction_id,'') ILIKE $${rparams.length} OR COALESCE(r.error_text,'') ILIKE $${rparams.length})`)}if(rst){rparams.push(rst);rw.push(`r.status=$${rparams.length}`)}const rwhere=rw.length?`WHERE ${rw.join(' AND ')}`:'';
  const rtotal=Number((await pool.query(`SELECT COUNT(*)::int n FROM payment_renewal_attempts r JOIN companies c ON c.id=r.company_id ${rwhere}`,rparams)).rows[0]?.n||0),rpages=Math.max(1,Math.ceil(rtotal/pageSize)),rpage=Math.min(rp,rpages),roff=(rpage-1)*pageSize;
  const rq=[...rparams,pageSize,roff],rli=rparams.length+1,roi=rparams.length+2;const renewals=(await pool.query(`SELECT r.*,c.name company_name,p.display_name provider_name FROM payment_renewal_attempts r JOIN companies c ON c.id=r.company_id LEFT JOIN payment_providers p ON p.id=r.provider_id ${rwhere} ORDER BY r.id DESC LIMIT $${rli} OFFSET $${roi}`,rq)).rows;
  res.json({retentionDays:PAYMENT_TECH_LOG_RETENTION_DAYS,cleanup,webhooks,renewals,webhookPagination:{page:wpage,pageSize,total:wtotal,totalPages:wpages,search:ws,status:wst},renewalPagination:{page:rpage,pageSize,total:rtotal,totalPages:rpages,search:rs,status:rst}})
}catch(e){next(e)}});
app.delete('/api/super/subscriptions/webhooks/:id',superAuth,async(req,res,next)=>{try{const id=Number(req.params.id);if(!Number.isFinite(id))return res.status(400).json({error:'無效紀錄編號'});const row=(await pool.query(`DELETE FROM payment_webhook_events WHERE id=$1 RETURNING id,provider_id,provider_event_id,event_type,status`,[id])).rows[0];if(!row)return res.status(404).json({error:'找不到 Webhook 紀錄'});await auditSecurityEvent(req,{action:'payment_webhook_log_deleted',category:'subscription',targetType:'payment_webhook_event',targetId:String(id),detail:`刪除 Webhook 技術紀錄：${row.provider_id}/${row.provider_event_id}/${row.status}`});res.json({ok:true})}catch(e){next(e)}});
app.delete('/api/super/subscriptions/renewal-attempts/:id',superAuth,async(req,res,next)=>{try{const id=Number(req.params.id);if(!Number.isFinite(id))return res.status(400).json({error:'無效紀錄編號'});const row=(await pool.query(`DELETE FROM payment_renewal_attempts WHERE id=$1 RETURNING id,company_id,attempt_key,status`,[id])).rows[0];if(!row)return res.status(404).json({error:'找不到續費嘗試紀錄'});await auditSecurityEvent(req,{action:'payment_renewal_log_deleted',category:'subscription',targetType:'payment_renewal_attempt',targetId:String(id),companyId:row.company_id,detail:`刪除續費嘗試技術紀錄：${row.attempt_key}/${row.status}`});res.json({ok:true})}catch(e){next(e)}});
app.patch('/api/super/subscriptions/providers/:id' ,superAuth,async(req,res,next)=>{try{const id=String(req.params.id||''),b=req.body||{},old=(await pool.query('SELECT * FROM payment_providers WHERE id=$1',[id])).rows[0];if(!old)return res.status(404).json({error:'找不到付款通道'});if(id==='manual'&&b.enabled===false)return res.status(400).json({error:'人工收款為基礎通道，不建議停用'});await pool.query(`UPDATE payment_providers SET enabled=$1,mode=$2,webhook_enabled=$3,updated_at=$4 WHERE id=$5`,[b.enabled===undefined?old.enabled:!!b.enabled,['test','live'].includes(b.mode)?b.mode:old.mode,b.webhookEnabled===undefined?old.webhook_enabled:!!b.webhookEnabled,now(),id]);await auditSecurityEvent(req,{action:'payment_provider_updated',category:'subscription',targetType:'payment_provider',targetId:id,detail:`付款通道設定更新：${id}`});res.json({ok:true})}catch(e){next(e)}});
app.post('/api/super/subscriptions/providers/:id/rotate-secret',superAuth,async(req,res,next)=>{try{const id=String(req.params.id||''),secret=crypto.randomBytes(24).toString('hex');const q=await pool.query(`UPDATE payment_providers SET webhook_secret=$1,updated_at=$2 WHERE id=$3 AND webhook_enabled=TRUE RETURNING id`,[secret,now(),id]);if(!q.rowCount)return res.status(404).json({error:'找不到支援 Webhook 的通道'});await auditSecurityEvent(req,{action:'webhook_secret_rotated',category:'subscription',targetType:'payment_provider',targetId:id,detail:'Webhook Secret 已重新產生'});res.json({ok:true,secret,note:'此 Secret 僅在本次回應顯示，請妥善保存。'})}catch(e){next(e)}});
app.post('/api/super/subscriptions/webhook-test',superAuth,async(req,res,next)=>{const client=await pool.connect();try{const b=req.body||{},providerId=String(b.providerId||'webhook_generic'),provider=(await client.query('SELECT * FROM payment_providers WHERE id=$1',[providerId])).rows[0];if(!provider)return res.status(404).json({error:'找不到付款通道'});const payload={companyId:String(b.companyId||''),eventType:String(b.eventType||'payment_succeeded'),providerEventId:String(b.providerEventId||`test_evt_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`),providerTransactionId:String(b.providerTransactionId||`test_tx_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`),amountCents:Math.max(0,Number(b.amountCents||0)),currency:'TWD',test:true};await client.query('BEGIN');const r=await applyProviderPayment(client,{provider,eventId:payload.providerEventId,eventType:payload.eventType,companyId:payload.companyId,providerTransactionId:payload.providerTransactionId,amountCents:payload.amountCents,currency:payload.currency,payload,actor:req.auth.username||req.auth.sub||'super_admin_test'});await client.query(`UPDATE payment_providers SET last_test_at=$1,last_test_status='success',updated_at=$1 WHERE id=$2`,[now(),provider.id]);await client.query('COMMIT');res.json({...r,testPayload:payload})}catch(e){try{await client.query('ROLLBACK')}catch{}next(e)}finally{client.release()}});
app.post('/api/super/subscriptions/auto-renew/run',superAuth,async(req,res,next)=>{try{await cleanupPaymentTechLogs();const r=await runAutoRenewalSweep();await auditSecurityEvent(req,{action:'auto_renewal_sweep',category:'subscription',targetType:'billing_engine',targetId:'phase12g',detail:`自動續費掃描：${r.scanned} 筆，建立 ${r.attempted} 筆`});res.json(r)}catch(e){next(e)}});
app.post('/api/payments/webhook/:providerId',async(req,res,next)=>{const client=await pool.connect();try{const provider=(await client.query(`SELECT * FROM payment_providers WHERE id=$1`,[req.params.providerId])).rows[0];if(!provider||!provider.enabled||!provider.webhook_enabled)return res.status(503).json({error:'此 Webhook 通道尚未啟用'});const sig=String(req.headers['x-webhook-signature']||'').replace(/^sha256=/,'').trim(),expected=webhookSignature(provider.webhook_secret,req.body||{});if(!safeEqualHex(sig,expected)){const b=req.body||{},eventId=String(b.providerEventId||`rejected_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`);await pool.query(`INSERT INTO payment_webhook_events(provider_id,provider_event_id,event_type,status,transaction_id,payload,error_text,received_at,processed_at) VALUES($1,$2,$3,'rejected_signature',$4,$5::jsonb,'Webhook 簽章驗證失敗',$6,$6) ON CONFLICT(provider_id,provider_event_id) DO NOTHING`,[provider.id,eventId,String(b.eventType||''),String(b.providerTransactionId||''),JSON.stringify({...b,companyId:String(b.companyId||'')}),now()]);return res.status(401).json({error:'Webhook 簽章驗證失敗'});}const b=req.body||{};await client.query('BEGIN');const r=await applyProviderPayment(client,{provider,eventId:b.providerEventId,eventType:b.eventType,companyId:b.companyId,providerTransactionId:b.providerTransactionId,amountCents:b.amountCents,currency:b.currency||'TWD',payload:b,actor:`webhook:${provider.id}`});await client.query('COMMIT');res.json(r)}catch(e){try{await client.query('ROLLBACK')}catch{}next(e)}finally{client.release()}});

app.use((err,req,res,next)=>{
  console.error(err);
  const code=String(err?.code||'SERVER_UNHANDLED_001');
  const companyId=req?.auth?.companyId||null;
  recordDiagnostic(companyId,code,'central_api',err?.message||'伺服器發生錯誤',{severity:'error',actor:req?.auth?.username||'',context:{method:req?.method,path:req?.path,httpStatus:500}}).catch(()=>{});
  res.status(500).json({error:'伺服器發生錯誤',errorCode:'SERVER_UNHANDLED_001'});
});

async function start(){
  if(CENTRAL_HA_ENABLED){
    const initial=await refreshHaRuntime({allowMigration:false,recordTransition:false});
    if(initial.dbRole==='primary'){
      await initDb();
      await refreshHaRuntime({allowMigration:false,recordTransition:false});
    }else if(initial.dbRole==='standby'){
      // Standby PostgreSQL is read-only. Never run migrations here; they arrive through WAL replication.
      console.log(`HA standby detected | instance=${CENTRAL_HA_INSTANCE_ID} site=${CENTRAL_HA_SITE} | waiting for promotion`);
    }else throw new Error(`Unable to determine PostgreSQL HA role: ${initial.lastError||'unknown'}`);
    setInterval(()=>{refreshHaRuntime({allowMigration:true,recordTransition:true}).catch(()=>{})},5000).unref();
  }else{
    await initDb();
    await refreshHaRuntime({allowMigration:false,recordTransition:false});
  }
  await loadMaintenanceRuntime();
  await refreshSubscriptionStatuses();
  setInterval(()=>{if(!CENTRAL_HA_ENABLED||haRuntime.dbRole==='primary')refreshSubscriptionStatuses()},60*1000).unref();
  setInterval(()=>{if(!CENTRAL_HA_ENABLED||haRuntime.dbRole==='primary')maybeRunScheduledCentralBackup()},15*60*1000).unref();
  setInterval(async()=>{
    try{
      if(CENTRAL_HA_ENABLED&&haRuntime.dbRole!=='primary')return;
      const m=await collectSystemMetrics();
      await pool.query(`INSERT INTO system_metric_samples(instance_id,site,sampled_at,cpu_percent,rss_bytes,heap_used_bytes,heap_total_bytes,system_free_bytes,system_total_bytes,event_loop_p95_ms,event_loop_max_ms,api_rps,api_p95_ms,api_error_rate,pg_total,pg_idle,pg_waiting,pg_query_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,[m.instanceId,m.site,m.sampledAt,m.cpuPercent,m.rssBytes,m.heapUsedBytes,m.heapTotalBytes,m.systemFreeBytes,m.systemTotalBytes,m.eventLoopP95Ms,m.eventLoopMaxMs,m.apiRps,m.apiP95Ms,m.apiErrorRate,m.pgTotal,m.pgIdle,m.pgWaiting,m.pgQueryMs]);
      await evaluatePerformanceAlerts(m);
      const cutoff=new Date(Date.now()-METRICS_RETENTION_HOURS*3600*1000).toISOString();
      await pool.query('DELETE FROM system_metric_samples WHERE sampled_at<$1',[cutoff]);
    }catch(e){console.warn('performance sample failed:',e?.message||e)}
  },METRICS_SAMPLE_MS).unref();
  setTimeout(()=>{if(!CENTRAL_HA_ENABLED||haRuntime.dbRole==='primary')maybeRunScheduledCentralBackup()},15*1000).unref();
  app.listen(PORT,()=>console.log(`Car Dealer Central API listening on http://localhost:${PORT} | HA=${CENTRAL_HA_ENABLED?'on':'off'} role=${haRuntime.dbRole}`));
}
start().catch(err=>{console.error('Server startup failed:',err);process.exit(1);});
