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
  const payload={v:1,type:'sales-lan-auth',companyId:company.id,company:companyDto(company),issuedAtMs,offlineUntilMs:issuedAtMs+duration*1000,users:(users||[]).filter(u=>u.role==='sales'&&u.enabled!==false).map(u=>({id:u.id,username:u.username,name:u.name,role:'sales',commissionRate:Number(u.commission_rate||0),baseSalary:Number(u.base_salary||0),tokenVersion:Number(u.token_version||0),passwordHash:String(u.password_hash||'')}))};
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
    mainUsername:c.main_username||''
  };
}
function userDto(u){
  return {
    id:u.id,
    username:u.username,
    name:u.name,
    role:u.role,
    commissionRate:Number(u.commission_rate||0),
    baseSalary:Number(u.base_salary||0),
    enabled:!!u.enabled,
    passwordChangedAt:u.password_changed_at||'',
    passwordChangedBy:u.password_changed_by||''
  };
}

function salesSafeSnapshot(snapshot,user){
  const d=snapshot&&typeof snapshot==='object'?snapshot:{};
  const cars=(Array.isArray(d.cars)?d.cars:[])
    .filter(c=>c&&c.status==='在庫')
    .map(c=>({
      id:c.id,plate:c.plate||'',model:c.model||'',year:c.year||'',mileage:Number(c.mileage||0),
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
      id:r.id,operationId:r.operationId||'',carId:r.carId,plate:r.plate||'',model:r.model||'',floorPrice:Number(r.floorPrice||0),
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
    // Phase 3: actual photos and sensitive business fields stay Dealer Node local-only.
    for(const k of ['purchasePrice','costs','totalCost','source','sourceNote','salesNote','inspectionCertPhotos','intakePhotos','companyProfit','saleTransferFee','saleFuelFee','saleLicenseTax','saleOtherFee','saleOtherFeeName','saleExtraCost']) delete x[k];
    return x;
  });
  // Detailed operation/salary history is authoritative on the Dealer Node.
  delete d.operationLogs;
  delete d.salaryHistory;
  return d;
}
function snapshotForUser(snapshot,user){
  return user?.role==='sales'?salesSafeSnapshot(snapshot,user):snapshot;
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

const SERVER_SCHEMA_TARGET=12;
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
      UPDATE desktop_update_policy SET latest_version='0.10.5',updated_at=CURRENT_TIMESTAMP::text,updated_by='migration-v12' WHERE id=1 AND latest_version IN ('0.10.1','0.10.2','0.10.3','0.10.4');
    `
  }
];

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

async function initDb(){
  await runServerMigrations();
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
    if(st!=='啟用中')return res.status(403).json({error:`車行授權狀態：${st}`});
    req.company=c;
    next();
  }catch(e){ next(e); }
}
function superAuth(req,res,next){
  auth(req,res,()=>{
    if(req.auth.role!=='platformAdmin')return res.status(403).json({error:'權限不足'});
    next();
  });
}

const app=express();
app.use(cors({origin:true,credentials:false}));
app.use(express.json({limit:'30mb'}));
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

app.get('/api/ready',async(req,res)=>{
  const st=await refreshHaRuntime({allowMigration:false,recordTransition:false});
  const ready=!CENTRAL_HA_ENABLED?st.schemaReady:(st.dbRole==='primary'&&st.schemaReady);
  const body={ok:ready,time:now(),service:'car-dealer-central',version:'2.4.53',haEnabled:CENTRAL_HA_ENABLED,dbRole:st.dbRole,writeReady:ready,schemaReady:st.schemaReady,site:CENTRAL_HA_SITE,instanceId:CENTRAL_HA_INSTANCE_ID};
  res.status(ready?200:503).json(body);
});

app.get('/api/health',async(req,res)=>{
  try{
    await pool.query('SELECT 1');
    res.json({ok:true,time:now(),service:'car-dealer-central',database:'postgres',version:'2.4.53',schemaVersion:SERVER_SCHEMA_TARGET,architecture:'production-phase8d-alert-center-ha'});
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
      settings:{companyName,taxRate:0},
      users:[{id:user.id,username:user.username,password:'',name:user.name,role:'admin',commissionRate:0,baseSalary:0}],
      cars:[],saleRequests:[],operationLogs:[]
    };

    await client.query('BEGIN');
    await client.query(`
      INSERT INTO companies(id,name,enabled,start_date,expires_at,created_at,created_by,contact_email,trial)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
    `,[company.id,company.name,true,company.start_date,company.expires_at,company.created_at,company.created_by,company.contact_email,true]);
    await client.query(`
      INSERT INTO users(id,company_id,username,password_hash,name,role,commission_rate,base_salary,enabled,updated_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    `,[user.id,user.company_id,user.username,hashPassword(password),user.name,user.role,0,0,true,user.updated_at]);
    await client.query(`
      INSERT INTO snapshots(company_id,version,json,updated_at) VALUES($1,$2,$3::jsonb,$4)
    `,[companyCode,1,JSON.stringify(snapshot),now()]);
    await client.query('COMMIT');

    const registeredCompany={...company,main_username:username};
    res.json({token:signUser(user),company:companyDto(registeredCompany),user:userDto(user),snapshot,version:1,offlineTicket:issueOfflineTicket(registeredCompany,user,password,OFFLINE_GRACE_SECONDS),offlinePolicy:{graceSeconds:OFFLINE_GRACE_SECONDS,test:false}});
  }catch(e){
    try{ await client.query('ROLLBACK'); }catch{}
    next(e);
  }finally{ client.release(); }
});

app.post('/api/auth/login',async(req,res,next)=>{
  try{
    const {companyCode,username,password,rememberLogin=false}=req.body||{};
    const c=await getCompany(companyCode);
    if(!c)return res.status(401).json({error:'找不到此車行代碼'});
    const st=companyStatus(c);
    if(st!=='啟用中')return res.status(403).json({error:`車行目前${st}`});

    const {rows}=await pool.query('SELECT * FROM users WHERE company_id=$1 AND username=$2 AND enabled=TRUE',[companyCode,username]);
    const u=rows[0];
    if(!u||!verifyPassword(password,u.password_hash))return res.status(401).json({error:'帳號或密碼錯誤'});

    const test=(await pool.query('SELECT * FROM offline_license_tests WHERE company_id=$1',[companyCode])).rows[0];
    if(test?.enabled && test?.simulate_outage)return res.status(503).json({error:'授權服務暫時無回應',offlineFaultTest:true});
    const snap=await getSnapshot(companyCode);
    await pool.query('UPDATE companies SET last_auth_at=$1 WHERE id=$2',[now(),companyCode]);
    const fresh=await getCompany(companyCode);
    const offlineSeconds=test?.enabled?Number(test.duration_seconds||60):OFFLINE_GRACE_SECONDS;
    res.json({token:signUser(u,!!rememberLogin),company:companyDto(fresh),user:userDto(u),snapshot:snapshotForUser(snap.snapshot,u),version:snap.version,offlineTicket:issueOfflineTicket(fresh,u,password,offlineSeconds),offlinePolicy:{graceSeconds:offlineSeconds,test:!!test?.enabled},rememberLogin:!!rememberLogin});
  }catch(e){ next(e); }
});

app.get('/api/session/restore',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    const u=await getUserById(req.auth.companyId,req.auth.sub);
    if(!u)return res.status(401).json({error:'帳號已失效'});
    const snap=await getSnapshot(req.auth.companyId);
    res.json({token:refreshedUserToken(req,u),company:companyDto(req.company),user:userDto(u),snapshot:snapshotForUser(snap.snapshot,u),version:snap.version});
  }catch(e){ next(e); }
});


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
    res.json({token:refreshedUserToken(req,u),company:companyDto(req.company),user:userDto(u),snapshot:snapshotForUser(snap.snapshot,u),version:snap.version,updatedAt:snap.updatedAt});
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
    if(req.auth.role==='sales')return res.status(403).json({error:'業務端不可直接覆寫整份車行資料，請使用業務專用操作'});

    await client.query('BEGIN');
    const lock=await client.query('SELECT version,json FROM snapshots WHERE company_id=$1 FOR UPDATE',[req.auth.companyId]);
    const existing=lock.rows[0]
      ? {version:Number(lock.rows[0].version),snapshot:lock.rows[0].json}
      : {version:0,snapshot:{settings:{companyName:'車行',taxRate:0},users:[],cars:[],saleRequests:[],operationLogs:[]}};
    if(baseVersion!==existing.version){
      await client.query('ROLLBACK');
      return res.status(409).json({error:'中央資料已有新版本',version:existing.version});
    }

    const clean=JSON.parse(JSON.stringify(incoming));
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
      if(old){
        await client.query(`
          UPDATE users SET username=$1,password_hash=$2,name=$3,role=$4,commission_rate=$5,base_salary=$6,enabled=TRUE,updated_at=$7
          WHERE id=$8 AND company_id=$9
        `,[x.username,ph||old.password_hash,x.name||x.username,x.role||'sales',Number(x.commissionRate||0),Number(x.baseSalary||0),now(),old.id,req.auth.companyId]);
        if(old.id!==x.id){ x.id=old.id; keep.add(old.id); }
      }else{
        if(!ph)return res.status(400).json({error:`新帳號 ${x.username} 必須設定密碼`});
        await client.query(`
          INSERT INTO users(id,company_id,username,password_hash,name,role,commission_rate,base_salary,enabled,updated_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,TRUE,$9)
        `,[x.id,req.auth.companyId,x.username,ph,x.name||x.username,x.role||'sales',Number(x.commissionRate||0),Number(x.baseSalary||0),now()]);
      }
      x.password='';
    }

    const all=await client.query('SELECT id,role FROM users WHERE company_id=$1',[req.auth.companyId]);
    for(const u of all.rows){
      if(u.role==='sales'&&!keep.has(u.id))await client.query('UPDATE users SET enabled=FALSE,updated_at=$1 WHERE id=$2',[now(),u.id]);
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


// ---- Password management v8.3 ----
// Dealership admin settings: company display name is canonical in companies + snapshot settings.
app.put('/api/admin/company/settings',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    if(req.auth.role!=='admin')return res.status(403).json({error:'僅車行管理員可修改車行設定'});
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
    if(req.auth.role!=='admin')return res.status(403).json({error:'僅車行管理員可重設業務密碼'});
    const newPassword=String(req.body?.newPassword||'');
    if(newPassword.length<6)return res.status(400).json({error:'新密碼至少 6 碼'});
    const {rows}=await pool.query("SELECT * FROM users WHERE id=$1 AND company_id=$2 AND role='sales' AND enabled=TRUE",[req.params.userId,req.auth.companyId]);
    const target=rows[0]; if(!target)return res.status(404).json({error:'找不到此業務帳號'});
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
    if(d.saleRequests.some(r=>r.carId===c.id&&r.status==='待確認')){await client.query('ROLLBACK');return res.status(409).json({error:'此車已有待確認成交申請'});}
    const sell=Number(body.sellPrice||0);
    if(sell<=0){await client.query('ROLLBACK');return res.status(400).json({error:'售價錯誤'});}
    const rate=Number(u.commission_rate||0),floor=Number(c.floorPrice||0);
    const commissionMode=c.commissionMode==='fixed'?'fixed':'percentage',fixedCommissionAmount=Math.max(0,Number(c.fixedCommissionAmount||0));
    const expectedCommission=commissionMode==='fixed'?fixedCommissionAmount:Math.max(0,sell-floor)*rate/100;
    d.saleRequests.push({
      id:`req_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,operationId:operationId||`legacy_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,carId:c.id,plate:c.plate,model:c.model,
      floorPrice:floor,sellPrice:sell,saleDate:body.saleDate||today(),requestedAt:today(),salesId:u.id,salesName:u.name,
      commissionRate:rate,commissionMode,fixedCommissionAmount,expectedCommission,status:'待確認'
    });
    const ver=existing.version+1;
    await client.query('UPDATE snapshots SET version=$1,json=$2::jsonb,updated_at=$3 WHERE company_id=$4',[ver,JSON.stringify(cloudOperationalSnapshot(d)),now(),req.auth.companyId]);
    await client.query('COMMIT');
    recordSyncEvent(req.auth.companyId,'sale_request',`成交申請已送達：${c.plate||c.model||c.id}`,{actor:u.username||u.name,operationId:operationId||null});
    notifySalesInventoryChanged(req.auth.companyId,ver,'saleRequest');
    res.json({ok:true,ackOperationId:operationId||null,version:ver,snapshot:salesSafeSnapshot(d,u)});
  }catch(e){
    try{ await client.query('ROLLBACK'); }catch{}
    next(e);
  }finally{ client.release(); }
});


// -------------------- Dealership admin sale workflow --------------------
app.post('/api/admin/sale/direct-request',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    if(req.auth.role!=='admin')return res.status(403).json({error:'僅車行後台可使用'});
    const {carId,salesId,sellPrice,saleDate}=req.body||{};
    await client.query('BEGIN');
    const lock=await client.query('SELECT version,json FROM snapshots WHERE company_id=$1 FOR UPDATE',[req.auth.companyId]);
    if(!lock.rows[0]){await client.query('ROLLBACK');return res.status(404).json({error:'車行資料不存在'});}
    const d=lock.rows[0].json||{};d.cars=Array.isArray(d.cars)?d.cars:[];d.saleRequests=Array.isArray(d.saleRequests)?d.saleRequests:[];
    const c=d.cars.find(x=>String(x.id)===String(carId));
    if(!c||c.status!=='在庫'){await client.query('ROLLBACK');return res.status(409).json({error:'此車已售或不存在，不能再次建立成交'});}
    if(d.saleRequests.some(r=>String(r.carId)===String(c.id)&&r.status==='待確認')){await client.query('ROLLBACK');return res.status(409).json({error:'此車已有待確認成交申請，請直接處理原申請'});}
    if(d.saleRequests.some(r=>String(r.carId)===String(c.id)&&r.status==='已成交')){await client.query('ROLLBACK');return res.status(409).json({error:'此車已有成交紀錄'});}
    const ur=await client.query("SELECT * FROM users WHERE id=$1 AND company_id=$2 AND role='sales' AND enabled=TRUE",[salesId,req.auth.companyId]);
    const u=ur.rows[0];if(!u){await client.query('ROLLBACK');return res.status(400).json({error:'業務帳號不存在或已停用'});}
    const sell=Number(sellPrice||0);if(sell<=0){await client.query('ROLLBACK');return res.status(400).json({error:'售價錯誤'});}
    const floor=Number(c.floorPrice||0),rate=Number(u.commission_rate||0);
    const commissionMode=c.commissionMode==='fixed'?'fixed':'percentage',fixedCommissionAmount=Math.max(0,Number(c.fixedCommissionAmount||0));
    const expectedCommission=commissionMode==='fixed'?fixedCommissionAmount:Math.max(0,sell-floor)*rate/100;
    const r={id:`req_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,carId:c.id,plate:c.plate,model:c.model,floorPrice:floor,sellPrice:sell,saleDate:saleDate||today(),requestedAt:today(),salesId:u.id,salesName:u.name,commissionRate:rate,commissionMode,fixedCommissionAmount,expectedCommission,status:'待確認',directByAdmin:true};
    d.saleRequests.push(r);
    const ver=Number(lock.rows[0].version||0)+1;
    await client.query('UPDATE snapshots SET version=$1,json=$2::jsonb,updated_at=$3 WHERE company_id=$4',[ver,JSON.stringify(cloudOperationalSnapshot(d)),now(),req.auth.companyId]);
    await client.query('COMMIT');recordSyncEvent(req.auth.companyId,'sale_request','後台建立成交申請',{actor:req.auth.username||req.auth.sub});notifySalesInventoryChanged(req.auth.companyId,ver,'saleConfirmed');res.json({ok:true,version:ver,snapshot:d,request:r});
  }catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}
});

app.post('/api/admin/sale/confirm',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    if(req.auth.role!=='admin')return res.status(403).json({error:'僅車行後台可確認成交'});
    const {requestId,transfer=0,fuel=0,license=0,other=0,otherName='',localTotalCost=0}=req.body||{};
    await client.query('BEGIN');
    const lock=await client.query('SELECT version,json FROM snapshots WHERE company_id=$1 FOR UPDATE',[req.auth.companyId]);
    if(!lock.rows[0]){await client.query('ROLLBACK');return res.status(404).json({error:'車行資料不存在'});}
    const d=lock.rows[0].json||{};d.cars=Array.isArray(d.cars)?d.cars:[];d.saleRequests=Array.isArray(d.saleRequests)?d.saleRequests:[];
    const r=d.saleRequests.find(x=>String(x.id)===String(requestId));
    if(!r){await client.query('ROLLBACK');return res.status(404).json({error:'找不到成交申請'});}
    if(r.status!=='待確認'){await client.query('ROLLBACK');return res.status(409).json({error:`此申請目前為「${r.status}」，不可重複確認`});}
    const c=d.cars.find(x=>String(x.id)===String(r.carId));
    if(!c){await client.query('ROLLBACK');return res.status(404).json({error:'找不到車輛'});}
    if(c.status!=='在庫'){await client.query('ROLLBACK');return res.status(409).json({error:'此車已完成成交，不可再次確認'});}
    if(d.saleRequests.some(x=>String(x.carId)===String(c.id)&&x.status==='已成交')){await client.query('ROLLBACK');return res.status(409).json({error:'此車已有成交紀錄，不可重複成交'});}
    const tr=Number(transfer||0),fu=Number(fuel||0),li=Number(license||0),ot=Number(other||0);
    const commission=r.commissionMode==='fixed'?Math.max(0,Number(r.fixedCommissionAmount||r.expectedCommission||0)):Math.max(0,Number(r.sellPrice||0)-Number(r.floorPrice||0))*Number(r.commissionRate||0)/100;
    const extra=tr+fu+li+ot,totalCost=Math.max(0,Number(localTotalCost||0));
    Object.assign(c,{status:'已售',outDate:r.saleDate,sellPrice:Number(r.sellPrice||0),salesId:r.salesId,salesName:r.salesName,commissionRate:Number(r.commissionRate||0),commissionMode:r.commissionMode==='fixed'?'fixed':'percentage',fixedCommissionAmount:Math.max(0,Number(r.fixedCommissionAmount||0)),commissionAmount:commission,saleTransferFee:tr,saleFuelFee:fu,saleLicenseTax:li,saleOtherFee:ot,saleOtherFeeName:String(otherName||''),saleExtraCost:extra,companyProfit:Number(r.sellPrice||0)-totalCost-extra-commission});
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
    await client.query('COMMIT');recordSyncEvent(req.auth.companyId,'sale_confirm',`確認成交：${c.plate||c.model||c.id}`,{actor:req.auth.username||req.auth.sub,operationId:r.operationId||null});notifySalesInventoryChanged(req.auth.companyId,ver,'saleStatusChanged');res.json({ok:true,version:ver,snapshot:d});
  }catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}
});

app.post('/api/admin/sale/cancel',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    if(req.auth.role!=='admin')return res.status(403).json({error:'僅車行後台可取消已確認成交'});
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
    res.json({ok:true,version:ver,snapshot:d,canceledRequestId:r.id});
  }catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}
});

app.post('/api/admin/sale/reject',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    if(req.auth.role!=='admin')return res.status(403).json({error:'僅車行後台可駁回成交申請'});
    const {requestId,reason}=req.body||{};if(!String(reason||'').trim())return res.status(400).json({error:'駁回原因不可空白'});
    await client.query('BEGIN');
    const lock=await client.query('SELECT version,json FROM snapshots WHERE company_id=$1 FOR UPDATE',[req.auth.companyId]);
    if(!lock.rows[0]){await client.query('ROLLBACK');return res.status(404).json({error:'車行資料不存在'});}
    const d=lock.rows[0].json||{};d.saleRequests=Array.isArray(d.saleRequests)?d.saleRequests:[];
    const r=d.saleRequests.find(x=>String(x.id)===String(requestId));
    if(!r){await client.query('ROLLBACK');return res.status(404).json({error:'找不到成交申請'});}
    if(r.status!=='待確認'){await client.query('ROLLBACK');return res.status(409).json({error:`此申請目前為「${r.status}」，不可再次處理`});}
    r.status='已駁回';r.rejectReason=String(reason).trim();r.rejectedAt=now();
    d.operationLogs=Array.isArray(d.operationLogs)?d.operationLogs:[];
    d.operationLogs.push({id:`log_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,action:'駁回成交申請',carId:r.carId,plate:r.plate||'',requestId:r.id,reason:r.rejectReason,operatedAt:r.rejectedAt,operatedBy:req.auth.username||req.auth.sub});
    const ver=Number(lock.rows[0].version||0)+1;
    await client.query('UPDATE snapshots SET version=$1,json=$2::jsonb,updated_at=$3 WHERE company_id=$4',[ver,JSON.stringify(cloudOperationalSnapshot(d)),now(),req.auth.companyId]);
    await client.query('COMMIT');recordSyncEvent(req.auth.companyId,'sale_reject',`駁回成交申請：${r.plate||r.carId}`,{actor:req.auth.username||req.auth.sub,operationId:r.operationId||null});notifySalesInventoryChanged(req.auth.companyId,ver,'saleStatusChanged');res.json({ok:true,version:ver,snapshot:d});
  }catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}
});

// -------------------- Super Admin cloud API --------------------
app.post('/api/super/login',(req,res)=>{
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
    const seq=Math.max(0,Number(b.seq||0)),appVersion=String(b.appVersion||'0.10.5').slice(0,40),payloadBytes=Math.max(0,Math.min(1000000,Number(b.payloadBytes||0)));
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
              [`managed_${runId}_${n}`,runId,`managed_company_${n}`,'0.10.5',seq,512,now()]);
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
    const salesUsers=(await pool.query("SELECT id,company_id,username,password_hash,name,role,commission_rate,base_salary,enabled,token_version FROM users WHERE company_id=$1 AND role='sales' AND enabled=TRUE ORDER BY updated_at ASC",[req.auth.companyId])).rows;
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
const NODE_RESOURCES=new Set(['companyData','vehicleDetail','vehiclePhoto','vehiclePhotoBundle','salesInventory','backupStatus','createBackup']);
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
    const n=(await pool.query('SELECT * FROM dealer_nodes WHERE company_id=$1',[req.auth.companyId])).rows[0];
    if(!n||!nodeOnline(n))return res.status(409).json({error:'車行主機目前離線，暫時無法讀取照片'});
    const id=`sphotos_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
    const requestedAt=now(),expiresAt=new Date(Date.now()+60000).toISOString();
    const payload={carId,max:8,requesterSalesId:String(req.auth.sub)};
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
    const count=kind==='inspection'?Number(car.inspectionPhotoCount||0):Number(car.intakePhotoCount||0);
    if(index>=count)return res.status(404).json({error:'此照片不存在'});

    const n=(await pool.query('SELECT * FROM dealer_nodes WHERE company_id=$1',[req.auth.companyId])).rows[0];
    if(!n||!nodeOnline(n))return res.status(409).json({error:'車行主機目前離線，暫時無法讀取照片'});

    const id=`sphoto_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
    const requestedAt=now(),expiresAt=new Date(Date.now()+60000).toISOString();
    const payload={carId,kind,index,requesterSalesId:String(req.auth.sub)};
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
    const n=(await pool.query('SELECT * FROM dealer_nodes WHERE company_id=$1',[req.auth.companyId])).rows[0];
    if(!n||!nodeOnline(n))return res.status(409).json({error:'車行主機目前離線'});
    const id=`sinv_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
    const requestedAt=now(),expiresAt=new Date(Date.now()+60000).toISOString();
    const payload={requesterSalesId:String(req.auth.sub)};
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


const CENTRAL_BACKUP_TABLES=['companies','users','snapshots','dealer_nodes','offline_license_tests','sync_events','dealer_node_requests','schema_migrations','migration_safety_events','diagnostic_events','desktop_update_policy','desktop_update_events','central_backup_policy','central_ha_events','load_test_runs'];
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
    const payload={format:'car-dealer-central-logical-backup',formatVersion:1,createdAt:now(),serverVersion:'9.3.41',apiVersion:'2.4.53',schemaVersion:schema.currentVersion,tables:data};
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

const CENTRAL_RESTORE_TABLES=['companies','users','snapshots','dealer_nodes','offline_license_tests','sync_events','dealer_node_requests','diagnostic_events','desktop_update_policy','desktop_update_events','central_backup_policy','central_ha_events','load_test_runs'];
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
    const nodes=(await pool.query('SELECT * FROM dealer_nodes')).rows;
    const nodeBy=new Map(nodes.map(n=>[n.company_id,n]));
    const usersBy=new Map(),snapBy=new Map();
    for(const u of users){if(!usersBy.has(u.company_id))usersBy.set(u.company_id,[]);usersBy.get(u.company_id).push(userDto(u));}
    for(const s of snaps)snapBy.set(s.company_id,{snapshot:s.json,version:Number(s.version||0),updatedAt:s.updated_at});
    res.json({
      companies:companies.map(c=>{
        const s=snapBy.get(c.id)||{snapshot:{settings:{companyName:c.name,taxRate:0},users:[],cars:[],saleRequests:[]},version:0,updatedAt:null};
        return {company:companyDto(c),users:usersBy.get(c.id)||[],snapshot:s.snapshot,version:s.version,updatedAt:s.updatedAt,node:nodeBy.get(c.id)||null};
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
    const main=rows.find(x=>x.role==='admin'&&x.enabled)?.username||'';
    res.json({company:companyDto({...c,main_username:main}),users:rows.map(userDto),snapshot:snap.snapshot,version:snap.version,updatedAt:snap.updatedAt});
  }catch(e){ next(e); }
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
    const snapshot={settings:{companyName,taxRate:0},users:[{id,username,password:'',name:ownerName,role:'admin',commissionRate:0,baseSalary:0}],cars:[],saleRequests:[],operationLogs:[]};
    await client.query('BEGIN');
    await client.query(`INSERT INTO companies(id,name,enabled,start_date,expires_at,created_at,created_by,contact_email,trial) VALUES($1,$2,$3,$4,$5,$6,'manual',$7,$8)`,[companyCode,companyName,enabled,startDate,expiresAt,now(),String(b.email||''),trial]);
    await client.query(`INSERT INTO users(id,company_id,username,password_hash,name,role,commission_rate,base_salary,enabled,updated_at) VALUES($1,$2,$3,$4,$5,'admin',0,0,TRUE,$6)`,[id,companyCode,username,hashPassword(password),ownerName,now()]);
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
  try{
    const c=await getCompany(req.params.id);
    if(!c)return res.status(404).json({error:'找不到車行'});
    const enabled=req.body.enabled===undefined?c.enabled:!!req.body.enabled;
    const start=req.body.startDate===undefined?c.start_date:req.body.startDate;
    const exp=req.body.expiresAt===undefined?c.expires_at:req.body.expiresAt;
    const trial=req.body.trial===undefined?c.trial:!!req.body.trial;
    if(start&&exp&&exp<start)return res.status(400).json({error:'到期日不能早於啟用日'});
    await pool.query('UPDATE companies SET enabled=$1,start_date=$2,expires_at=$3,trial=$4 WHERE id=$5',[enabled,start||'',exp||'',trial,c.id]);
    const updated=await getCompany(c.id);
    res.json({ok:true,company:companyDto(updated)});
  }catch(e){ next(e); }
});

app.delete('/api/super/companies/:id',superAuth,async(req,res,next)=>{
  try{
    const c=await getCompany(req.params.id);
    if(!c)return res.status(404).json({error:'找不到車行'});
    await pool.query('DELETE FROM companies WHERE id=$1',[c.id]);
    res.json({ok:true,deleted:{id:c.id,name:c.name}});
  }catch(e){ next(e); }
});

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
