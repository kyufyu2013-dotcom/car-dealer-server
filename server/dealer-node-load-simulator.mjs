#!/usr/bin/env node
import { randomUUID } from 'crypto';

const args=Object.fromEntries(process.argv.slice(2).map((x,i,a)=>x.startsWith('--')?[x.slice(2),a[i+1]&&!a[i+1].startsWith('--')?a[i+1]:'true']:null).filter(Boolean));
const base=String(args.url||process.env.LOAD_TEST_URL||'http://127.0.0.1:8787').replace(/\/$/,'');
const token=String(args.token||process.env.LOAD_TEST_TOKEN||'');
const nodes=Math.max(1,Math.min(100000,Number(args.nodes||10000)));
const durationSec=Math.max(1,Math.min(86400,Number(args.duration||60)));
const intervalMs=Math.max(1000,Math.min(300000,Number(args.interval||15000)));
const concurrency=Math.max(1,Math.min(5000,Number(args.concurrency||200)));
const confirm=String(args.confirm||'');
const u=new URL(base);const local=['localhost','127.0.0.1','::1'].includes(u.hostname);
if(!local&&String(process.env.ALLOW_REMOTE_LOAD_TEST||'').toLowerCase()!=='true')throw new Error('遠端壓力測試被安全鎖阻擋。確認是你有權測試的主機後，設定 ALLOW_REMOTE_LOAD_TEST=true。');
if(confirm!=='I_UNDERSTAND_LOAD_TEST')throw new Error('請加上 --confirm I_UNDERSTAND_LOAD_TEST，避免誤觸大量流量。');
if(token.length<16)throw new Error('LOAD_TEST_TOKEN 至少需要 16 字元。');
const headers={'content-type':'application/json','x-loadtest-token':token};
const runId=`lt_${new Date().toISOString().replace(/[-:.TZ]/g,'').slice(0,14)}_${randomUUID().slice(0,8)}`;
const samples=[];let ok=0,errors=0,total=0,stopped=false,nextIndex=0,inFlight=0,seq=0;
const startWall=Date.now();
function percentile(a,p){if(!a.length)return 0;const x=[...a].sort((m,n)=>m-n);return x[Math.min(x.length-1,Math.floor((x.length-1)*p))]}
async function post(path,body){const t=performance.now();const r=await fetch(base+path,{method:'POST',headers,body:JSON.stringify(body)});const ms=performance.now()-t;if(!r.ok){let msg='HTTP '+r.status;try{msg=(await r.json()).error||msg}catch{}throw Object.assign(new Error(msg),{ms,status:r.status})}return {body:await r.json(),ms}}
const start=await post('/api/load-test/run/start',{runId,targetNodes:nodes,durationSeconds:durationSec,heartbeatIntervalMs:intervalMs,concurrency});
console.log(`Phase 8B run ${runId}`);console.log(`target=${base} nodes=${nodes.toLocaleString()} interval=${intervalMs}ms duration=${durationSec}s concurrency=${concurrency} serverLimit=${start.body.maxRps}rps`);
const targetRps=nodes/(intervalMs/1000);console.log(`理論 heartbeat 流量：約 ${targetRps.toFixed(1)} req/s`);
const endAt=startWall+durationSec*1000;
async function sendOne(i){inFlight++;total++;const nodeNum=i%nodes;const payload={runId,nodeId:`sim-node-${String(nodeNum).padStart(6,'0')}`,companyId:`SIM${String(nodeNum).padStart(6,'0')}`,appVersion:'0.10.1',seq:++seq,payloadBytes:512};try{const r=await post('/api/load-test/heartbeat',payload);ok++;samples.push(r.ms);if(samples.length>250000)samples.shift()}catch(e){errors++;if(errors<=10)console.error('request failed:',e.message)}finally{inFlight--}}
// Evenly distribute virtual node heartbeats instead of creating a one-second thundering herd.
const spacingMs=1000/targetRps;let nextDue=performance.now();
while(Date.now()<endAt){while(inFlight<concurrency&&performance.now()>=nextDue&&Date.now()<endAt){sendOne(nextIndex++);nextDue+=spacingMs}if(total&&total%Math.max(1000,Math.round(targetRps*10))===0){process.stdout.write(`\rrequests=${total} ok=${ok} error=${errors} inflight=${inFlight}   `)}await new Promise(r=>setTimeout(r,Math.min(10,Math.max(1,nextDue-performance.now()))))}
while(inFlight>0)await new Promise(r=>setTimeout(r,20));
const elapsed=(Date.now()-startWall)/1000;const result={runId,status:errors?'completed_with_errors':'completed',totalRequests:total,successCount:ok,errorCount:errors,rps:total/elapsed,p50Ms:percentile(samples,.50),p95Ms:percentile(samples,.95),p99Ms:percentile(samples,.99),maxMs:samples.length?Math.max(...samples):0,detail:{elapsedSeconds:elapsed,targetRps,successRate:total?ok/total:0}};
await post('/api/load-test/run/finish',result);
console.log('\n');console.log(JSON.stringify({...result,rps:Number(result.rps.toFixed(2)),p50Ms:Number(result.p50Ms.toFixed(2)),p95Ms:Number(result.p95Ms.toFixed(2)),p99Ms:Number(result.p99Ms.toFixed(2)),maxMs:Number(result.maxMs.toFixed(2))},null,2));
if(errors)process.exitCode=2;
