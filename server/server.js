import express from 'express';
import cors from 'cors';
import pg from 'pg';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 8787);
const JWT_SECRET = process.env.JWT_SECRET || 'DEV_ONLY_CHANGE_THIS_SECRET_BEFORE_DEPLOYING_0123456789';
const SUPER_ADMIN_USER = process.env.SUPER_ADMIN_USER || 'master';
const SUPER_ADMIN_PASSWORD = process.env.SUPER_ADMIN_PASSWORD || 'ChangeMe123!';
const DATABASE_URL = process.env.DATABASE_URL;

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
    enabled:!!u.enabled
  };
}

function salesSafeSnapshot(snapshot,user){
  const d=snapshot&&typeof snapshot==='object'?snapshot:{};
  const cars=(Array.isArray(d.cars)?d.cars:[])
    .filter(c=>c&&c.status==='在庫')
    .map(c=>({
      id:c.id,plate:c.plate||'',model:c.model||'',year:c.year||'',mileage:Number(c.mileage||0),
      inDate:c.inDate||'',floorPrice:Number(c.floorPrice||0),status:'在庫',
      inspectionStatus:c.inspectionStatus||'',
      inspectionCertPhotos:Array.isArray(c.inspectionCertPhotos)?c.inspectionCertPhotos:[],
      intakePhotos:Array.isArray(c.intakePhotos)?c.intakePhotos:[]
    }));
  const requests=(Array.isArray(d.saleRequests)?d.saleRequests:[])
    .filter(r=>r&&String(r.salesId)===String(user.id))
    .map(r=>({
      id:r.id,carId:r.carId,plate:r.plate||'',model:r.model||'',floorPrice:Number(r.floorPrice||0),
      sellPrice:Number(r.sellPrice||0),saleDate:r.saleDate||'',requestedAt:r.requestedAt||'',
      salesId:r.salesId,salesName:r.salesName||user.name,commissionRate:Number(r.commissionRate??user.commission_rate??0),
      expectedCommission:Number(r.expectedCommission||0),status:r.status||'待確認',
      rejectReason:r.rejectReason||'',rejectedAt:r.rejectedAt||'',confirmedAt:r.confirmedAt||'',cancelReason:r.cancelReason||'',canceledAt:r.canceledAt||''
    }));
  return {
    settings:{companyName:d.settings?.companyName||''},
    users:[{...userDto(user),password:''}],
    cars,
    saleRequests:requests
  };
}
function snapshotForUser(snapshot,user){
  return user?.role==='sales'?salesSafeSnapshot(snapshot,user):snapshot;
}

function signUser(u){
  return jwt.sign(
    {sub:u.id,companyId:u.company_id,role:u.role,username:u.username},
    JWT_SECRET,
    {expiresIn:'12h'}
  );
}
function signSuper(){
  return jwt.sign({sub:'platform-admin',role:'platformAdmin'},JWT_SECRET,{expiresIn:'12h'});
}

async function initDb(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS companies(
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      enabled BOOLEAN NOT NULL DEFAULT TRUE,
      start_date TEXT,
      expires_at TEXT,
      created_at TEXT NOT NULL,
      created_by TEXT NOT NULL DEFAULT 'self',
      contact_email TEXT,
      trial BOOLEAN NOT NULL DEFAULT TRUE
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

    ALTER TABLE users ADD COLUMN IF NOT EXISTS base_salary DOUBLE PRECISION NOT NULL DEFAULT 0;

    CREATE INDEX IF NOT EXISTS idx_users_company ON users(company_id);
    CREATE INDEX IF NOT EXISTS idx_users_company_role ON users(company_id,role);
  `);
  const r = await pool.query('SELECT NOW() AS now');
  console.log('PostgreSQL connected:', r.rows[0].now);
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

function auth(req,res,next){
  const token=(req.headers.authorization||'').replace(/^Bearer\s+/i,'');
  if(!token)return res.status(401).json({error:'未登入'});
  try{
    req.auth=jwt.verify(token,JWT_SECRET);
    next();
  }catch{
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
app.use('/sales', express.static(path.join(__dirname,'public','sales')));
app.get('/sales',(req,res)=>res.redirect('/sales/'));

app.get('/api/health',async(req,res)=>{
  try{
    await pool.query('SELECT 1');
    res.json({ok:true,time:now(),service:'car-dealer-central',database:'postgres',version:'2.2.5'});
  }catch(e){
    res.status(503).json({ok:false,error:'database unavailable'});
  }
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

    res.json({token:signUser(user),company:companyDto({...company,main_username:username}),user:userDto(user),snapshot,version:1});
  }catch(e){
    try{ await client.query('ROLLBACK'); }catch{}
    next(e);
  }finally{ client.release(); }
});

app.post('/api/auth/login',async(req,res,next)=>{
  try{
    const {companyCode,username,password}=req.body||{};
    const c=await getCompany(companyCode);
    if(!c)return res.status(401).json({error:'找不到此車行代碼'});
    const st=companyStatus(c);
    if(st!=='啟用中')return res.status(403).json({error:`車行目前${st}`});

    const {rows}=await pool.query('SELECT * FROM users WHERE company_id=$1 AND username=$2 AND enabled=TRUE',[companyCode,username]);
    const u=rows[0];
    if(!u||!verifyPassword(password,u.password_hash))return res.status(401).json({error:'帳號或密碼錯誤'});

    const snap=await getSnapshot(companyCode);
    res.json({token:signUser(u),company:companyDto(c),user:userDto(u),snapshot:snapshotForUser(snap.snapshot,u),version:snap.version});
  }catch(e){ next(e); }
});

app.get('/api/session/restore',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    const u=await getUserById(req.auth.companyId,req.auth.sub);
    if(!u)return res.status(401).json({error:'帳號已失效'});
    const snap=await getSnapshot(req.auth.companyId);
    res.json({company:companyDto(req.company),user:userDto(u),snapshot:snapshotForUser(snap.snapshot,u),version:snap.version});
  }catch(e){ next(e); }
});

app.get('/api/company/snapshot',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    const u=await getUserById(req.auth.companyId,req.auth.sub);
    if(!u)return res.status(401).json({error:'帳號已失效'});
    const snap=await getSnapshot(req.auth.companyId);
    res.json({company:companyDto(req.company),user:userDto(u),snapshot:snapshotForUser(snap.snapshot,u),version:snap.version,updatedAt:snap.updatedAt});
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
    `,[req.auth.companyId,ver,JSON.stringify(clean),now()]);
    await client.query('COMMIT');
    res.json({ok:true,version:ver});
  }catch(e){
    try{ await client.query('ROLLBACK'); }catch{}
    if(e?.code==='23505')return res.status(409).json({error:'同一車行內帳號名稱不可重複'});
    next(e);
  }finally{ client.release(); }
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
    const c=d.cars.find(x=>x.id===body.carId);
    if(!c||c.status!=='在庫'){await client.query('ROLLBACK');return res.status(400).json({error:'車輛不存在或已售'});}
    if(d.saleRequests.some(r=>r.carId===c.id&&r.status==='待確認')){await client.query('ROLLBACK');return res.status(409).json({error:'此車已有待確認成交申請'});}
    const {rows}=await client.query('SELECT * FROM users WHERE id=$1 AND company_id=$2 AND enabled=TRUE',[req.auth.sub,req.auth.companyId]);
    const u=rows[0];
    if(!u){await client.query('ROLLBACK');return res.status(401).json({error:'帳號不存在'});}
    const sell=Number(body.sellPrice||0);
    if(sell<=0){await client.query('ROLLBACK');return res.status(400).json({error:'售價錯誤'});}
    const rate=Number(u.commission_rate||0),floor=Number(c.floorPrice||0);
    d.saleRequests.push({
      id:`req_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,carId:c.id,plate:c.plate,model:c.model,
      floorPrice:floor,sellPrice:sell,saleDate:body.saleDate||today(),requestedAt:today(),salesId:u.id,salesName:u.name,
      commissionRate:rate,expectedCommission:Math.max(0,sell-floor)*rate/100,status:'待確認'
    });
    const ver=existing.version+1;
    await client.query('UPDATE snapshots SET version=$1,json=$2::jsonb,updated_at=$3 WHERE company_id=$4',[ver,JSON.stringify(d),now(),req.auth.companyId]);
    await client.query('COMMIT');
    res.json({ok:true,version:ver,snapshot:salesSafeSnapshot(d,u)});
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
    const r={id:`req_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,carId:c.id,plate:c.plate,model:c.model,floorPrice:floor,sellPrice:sell,saleDate:saleDate||today(),requestedAt:today(),salesId:u.id,salesName:u.name,commissionRate:rate,expectedCommission:Math.max(0,sell-floor)*rate/100,status:'待確認',directByAdmin:true};
    d.saleRequests.push(r);
    const ver=Number(lock.rows[0].version||0)+1;
    await client.query('UPDATE snapshots SET version=$1,json=$2::jsonb,updated_at=$3 WHERE company_id=$4',[ver,JSON.stringify(d),now(),req.auth.companyId]);
    await client.query('COMMIT');res.json({ok:true,version:ver,snapshot:d,request:r});
  }catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}
});

app.post('/api/admin/sale/confirm',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    if(req.auth.role!=='admin')return res.status(403).json({error:'僅車行後台可確認成交'});
    const {requestId,transfer=0,fuel=0,license=0,other=0,otherName=''}=req.body||{};
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
    const commission=Math.max(0,Number(r.sellPrice||0)-Number(r.floorPrice||0))*Number(r.commissionRate||0)/100;
    const extra=tr+fu+li+ot,totalCost=Number(c.totalCost||c.purchasePrice||0);
    Object.assign(c,{status:'已售',outDate:r.saleDate,sellPrice:Number(r.sellPrice||0),salesId:r.salesId,salesName:r.salesName,commissionRate:Number(r.commissionRate||0),commissionAmount:commission,saleTransferFee:tr,saleFuelFee:fu,saleLicenseTax:li,saleOtherFee:ot,saleOtherFeeName:String(otherName||''),saleExtraCost:extra,companyProfit:Number(r.sellPrice||0)-totalCost-extra-commission});
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
    await client.query('UPDATE snapshots SET version=$1,json=$2::jsonb,updated_at=$3 WHERE company_id=$4',[ver,JSON.stringify(d),now(),req.auth.companyId]);
    await client.query('COMMIT');res.json({ok:true,version:ver,snapshot:d});
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
    await client.query('UPDATE snapshots SET version=$1,json=$2::jsonb,updated_at=$3 WHERE company_id=$4',[ver,JSON.stringify(d),now(),req.auth.companyId]);
    await client.query('COMMIT');
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
    await client.query('UPDATE snapshots SET version=$1,json=$2::jsonb,updated_at=$3 WHERE company_id=$4',[ver,JSON.stringify(d),now(),req.auth.companyId]);
    await client.query('COMMIT');res.json({ok:true,version:ver,snapshot:d});
  }catch(e){try{await client.query('ROLLBACK')}catch{};next(e)}finally{client.release()}
});

// -------------------- Super Admin cloud API --------------------
app.post('/api/super/login',(req,res)=>{
  const {username,password}=req.body||{};
  if(username!==SUPER_ADMIN_USER||password!==SUPER_ADMIN_PASSWORD)return res.status(401).json({error:'Super Admin 帳號或密碼錯誤'});
  res.json({token:signSuper(),user:{username:SUPER_ADMIN_USER,role:'platformAdmin'}});
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

app.get('/api/super/data',superAuth,async(req,res,next)=>{
  try{
    const companies=(await pool.query(`
      SELECT c.*,
        (SELECT u.username FROM users u WHERE u.company_id=c.id AND u.role='admin' AND u.enabled=TRUE ORDER BY u.updated_at ASC LIMIT 1) AS main_username
      FROM companies c ORDER BY c.created_at DESC
    `)).rows;
    const users=(await pool.query('SELECT * FROM users ORDER BY company_id,role,name')).rows;
    const snaps=(await pool.query('SELECT * FROM snapshots')).rows;
    const usersBy=new Map(),snapBy=new Map();
    for(const u of users){if(!usersBy.has(u.company_id))usersBy.set(u.company_id,[]);usersBy.get(u.company_id).push(userDto(u));}
    for(const s of snaps)snapBy.set(s.company_id,{snapshot:s.json,version:Number(s.version||0),updatedAt:s.updated_at});
    res.json({
      companies:companies.map(c=>{
        const s=snapBy.get(c.id)||{snapshot:{settings:{companyName:c.name,taxRate:0},users:[],cars:[],saleRequests:[]},version:0,updatedAt:null};
        return {company:companyDto(c),users:usersBy.get(c.id)||[],snapshot:s.snapshot,version:s.version,updatedAt:s.updatedAt};
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
  res.status(500).json({error:'伺服器發生錯誤'});
});

async function start(){
  await initDb();
  app.listen(PORT,()=>console.log(`Car Dealer Central API listening on http://localhost:${PORT}`));
}
start().catch(err=>{console.error('Server startup failed:',err);process.exit(1);});
