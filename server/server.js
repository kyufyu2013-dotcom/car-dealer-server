import express from 'express';
import cors from 'cors';
import pg from 'pg';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const { Pool } = pg;

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
  // Render Internal Database URL normally does not need SSL.
  // If you later switch to an external provider, set PGSSL=true.
  ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : false
});

function now(){ return new Date().toISOString(); }
function today(){ return new Date().toISOString().slice(0,10); }
function addDays(n){ const d=new Date(); d.setUTCDate(d.getUTCDate()+n); return d.toISOString().slice(0,10); }

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
    status:companyStatus(c)
  };
}
function userDto(u){
  return {
    id:u.id,
    username:u.username,
    name:u.name,
    role:u.role,
    commissionRate:Number(u.commission_rate||0),
    enabled:!!u.enabled
  };
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

    CREATE INDEX IF NOT EXISTS idx_users_company ON users(company_id);
  `);
  const r = await pool.query('SELECT NOW() AS now');
  console.log('PostgreSQL connected:', r.rows[0].now);
}

async function getCompany(companyId){
  const {rows}=await pool.query('SELECT * FROM companies WHERE id=$1',[companyId]);
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
    return {
      version:Number(row.version||0),
      snapshot:row.json,
      updatedAt:row.updated_at
    };
  }
  return {
    version:0,
    snapshot:{settings:{companyName:'車行',taxRate:0},users:[],cars:[],saleRequests:[]},
    updatedAt:null
  };
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

app.get('/api/health',async(req,res)=>{
  try{
    await pool.query('SELECT 1');
    res.json({ok:true,time:now(),service:'car-dealer-central',database:'postgres'});
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
      id:companyCode,
      name:companyName,
      enabled:true,
      start_date:today(),
      expires_at:addDays(7),
      created_at:now(),
      created_by:'self',
      contact_email:email||'',
      trial:true
    };
    const user={
      id:`admin_${crypto.randomUUID()}`,
      company_id:companyCode,
      username,
      name:ownerName,
      role:'admin',
      commission_rate:0,
      enabled:true,
      updated_at:now()
    };
    const snapshot={
      settings:{companyName,taxRate:0},
      users:[{
        id:user.id,username:user.username,password:'',
        name:user.name,role:'admin',commissionRate:0
      }],
      cars:[],
      saleRequests:[]
    };

    await client.query('BEGIN');
    await client.query(`
      INSERT INTO companies
      (id,name,enabled,start_date,expires_at,created_at,created_by,contact_email,trial)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
    `,[company.id,company.name,true,company.start_date,company.expires_at,
       company.created_at,company.created_by,company.contact_email,true]);

    await client.query(`
      INSERT INTO users
      (id,company_id,username,password_hash,name,role,commission_rate,enabled,updated_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
    `,[user.id,user.company_id,user.username,hashPassword(password),user.name,
       user.role,0,true,user.updated_at]);

    await client.query(`
      INSERT INTO snapshots(company_id,version,json,updated_at)
      VALUES($1,$2,$3::jsonb,$4)
    `,[companyCode,1,JSON.stringify(snapshot),now()]);

    await client.query('COMMIT');

    res.json({
      token:signUser(user),
      company:companyDto(company),
      user:userDto(user),
      snapshot,
      version:1
    });
  }catch(e){
    try{ await client.query('ROLLBACK'); }catch{}
    next(e);
  }finally{
    client.release();
  }
});

app.post('/api/auth/login',async(req,res,next)=>{
  try{
    const {companyCode,username,password}=req.body||{};
    const c=await getCompany(companyCode);
    if(!c)return res.status(401).json({error:'找不到此車行代碼'});
    const st=companyStatus(c);
    if(st!=='啟用中')return res.status(403).json({error:`車行目前${st}`});

    const {rows}=await pool.query(
      'SELECT * FROM users WHERE company_id=$1 AND username=$2 AND enabled=TRUE',
      [companyCode,username]
    );
    const u=rows[0];
    if(!u||!verifyPassword(password,u.password_hash))
      return res.status(401).json({error:'帳號或密碼錯誤'});

    const snap=await getSnapshot(companyCode);
    res.json({
      token:signUser(u),
      company:companyDto(c),
      user:userDto(u),
      snapshot:snap.snapshot,
      version:snap.version
    });
  }catch(e){ next(e); }
});

app.get('/api/session/restore',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    const u=await getUserById(req.auth.companyId,req.auth.sub);
    if(!u)return res.status(401).json({error:'帳號已失效'});
    const snap=await getSnapshot(req.auth.companyId);
    res.json({
      company:companyDto(req.company),
      user:userDto(u),
      snapshot:snap.snapshot,
      version:snap.version
    });
  }catch(e){ next(e); }
});

app.get('/api/company/snapshot',auth,requireActiveCompany,async(req,res,next)=>{
  try{
    const snap=await getSnapshot(req.auth.companyId);
    res.json({
      company:companyDto(req.company),
      snapshot:snap.snapshot,
      version:snap.version,
      updatedAt:snap.updatedAt
    });
  }catch(e){ next(e); }
});

app.put('/api/company/snapshot',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    const incoming=req.body?.snapshot;
    const baseVersion=Number(req.body?.baseVersion||0);

    if(!incoming||typeof incoming!=='object')
      return res.status(400).json({error:'snapshot 不正確'});
    if(req.auth.role==='sales')
      return res.status(403).json({error:'業務端不可直接覆寫整份車行資料，請使用業務專用操作'});

    await client.query('BEGIN');
    const lock=await client.query(
      'SELECT version,json FROM snapshots WHERE company_id=$1 FOR UPDATE',
      [req.auth.companyId]
    );
    const existing=lock.rows[0]
      ? {version:Number(lock.rows[0].version),snapshot:lock.rows[0].json}
      : {version:0,snapshot:{settings:{companyName:'車行',taxRate:0},users:[],cars:[],saleRequests:[]}};

    if(baseVersion!==existing.version){
      await client.query('ROLLBACK');
      return res.status(409).json({error:'中央資料已有新版本',version:existing.version});
    }

    const clean=JSON.parse(JSON.stringify(incoming));
    const users=Array.isArray(clean.users)?clean.users:[];
    const keep=new Set();

    for(const x of users){
      if(!x?.id||!x?.username)continue;
      keep.add(x.id);

      const existingUser=await client.query(
        'SELECT * FROM users WHERE company_id=$1 AND username=$2',
        [req.auth.companyId,x.username]
      );
      const old=existingUser.rows[0];
      const ph=x.password?hashPassword(x.password):(old?.password_hash||'');

      await client.query(`
        INSERT INTO users
        (id,company_id,username,password_hash,name,role,commission_rate,enabled,updated_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,TRUE,$8)
        ON CONFLICT(company_id,username)
        DO UPDATE SET
          name=EXCLUDED.name,
          role=EXCLUDED.role,
          commission_rate=EXCLUDED.commission_rate,
          enabled=TRUE,
          updated_at=EXCLUDED.updated_at,
          password_hash=CASE
            WHEN EXCLUDED.password_hash='' THEN users.password_hash
            ELSE EXCLUDED.password_hash
          END
      `,[x.id,req.auth.companyId,x.username,ph,x.name||x.username,
         x.role||'sales',Number(x.commissionRate||0),now()]);

      x.password='';
    }

    const all=await client.query(
      'SELECT id,role FROM users WHERE company_id=$1',
      [req.auth.companyId]
    );
    for(const u of all.rows){
      if(u.role==='sales'&&!keep.has(u.id)){
        await client.query(
          'UPDATE users SET enabled=FALSE,updated_at=$1 WHERE id=$2',
          [now(),u.id]
        );
      }
    }

    const ver=existing.version+1;
    await client.query(`
      INSERT INTO snapshots(company_id,version,json,updated_at)
      VALUES($1,$2,$3::jsonb,$4)
      ON CONFLICT(company_id)
      DO UPDATE SET version=EXCLUDED.version,json=EXCLUDED.json,updated_at=EXCLUDED.updated_at
    `,[req.auth.companyId,ver,JSON.stringify(clean),now()]);

    await client.query('COMMIT');
    res.json({ok:true,version:ver});
  }catch(e){
    try{ await client.query('ROLLBACK'); }catch{}
    next(e);
  }finally{
    client.release();
  }
});

app.post('/api/sales/request',auth,requireActiveCompany,async(req,res,next)=>{
  const client=await pool.connect();
  try{
    if(req.auth.role!=='sales')
      return res.status(403).json({error:'僅業務帳號可使用'});

    const body=req.body||{};
    await client.query('BEGIN');

    const lock=await client.query(
      'SELECT version,json FROM snapshots WHERE company_id=$1 FOR UPDATE',
      [req.auth.companyId]
    );
    if(!lock.rows[0]){
      await client.query('ROLLBACK');
      return res.status(404).json({error:'車行資料不存在'});
    }

    const existing={
      version:Number(lock.rows[0].version),
      snapshot:lock.rows[0].json
    };
    const d=existing.snapshot;
    d.saleRequests=Array.isArray(d.saleRequests)?d.saleRequests:[];
    d.cars=Array.isArray(d.cars)?d.cars:[];

    const c=d.cars.find(x=>x.id===body.carId);
    if(!c||c.status!=='在庫'){
      await client.query('ROLLBACK');
      return res.status(400).json({error:'車輛不存在或已售'});
    }
    if(d.saleRequests.some(r=>r.carId===c.id&&r.status==='待確認')){
      await client.query('ROLLBACK');
      return res.status(409).json({error:'此車已有待確認成交申請'});
    }

    const {rows}=await client.query('SELECT * FROM users WHERE id=$1',[req.auth.sub]);
    const u=rows[0];
    if(!u){
      await client.query('ROLLBACK');
      return res.status(401).json({error:'帳號不存在'});
    }

    const sell=Number(body.sellPrice||0);
    if(sell<=0){
      await client.query('ROLLBACK');
      return res.status(400).json({error:'售價錯誤'});
    }

    const rate=Number(u.commission_rate||0);
    const floor=Number(c.floorPrice||0);

    d.saleRequests.push({
      id:`req_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
      carId:c.id,
      plate:c.plate,
      model:c.model,
      floorPrice:floor,
      sellPrice:sell,
      saleDate:body.saleDate||today(),
      requestedAt:today(),
      salesId:u.id,
      salesName:u.name,
      commissionRate:rate,
      expectedCommission:Math.max(0,sell-floor)*rate/100,
      status:'待確認'
    });

    const ver=existing.version+1;
    await client.query(
      'UPDATE snapshots SET version=$1,json=$2::jsonb,updated_at=$3 WHERE company_id=$4',
      [ver,JSON.stringify(d),now(),req.auth.companyId]
    );
    await client.query('COMMIT');

    res.json({ok:true,version:ver,snapshot:d});
  }catch(e){
    try{ await client.query('ROLLBACK'); }catch{}
    next(e);
  }finally{
    client.release();
  }
});

app.post('/api/super/login',(req,res)=>{
  const {username,password}=req.body||{};
  if(username!==SUPER_ADMIN_USER||password!==SUPER_ADMIN_PASSWORD)
    return res.status(401).json({error:'Super Admin 帳號或密碼錯誤'});
  res.json({token:signSuper()});
});

app.get('/api/super/companies',superAuth,async(req,res,next)=>{
  try{
    const {rows}=await pool.query('SELECT * FROM companies ORDER BY created_at DESC');
    res.json({companies:rows.map(companyDto)});
  }catch(e){ next(e); }
});

app.get('/api/super/companies/:id',superAuth,async(req,res,next)=>{
  try{
    const c=await getCompany(req.params.id);
    if(!c)return res.status(404).json({error:'找不到車行'});

    const {rows}=await pool.query(
      'SELECT * FROM users WHERE company_id=$1 ORDER BY role,name',
      [c.id]
    );
    const snap=await getSnapshot(c.id);

    res.json({
      company:companyDto(c),
      users:rows.map(userDto),
      snapshot:snap.snapshot,
      version:snap.version,
      updatedAt:snap.updatedAt
    });
  }catch(e){ next(e); }
});

app.patch('/api/super/companies/:id/license',superAuth,async(req,res,next)=>{
  try{
    const c=await getCompany(req.params.id);
    if(!c)return res.status(404).json({error:'找不到車行'});

    const enabled=req.body.enabled===undefined?c.enabled:!!req.body.enabled;
    const start=req.body.startDate===undefined?c.start_date:req.body.startDate;
    const exp=req.body.expiresAt===undefined?c.expires_at:req.body.expiresAt;
    const trial=req.body.trial===undefined?c.trial:!!req.body.trial;

    await pool.query(
      'UPDATE companies SET enabled=$1,start_date=$2,expires_at=$3,trial=$4 WHERE id=$5',
      [enabled,start||'',exp||'',trial,c.id]
    );
    const updated=await getCompany(c.id);
    res.json({ok:true,company:companyDto(updated)});
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

start().catch(err=>{
  console.error('Server startup failed:',err);
  process.exit(1);
});