import express from 'express';
import cors from 'cors';
import Database from 'better-sqlite3';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const PORT = Number(process.env.PORT || 8787);
const JWT_SECRET = process.env.JWT_SECRET || 'DEV_ONLY_CHANGE_THIS_SECRET_BEFORE_DEPLOYING_0123456789';
const SUPER_ADMIN_USER = process.env.SUPER_ADMIN_USER || 'master';
const SUPER_ADMIN_PASSWORD = process.env.SUPER_ADMIN_PASSWORD || 'ChangeMe123!';

const db = new Database('car-dealer-central.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS companies(
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1,
 start_date TEXT,
 expires_at TEXT,
 created_at TEXT NOT NULL,
 created_by TEXT NOT NULL DEFAULT 'self',
 contact_email TEXT,
 trial INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS users(
 id TEXT PRIMARY KEY,
 company_id TEXT NOT NULL,
 username TEXT NOT NULL,
 password_hash TEXT NOT NULL,
 name TEXT NOT NULL,
 role TEXT NOT NULL,
 commission_rate REAL NOT NULL DEFAULT 0,
 enabled INTEGER NOT NULL DEFAULT 1,
 updated_at TEXT NOT NULL,
 UNIQUE(company_id, username)
);
CREATE TABLE IF NOT EXISTS snapshots(
 company_id TEXT PRIMARY KEY,
 version INTEGER NOT NULL DEFAULT 0,
 json TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
`);

function now(){ return new Date().toISOString(); }
function today(){ return new Date().toISOString().slice(0,10); }
function addDays(n){ const d=new Date(); d.setUTCDate(d.getUTCDate()+n); return d.toISOString().slice(0,10); }
function hashPassword(password, salt=crypto.randomBytes(16).toString('hex')){
 const hash=crypto.scryptSync(String(password),salt,64).toString('hex');
 return `${salt}:${hash}`;
}
function verifyPassword(password, stored){
 try{ const [salt,hash]=String(stored).split(':'); const calc=crypto.scryptSync(String(password),salt,64); return crypto.timingSafeEqual(calc,Buffer.from(hash,'hex')); }catch{return false;}
}
function companyStatus(c){
 const t=today(); if(!c.enabled)return '已停用'; if(c.start_date&&c.start_date>t)return '尚未啟用'; if(c.expires_at&&c.expires_at<t)return '已到期'; return '啟用中';
}
function companyDto(c){return {id:c.id,name:c.name,enabled:!!c.enabled,startDate:c.start_date||'',expiresAt:c.expires_at||'',createdAt:c.created_at,createdBy:c.created_by,contactEmail:c.contact_email||'',trial:!!c.trial,status:companyStatus(c)}}
function userDto(u){return {id:u.id,username:u.username,name:u.name,role:u.role,commissionRate:Number(u.commission_rate||0),enabled:!!u.enabled}}
function signUser(u){return jwt.sign({sub:u.id,companyId:u.company_id,role:u.role,username:u.username},JWT_SECRET,{expiresIn:'12h'})}
function signSuper(){return jwt.sign({sub:'platform-admin',role:'platformAdmin'},JWT_SECRET,{expiresIn:'12h'})}
function getSnapshot(companyId){
 const row=db.prepare('SELECT * FROM snapshots WHERE company_id=?').get(companyId);
 return row ? {version:row.version,snapshot:JSON.parse(row.json),updatedAt:row.updated_at} : {version:0,snapshot:{settings:{companyName:'車行',taxRate:0},users:[],cars:[],saleRequests:[]},updatedAt:null};
}
function auth(req,res,next){
 const token=(req.headers.authorization||'').replace(/^Bearer\s+/i,''); if(!token)return res.status(401).json({error:'未登入'});
 try{req.auth=jwt.verify(token,JWT_SECRET);next()}catch{return res.status(401).json({error:'登入已失效，請重新登入'})}
}
function requireActiveCompany(req,res,next){
 const c=db.prepare('SELECT * FROM companies WHERE id=?').get(req.auth.companyId); if(!c)return res.status(403).json({error:'車行不存在'});
 const st=companyStatus(c); if(st!=='啟用中')return res.status(403).json({error:`車行授權狀態：${st}`}); req.company=c; next();
}
function superAuth(req,res,next){auth(req,res,()=>{if(req.auth.role!=='platformAdmin')return res.status(403).json({error:'權限不足'});next()})}

const app=express();
app.use(cors({origin:true,credentials:false}));
app.use(express.json({limit:'30mb'}));
app.get('/api/health',(req,res)=>res.json({ok:true,time:now(),service:'car-dealer-central'}));

app.post('/api/company/register',(req,res)=>{
 const {companyName,companyCode,ownerName,email,username,password}=req.body||{};
 if(!companyName||!companyCode||!ownerName||!username||!password)return res.status(400).json({error:'資料不完整'});
 if(!/^[A-Za-z0-9_-]{3,40}$/.test(companyCode))return res.status(400).json({error:'車行代碼格式不正確'});
 if(db.prepare('SELECT 1 FROM companies WHERE id=?').get(companyCode))return res.status(409).json({error:'車行代碼已被使用'});
 const company={id:companyCode,name:companyName,enabled:1,start_date:today(),expires_at:addDays(7),created_at:now(),created_by:'self',contact_email:email||'',trial:1};
 const user={id:`admin_${crypto.randomUUID()}`,company_id:companyCode,username,name:ownerName,role:'admin',commission_rate:0,enabled:1,updated_at:now()};
 const snapshot={settings:{companyName,taxRate:0},users:[{id:user.id,username:user.username,password:'',name:user.name,role:'admin',commissionRate:0}],cars:[],saleRequests:[]};
 const tx=db.transaction(()=>{
  db.prepare('INSERT INTO companies(id,name,enabled,start_date,expires_at,created_at,created_by,contact_email,trial) VALUES(?,?,?,?,?,?,?,?,?)').run(company.id,company.name,1,company.start_date,company.expires_at,company.created_at,company.created_by,company.contact_email,1);
  db.prepare('INSERT INTO users(id,company_id,username,password_hash,name,role,commission_rate,enabled,updated_at) VALUES(?,?,?,?,?,?,?,?,?)').run(user.id,user.company_id,user.username,hashPassword(password),user.name,user.role,0,1,user.updated_at);
  db.prepare('INSERT INTO snapshots(company_id,version,json,updated_at) VALUES(?,?,?,?)').run(companyCode,1,JSON.stringify(snapshot),now());
 }); tx();
 res.json({token:signUser(user),company:companyDto(company),user:userDto(user),snapshot,version:1});
});

app.post('/api/auth/login',(req,res)=>{
 const {companyCode,username,password}=req.body||{}; const c=db.prepare('SELECT * FROM companies WHERE id=?').get(companyCode);
 if(!c)return res.status(401).json({error:'找不到此車行代碼'}); const st=companyStatus(c); if(st!=='啟用中')return res.status(403).json({error:`車行目前${st}`});
 const u=db.prepare('SELECT * FROM users WHERE company_id=? AND username=? AND enabled=1').get(companyCode,username); if(!u||!verifyPassword(password,u.password_hash))return res.status(401).json({error:'帳號或密碼錯誤'});
 const snap=getSnapshot(companyCode);res.json({token:signUser(u),company:companyDto(c),user:userDto(u),snapshot:snap.snapshot,version:snap.version});
});

app.get('/api/session/restore',auth,requireActiveCompany,(req,res)=>{
 const u=db.prepare('SELECT * FROM users WHERE id=? AND company_id=? AND enabled=1').get(req.auth.sub,req.auth.companyId);if(!u)return res.status(401).json({error:'帳號已失效'});
 const snap=getSnapshot(req.auth.companyId);res.json({company:companyDto(req.company),user:userDto(u),snapshot:snap.snapshot,version:snap.version});
});

app.get('/api/company/snapshot',auth,requireActiveCompany,(req,res)=>{
 const snap=getSnapshot(req.auth.companyId);res.json({company:companyDto(req.company),snapshot:snap.snapshot,version:snap.version,updatedAt:snap.updatedAt});
});

app.put('/api/company/snapshot',auth,requireActiveCompany,(req,res)=>{
 const incoming=req.body?.snapshot;const baseVersion=Number(req.body?.baseVersion||0);if(!incoming||typeof incoming!=='object')return res.status(400).json({error:'snapshot 不正確'});
 const existing=getSnapshot(req.auth.companyId);if(baseVersion!==existing.version)return res.status(409).json({error:'中央資料已有新版本',version:existing.version});
 // 業務端只能同步自己新增的成交申請，不能覆寫整個車行快照。
 if(req.auth.role==='sales')return res.status(403).json({error:'業務端不可直接覆寫整份車行資料，請使用業務專用操作'});
 const clean=JSON.parse(JSON.stringify(incoming));
 const users=Array.isArray(clean.users)?clean.users:[];
 const upsert=db.prepare(`INSERT INTO users(id,company_id,username,password_hash,name,role,commission_rate,enabled,updated_at)
 VALUES(@id,@company_id,@username,@password_hash,@name,@role,@commission_rate,1,@updated_at)
 ON CONFLICT(company_id,username) DO UPDATE SET name=excluded.name,role=excluded.role,commission_rate=excluded.commission_rate,enabled=1,updated_at=excluded.updated_at,password_hash=CASE WHEN excluded.password_hash='' THEN users.password_hash ELSE excluded.password_hash END`);
 const keep=new Set();
 const tx=db.transaction(()=>{
  for(const x of users){if(!x?.id||!x?.username)continue;keep.add(x.id);const existingUser=db.prepare('SELECT * FROM users WHERE company_id=? AND username=?').get(req.auth.companyId,x.username);const ph=x.password?hashPassword(x.password):(existingUser?.password_hash||'');upsert.run({id:x.id,company_id:req.auth.companyId,username:x.username,password_hash:ph,name:x.name||x.username,role:x.role||'sales',commission_rate:Number(x.commissionRate||0),updated_at:now()});x.password='';}
  const all=db.prepare('SELECT id,role FROM users WHERE company_id=?').all(req.auth.companyId);for(const u of all){if(u.role==='sales'&&!keep.has(u.id))db.prepare('UPDATE users SET enabled=0,updated_at=? WHERE id=?').run(now(),u.id)}
  const ver=existing.version+1;db.prepare('INSERT INTO snapshots(company_id,version,json,updated_at) VALUES(?,?,?,?) ON CONFLICT(company_id) DO UPDATE SET version=excluded.version,json=excluded.json,updated_at=excluded.updated_at').run(req.auth.companyId,ver,JSON.stringify(clean),now());
 });tx();res.json({ok:true,version:existing.version+1});
});

app.post('/api/sales/request',auth,requireActiveCompany,(req,res)=>{
 if(req.auth.role!=='sales')return res.status(403).json({error:'僅業務帳號可使用'});
 const body=req.body||{};const existing=getSnapshot(req.auth.companyId);const d=existing.snapshot;d.saleRequests=Array.isArray(d.saleRequests)?d.saleRequests:[];d.cars=Array.isArray(d.cars)?d.cars:[];
 const c=d.cars.find(x=>x.id===body.carId);if(!c||c.status!=='在庫')return res.status(400).json({error:'車輛不存在或已售'});if(d.saleRequests.some(r=>r.carId===c.id&&r.status==='待確認'))return res.status(409).json({error:'此車已有待確認成交申請'});
 const u=db.prepare('SELECT * FROM users WHERE id=?').get(req.auth.sub);const sell=Number(body.sellPrice||0);if(sell<=0)return res.status(400).json({error:'售價錯誤'});const rate=Number(u.commission_rate||0);const floor=Number(c.floorPrice||0);
 d.saleRequests.push({id:`req_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,carId:c.id,plate:c.plate,model:c.model,floorPrice:floor,sellPrice:sell,saleDate:body.saleDate||today(),requestedAt:today(),salesId:u.id,salesName:u.name,commissionRate:rate,expectedCommission:Math.max(0,sell-floor)*rate/100,status:'待確認'});
 const ver=existing.version+1;db.prepare('UPDATE snapshots SET version=?,json=?,updated_at=? WHERE company_id=?').run(ver,JSON.stringify(d),now(),req.auth.companyId);res.json({ok:true,version:ver,snapshot:d});
});

app.post('/api/super/login',(req,res)=>{const {username,password}=req.body||{};if(username!==SUPER_ADMIN_USER||password!==SUPER_ADMIN_PASSWORD)return res.status(401).json({error:'Super Admin 帳號或密碼錯誤'});res.json({token:signSuper()})});
app.get('/api/super/companies',superAuth,(req,res)=>{const rows=db.prepare('SELECT * FROM companies ORDER BY created_at DESC').all();res.json({companies:rows.map(companyDto)});});
app.get('/api/super/companies/:id',superAuth,(req,res)=>{const c=db.prepare('SELECT * FROM companies WHERE id=?').get(req.params.id);if(!c)return res.status(404).json({error:'找不到車行'});const users=db.prepare('SELECT * FROM users WHERE company_id=? ORDER BY role,name').all(c.id).map(userDto);const snap=getSnapshot(c.id);res.json({company:companyDto(c),users,snapshot:snap.snapshot,version:snap.version,updatedAt:snap.updatedAt});});
app.patch('/api/super/companies/:id/license',superAuth,(req,res)=>{const c=db.prepare('SELECT * FROM companies WHERE id=?').get(req.params.id);if(!c)return res.status(404).json({error:'找不到車行'});const enabled=req.body.enabled===undefined?c.enabled:(req.body.enabled?1:0);const start=req.body.startDate===undefined?c.start_date:req.body.startDate;const exp=req.body.expiresAt===undefined?c.expires_at:req.body.expiresAt;db.prepare('UPDATE companies SET enabled=?,start_date=?,expires_at=?,trial=? WHERE id=?').run(enabled,start||'',exp||'',req.body.trial===undefined?c.trial:(req.body.trial?1:0),c.id);res.json({ok:true,company:companyDto(db.prepare('SELECT * FROM companies WHERE id=?').get(c.id))});});

app.listen(PORT,()=>console.log(`Car Dealer Central API listening on http://localhost:${PORT}`));
