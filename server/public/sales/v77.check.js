
const LAN_MODE=location.protocol==='http:'&&location.port==='18765';const API='/api';const SESSION='carDealerSalesWebSession_v9_2_6';let token='',me=null,company=null,data={cars:[],saleRequests:[]},version=0,currentPage='cars',timer=null,nodeTimer=null,nodeIsOnline=false,lastNodeOnline=null,nodeInventoryBusy=false,salesPhotoCache={},salesPhotoLoading={},saleQueueTimer=null,saleQueueBusy=false;
const $=id=>document.getElementById(id);const money=n=>'NT$ '+Number(n||0).toLocaleString('zh-TW');const esc=s=>String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));const rate=v=>{let n=Number(v||0);return Number.isInteger(n)?String(n):n.toFixed(2).replace(/0+$/,'').replace(/\.$/,'')};
async function api(path,opt={}){opt.headers={...(opt.headers||{}),'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})};let r=await fetch(API+path,opt);let j={};try{j=await r.json()}catch{};if((r.status===401||r.status===403)&&token){logout(j.error||'登入或授權已失效');throw new Error(j.error||'授權失效')}if(!r.ok)throw new Error(j.error||'操作失敗');return j}
function togglePassword(){const p=$('password');if(!p)return;p.type=p.type==='password'?'text':'password'}
async function health(){try{let r=await fetch(API+'/health',{cache:'no-store'});if(!r.ok)throw 0;$('netState').className='notice';$('netState').textContent=LAN_MODE?'🟢 本機資料伺服器正常':'🟢 系統連線正常';return true}catch{$('netState').className='notice error';$('netState').textContent=LAN_MODE?'🔴 無法連線本機資料伺服器':'🔴 系統目前無法連線，請稍後再試';return false}}
async function doLogin(){if(!(await health()))return;let b=$('loginBtn');b.disabled=true;b.textContent='登入中…';try{let j=await api('/auth/login',{method:'POST',body:JSON.stringify({companyCode:$('companyCode').value.trim(),username:$('username').value.trim(),password:$('password').value})});if(j.user?.role!=='sales')throw new Error('這個入口只允許業務帳號登入');token=j.token;me=j.user;company=j.company;data=j.snapshot||data;version=Number(j.version||0);saveSession();enter();await refreshNodeStateAndInventory(true)}catch(e){alert(e.message)}finally{b.disabled=false;b.textContent='登入'}}
function saveSession(){if(token)localStorage.setItem(SESSION,JSON.stringify({token,page:currentPage}))}

function queueKey(){return `carDealerSalesQueue_v77_${company?.id||'none'}_${me?.id||'none'}`}
function historyKey(){return `carDealerSalesQueueHistory_v77_${company?.id||'none'}_${me?.id||'none'}`}
function loadSaleQueue(){try{let q=JSON.parse(localStorage.getItem(queueKey())||'[]');return Array.isArray(q)?q:[]}catch{return []}}
function saveSaleQueue(q){localStorage.setItem(queueKey(),JSON.stringify((q||[]).slice(-100)))}
function loadSyncHistory(){try{let q=JSON.parse(localStorage.getItem(historyKey())||'[]');return Array.isArray(q)?q:[]}catch{return []}}
function addSyncHistory(item,state,message=''){let h=loadSyncHistory();h.unshift({...item,state,message,finishedAt:new Date().toISOString()});localStorage.setItem(historyKey(),JSON.stringify(h.slice(0,20)))}
function operationId(){try{return 'sale_'+crypto.randomUUID()}catch{return 'sale_'+Date.now()+'_'+Math.random().toString(36).slice(2,12)}}
function retryDelay(attempts){return [0,5000,15000,30000,60000][Math.min(Math.max(0,attempts||0),4)]}
function queueBadge(){const q=loadSaleQueue(),n=q.filter(x=>x.state!=='failed').length;return n?` <span class="status pending">${n}</span>`:''}
function scheduleSaleQueue(ms=1200){clearTimeout(saleQueueTimer);saleQueueTimer=setTimeout(processSaleQueue,ms)}
async function postQueuedSale(item){
 const r=await fetch(API+'/sales/request',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify({...item.payload,operationId:item.operationId})});
 let j={};try{j=await r.json()}catch{}
 if((r.status===401||r.status===403)&&token){logout(j.error||'登入或授權已失效');let e=new Error(j.error||'授權失效');e.permanent=true;throw e}
 if(!r.ok){let e=new Error(j.error||'同步失敗');e.status=r.status;e.permanent=r.status>=400&&r.status<500;throw e}
 return j
}
async function processSaleQueue(force=false){
 if(LAN_MODE||!token||saleQueueBusy||!navigator.onLine)return;
 let q=loadSaleQueue();if(!q.length)return;
 const now=Date.now();let idx=q.findIndex(x=>x.state!=='failed'&&(force||!x.nextTryAt||x.nextTryAt<=now));if(idx<0){let next=Math.min(...q.filter(x=>x.state!=='failed').map(x=>x.nextTryAt||now+60000));scheduleSaleQueue(Math.max(1000,next-now));return}
 saleQueueBusy=true;let item=q[idx];item.state='syncing';saveSaleQueue(q);if(currentPage==='sync')renderSync();
 try{let j=await postQueuedSale(item);if(j.snapshot)data=j.snapshot;if(j.version!=null)version=Number(j.version||version);q=loadSaleQueue().filter(x=>x.operationId!==item.operationId);saveSaleQueue(q);addSyncHistory(item,'acked',j.duplicate?'伺服器已確認此申請先前已收到':'已送達並確認收到');if(currentPage==='sync')renderSync();else render();setTimeout(sync,0)}
 catch(e){q=loadSaleQueue();let i=q.findIndex(x=>x.operationId===item.operationId);if(i>=0){q[i].attempts=Number(q[i].attempts||0)+1;q[i].lastError=e.message||'同步失敗';if(e.permanent){q[i].state='failed';q[i].nextTryAt=0;addSyncHistory(q[i],'failed',q[i].lastError)}else{q[i].state='pending';q[i].nextTryAt=Date.now()+retryDelay(q[i].attempts)}}saveSaleQueue(q);if(currentPage==='sync')renderSync()}
 finally{saleQueueBusy=false;let remain=loadSaleQueue().some(x=>x.state!=='failed');if(remain)scheduleSaleQueue(1200)}
}
function enqueueSale(car,payload){let q=loadSaleQueue();if(q.some(x=>String(x.carId)===String(car.id)&&x.state!=='failed'))throw new Error('這台車已有一筆成交申請正在等待同步');let item={operationId:operationId(),type:'saleRequest',carId:car.id,plate:car.plate||'',model:car.model||'',payload,createdAt:new Date().toISOString(),attempts:0,nextTryAt:0,state:'pending',lastError:''};q.push(item);saveSaleQueue(q);scheduleSaleQueue(50);return item}
function retryQueueItem(id){let q=loadSaleQueue(),i=q.findIndex(x=>x.operationId===id);if(i<0)return;q[i].state='pending';q[i].nextTryAt=0;q[i].lastError='';saveSaleQueue(q);processSaleQueue(true);renderSync()}
function deleteQueueItem(id){let q=loadSaleQueue().filter(x=>x.operationId!==id);saveSaleQueue(q);renderSync()}


async function fetchNodeInventory(){
 if(nodeInventoryBusy)return null;
 nodeInventoryBusy=true;
 try{
   if(LAN_MODE){const j=await api('/lan/inventory');return Array.isArray(j.cars)?j.cars:[]}
   const q=await api('/sales/node-inventory/request',{method:'POST',body:'{}'});
   const deadline=Date.now()+20000;
   while(Date.now()<deadline){
     await new Promise(r=>setTimeout(r,450));
     const rr=await api('/sales/node-inventory-requests/'+encodeURIComponent(q.requestId));
     if(rr.status==='completed')return Array.isArray(rr.result?.cars)?rr.result.cars:[];
     if(rr.status==='failed'||rr.status==='expired')throw new Error(rr.error||'庫存讀取失敗');
   }
   throw new Error('車行主機回應逾時');
 }finally{nodeInventoryBusy=false}
}
function setDealerNodeBadge(state,text){
 const badge=$('dealerNode');if(!badge)return;
 badge.className=state==='on'?'badge':state==='checking'?'badge':'badge off';
 badge.textContent=text;
}
async function refreshNodeStatus(showOfflineAlert=false){
 if(!token)return false;
 try{
   const ns=await api('/node/status');
   const online=!!ns.online;
   const changed=lastNodeOnline!==online;
   nodeIsOnline=online;lastNodeOnline=online;
   setDealerNodeBadge(online?'on':'off',online?(LAN_MODE?'● 本機資料伺服器正常':'● 公司資料主機連線'):(LAN_MODE?'● 本機資料伺服器離線':'● 公司資料主機離線'));
   if(!online&&changed&&showOfflineAlert)alert('⚠ 車行主機離線中，照片無法讀取。');
   if(online&&changed){salesPhotoCache={};salesPhotoLoading={};setTimeout(refreshNodeInventory,0)}
   return online;
 }catch(e){
   nodeIsOnline=false;
   setDealerNodeBadge('off','● 車行主機狀態未知');
   return false;
 }
}
async function refreshNodeInventory(){
 if(!token||!nodeIsOnline||nodeInventoryBusy)return;
 try{
   const cars=await fetchNodeInventory();
   if(cars===null)return;
   data={...(data||{}),cars};
   salesPhotoCache={};salesPhotoLoading={};
   render();
 }catch(e){
   setDealerNodeBadge('off','● 車行主機讀取失敗');
 }
}
async function refreshNodeStateAndInventory(showLoginAlert=false){
 setDealerNodeBadge('checking',LAN_MODE?'● 本機資料伺服器檢查中':'● 公司資料主機檢查中');
 const online=await refreshNodeStatus(showLoginAlert);
 if(online)await refreshNodeInventory();
}
function enter(){$('loginPage').classList.add('hidden');$('app').classList.remove('hidden');$('who').textContent=me.name+'｜業務獎金 '+rate(me.commissionRate)+'%';$('shop').textContent=company.name+'｜'+company.id;setDealerNodeBadge('checking',LAN_MODE?'● 本機資料伺服器檢查中':'● 公司資料主機檢查中');showPage(currentPage||'cars');clearInterval(timer);clearInterval(nodeTimer);timer=setInterval(sync,5000);nodeTimer=setInterval(()=>LAN_MODE?refreshNodeInventory():refreshNodeStatus(false),2000);if(!LAN_MODE){scheduleSaleQueue(300);setInterval(()=>processSaleQueue(false),5000)}}
function openAccountSettings(){
 $('modal').innerHTML=`<h2>⚙ 帳號設定</h2><div class="notice">${esc(me?.name||'')}｜${esc(me?.username||'')}<br>你可以在這裡修改自己的登入密碼。</div><div class="field"><label>目前密碼</label><input id="currentPw" type="password" autocomplete="current-password" placeholder="輸入目前密碼"></div><div class="field"><label>新密碼</label><input id="newPw" type="password" autocomplete="new-password" placeholder="至少 6 碼"></div><div class="field"><label>再次輸入新密碼</label><input id="newPw2" type="password" autocomplete="new-password" placeholder="再次輸入新密碼"></div><div class="row"><button id="changePwBtn" class="btn primary" style="flex:1" onclick="changeMyPassword()">確認修改密碼</button><button class="btn ghost" onclick="closeModal()">取消</button></div>`;
 $('modalBg').classList.add('show');setTimeout(()=>$('currentPw')?.focus(),50)
}
async function changeMyPassword(){
 if(LAN_MODE)return alert('目前為內網備用模式，密碼修改請待服務恢復後操作。');
 const currentPassword=$('currentPw')?.value||'',newPassword=$('newPw')?.value||'',again=$('newPw2')?.value||'';
 if(!currentPassword)return alert('請輸入目前密碼');if(newPassword.length<6)return alert('新密碼至少 6 碼');if(again!==newPassword)return alert('兩次新密碼不一致');
 const b=$('changePwBtn');if(b){b.disabled=true;b.textContent='修改中…'}
 try{await api('/account/change-password',{method:'POST',body:JSON.stringify({currentPassword,newPassword})});alert('密碼修改成功，請使用新密碼重新登入');closeModal();logout()}catch(e){alert(e.message||'修改密碼失敗');if(b){b.disabled=false;b.textContent='確認修改密碼'}}
}
function logout(msg=''){clearInterval(timer);clearInterval(nodeTimer);clearTimeout(saleQueueTimer);timer=null;nodeTimer=null;saleQueueTimer=null;saleQueueBusy=false;token='';me=null;company=null;nodeIsOnline=false;lastNodeOnline=null;nodeInventoryBusy=false;salesPhotoCache={};salesPhotoLoading={};data={cars:[],saleRequests:[]};localStorage.removeItem(SESSION);$('app').classList.add('hidden');$('loginPage').classList.remove('hidden');$('password').value='';if(msg)alert(msg);health()}
async function restore(){let s;try{s=JSON.parse(localStorage.getItem(SESSION))}catch{};if(!s?.token)return false;token=s.token;currentPage=s.page||'cars';try{let j=await api('/session/restore');if(j.user?.role!=='sales')throw new Error('角色不符');me=j.user;company=j.company;data=j.snapshot||data;version=Number(j.version||0);enter();await refreshNodeStateAndInventory(false);return true}catch{token='';localStorage.removeItem(SESSION);return false}}
async function sync(){if(!token)return;if(!LAN_MODE)processSaleQueue(false);try{let j=await api('/company/snapshot');company=j.company||company;if(j.user)me=j.user;if(LAN_MODE){data=j.snapshot||data;render();return}if(Number(j.version||0)!==version){version=Number(j.version||0);const keepCars=data?.cars||[];data=j.snapshot||data;data.cars=keepCars;render();if(nodeIsOnline)setTimeout(refreshNodeInventory,0)}}catch(e){}}
function showPage(p){currentPage=p;saveSession();$('tabCars').classList.toggle('active',p==='cars');$('tabReq').classList.toggle('active',p==='requests');$('tabSync')?.classList.toggle('active',p==='sync');render();if(p==='cars'&&nodeIsOnline)setTimeout(refreshNodeInventory,0)}
function carPhotos(c){
 let legacy=[...(c.intakePhotos||[]),...(c.inspectionCertPhotos||[])];
 if(legacy.length)return `<div class="thumbs">${legacy.slice(0,8).map(x=>`<img src="${x}" onclick="openImage(this.src)">`).join('')}</div>`;
 let total=Number(c.intakePhotoCount||0)+Number(c.inspectionPhotoCount||0);
 if(!total)return `<div class="muted" style="margin-top:8px">尚無照片</div>`;
 let cached=salesPhotoCache[String(c.id)]||[];
 if(cached.length)return `<div class="thumbs">${cached.map(x=>`<img src="${x}" onclick="openImage(this.src)">`).join('')}</div>`;
 return `<div class="thumbs" id="photoStrip_${esc(c.id)}"><div class="photoLoading">載入中…</div></div>`;
}
async function fetchSalesPhotoBundle(carId){
 const k=String(carId);
 if(salesPhotoCache[k]?.length)return salesPhotoCache[k];
 if(salesPhotoLoading[k])return salesPhotoLoading[k];
 salesPhotoLoading[k]=(async()=>{
   if(LAN_MODE){const rr=await api('/lan/photos/'+encodeURIComponent(carId));const photos=(rr.photos||[]).map(x=>x?.src).filter(Boolean).slice(0,8);salesPhotoCache[k]=photos;return photos}
   const q=await api('/sales/node-photos/request',{method:'POST',body:JSON.stringify({carId})});
   const deadline=Date.now()+65000;
   while(Date.now()<deadline){
     await new Promise(r=>setTimeout(r,550));
     const rr=await api('/sales/node-photo-bundles/'+encodeURIComponent(q.requestId));
     if(rr.status==='completed'){
       const photos=(rr.result?.photos||[]).map(x=>x?.src).filter(Boolean).slice(0,8);
       salesPhotoCache[k]=photos;
       return photos;
     }
     if(rr.status==='failed'||rr.status==='expired')throw new Error(rr.error||'照片讀取失敗');
   }
   throw new Error('照片讀取逾時');
 })();
 try{return await salesPhotoLoading[k]}finally{delete salesPhotoLoading[k]}
}
async function hydrateAutoPhotos(){
 if(currentPage!=='cars')return;
 for(const c of (data.cars||[])){
   const total=Number(c.intakePhotoCount||0)+Number(c.inspectionPhotoCount||0);
   if(!total)continue;
   const box=$(`photoStrip_${c.id}`);if(!box)continue;
   if(!nodeIsOnline){box.innerHTML='<div class="photoLoading photoOffline">主機離線</div>';continue}
   try{
     const photos=await fetchSalesPhotoBundle(c.id);
     box.innerHTML=photos.length?photos.map(src=>`<img src="${src}" onclick="openImage(this.src)">`).join(''):'<div class="photoLoading photoOffline">無照片</div>';
   }catch(e){box.innerHTML='<div class="photoLoading photoOffline">無法讀取</div>'}
 }
}
function monthlyBonusInfo(){let mk=new Date().toLocaleDateString('en-CA',{timeZone:'Asia/Taipei'}).slice(0,7),rs=(data.saleRequests||[]).filter(r=>r.status==='已成交'&&String(r.saleDate||'').slice(0,7)===mk),bonus=rs.reduce((sum,r)=>sum+Number((r.finalCommission??r.expectedCommission)||0),0);return {mk,rs,bonus}}
function renderBonusSummary(){let x=monthlyBonusInfo(),el=$('bonusSummary');if(!el)return;el.innerHTML=`<div class="card"><div class="muted">💰 本月目前獎金</div><div class="big" style="font-size:30px;margin-top:4px">${money(x.bonus)}</div><div class="muted" style="margin-top:6px">本月已確認成交 ${x.rs.length} 台</div></div>`}
function render(){renderBonusSummary();if(currentPage==='cars')renderCars();else if(currentPage==='requests')renderRequests();else renderSync()}
let carSearchComposing=false;
function carSearchValue(){return ($('searchCars')?.value||'').trim().toLowerCase()}
function renderCarList(q=carSearchValue()){
 let cars=(data.cars||[]).filter(c=>(String(c.plate||'')+' '+String(c.model||'')+' '+String(c.year||'')+' '+String(c.salesNote||'')).toLowerCase().includes(q));
 return cars.map(c=>`<div class="car"><div class="carhead"><div><div class="plate">${esc(c.plate)}</div><div>${esc(c.model)}</div></div><span class="status approved">在庫</span></div><div class="row muted"><span>${esc(c.year||'-')} 年</span><span>｜</span><span>${Number(c.mileage||0).toLocaleString()} km</span></div><div class="price">公司底價 ${money(c.floorPrice)}</div>${c.commissionMode==='fixed'?`<div class="notice" style="margin-top:10px"><b>💰 固定獎金 ${money(c.fixedCommissionAmount)}</b><br>本車不依個人獎金比例計算</div>`:""}${c.salesNote?`<div class="notice" style="margin-top:10px"><b>📝 車輛備註</b><br>${esc(c.salesNote)}</div>`:""}${carPhotos(c)}<button class="btn primary full" style="margin-top:12px" onclick="openApply('${esc(c.id)}')">提交成交申請</button></div>`).join('')||'<div class="card muted">目前沒有符合條件的在庫車輛</div>';
}
function updateCarSearch(){
 if(carSearchComposing)return;
 const list=$('carSearchResults');if(!list)return;
 list.innerHTML=renderCarList();
 setTimeout(hydrateAutoPhotos,0);
}
function finishCarSearchComposition(){carSearchComposing=false;updateCarSearch()}
function renderCars(){
 let q=carSearchValue(),mk=new Date().toLocaleDateString('en-CA',{timeZone:'Asia/Taipei'}).slice(0,7),bonus=(data.saleRequests||[]).filter(r=>r.status==='已成交'&&String(r.saleDate||'').slice(0,7)===mk).reduce((s,r)=>s+Number((r.finalCommission??r.expectedCommission)||0),0);
 $('page').innerHTML=`<div class="card"><div class="kpi"><div><div class="muted">本月目前獎金</div><div class="big">${money(bonus)}</div></div><div><div class="muted">本月已成交</div><div class="big">${(data.saleRequests||[]).filter(r=>r.status==='已成交'&&String(r.saleDate||'').slice(0,7)===mk).length}</div></div></div></div><div class="card"><h2 style="margin-top:0">目前庫存</h2><input id="searchCars" class="search" placeholder="搜尋車牌／車型／年份／備註" value="${esc(q)}" autocomplete="off" oncompositionstart="carSearchComposing=true" oncompositionend="finishCarSearchComposition()" oninput="updateCarSearch()"></div><div id="carSearchResults" class="cardsGrid">${renderCarList(q)}</div>`;
 setTimeout(hydrateAutoPhotos,0);
}
function renderSync(){
 let q=loadSaleQueue(),h=loadSyncHistory(),active=q.filter(x=>x.state!=='failed'),failed=q.filter(x=>x.state==='failed');
 let stateLabel=x=>x.state==='syncing'?'🔵 同步中':x.state==='failed'?'🔴 需要處理':'🟡 待同步';
 $('page').innerHTML=`<div class="card"><h2 style="margin-top:0">🔄 同步中心</h2><div class="kpi"><div><div class="muted">等待同步</div><div class="big">${active.length}</div></div><div><div class="muted">需要處理</div><div class="big">${failed.length}</div></div></div>${LAN_MODE?'<div class="notice">目前使用店內備用入口。成交申請暫不送出；回到一般業務入口後會繼續同步。</div>':active.length?'<div class="notice">系統會自動重試，不需要重複提交成交申請。</div>':'<div class="notice">✅ 目前沒有等待同步的成交申請。</div>'}</div>`+
 q.map(x=>`<div class="car"><div class="carhead"><div><div class="plate">${esc(x.plate||'-')}</div><div>${esc(x.model||'')}</div></div><span class="status ${x.state==='failed'?'rejected':'pending'}">${stateLabel(x)}</span></div><div>成交價：<b>${money(x.payload?.sellPrice)}</b></div><div class="muted">建立時間 ${esc(new Date(x.createdAt).toLocaleString('zh-TW',{hour12:false}))}｜重試 ${Number(x.attempts||0)} 次</div>${x.lastError?`<div class="notice error">${esc(x.lastError)}</div>`:''}${x.state==='failed'?`<div class="row"><button class="btn primary" onclick="retryQueueItem('${esc(x.operationId)}')">重新同步</button><button class="btn dangerBtn" onclick="deleteQueueItem('${esc(x.operationId)}')">移除</button></div>`:''}</div>`).join('')+
 (h.length?`<div class="card"><h3 style="margin-top:0">最近同步紀錄</h3>${h.slice(0,10).map(x=>`<div style="padding:9px 0;border-bottom:1px solid #e2e8f0"><b>${x.state==='acked'?'✅ 已送達':'❌ 未完成'}｜${esc(x.plate||'-')} ${esc(x.model||'')}</b><div class="muted">${esc(x.message||'')}｜${esc(new Date(x.finishedAt).toLocaleString('zh-TW',{hour12:false}))}</div></div>`).join('')}</div>`:'');
}

function statusClass(s){return s==='待確認'?'pending':(s==='已確認'||s==='已成交'||s==='通過')?'approved':'rejected'}
function renderRequests(){let rs=[...(data.saleRequests||[])].sort((a,b)=>String(b.requestedAt||'').localeCompare(String(a.requestedAt||''))),mk=new Date().toLocaleDateString('en-CA',{timeZone:'Asia/Taipei'}).slice(0,7),bonus=rs.filter(r=>r.status==='已成交'&&String(r.saleDate||'').slice(0,7)===mk).reduce((s,r)=>s+Number((r.finalCommission??r.expectedCommission)||0),0);$('page').innerHTML=`<div class="card"><h2 style="margin-top:0">我的成交申請</h2><div class="kpi"><div><div class="muted">申請數</div><div class="big">${rs.length}</div></div><div><div class="muted">待確認</div><div class="big">${rs.filter(r=>r.status==='待確認').length}</div></div><div><div class="muted">本月目前獎金</div><div class="big">${money(bonus)}</div></div></div></div>${rs.map(r=>`<div class="car"><div class="carhead"><div><div class="plate">${esc(r.plate)}</div><div>${esc(r.model)}</div></div><span class="status ${statusClass(r.status)}">${esc(r.status)}</span></div><div>成交售價：<b>${money(r.sellPrice)}</b></div><div>公司底價：${money(r.floorPrice)}</div><div>預估獎金：<b>${money(r.expectedCommission)}</b>${r.commissionMode==='fixed'?"（固定獎金）":`（${rate(r.commissionRate)}%）`}</div><div class="muted">成交日 ${esc(r.saleDate||'-')}｜申請日 ${esc(r.requestedAt||'-')}</div>${r.rejectReason?`<div class="notice error">駁回原因：${esc(r.rejectReason)}</div>`:''}${r.cancelReason?`<div class="notice error">取消原因：${esc(r.cancelReason)}</div>`:''}${r.canceledAt?`<div class="muted">取消時間 ${esc(new Date(r.canceledAt).toLocaleString('zh-TW',{timeZone:'Asia/Taipei',hour12:false}))}</div>`:''}</div>`).join('')||'<div class="card muted">目前沒有成交申請</div>'}`}
function openApply(id){let c=(data.cars||[]).find(x=>String(x.id)===String(id));if(!c)return;let today=new Date().toISOString().slice(0,10);$('modal').innerHTML=`<h2>提交成交申請</h2><div class="notice">${esc(c.plate)}｜${esc(c.model)}<br>公司底價：<b>${money(c.floorPrice)}</b>${c.commissionMode==='fixed'?`<br><br><b>⚠️ 此車輛採固定獎金制</b><br>成交後獎金固定為 <b>${money(c.fixedCommissionAmount)}</b>，不依個人獎金比例計算。`:`<br>你的獎金比例：<b>${rate(me.commissionRate)}%</b>`}</div><div class="field"><label>成交售價</label><input id="sellPrice" type="number" inputmode="numeric" value="${Number(c.floorPrice||0)}" oninput="updateCommission('${esc(id)}')"></div><div class="field"><label>成交日期</label><input id="saleDate" type="date" value="${today}"></div><div id="commissionPreview" class="notice"></div><div class="row"><button class="btn primary" style="flex:1" onclick="submitApply('${esc(id)}')">確認送出</button><button class="btn ghost" onclick="closeModal()">取消</button></div>`;$('modalBg').classList.add('show');updateCommission(id)}
function updateCommission(id){let c=(data.cars||[]).find(x=>String(x.id)===String(id)),sell=Number($('sellPrice')?.value||0),diff=Math.max(0,sell-Number(c?.floorPrice||0)),bonus=c?.commissionMode==='fixed'?Math.max(0,Number(c.fixedCommissionAmount||0)):diff*Number(me?.commissionRate||0)/100;if($('commissionPreview'))$('commissionPreview').innerHTML=c?.commissionMode==='fixed'?`固定業務獎金：<b>${money(bonus)}</b><br><span class="muted">不依成交價與個人獎金比例計算</span>`:`超過底價：<b>${money(diff)}</b><br>預估業務獎金：<b>${money(bonus)}</b>`}
async function submitApply(carId){if(LAN_MODE)return alert('目前為店內備用入口，可查看庫存與照片；成交申請請回到一般業務入口後送出。');let sell=Number($('sellPrice').value||0),date=$('saleDate').value;if(sell<=0||!date)return alert('請確認售價與成交日期');let c=(data.cars||[]).find(x=>String(x.id)===String(carId));if(!c)return alert('找不到車輛資料');try{enqueueSale(c,{carId,sellPrice:sell,saleDate:date});closeModal();showPage('sync');processSaleQueue(true);alert('成交申請已加入同步佇列。系統會自動送出，請勿重複提交。')}catch(e){alert(e.message)}}
function closeModal(){$('modalBg').classList.remove('show')}function openImage(src){$('bigImage').src=src;$('imageBg').classList.add('show')}function closeImage(){$('imageBg').classList.remove('show');$('bigImage').src=''}
$('password').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin()});window.addEventListener('online',()=>{if(token){sync();processSaleQueue(true)}else health()});window.addEventListener('offline',()=>{$('netState').className='notice error';$('netState').textContent='🔴 目前沒有網路'});
(async()=>{await health();if(!(await restore())){};if(!LAN_MODE&&'serviceWorker' in navigator)navigator.serviceWorker.register('sw.js?v=9.3.13',{updateViaCache:'none'}).then(r=>r.update()).catch(()=>{})})();
