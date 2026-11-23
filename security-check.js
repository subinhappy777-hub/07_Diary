// Run disposable authentication checks against an isolated temporary SQLite database.
const {spawn}=require('node:child_process');
const {DatabaseSync}=require('node:sqlite');
const crypto=require('node:crypto');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const net=require('node:net');
const root=__dirname,temp=fs.mkdtempSync(path.join(os.tmpdir(),'harugyeol-security-')),dbFile=path.join(temp,'check.sqlite');
const assert=(ok,label)=>{if(!ok)throw Error(label)};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const pickPort=()=>new Promise((resolve,reject)=>{const s=net.createServer();s.once('error',reject);s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p))})});
async function main(){const port=await pickPort(),server=spawn(process.execPath,[path.join(root,'server.js')],{cwd:root,env:{...process.env,PORT:String(port),HOST:'127.0.0.1',DIARY_DB_PATH:dbFile},stdio:'ignore'}),base=`http://127.0.0.1:${port}`;
 const request=async(route,{method='GET',cookie,body}={})=>{const r=await fetch(base+route,{method,headers:{...(cookie?{cookie}:{}),...(body?{'content-type':'application/json'}:{})},body:body?JSON.stringify(body):undefined});return{status:r.status,data:await r.json().catch(()=>({})),cookie:r.headers.get('set-cookie')?.split(';')[0]||cookie||null}};
 try{let ready=false;for(let i=0;i<80;i++){try{if((await fetch(base+'/')).ok){ready=true;break}}catch{}await sleep(100)}assert(ready,'서버 시작');
   const suffix=crypto.randomBytes(4).toString('hex'),usernameA=`proof_a_${suffix}`,usernameB=`proof_b_${suffix}`,password=crypto.randomBytes(18).toString('base64url');
   const a=await request('/api/signup',{method:'POST',body:{username:usernameA,password}}),b=await request('/api/signup',{method:'POST',body:{username:usernameB,password}});assert(a.status===201&&b.status===201,'동일 비밀번호 계정 생성');
   const duplicate=await request('/api/signup',{method:'POST',body:{username:usernameA,password}});assert(duplicate.status===409,'중복 가입 거절');
   const unknown=await request('/api/login',{method:'POST',body:{username:`missing_${suffix}`,password}}),wrong=await request('/api/login',{method:'POST',body:{username:usernameA,password:'incorrect-password'}});assert(unknown.status===401&&wrong.status===401&&unknown.data.error===wrong.data.error,'로그인 실패 안내 통일');
   assert((await request('/api/data')).status===401,'비로그인 자료 요청 거절');
   const db=new DatabaseSync(dbFile),accounts=db.prepare('SELECT username,password_hash,salt FROM users ORDER BY username').all();assert(accounts.length===2&&accounts[0].salt!==accounts[1].salt&&accounts[0].password_hash!==accounts[1].password_hash,'계정별 salt 및 해시 분리');
   const sessions=db.prepare('SELECT token_hash,expires_at FROM sessions').all();assert(sessions.length===2&&sessions.every(s=>s.expires_at>Date.now()+6*24*60*60*1000&&s.expires_at<=Date.now()+7*24*60*60*1000+5000),'세션 만료 시각 저장');assert(sessions.every(s=>/^[a-f0-9]{64}$/.test(s.token_hash)),'세션 원문 대신 SHA-256 지문 저장');
   const userRows=db.prepare('SELECT id,username FROM users ORDER BY username').all(),ownerA=userRows.find(x=>x.username===usernameA).id,ownerB=userRows.find(x=>x.username===usernameB).id,taskA=`task_a_${suffix}`,taskB=`task_b_${suffix}`;
   const docA={plans:[],tasks:[{id:taskA,title:'private A'}],runs:[],expenses:[],media:[],weekGoals:[],reflection:'',monthBudgets:{}},docB={plans:[],tasks:[{id:taskB,title:'private B'}],runs:[],expenses:[],media:[],weekGoals:[],reflection:'',monthBudgets:{}};
   assert((await request('/api/data',{method:'PUT',cookie:a.cookie,body:{data:docA}})).status===200,'A own-data setup');assert((await request('/api/data',{method:'PUT',cookie:b.cookie,body:{data:docB}})).status===200,'B own-data setup');
   const getOwn=async c=>(await request('/api/data',{cookie:c})).data.data,count=d=>['plans','tasks','runs','expenses','media','weekGoals'].reduce((n,k)=>n+(d[k]?.length||0),0),beforeA=await getOwn(a.cookie),beforeB=await getOwn(b.cookie),countA=count(beforeA),countB=count(beforeB);assert(countA===1&&countB===1,'baseline record counts');
   for(const [cookie,ownId,otherId,ownTask,otherTask] of [[a.cookie,ownerA,ownerB,taskA,taskB],[b.cookie,ownerB,ownerA,taskB,taskA]]){
     const list=await request('/api/data?userId='+encodeURIComponent(otherId),{cookie});assert(list.status===200&&list.data.data.tasks.length===1&&list.data.data.tasks[0].id===ownTask&&!JSON.stringify(list.data).includes(otherTask),'list scope is session owner only');
     const read=await request('/api/data/'+encodeURIComponent(otherId),{cookie});assert(read.status===404,'cross-owner read denied');
     const edit=await request('/api/data/'+encodeURIComponent(otherId),{method:'PUT',cookie,body:{data:{tasks:[]}}});assert(edit.status===404,'cross-owner edit denied');
     const del=await request('/api/data/'+encodeURIComponent(otherId),{method:'DELETE',cookie});assert(del.status===404,'cross-owner delete denied');
   }
   const afterA=await getOwn(a.cookie),afterB=await getOwn(b.cookie);assert(count(afterA)===countA&&count(afterB)===countB,'cross-owner attempts preserve both record counts');assert(afterA.tasks[0].id===taskA&&afterB.tasks[0].id===taskB,'both owners retain original records');
   assert((await request('/api/data',{method:'PUT',body:{data:{tasks:[]}}})).status===401,'anonymous direct write denied');assert((await request('/api/data',{method:'DELETE'})).status===401,'anonymous direct delete denied');
   const afterLogout=await request('/api/logout',{method:'POST',cookie:a.cookie});assert(afterLogout.status===200,'로그아웃 완료');assert((await request('/api/data',{cookie:a.cookie})).status===401,'로그아웃 뒤 세션 무효화');db.close();
   const report=`# 인증·세션 보안 점검\n\n- 실행 시각 (Asia/Seoul): ${new Date().toLocaleString('ko-KR',{timeZone:'Asia/Seoul'})}\n- 점검 범위: 임시 DB의 서로 다른 두 테스트 계정, 동일 테스트 비밀번호 사용\n- 계정별 무작위 salt와 저장 해시가 서로 다름: PASS\n- 중복 가입 거절(409): PASS\n- 미등록 아이디와 잘못된 비밀번호에 같은 안내 반환(401): PASS\n- 비로그인 자료 직접 요청 거절(401): PASS\n- 세션 만료: 생성 시각으로부터 7일 후 만료되도록 저장: PASS\n- 로그아웃 뒤 기존 세션 거절(401): PASS\n- 세션 원문 대신 SHA-256 지문 저장: PASS\n- 서명 비밀키: 사용하지 않음. 세션은 256비트 무작위 opaque token이고 DB에는 지문만 저장. 기본 바인딩 주소는 127.0.0.1.\n- 보고서 내 비밀번호: [MASKED]; 세션 토큰: [MASKED]; 비밀키: [MASKED / NOT USED]\n- 근거 코드: server.js의 scrypt 가입 처리, issueSession/sessionUser, 로그아웃 처리 및 인증된 /api/data 라우트.\n- 검증 스크립트: security-check.js. 테스트 계정과 임시 DB는 실행 중 메모리/임시 폴더에서만 사용하고 종료 후 임시 DB를 삭제함.\n`;
   const isolation=`\n## 계정 간 자료 격리 점검\n\n- 테스트 계정 A/B 각각 비공개 자료 1건을 준비하고 상호 읽기·수정·삭제를 시도함.\n- A→B 및 B→A의 추측 자료 경로 GET/PUT/DELETE 응답: 각 404.\n- 상대 계정 ID를 지정한 목록 요청은 세션 소유자의 자료만 반환했고, 상대 계정 자료는 응답에 없음: PASS.\n- 양방향 공격 전후 자료 건수: A ${countA}→${count(afterA)}, B ${countB}→${count(afterB)} (변화 없음): PASS.\n- 로그인 없는 자료 직접 GET/PUT/DELETE 응답: 각 401: PASS.\n- 처리 근거: server.js의 requireUser()는 인증 없는 /api 요청을 401로 거절하고, /api/data GET/PUT은 세션에서 확인한 user.id만 사용함. 그 외 /api/data/:id 요청은 인증 후 404.\n- 응답에 포함된 테스트 자료와 계정 식별자는 실제 계정이 아니며, 비밀번호·토큰·비밀키는 보고서에 기록하지 않음.\n`;
   fs.writeFileSync(path.join(root,'SECURITY-REPORT.md'),report+isolation,'utf8');console.log('인증 및 양방향 자료 격리 점검 통과. 비밀번호·토큰·비밀키는 출력하지 않았습니다.');
 }finally{server.kill();await sleep(150);try{fs.rmSync(temp,{recursive:true,force:true})}catch{}}
}
main().catch(e=>{console.error(`인증 보안 점검 실패: ${e.message}`);process.exitCode=1});
