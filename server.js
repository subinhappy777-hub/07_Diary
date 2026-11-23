// 하루결 local account server. Requires Node.js 24+ (built-in node:sqlite).
const http=require('node:http');
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const {promisify}=require('node:util');
const {DatabaseSync}=require('node:sqlite');
const scrypt=promisify(crypto.scrypt);
const ROOT=__dirname,PORT=Number(process.env.PORT||4173),HOST=process.env.HOST||'127.0.0.1';
const DB=new DatabaseSync(process.env.DIARY_DB_PATH||path.join(ROOT,'diary.sqlite'));
const SESSION_MS=7*24*60*60*1000,COOKIE='harugyeol_session';
DB.exec(`PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT NOT NULL UNIQUE COLLATE NOCASE,password_hash TEXT NOT NULL,salt TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS diary_data(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,data_json TEXT NOT NULL,updated_at TEXT NOT NULL);`);
const reply=(res,status,data,headers={})=>{res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers});res.end(JSON.stringify(data))};
const error=(res,status,message)=>reply(res,status,{error:message});
const digest=t=>crypto.createHash('sha256').update(t).digest('hex');
const cookies=req=>Object.fromEntries((req.headers.cookie||'').split(';').map(x=>x.trim().split(/=(.*)/s).slice(0,2)).filter(x=>x.length===2));
function cookie(res,token,clear=false){res.setHeader('Set-Cookie',`${COOKIE}=${clear?'':token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${clear?0:Math.floor(SESSION_MS/1000)}${process.env.COOKIE_SECURE==='1'?'; Secure':''}`)}
async function readBody(req){let s='';for await(const c of req){s+=c;if(s.length>15_000_000)throw Object.assign(Error('요청이 너무 큽니다.'),{status:413})}try{return JSON.parse(s||'{}')}catch{throw Object.assign(Error('요청 형식이 올바르지 않습니다.'),{status:400})}}
function cleanData(data){const d=data&&typeof data==='object'&&!Array.isArray(data)?data:{};return{plans:Array.isArray(d.plans)?d.plans:[],tasks:Array.isArray(d.tasks)?d.tasks:[],runs:Array.isArray(d.runs)?d.runs:[],expenses:Array.isArray(d.expenses)?d.expenses:[],media:Array.isArray(d.media)?d.media:[],weekGoals:Array.isArray(d.weekGoals)?d.weekGoals:[],reflection:d.reflection||'',monthBudgets:d.monthBudgets||{},experiment:d.experiment&&typeof d.experiment==='object'?d.experiment:null}}
function mergeLegacy(oldData,currentData){const old=cleanData(oldData),current=cleanData(currentData);for(const k of ['plans','tasks','runs','expenses','media','weekGoals']){const ids=new Set(current[k].map(x=>x?.id).filter(Boolean));current[k]=[...current[k],...old[k].filter(x=>!x?.id||!ids.has(x.id))]}if(!current.reflection)current.reflection=old.reflection;if(!Object.keys(current.monthBudgets).length)current.monthBudgets=old.monthBudgets;if(!current.experiment)current.experiment=old.experiment;return current}
function sessionUser(req){const t=cookies(req)[COOKIE];if(!t)return null;return DB.prepare('SELECT u.id,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').get(digest(t),Date.now())||null}
function requireUser(req,res){const u=sessionUser(req);if(!u)error(res,401,'로그인이 필요합니다.');return u}
function issueSession(userId,res){const t=crypto.randomBytes(32).toString('base64url');DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(digest(t),userId,Date.now()+SESSION_MS);cookie(res,t)}
const server=http.createServer(async(req,res)=>{const url=new URL(req.url,'http://localhost');try{
 if(req.method==='GET'&&url.pathname==='/api/session'){const u=sessionUser(req);return u?reply(res,200,{username:u.username}):error(res,401,'로그인이 필요합니다.')}
 if(req.method==='POST'&&url.pathname==='/api/signup'){const b=await readBody(req),username=String(b.username||'').trim(),password=String(b.password||'');if(!/^[\p{L}\p{N}_.-]{3,32}$/u.test(username))return error(res,400,'아이디는 3~32자의 문자, 숫자, ., _, -로 입력해 주세요.');if(password.length<10||Buffer.byteLength(password)>1024)return error(res,400,'비밀번호는 10자 이상 입력해 주세요.');const salt=crypto.randomBytes(16),hash=await scrypt(password,salt,64,{N:16384,r:8,p:1}),id=crypto.randomUUID();try{DB.prepare('INSERT INTO users VALUES(?,?,?,?,?)').run(id,username,hash.toString('hex'),salt.toString('hex'),new Date().toISOString())}catch(e){if(String(e.message).includes('UNIQUE'))return error(res,409,'이미 사용 중인 아이디입니다.');throw e}DB.prepare('INSERT INTO diary_data VALUES(?,?,?)').run(id,JSON.stringify(cleanData(b.legacyData)),new Date().toISOString());issueSession(id,res);return reply(res,201,{username})}
 if(req.method==='POST'&&url.pathname==='/api/login'){const b=await readBody(req),username=String(b.username||'').trim(),u=DB.prepare('SELECT * FROM users WHERE username=? COLLATE NOCASE').get(username);if(!u){await scrypt(String(b.password||''),Buffer.alloc(16),64,{N:16384,r:8,p:1});return error(res,401,'아이디 또는 비밀번호가 올바르지 않습니다.')}const hash=await scrypt(String(b.password||''),Buffer.from(u.salt,'hex'),64,{N:16384,r:8,p:1});if(!crypto.timingSafeEqual(hash,Buffer.from(u.password_hash,'hex')))return error(res,401,'아이디 또는 비밀번호가 올바르지 않습니다.');if(b.legacyData&&typeof b.legacyData==='object'){const row=DB.prepare('SELECT data_json FROM diary_data WHERE user_id=?').get(u.id),merged=mergeLegacy(b.legacyData,JSON.parse(row?.data_json||'{}'));DB.prepare('UPDATE diary_data SET data_json=?,updated_at=? WHERE user_id=?').run(JSON.stringify(merged),new Date().toISOString(),u.id)}issueSession(u.id,res);return reply(res,200,{username:u.username})}
 if(req.method==='POST'&&url.pathname==='/api/logout'){const t=cookies(req)[COOKIE];if(t)DB.prepare('DELETE FROM sessions WHERE token_hash=?').run(digest(t));cookie(res,'',true);return reply(res,200,{ok:true})}
 if(url.pathname.startsWith('/api/')){const u=requireUser(req,res);if(!u)return;if(req.method==='GET'&&url.pathname==='/api/data'){const row=DB.prepare('SELECT data_json FROM diary_data WHERE user_id=?').get(u.id);return reply(res,200,{data:JSON.parse(row?.data_json||'{}')})}if(req.method==='PUT'&&url.pathname==='/api/data'){const b=await readBody(req);DB.prepare('UPDATE diary_data SET data_json=?,updated_at=? WHERE user_id=?').run(JSON.stringify(cleanData(b.data)),new Date().toISOString(),u.id);return reply(res,200,{ok:true})}return error(res,404,'요청한 자료를 찾을 수 없습니다.')}
 if(req.method==='GET'&&(url.pathname==='/'||url.pathname==='/index.html')){res.writeHead(200,{'content-type':'text/html; charset=utf-8','cache-control':'no-store'});return fs.createReadStream(path.join(ROOT,'index.html')).pipe(res)}
 if(req.method==='GET'&&url.pathname==='/app-auth.js'){res.writeHead(200,{'content-type':'text/javascript; charset=utf-8','cache-control':'no-store'});return fs.createReadStream(path.join(ROOT,'app-auth.js')).pipe(res)}
 if(req.method==='GET'&&url.pathname==='/five-day-study.js'){res.writeHead(200,{'content-type':'text/javascript; charset=utf-8','cache-control':'no-store'});return fs.createReadStream(path.join(ROOT,'five-day-study.js')).pipe(res)}
 if(req.method==='GET'&&/^\/assets\/fonts\/[a-zA-Z0-9_.-]+\.(otf|ttf)$/.test(url.pathname)){const f=path.join(ROOT,url.pathname.slice(1));res.writeHead(200,{'content-type':f.endsWith('.otf')?'font/otf':'font/ttf'});return fs.createReadStream(f).pipe(res)}
 return error(res,404,'페이지를 찾을 수 없습니다.')
}catch(e){return error(res,e.status||500,e.status?e.message:'서버 오류가 발생했습니다.')}});
server.listen(PORT,HOST,()=>console.log(`하루결 실행: http://${HOST}:${PORT}`));
