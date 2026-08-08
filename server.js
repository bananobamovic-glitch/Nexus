/**
 * NEXUS SERVER v3
 * - Пароли (sha256+salt, встроенный crypto)
 * - Сессии 365 дней
 * - Все сообщения (текст + медиа base64) хранятся на сервере
 * - Офлайн-звонки → "пропущенный звонок" сохраняется как сообщение
 * - Закреплённые сообщения, реакции, ответы, пересылки
 *
 * Запуск: npm install && node server.js
 * Render: Build=npm install, Start=node server.js
 */

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { WebSocketServer, WebSocket } = require('ws');

const PORT    = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'db.json');
const SESSION_TTL = 365 * 24 * 60 * 60 * 1000; // 1 год

// ─── DB ──────────────────────────────────────────
function loadDB() {
  try { if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE,'utf8')); } catch {}
  return { users:{}, sessions:{}, messages:{}, counter:0 };
}
let db = loadDB();
if (!db.sessions) db.sessions = {};
if (!db.messages) db.messages = {};

let saveTimer = null;
function schedSave() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => { saveTimer=null; try{fs.writeFileSync(DB_FILE,JSON.stringify(db));} catch(e){console.error('DB save:',e);} }, 300);
}

console.log(`✅ Nexus DB: ${Object.keys(db.users).length} users, ${Object.keys(db.messages).length} rooms`);

// ─── Crypto ──────────────────────────────────────
const hashPw  = (pw,salt) => crypto.createHmac('sha256',salt).update(pw).digest('hex');
const newSalt  = () => crypto.randomBytes(16).toString('hex');
const newToken = () => crypto.randomBytes(32).toString('hex');

// ─── Sessions ────────────────────────────────────
function createSession(username) {
  const token = newToken();
  db.sessions[token] = { username: username.toLowerCase(), ts: Date.now() };
  // Prune old
  const cut = Date.now() - SESSION_TTL;
  Object.keys(db.sessions).forEach(t=>{ if(db.sessions[t].ts<cut) delete db.sessions[t]; });
  schedSave();
  return token;
}
function validateSession(token) {
  if (!token) return null;
  const s = db.sessions[token];
  if (!s || Date.now()-s.ts > SESSION_TTL) { delete db.sessions[token]; return null; }
  return db.users[s.username] || null;
}
function safeUser(u) {
  if (!u) return null;
  const { salt, passwordHash, ...safe } = u;
  return safe;
}

// ─── Messages ────────────────────────────────────
function roomId(a, b) { return [a,b].sort().join('|'); }
function getRoom(a, b) { const r=roomId(a,b); if(!db.messages[r])db.messages[r]=[]; return db.messages[r]; }
function saveMsg(msg) {
  const room = getRoom(msg.from, msg.to);
  if (room.find(m=>m.id===msg.id)) return; // deduplicate
  room.push(msg);
  if (room.length > 500) room.splice(0, room.length-500);
  schedSave();
}
function deleteMsg(msgId, roomA, roomB) {
  const room = getRoom(roomA, roomB);
  const i = room.findIndex(m=>m.id===msgId);
  if (i!==-1) { room[i].deleted=true; room[i].text=''; room[i].src=undefined; schedSave(); return true; }
  return false;
}
function pinMsg(msgId, roomA, roomB, pin) {
  const room = getRoom(roomA, roomB);
  room.forEach(m=>{ if(m.id===msgId) m.pinned=pin; });
  schedSave();
}
function reactMsg(msgId, roomA, roomB, user, emoji) {
  const room = getRoom(roomA, roomB);
  const m = room.find(m=>m.id===msgId); if(!m) return;
  if (!m.reactions) m.reactions={};
  if (!m.reactions[emoji]) m.reactions[emoji]=[];
  const idx = m.reactions[emoji].indexOf(user);
  if (idx===-1) m.reactions[emoji].push(user);
  else m.reactions[emoji].splice(idx,1);
  schedSave();
}

// ─── HTTP ─────────────────────────────────────────
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');
  if (req.method==='OPTIONS') { res.writeHead(204); res.end(); return; }

  if (!url.pathname.startsWith('/api/')) { serve(res); return; }

  let body='';
  req.on('data',d=>body+=d);
  req.on('end',()=>{
    const data = body ? (() => { try{return JSON.parse(body);}catch{return {};} })() : {};
    const token = (req.headers.authorization||'').replace('Bearer ','').trim();

    // POST /api/register
    if (req.method==='POST' && url.pathname==='/api/register') {
      const { username,nickname,visibleName,color,password } = data;
      if (!username||!nickname||!password) return send(res,400,{error:'Заполни все поля'});
      if (password.length<4) return send(res,400,{error:'Пароль минимум 4 символа'});
      const uname=username.toLowerCase().trim();
      if (!/^[a-z0-9_]{3,24}$/.test(uname)) return send(res,400,{error:'Username: 3–24 символа a-z 0-9 _'});
      if (db.users[uname]) return send(res,409,{error:'Username уже занят'});
      db.counter=(db.counter||0)+1;
      const salt=newSalt();
      const user={
        uuid:'#'+String(db.counter).padStart(7,'0'),
        username:uname, nickname, visibleName:visibleName||nickname, color:color||'#4f8aff',
        salt, passwordHash:hashPw(password,salt),
        createdAt:Date.now(), lastSeen:Date.now(),
      };
      db.users[uname]=user; schedSave();
      const t=createSession(uname);
      return send(res,200,{ok:true,token:t,user:safeUser(user)});
    }

    // POST /api/login
    if (req.method==='POST' && url.pathname==='/api/login') {
      const { username,password } = data;
      if (!username||!password) return send(res,400,{error:'Введи логин и пароль'});
      const q=username.toLowerCase().trim().replace(/^@/,'');
      let user = db.users[q];
      if (!user) user=Object.values(db.users).find(u=>u.uuid===q||u.uuid==='#'+q);
      if (!user) return send(res,401,{error:'Пользователь не найден'});
      if (hashPw(password,user.salt)!==user.passwordHash) return send(res,401,{error:'Неверный пароль'});
      user.lastSeen=Date.now(); schedSave();
      const t=createSession(user.username);
      return send(res,200,{ok:true,token:t,user:safeUser(user)});
    }

    // GET /api/me
    if (req.method==='GET' && url.pathname==='/api/me') {
      const u=validateSession(token);
      if (!u) return send(res,401,{error:'Сессия истекла'});
      u.lastSeen=Date.now(); schedSave();
      return send(res,200,{ok:true,user:safeUser(u)});
    }

    // POST /api/logout
    if (req.method==='POST' && url.pathname==='/api/logout') {
      if (token) { delete db.sessions[token]; schedSave(); }
      return send(res,200,{ok:true});
    }

    // GET /api/users?q=
    if (req.method==='GET' && url.pathname==='/api/users') {
      const q=(url.searchParams.get('q')||'').toLowerCase().replace(/^[@#]/,'');
      if (!q) return send(res,400,{error:'Empty'});
      const list=Object.values(db.users).filter(u=>
        u.username?.includes(q)||u.uuid?.replace('#','').includes(q)||u.nickname?.toLowerCase().includes(q)
      ).map(safeUser);
      return send(res,200,list.slice(0,10));
    }

    // GET /api/messages?with=username
    if (req.method==='GET' && url.pathname==='/api/messages') {
      const me=validateSession(token); if(!me) return send(res,401,{error:'Unauthorized'});
      const withUser=url.searchParams.get('with');
      if (!withUser) return send(res,400,{error:'Missing with'});
      return send(res,200, getRoom(me.username,withUser));
    }

    // DELETE /api/messages/:id?with=username
    if (req.method==='DELETE' && url.pathname.startsWith('/api/messages/')) {
      const me=validateSession(token); if(!me) return send(res,401,{error:'Unauthorized'});
      const msgId=url.pathname.split('/').pop();
      const withUser=url.searchParams.get('with');
      const ok=deleteMsg(msgId,me.username,withUser);
      return send(res,200,{ok});
    }

    send(res,404,{error:'Not found'});
  });
});

function send(res,status,data) { res.writeHead(status,{'Content-Type':'application/json'}); res.end(JSON.stringify(data)); }
function serve(res) {
  const f=path.join(__dirname,'index.html');
  if (fs.existsSync(f)) { res.writeHead(200,{'Content-Type':'text/html;charset=utf-8'}); res.end(fs.readFileSync(f)); }
  else { res.writeHead(200,{'Content-Type':'text/html'}); res.end('<h2>Nexus v3 ✓</h2>'); }
}

// ─── WebSocket ───────────────────────────────────
const wss = new WebSocketServer({ server });
const clients = new Map(); // username → ws

wss.on('connection', ws => {
  let me = null;

  ws.on('message', raw => {
    let msg; try { msg=JSON.parse(raw); } catch { return; }

    switch (msg.type) {

      case 'auth': {
        const user=validateSession(msg.token);
        if (!user) { ws.send(J({type:'auth_fail'})); return; }
        me=user.username;
        clients.set(me,ws);
        user.lastSeen=Date.now(); user.online=true; schedSave();
        ws.send(J({type:'auth_ok',user:safeUser(user)}));
        broadcast({type:'presence',username:me,online:true},me);
        ws.send(J({type:'online_list',users:[...clients.keys()].filter(u=>u!==me)}));
        break;
      }

      case 'message': {
        if (!me) return;
        const m={...msg, from:me, ts:msg.ts||Date.now(), read:false};
        delete m.type;
        if (!m.id) return;
        saveMsg(m);
        relay(m.to, {type:'message',...m});
        // ACK back to sender (for dedup confirmation)
        ws.send(J({type:'msg_ack',id:m.id}));
        break;
      }

      case 'read': {
        if (!me) return;
        const room=getRoom(me,msg.from);
        room.forEach(m=>{ if(m.to===me&&!m.read) m.read=true; });
        schedSave();
        relay(msg.from,{type:'read',by:me});
        break;
      }

      case 'delete': {
        if (!me) return;
        deleteMsg(msg.mid, me, msg.with);
        relay(msg.with,{type:'deleted',mid:msg.mid});
        break;
      }

      case 'pin': {
        if (!me) return;
        pinMsg(msg.mid, me, msg.with, msg.pin);
        relay(msg.with,{type:'pinned',mid:msg.mid,pin:msg.pin});
        break;
      }

      case 'react': {
        if (!me) return;
        reactMsg(msg.mid, me, msg.with, me, msg.emoji);
        const room=getRoom(me,msg.with);
        const m=room.find(x=>x.id===msg.mid);
        relay(msg.with,{type:'reaction',mid:msg.mid,reactions:m?.reactions||{}});
        ws.send(J({type:'reaction',mid:msg.mid,reactions:m?.reactions||{}}));
        break;
      }

      case 'typing':
      case 'stop_typing':
        if (!me||!msg.to) return;
        relay(msg.to,{type:msg.type,from:me});
        break;

      // ── WebRTC ──
      case 'offer':
      case 'answer':
      case 'ice':
        if (!me||!msg.to) return;
        // If recipient is offline → save missed call message
        if (msg.type==='offer' && !clients.has(msg.to)) {
          const missed={
            id:`missed_${Date.now()}`, from:me, to:msg.to,
            type:'missed_call', callType:msg.ct||'audio',
            ts:Date.now(), read:false,
          };
          saveMsg(missed);
          ws.send(J({type:'call_missed_sent',to:msg.to}));
          return;
        }
        relay(msg.to,{...msg,from:me});
        break;

      case 'call_decline':
      case 'call_end':
        if (!me||!msg.to) return;
        relay(msg.to,{...msg,from:me});
        break;
    }
  });

  ws.on('close',()=>{
    if (!me) return;
    clients.delete(me);
    if (db.users[me]) { db.users[me].online=false; db.users[me].lastSeen=Date.now(); schedSave(); }
    broadcast({type:'presence',username:me,online:false},me);
  });
  ws.on('error',()=>{});
});

function relay(to,msg) {
  const sock=clients.get(to?.toLowerCase());
  if (sock&&sock.readyState===WebSocket.OPEN) sock.send(J(msg));
}
function broadcast(msg,except) {
  const raw=J(msg);
  clients.forEach((s,u)=>{ if(u!==except&&s.readyState===WebSocket.OPEN) s.send(raw); });
}
function J(o) { return JSON.stringify(o); }

server.listen(PORT,()=>{
  console.log(`\n🚀 Nexus v3  →  http://localhost:${PORT}`);
  console.log(`   DB: ${DB_FILE}\n`);
});
