/**
 * NEXUS SERVER v2 — пароли + сессии + автологин
 *
 * npm install ws
 * node server.js
 */

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto'); // встроен в Node — не нужно устанавливать
const { WebSocketServer, WebSocket } = require('ws');

const PORT    = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'db.json');

// ─────────────────────────────────────────────
//  DB
// ─────────────────────────────────────────────
function loadDB() {
  try { if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch {}
  return { users: {}, messages: {}, sessions: {}, counter: 0 };
}
function saveDB() {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); } catch(e) { console.error('DB:', e); }
}
let db = loadDB();
if (!db.sessions) db.sessions = {};
console.log(`✅ DB loaded — ${Object.keys(db.users).length} users, ${Object.keys(db.sessions).length} sessions`);

// ─────────────────────────────────────────────
//  CRYPTO helpers
// ─────────────────────────────────────────────
// Hash password: sha256( password + salt )
function hashPassword(password, salt) {
  return crypto.createHmac('sha256', salt).update(password).digest('hex');
}
function newSalt() { return crypto.randomBytes(16).toString('hex'); }
function newToken() { return crypto.randomBytes(32).toString('hex'); }

// ─────────────────────────────────────────────
//  SESSION helpers
// ─────────────────────────────────────────────
const SESSION_TTL = 30 * 24 * 60 * 60 * 1000; // 30 дней

function createSession(username) {
  const token = newToken();
  db.sessions[token] = { username: username.toLowerCase(), createdAt: Date.now() };
  // Clean expired sessions
  const now = Date.now();
  Object.keys(db.sessions).forEach(t => {
    if (now - db.sessions[t].createdAt > SESSION_TTL) delete db.sessions[t];
  });
  saveDB();
  return token;
}

function validateSession(token) {
  if (!token) return null;
  const s = db.sessions[token];
  if (!s) return null;
  if (Date.now() - s.createdAt > SESSION_TTL) { delete db.sessions[token]; saveDB(); return null; }
  return db.users[s.username] || null;
}

// ─────────────────────────────────────────────
//  HTTP / REST API
// ─────────────────────────────────────────────
const httpServer = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  if (!url.pathname.startsWith('/api/')) { serveFile(res); return; }

  let body = '';
  req.on('data', d => body += d);
  req.on('end', () => {
    const data = body ? safeJSON(body) : {};
    const token = (req.headers.authorization || '').replace('Bearer ', '').trim();

    // ── POST /api/register ──────────────────────────────
    if (req.method === 'POST' && url.pathname === '/api/register') {
      const { username, nickname, visibleName, color, password } = data;
      if (!username || !nickname || !password)
        return send(res, 400, { error: 'Заполни все поля' });
      if (password.length < 4)
        return send(res, 400, { error: 'Пароль минимум 4 символа' });

      const uname = username.toLowerCase().trim();
      if (db.users[uname]) return send(res, 409, { error: 'Username уже занят' });

      db.counter = (db.counter || 0) + 1;
      const salt = newSalt();
      const user = {
        uuid: '#' + String(db.counter).padStart(7, '0'),
        username: uname, nickname, visibleName: visibleName || nickname,
        color: color || '#4f8aff',
        salt,
        passwordHash: hashPassword(password, salt),
        createdAt: Date.now(), lastSeen: Date.now(),
      };
      db.users[uname] = user;
      saveDB();

      const sessionToken = createSession(uname);
      // Return user without sensitive fields
      return send(res, 200, { ok: true, token: sessionToken, user: safeUser(user) });
    }

    // ── POST /api/login ─────────────────────────────────
    if (req.method === 'POST' && url.pathname === '/api/login') {
      const { username, password } = data;
      if (!username || !password) return send(res, 400, { error: 'Введи логин и пароль' });

      const uname = username.toLowerCase().trim().replace(/^@/, '');

      // Search by username or UUID
      let user = db.users[uname];
      if (!user) {
        // Try UUID search
        user = Object.values(db.users).find(u =>
          u.uuid?.toLowerCase() === uname ||
          u.uuid?.replace('#','') === uname.replace('#','')
        );
      }

      if (!user) return send(res, 401, { error: 'Пользователь не найден' });

      const hash = hashPassword(password, user.salt);
      if (hash !== user.passwordHash) return send(res, 401, { error: 'Неверный пароль' });

      user.lastSeen = Date.now();
      saveDB();
      const sessionToken = createSession(user.username);
      return send(res, 200, { ok: true, token: sessionToken, user: safeUser(user) });
    }

    // ── GET /api/me — restore session ───────────────────
    if (req.method === 'GET' && url.pathname === '/api/me') {
      const user = validateSession(token);
      if (!user) return send(res, 401, { error: 'Сессия истекла' });
      return send(res, 200, { ok: true, user: safeUser(user) });
    }

    // ── POST /api/logout ────────────────────────────────
    if (req.method === 'POST' && url.pathname === '/api/logout') {
      if (token && db.sessions[token]) { delete db.sessions[token]; saveDB(); }
      return send(res, 200, { ok: true });
    }

    // ── GET /api/user?q=... ─────────────────────────────
    if (req.method === 'GET' && url.pathname === '/api/user') {
      const q = (url.searchParams.get('q') || '').toLowerCase().replace(/^[@#]/, '');
      if (!q) return send(res, 400, { error: 'Empty query' });
      const results = Object.values(db.users).filter(u =>
        u.username?.includes(q) ||
        u.uuid?.replace('#','').includes(q) ||
        u.nickname?.toLowerCase().includes(q)
      ).map(safeUser);
      return send(res, 200, results.slice(0, 10));
    }

    // ── GET /api/messages?a=&b= ─────────────────────────
    if (req.method === 'GET' && url.pathname === '/api/messages') {
      if (!validateSession(token)) return send(res, 401, { error: 'Unauthorized' });
      const a = url.searchParams.get('a'), b = url.searchParams.get('b');
      if (!a || !b) return send(res, 400, { error: 'Missing a/b' });
      const rid = [a, b].sort().join('__');
      return send(res, 200, db.messages[rid] || []);
    }

    send(res, 404, { error: 'Not found' });
  });
});

// ─────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────
function safeUser(u) {
  // Never send password hash / salt to client
  const { salt, passwordHash, ...safe } = u;
  return safe;
}
function send(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}
function safeJSON(str) { try { return JSON.parse(str); } catch { return {}; } }
function serveFile(res) {
  const f = path.join(__dirname, 'index.html');
  if (fs.existsSync(f)) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(fs.readFileSync(f));
  } else {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<h2>Nexus ✓</h2><p>Place index.html next to server.js</p>');
  }
}

// ─────────────────────────────────────────────
//  WEBSOCKET — real-time relay
// ─────────────────────────────────────────────
const wss = new WebSocketServer({ server: httpServer });
const clients = new Map(); // username → WebSocket

wss.on('connection', ws => {
  let myUser = null;

  ws.on('message', raw => {
    let msg; try { msg = JSON.parse(raw); } catch { return; }

    switch (msg.type) {

      case 'auth': {
        // Validate session token
        const user = validateSession(msg.token);
        if (!user) { ws.send(JSON.stringify({ type: 'auth_fail' })); return; }
        myUser = user.username;
        clients.set(myUser, ws);
        user.lastSeen = Date.now(); user.online = true; saveDB();
        ws.send(JSON.stringify({ type: 'auth_ok', username: myUser }));
        broadcast({ type: 'presence', username: myUser, online: true }, myUser);
        ws.send(JSON.stringify({ type: 'online_list', users: [...clients.keys()].filter(u => u !== myUser) }));
        break;
      }

      case 'message': {
        if (!myUser) return;
        msg.from = myUser;
        msg.ts   = msg.ts || Date.now();
        msg.read = false;
        const rid = [msg.from, msg.to].sort().join('__');
        if (!db.messages[rid]) db.messages[rid] = [];
        if (!db.messages[rid].find(m => m.id === msg.id)) {
          db.messages[rid].push(msg);
          if (db.messages[rid].length > 500) db.messages[rid] = db.messages[rid].slice(-500);
          saveDB();
        }
        relay(msg.to, { type: 'message', ...msg });
        break;
      }

      case 'read': {
        if (!myUser) return;
        const rid2 = [myUser, msg.to].sort().join('__');
        if (db.messages[rid2]) {
          db.messages[rid2] = db.messages[rid2].map(m => m.id === msg.mid ? { ...m, read: true } : m);
          saveDB();
        }
        relay(msg.to, { type: 'read', mid: msg.mid });
        break;
      }

      case 'typing':
      case 'stop_typing':
        if (!myUser || !msg.to) return;
        relay(msg.to, { type: msg.type, from: myUser });
        break;

      case 'offer':
      case 'answer':
      case 'ice':
      case 'call_decline':
      case 'call_end':
        if (!myUser || !msg.to) return;
        relay(msg.to, { ...msg, from: myUser });
        break;
    }
  });

  ws.on('close', () => {
    if (myUser) {
      clients.delete(myUser);
      if (db.users[myUser]) { db.users[myUser].online = false; db.users[myUser].lastSeen = Date.now(); saveDB(); }
      broadcast({ type: 'presence', username: myUser, online: false }, myUser);
      if (myUser && callPartners.has(myUser)) {
        const partner = callPartners.get(myUser);
        relay(partner, { type: 'call_end', from: myUser });
        callPartners.delete(myUser); callPartners.delete(partner);
      }
    }
  });

  ws.on('error', () => {});
});

// Track call pairs for cleanup on disconnect
const callPartners = new Map();

function relay(to, msg) {
  const sock = clients.get(to?.toLowerCase());
  if (sock && sock.readyState === WebSocket.OPEN) sock.send(JSON.stringify(msg));
}
function broadcast(msg, except) {
  const raw = JSON.stringify(msg);
  clients.forEach((sock, user) => {
    if (user !== except && sock.readyState === WebSocket.OPEN) sock.send(raw);
  });
}

httpServer.listen(PORT, () => {
  console.log(`\n🚀 Nexus Server v2`);
  console.log(`   http://localhost:${PORT}`);
  console.log(`   DB: ${DB_FILE}\n`);
});
