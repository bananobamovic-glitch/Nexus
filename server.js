/**
 * NEXUS SERVER — один файл, всё включено
 * 
 * Запуск локально:
 *   npm install ws
 *   node server.js
 * 
 * Деплой на Render.com (бесплатно):
 *   1. github.com → New repo → загрузи server.js и package.json
 *   2. render.com → New Web Service → подключи repo
 *   3. Build: npm install  |  Start: node server.js
 *   4. Получишь URL вида https://nexus-xxxx.onrender.com
 *   5. Вставь этот URL в index.html (переменная SERVER_URL)
 */

const http  = require('http');
const fs    = require('fs');
const path  = require('path');
const { WebSocketServer, WebSocket } = require('ws');

const PORT   = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'db.json');

// ── DB helpers ──────────────────────────────────────────
function loadDB() {
  try {
    if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch {}
  return { users: {}, messages: {}, counter: 0 };
}

function saveDB(db) {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); } catch(e) { console.error('DB save error:', e); }
}

let db = loadDB();
console.log(`DB loaded: ${Object.keys(db.users).length} users`);

// ── HTTP server (serves index.html + REST API) ──────────
const httpServer = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost`);

  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ── REST API ──────────────────────────────────────────
  if (url.pathname.startsWith('/api/')) {

    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      const data = body ? (() => { try { return JSON.parse(body) } catch { return {} } })() : {};

      // POST /api/register
      if (req.method === 'POST' && url.pathname === '/api/register') {
        const { username, nickname, visibleName, color } = data;
        if (!username || !nickname) return send(res, 400, { error: 'Missing fields' });
        const uname = username.toLowerCase().trim();
        if (db.users[uname]) return send(res, 409, { error: 'Username занят' });
        db.counter = (db.counter || 0) + 1;
        const user = {
          uuid: '#' + String(db.counter).padStart(7, '0'),
          username: uname, nickname, visibleName, color,
          createdAt: Date.now(), lastSeen: Date.now(),
        };
        db.users[uname] = user;
        saveDB(db);
        return send(res, 200, { ok: true, user });
      }

      // GET /api/user?q=username_or_uuid
      if (req.method === 'GET' && url.pathname === '/api/user') {
        const q = (url.searchParams.get('q') || '').toLowerCase().replace(/^[@#]/, '');
        const results = Object.values(db.users).filter(u =>
          u.username?.includes(q) ||
          u.uuid?.replace('#','').includes(q) ||
          u.nickname?.toLowerCase().includes(q)
        );
        return send(res, 200, results.slice(0, 10));
      }

      // GET /api/messages?a=user1&b=user2
      if (req.method === 'GET' && url.pathname === '/api/messages') {
        const a = url.searchParams.get('a'), b = url.searchParams.get('b');
        if (!a || !b) return send(res, 400, { error: 'Missing a/b' });
        const rid = [a, b].sort().join('__');
        return send(res, 200, db.messages[rid] || []);
      }

      // POST /api/messages
      if (req.method === 'POST' && url.pathname === '/api/messages') {
        const { id, from, to, text, ts } = data;
        if (!id || !from || !to || !text) return send(res, 400, { error: 'Missing fields' });
        const rid = [from, to].sort().join('__');
        if (!db.messages[rid]) db.messages[rid] = [];
        if (!db.messages[rid].find(m => m.id === id)) {
          db.messages[rid].push({ id, from, to, text, ts: ts || Date.now(), read: false });
          if (db.messages[rid].length > 500) db.messages[rid] = db.messages[rid].slice(-500);
          saveDB(db);
        }
        return send(res, 200, { ok: true });
      }

      // Serve index.html for everything else
      serveFile(res);
    });
    return;
  }

  serveFile(res);
});

function send(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function serveFile(res) {
  const f = path.join(__dirname, 'index.html');
  if (fs.existsSync(f)) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(fs.readFileSync(f));
  } else {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<h2>Nexus Server running ✓</h2><p>Upload index.html to serve the app.</p>');
  }
}

// ── WebSocket server ────────────────────────────────────
const wss = new WebSocketServer({ server: httpServer });

// clients: Map<username, WebSocket>
const clients = new Map();

wss.on('connection', (ws) => {
  let myUser = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    switch (msg.type) {

      // Client identifies itself
      case 'auth':
        myUser = msg.username?.toLowerCase();
        if (!myUser) return;
        clients.set(myUser, ws);
        ws.send(JSON.stringify({ type: 'auth_ok', username: myUser }));
        // Update lastSeen
        if (db.users[myUser]) {
          db.users[myUser].lastSeen = Date.now();
          db.users[myUser].online = true;
          saveDB(db);
        }
        // Broadcast presence
        broadcast({ type: 'presence', username: myUser, online: true }, myUser);
        // Send online list to new client
        const onlineList = [...clients.keys()].filter(u => u !== myUser);
        ws.send(JSON.stringify({ type: 'online_list', users: onlineList }));
        break;

      // Chat message (relay + save)
      case 'message':
        if (!myUser) return;
        msg.from = myUser; // enforce sender
        msg.ts   = msg.ts || Date.now();
        msg.read = false;
        // Save to DB
        const rid = [msg.from, msg.to].sort().join('__');
        if (!db.messages[rid]) db.messages[rid] = [];
        if (!db.messages[rid].find(m => m.id === msg.id)) {
          db.messages[rid].push(msg);
          if (db.messages[rid].length > 500) db.messages[rid] = db.messages[rid].slice(-500);
          saveDB(db);
        }
        // Relay to recipient
        relay(msg.to, { type: 'message', ...msg });
        break;

      // Read receipt
      case 'read':
        if (!myUser) return;
        // Update DB
        const r2 = [msg.from || myUser, msg.to].sort().join('__');
        if (db.messages[r2]) {
          db.messages[r2] = db.messages[r2].map(m =>
            m.id === msg.mid ? { ...m, read: true } : m
          );
          saveDB(db);
        }
        relay(msg.to, { type: 'read', mid: msg.mid });
        break;

      // Typing indicator
      case 'typing':
      case 'stop_typing':
        if (!myUser || !msg.to) return;
        relay(msg.to, { type: msg.type, from: myUser });
        break;

      // WebRTC signaling — pure relay
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
      if (db.users[myUser]) {
        db.users[myUser].online = false;
        db.users[myUser].lastSeen = Date.now();
        saveDB(db);
      }
      broadcast({ type: 'presence', username: myUser, online: false }, myUser);
    }
  });

  ws.on('error', () => {});
});

function relay(to, msg) {
  const ws = clients.get(to?.toLowerCase());
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(msg));
  }
}

function broadcast(msg, exceptUser) {
  const raw = JSON.stringify(msg);
  clients.forEach((ws, user) => {
    if (user !== exceptUser && ws.readyState === WebSocket.OPEN) ws.send(raw);
  });
}

httpServer.listen(PORT, () => {
  console.log(`✅ Nexus server running on port ${PORT}`);
  console.log(`   Local:   http://localhost:${PORT}`);
  console.log(`   DB file: ${DB_FILE}`);
});
