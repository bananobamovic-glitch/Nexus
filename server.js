/**
 * NEXUS SERVER v5 — GitHub Gist как база данных
 *
 * Данные хранятся в GitHub Gist — не пропадают при перезапуске Render
 *
 * НАСТРОЙКА (1 минута):
 * 1. github.com/settings/tokens → Generate new token (classic)
 * 2. Поставь галочку "gist" → Generate token → скопируй ghp_...
 * 3. Render → Environment Variables:
 *    GITHUB_TOKEN = ghp_xxxxxxxxxxxxxxxx
 *    GIST_ID      = (пусто — создастся автоматически при первом запуске)
 */

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const https  = require('https');
const { WebSocketServer, WebSocket } = require('ws');

const PORT         = process.env.PORT || 3000;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const SESSION_TTL  = 365 * 24 * 60 * 60 * 1000;

// ─── In-memory DB ────────────────────────────────
let db = {
  users: {},
  sessions: {},
  messages: {},
  counter: 0,
  gistId: process.env.GIST_ID || '',
};

// ─── GitHub Gist helpers ─────────────────────────
function gistRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const options = {
      hostname: 'api.github.com',
      path,
      method,
      headers: {
        'Authorization': `token ${GITHUB_TOKEN}`,
        'User-Agent': 'Nexus-Messenger',
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/json',
        ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
      },
    };
    const req = https.request(options, res => {
      let raw = '';
      res.on('data', d => raw += d);
      res.on('end', () => {
        try { resolve(JSON.parse(raw)); }
        catch { resolve(null); }
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

// Сохраняем db в Gist (только users, sessions, counter — без сообщений т.к. большие)
let saveTimer = null;
async function schedSave() {
  if (!GITHUB_TOKEN) return;
  if (saveTimer) return;
  saveTimer = setTimeout(async () => {
    saveTimer = null;
    await saveToGist();
  }, 2000); // debounce 2s
}

async function saveToGist() {
  if (!GITHUB_TOKEN) return;
  // Сохраняем: users, sessions, counter, messages (последние 100 на комнату)
  const slim = {
    users: db.users,
    sessions: db.sessions,
    counter: db.counter,
    messages: {},
  };
  // Обрезаем messages до последних 100 на комнату
  Object.keys(db.messages).forEach(room => {
    const msgs = db.messages[room];
    slim.messages[room] = msgs.slice(-100);
  });

  const content = JSON.stringify(slim);
  const payload = {
    description: 'Nexus Messenger DB',
    files: { 'nexus-db.json': { content } },
  };

  try {
    if (db.gistId) {
      await gistRequest('PATCH', `/gists/${db.gistId}`, payload);
    } else {
      payload.public = false;
      const result = await gistRequest('POST', '/gists', payload);
      if (result && result.id) {
        db.gistId = result.id;
        console.log(`✅ Gist создан: ${result.id}`);
        console.log(`   Добавь в Render → Environment: GIST_ID = ${result.id}`);
      }
    }
  } catch (e) {
    console.error('Gist save error:', e.message);
  }
}

async function loadFromGist() {
  if (!GITHUB_TOKEN || !db.gistId) return;
  try {
    const result = await gistRequest('GET', `/gists/${db.gistId}`);
    if (!result || !result.files || !result.files['nexus-db.json']) return;
    const raw = result.files['nexus-db.json'].content;
    const parsed = JSON.parse(raw);
    db.users    = parsed.users    || {};
    db.sessions = parsed.sessions || {};
    db.counter  = parsed.counter  || 0;
    db.messages = parsed.messages || {};
    console.log(`✅ Gist загружен: ${Object.keys(db.users).length} users`);
  } catch (e) {
    console.error('Gist load error:', e.message);
  }
}

// ─── Crypto ──────────────────────────────────────
const hashPw   = (pw, salt) => crypto.createHmac('sha256', salt).update(pw).digest('hex');
const newSalt  = () => crypto.randomBytes(16).toString('hex');
const newToken = () => crypto.randomBytes(32).toString('hex');
const roomId   = (a, b) => [a, b].sort().join('|');

// ─── Sessions ────────────────────────────────────
function createSession(username) {
  const token = newToken();
  // Удаляем старые сессии этого пользователя (оставляем последние 5)
  const userSessions = Object.entries(db.sessions)
    .filter(([, s]) => s.username === username)
    .sort(([, a], [, b]) => b.ts - a.ts);
  if (userSessions.length >= 5) {
    userSessions.slice(4).forEach(([t]) => delete db.sessions[t]);
  }
  db.sessions[token] = { username: username.toLowerCase(), ts: Date.now() };
  // Чистим истёкшие
  const cut = Date.now() - SESSION_TTL;
  Object.keys(db.sessions).forEach(t => { if (db.sessions[t].ts < cut) delete db.sessions[t]; });
  schedSave();
  return token;
}

function validateSession(token) {
  if (!token) return null;
  const s = db.sessions[token];
  if (!s || Date.now() - s.ts > SESSION_TTL) { delete db.sessions[token]; return null; }
  return db.users[s.username] || null;
}

function safeUser(u) {
  if (!u) return null;
  const { salt, passwordHash, ...safe } = u;
  return safe;
}

// ─── Messages ────────────────────────────────────
function getRoom(a, b) {
  const r = roomId(a, b);
  if (!db.messages[r]) db.messages[r] = [];
  return db.messages[r];
}

function saveMsg(msg) {
  const room = getRoom(msg.from, msg.to);
  if (room.find(m => m.id === msg.id)) return;
  room.push(msg);
  if (room.length > 200) room.splice(0, room.length - 200);
  schedSave();
}

function deleteMsg(msgId) {
  Object.values(db.messages).forEach(room => {
    const m = room.find(x => x.id === msgId);
    if (m) { m.deleted = true; m.text = ''; delete m.src; }
  });
  schedSave();
}

function pinMsg(msgId, pin) {
  Object.values(db.messages).forEach(room => {
    const m = room.find(x => x.id === msgId);
    if (m) m.pinned = pin;
  });
  schedSave();
}

function reactMsg(msgId, user, emoji) {
  let reactions = null;
  Object.values(db.messages).forEach(room => {
    const m = room.find(x => x.id === msgId);
    if (!m) return;
    if (!m.reactions) m.reactions = {};
    if (!m.reactions[emoji]) m.reactions[emoji] = [];
    const idx = m.reactions[emoji].indexOf(user);
    if (idx === -1) m.reactions[emoji].push(user);
    else m.reactions[emoji].splice(idx, 1);
    reactions = m.reactions;
  });
  schedSave();
  return reactions;
}

function markRoomRead(userA, userB) {
  const room = getRoom(userA, userB);
  room.forEach(m => { if (m.to === userA) m.read = true; });
  schedSave();
}

// ─── HTTP ─────────────────────────────────────────
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
  if (!url.pathname.startsWith('/api/')) { serve(res); return; }

  let body = '';
  req.on('data', d => body += d);
  req.on('end', () => {
    const data = body ? (() => { try { return JSON.parse(body); } catch { return {}; } })() : {};
    const token = (req.headers.authorization || '').replace('Bearer ', '').trim();

    // POST /api/register
    if (req.method === 'POST' && url.pathname === '/api/register') {
      const { username, nickname, visibleName, color, password } = data;
      if (!username || !nickname || !password) return send(res, 400, { error: 'Заполни все поля' });
      if (password.length < 4) return send(res, 400, { error: 'Пароль минимум 4 символа' });
      const uname = username.toLowerCase().trim();
      if (!/^[a-z0-9_]{3,24}$/.test(uname)) return send(res, 400, { error: 'Username: 3–24 символа a-z 0-9 _' });
      if (db.users[uname]) return send(res, 409, { error: 'Username уже занят' });
      db.counter = (db.counter || 0) + 1;
      const salt = newSalt();
      const user = {
        uuid: '#' + String(db.counter).padStart(7, '0'),
        username: uname, nickname,
        visibleName: visibleName || nickname,
        color: color || '#4f8aff',
        salt, passwordHash: hashPw(password, salt),
        createdAt: Date.now(), lastSeen: Date.now(),
      };
      db.users[uname] = user;
      schedSave();
      const t = createSession(uname);
      return send(res, 200, { ok: true, token: t, user: safeUser(user) });
    }

    // POST /api/login
    if (req.method === 'POST' && url.pathname === '/api/login') {
      const { username, password } = data;
      if (!username || !password) return send(res, 400, { error: 'Введи логин и пароль' });
      const q = username.toLowerCase().trim().replace(/^@/, '');
      let user = db.users[q];
      if (!user) user = Object.values(db.users).find(u => u.uuid === q || u.uuid === '#' + q);
      if (!user) return send(res, 401, { error: 'Пользователь не найден' });
      if (hashPw(password, user.salt) !== user.passwordHash) return send(res, 401, { error: 'Неверный пароль' });
      user.lastSeen = Date.now();
      schedSave();
      const t = createSession(user.username);
      return send(res, 200, { ok: true, token: t, user: safeUser(user) });
    }

    // GET /api/me
    if (req.method === 'GET' && url.pathname === '/api/me') {
      const user = validateSession(token);
      if (!user) return send(res, 401, { error: 'Сессия истекла' });
      user.lastSeen = Date.now();
      return send(res, 200, { ok: true, user: safeUser(user) });
    }

    // POST /api/logout
    if (req.method === 'POST' && url.pathname === '/api/logout') {
      if (token) { delete db.sessions[token]; schedSave(); }
      return send(res, 200, { ok: true });
    }

    // GET /api/users?q=
    if (req.method === 'GET' && url.pathname === '/api/users') {
      const q = (url.searchParams.get('q') || '').toLowerCase().replace(/^[@#]/, '');
      if (!q) return send(res, 400, { error: 'Empty' });
      const list = Object.values(db.users).filter(u =>
        u.username?.includes(q) ||
        u.uuid?.replace('#', '').includes(q) ||
        u.nickname?.toLowerCase().includes(q)
      ).map(safeUser);
      return send(res, 200, list.slice(0, 10));
    }

    // GET /api/messages?with=
    if (req.method === 'GET' && url.pathname === '/api/messages') {
      const me = validateSession(token);
      if (!me) return send(res, 401, { error: 'Unauthorized' });
      const withUser = url.searchParams.get('with');
      if (!withUser) return send(res, 400, { error: 'Missing with' });
      markRoomRead(me.username, withUser);
      return send(res, 200, getRoom(me.username, withUser));
    }

    send(res, 404, { error: 'Not found' });
  });
});

function send(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}
function serve(res) {
  const f = path.join(__dirname, 'index.html');
  if (fs.existsSync(f)) {
    res.writeHead(200, { 'Content-Type': 'text/html;charset=utf-8' });
    res.end(fs.readFileSync(f));
  } else {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<h2>Nexus v5 ✓</h2>');
  }
}

// ─── WebSocket ────────────────────────────────────
const wss = new WebSocketServer({ server });
const clients = new Map();

wss.on('connection', ws => {
  let me = null;

  ws.on('message', raw => {
    let msg; try { msg = JSON.parse(raw); } catch { return; }

    switch (msg.type) {

      case 'auth': {
        const user = validateSession(msg.token);
        if (!user) { ws.send(J({ type: 'auth_fail' })); return; }
        me = user.username;
        clients.set(me, ws);
        user.lastSeen = Date.now(); user.online = true;
        ws.send(J({ type: 'auth_ok', user: safeUser(user) }));
        broadcast({ type: 'presence', username: me, online: true }, me);
        ws.send(J({ type: 'online_list', users: [...clients.keys()].filter(u => u !== me) }));
        break;
      }

      case 'message': {
        if (!me) return;
        const m = { ...msg, from: me, ts: msg.ts || Date.now(), read: false };
        delete m.type;
        if (!m.id) return;
        saveMsg(m);
        relay(m.to, { type: 'message', ...m });
        ws.send(J({ type: 'msg_ack', id: m.id }));
        break;
      }

      case 'read': {
        if (!me) return;
        markRoomRead(me, msg.from);
        relay(msg.from, { type: 'read', by: me });
        break;
      }

      case 'delete': {
        if (!me) return;
        deleteMsg(msg.mid);
        relay(msg.with, { type: 'deleted', mid: msg.mid });
        break;
      }

      case 'pin': {
        if (!me) return;
        pinMsg(msg.mid, msg.pin);
        relay(msg.with, { type: 'pinned', mid: msg.mid, pin: msg.pin });
        break;
      }

      case 'react': {
        if (!me) return;
        const reactions = reactMsg(msg.mid, me, msg.emoji);
        relay(msg.with, { type: 'reaction', mid: msg.mid, reactions: reactions || {} });
        ws.send(J({ type: 'reaction', mid: msg.mid, reactions: reactions || {} }));
        break;
      }

      case 'typing':
      case 'stop_typing':
        if (!me || !msg.to) return;
        relay(msg.to, { type: msg.type, from: me });
        break;

      case 'offer':
      case 'answer':
      case 'ice':
        if (!me || !msg.to) return;
        if (msg.type === 'offer' && !clients.has(msg.to)) {
          const missed = {
            id: `missed_${Date.now()}`, from: me, to: msg.to,
            type: 'missed_call', callType: msg.ct || 'audio',
            ts: Date.now(), read: false,
          };
          saveMsg(missed);
          ws.send(J({ type: 'call_missed_sent', to: msg.to }));
          return;
        }
        relay(msg.to, { ...msg, from: me });
        break;

      case 'call_decline':
      case 'call_end':
        if (!me || !msg.to) return;
        relay(msg.to, { ...msg, from: me });
        break;
    }
  });

  ws.on('close', () => {
    if (!me) return;
    clients.delete(me);
    if (db.users[me]) { db.users[me].online = false; db.users[me].lastSeen = Date.now(); }
    broadcast({ type: 'presence', username: me, online: false }, me);
  });

  ws.on('error', () => {});
});

function relay(to, msg) {
  const sock = clients.get(to?.toLowerCase());
  if (sock && sock.readyState === WebSocket.OPEN) sock.send(J(msg));
}
function broadcast(msg, except) {
  const raw = J(msg);
  clients.forEach((s, u) => { if (u !== except && s.readyState === WebSocket.OPEN) s.send(raw); });
}
function J(o) { return JSON.stringify(o); }

// ─── Start ────────────────────────────────────────
async function start() {
  if (!GITHUB_TOKEN) {
    console.warn('⚠️  GITHUB_TOKEN не задан — данные не сохранятся при перезапуске');
    console.warn('   Добавь в Render → Environment Variables: GITHUB_TOKEN = ghp_...');
  } else {
    console.log('📦 Загружаю данные из GitHub Gist...');
    await loadFromGist();
  }

  server.listen(PORT, () => {
    console.log(`\n🚀 Nexus v5 → http://localhost:${PORT}`);
    console.log(`   Users: ${Object.keys(db.users).length}`);
    console.log(`   Gist: ${db.gistId || 'создастся при первом сохранении'}\n`);
  });
}

start();
