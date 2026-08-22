/**
 * NEXUS SERVER v7
 * + Приватные аккаунты (скрыты из поиска)
 * + Каналы на сервере (публичные + приватные по инвайту)
 * + /api/invite/:code — резолв приватных ссылок
 * + /api/channels — список публичных каналов
 * + /api/channels/join — вступить в канал
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

// ─── In-memory DB ─────────────────────────────────
let db = {
  users:    {},
  sessions: {},
  messages: {},
  channels: {},   // id → channel object
  counter:  0,
  gistId:   process.env.GIST_ID || '',
};

// ─── GitHub Gist ───────────────────────────────────
function gistReq(method, p, body) {
  return new Promise((resolve) => {
    const data = body ? JSON.stringify(body) : null;
    const req = https.request({
      hostname: 'api.github.com', path: p, method,
      headers: {
        'Authorization': `token ${GITHUB_TOKEN}`,
        'User-Agent': 'Nexus-Messenger',
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/json',
        ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
      },
    }, res => {
      let raw = '';
      res.on('data', d => raw += d);
      res.on('end', () => { try { resolve(JSON.parse(raw)); } catch { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    if (data) req.write(data);
    req.end();
  });
}

let saveTimer = null;
function schedSave() {
  if (!GITHUB_TOKEN) return;
  if (saveTimer) return;
  saveTimer = setTimeout(async () => { saveTimer = null; await saveGist(); }, 2000);
}

async function saveGist() {
  if (!GITHUB_TOKEN) return;
  const slim = {
    users:    db.users,
    sessions: db.sessions,
    counter:  db.counter,
    channels: db.channels,
    messages: {},
  };
  Object.keys(db.messages).forEach(r => {
    slim.messages[r] = db.messages[r].slice(-100);
  });
  const payload = {
    description: 'Nexus DB',
    files: { 'nexus-db.json': { content: JSON.stringify(slim) } },
  };
  if (db.gistId) {
    await gistReq('PATCH', `/gists/${db.gistId}`, payload);
  } else {
    payload.public = false;
    const r = await gistReq('POST', '/gists', payload);
    if (r?.id) {
      db.gistId = r.id;
      console.log(`✅ Gist создан: ${r.id}`);
      console.log(`   Добавь в Render → Environment: GIST_ID = ${r.id}`);
    }
  }
}

async function loadGist() {
  if (!GITHUB_TOKEN || !db.gistId) return;
  const r = await gistReq('GET', `/gists/${db.gistId}`);
  if (!r?.files?.['nexus-db.json']) return;
  try {
    const p = JSON.parse(r.files['nexus-db.json'].content);
    db.users    = p.users    || {};
    db.sessions = p.sessions || {};
    db.counter  = p.counter  || 0;
    db.messages = p.messages || {};
    db.channels = p.channels || {};
    console.log(`✅ Gist загружен: ${Object.keys(db.users).length} users, ${Object.keys(db.channels).length} channels`);
  } catch(e) { console.error('Gist parse error:', e.message); }
}

// ─── Crypto ───────────────────────────────────────
const hashPw   = (pw, salt) => crypto.createHmac('sha256', salt).update(pw).digest('hex');
const newSalt  = () => crypto.randomBytes(16).toString('hex');
const newToken = () => crypto.randomBytes(32).toString('hex');
const roomId   = (a, b) => [a, b].sort().join('|');

// Генерация короткого invite-кода (10 символов)
function genInvite() {
  const chars = 'ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz123456789';
  let r = '';
  for (let i = 0; i < 10; i++) r += chars[Math.floor(Math.random() * chars.length)];
  return r;
}

// ─── Sessions ─────────────────────────────────────
function createSession(username, ua) {
  const token = newToken();
  const userSess = Object.entries(db.sessions)
    .filter(([,s]) => s.username === username)
    .sort(([,a],[,b]) => b.ts - a.ts);
  if (userSess.length >= 10) {
    userSess.slice(9).forEach(([t]) => delete db.sessions[t]);
  }
  db.sessions[token] = { username: username.toLowerCase(), ts: Date.now(), ua: ua || 'Unknown' };
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

// Safe channel (strip posts for listings)
function safeChannel(ch, withPosts = false) {
  if (!ch) return null;
  const { posts, ...meta } = ch;
  if (withPosts) return { ...meta, posts: posts || [] };
  return { ...meta, postCount: (posts || []).length };
}

// ─── Messages ─────────────────────────────────────
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
function markRoomRead(userA, userB) {
  getRoom(userA, userB).forEach(m => { if (m.to === userA) m.read = true; });
  schedSave();
}

// ─── HTTP ──────────────────────────────────────────
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,PATCH,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ── Статика ─────────────────────────────────────
  if (!url.pathname.startsWith('/api/')) {
    // Приватный инвайт: /Hv60KsH2Vz  (10 симв)
    // Редиректим на фронт с параметром
    const invMatch = url.pathname.match(/^\/([A-Za-z0-9]{10})$/);
    if (invMatch) {
      const code = invMatch[1];
      const ch = Object.values(db.channels).find(c => c.invite === code);
      if (ch) {
        // Редирект на SPA с параметром chi=code
        res.writeHead(302, { 'Location': `/?chi=${code}` });
        res.end();
        return;
      }
    }
    if (url.pathname === '/manifest.json') return serve(res, 'manifest.json');
    if (url.pathname === '/sw.js')         return serve(res, 'sw.js');
    if (url.pathname === '/icon-192.png')  return serve(res, 'icon-192.png');
    return serve(res, 'index.html');
  }

  let body = '';
  req.on('data', d => body += d);
  req.on('end', () => {
    const data  = body ? (() => { try { return JSON.parse(body); } catch { return {}; } })() : {};
    const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
    const ua    = req.headers['user-agent'] || 'Unknown';

    // ── POST /api/register ────────────────────────
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
        private: false,   // ← приватность аккаунта
      };
      db.users[uname] = user; schedSave();
      return send(res, 200, { ok: true, token: createSession(uname, ua), user: safeUser(user) });
    }

    // ── POST /api/login ───────────────────────────
    if (req.method === 'POST' && url.pathname === '/api/login') {
      const { username, password } = data;
      if (!username || !password) return send(res, 400, { error: 'Введи логин и пароль' });
      const q = username.toLowerCase().trim().replace(/^@/, '');
      let user = db.users[q];
      if (!user) user = Object.values(db.users).find(u => u.uuid === q || u.uuid === '#' + q);
      if (!user) return send(res, 401, { error: 'Пользователь не найден' });
      if (hashPw(password, user.salt) !== user.passwordHash) return send(res, 401, { error: 'Неверный пароль' });
      user.lastSeen = Date.now(); schedSave();
      return send(res, 200, { ok: true, token: createSession(user.username, ua), user: safeUser(user) });
    }

    // ── GET /api/me ───────────────────────────────
    if (req.method === 'GET' && url.pathname === '/api/me') {
      const user = validateSession(token);
      if (!user) return send(res, 401, { error: 'Сессия истекла' });
      user.lastSeen = Date.now();
      return send(res, 200, { ok: true, user: safeUser(user) });
    }

    // ── POST /api/logout ──────────────────────────
    if (req.method === 'POST' && url.pathname === '/api/logout') {
      if (token) { delete db.sessions[token]; schedSave(); }
      return send(res, 200, { ok: true });
    }

    // ── GET /api/users?q= ─────────────────────────
    // Приватные аккаунты НЕ видны в поиске чужим
    if (req.method === 'GET' && url.pathname === '/api/users') {
      const me = validateSession(token); // может быть null — анонимный запрос
      const myUsername = me?.username || null;
      const q = (url.searchParams.get('q') || '').toLowerCase().replace(/^[@#]/, '');
      if (!q) return send(res, 400, { error: 'Empty' });
      const list = Object.values(db.users).filter(u => {
        // Всегда показываем самого себя
        if (u.username === myUsername) return true;
        // Приватный — скрыт из общего поиска
        if (u.private) return false;
        return u.username?.includes(q)
          || u.uuid?.replace('#','').includes(q)
          || u.nickname?.toLowerCase().includes(q);
      }).map(safeUser);
      return send(res, 200, list.slice(0, 10));
    }

    // ── GET /api/messages?with= ───────────────────
    if (req.method === 'GET' && url.pathname === '/api/messages') {
      const me = validateSession(token);
      if (!me) return send(res, 401, { error: 'Unauthorized' });
      const withUser = url.searchParams.get('with');
      if (!withUser) return send(res, 400, { error: 'Missing with' });
      markRoomRead(me.username, withUser);
      return send(res, 200, getRoom(me.username, withUser));
    }

    // ── POST /api/profile ─────────────────────────
    // Поддерживает поле private (булево)
    if (req.method === 'POST' && url.pathname === '/api/profile') {
      const user = validateSession(token);
      if (!user) return send(res, 401, { error: 'Unauthorized' });
      const { nickname, visibleName, color, password } = data;
      if (nickname)     user.nickname     = nickname;
      if (visibleName)  user.visibleName  = visibleName;
      if (color)        user.color        = color;
      if (typeof data.private === 'boolean') user.private = data.private;
      if (password) {
        if (password.length < 4) return send(res, 400, { error: 'Пароль минимум 4 символа' });
        const salt = newSalt();
        user.salt         = salt;
        user.passwordHash = hashPw(password, salt);
      }
      db.users[user.username] = user; schedSave();
      return send(res, 200, { ok: true, user: safeUser(user) });
    }

    // ── GET /api/sessions ─────────────────────────
    if (req.method === 'GET' && url.pathname === '/api/sessions') {
      const user = validateSession(token);
      if (!user) return send(res, 401, { error: 'Unauthorized' });
      const sessions = Object.entries(db.sessions)
        .filter(([, s]) => s.username === user.username)
        .map(([tok, s]) => ({ token: tok, ts: s.ts, ua: s.ua || 'Unknown', isCurrent: tok === token }))
        .sort((a, b) => b.ts - a.ts);
      return send(res, 200, { ok: true, sessions });
    }

    // ── POST /api/sessions/revoke ─────────────────
    if (req.method === 'POST' && url.pathname === '/api/sessions/revoke') {
      const user = validateSession(token);
      if (!user) return send(res, 401, { error: 'Unauthorized' });
      const { token: rt } = data;
      if (rt && db.sessions[rt]?.username === user.username) { delete db.sessions[rt]; schedSave(); }
      return send(res, 200, { ok: true });
    }

    // ── POST /api/sessions/revoke-all ────────────
    if (req.method === 'POST' && url.pathname === '/api/sessions/revoke-all') {
      const user = validateSession(token);
      if (!user) return send(res, 401, { error: 'Unauthorized' });
      Object.keys(db.sessions).forEach(t => {
        if (t !== token && db.sessions[t]?.username === user.username) delete db.sessions[t];
      });
      schedSave();
      return send(res, 200, { ok: true });
    }

    // ── GET /api/ice ──────────────────────────────
    if (req.method === 'GET' && url.pathname === '/api/ice') {
      return send(res, 200, {
        iceServers: [
          { urls: 'stun:stun.l.google.com:19302' },
          { urls: 'stun:stun1.l.google.com:19302' },
          { urls: 'stun:stun.relay.metered.ca:80' },
          { urls: 'turn:global.relay.metered.ca:80',    username: 'openrelayproject', credential: 'openrelayproject' },
          { urls: 'turn:global.relay.metered.ca:443',   username: 'openrelayproject', credential: 'openrelayproject' },
          { urls: 'turns:global.relay.metered.ca:443',  username: 'openrelayproject', credential: 'openrelayproject' },
        ]
      });
    }

    // ════════════════════════════════════════════════
    //  CHANNELS API
    // ════════════════════════════════════════════════

    // ── GET /api/channels ─────────────────────────
    // Список публичных каналов (для discovery)
    // ?q= — поиск по имени/slug
    // ?slug= — точный поиск по slug
    if (req.method === 'GET' && url.pathname === '/api/channels') {
      const q    = (url.searchParams.get('q')    || '').toLowerCase().trim();
      const slug = (url.searchParams.get('slug') || '').toLowerCase().trim();

      let list = Object.values(db.channels).filter(c => c.type === 'public');

      if (slug) {
        list = list.filter(c => c.slug === slug);
      } else if (q) {
        list = list.filter(c =>
          c.name?.toLowerCase().includes(q) ||
          c.slug?.toLowerCase().includes(q) ||
          c.desc?.toLowerCase().includes(q)
        );
      }

      return send(res, 200, {
        ok: true,
        channels: list.sort((a,b) => (b.memberCount||0)-(a.memberCount||0))
                      .slice(0, 30)
                      .map(c => safeChannel(c)),
      });
    }

    // ── POST /api/channels ────────────────────────
    // Создать канал
    if (req.method === 'POST' && url.pathname === '/api/channels') {
      const me = validateSession(token);
      if (!me) return send(res, 401, { error: 'Unauthorized' });

      const { name, desc, emoji, color, type, slug } = data;
      if (!name || name.trim().length < 1) return send(res, 400, { error: 'Укажи название канала' });

      const chType = type === 'private' ? 'private' : 'public';

      // Для публичного — проверяем slug
      if (chType === 'public') {
        const s = (slug || '').toLowerCase().trim().replace(/[^a-z0-9_]/g, '');
        if (s.length < 3) return send(res, 400, { error: 'Адрес канала минимум 3 символа' });
        if (Object.values(db.channels).some(c => c.slug === s && c.type === 'public')) {
          return send(res, 409, { error: 'Этот адрес уже занят' });
        }
      }

      const id      = 'ch_' + crypto.randomBytes(8).toString('hex');
      const invite  = genInvite();
      const cleanSlug = chType === 'public'
        ? (slug || '').toLowerCase().trim().replace(/[^a-z0-9_]/g, '')
        : '';

      const ch = {
        id,
        name:        name.trim(),
        desc:        (desc || '').trim(),
        emoji:       emoji  || '📢',
        color:       color  || '#4f8aff',
        type:        chType,
        slug:        cleanSlug,
        invite,                          // всегда генерируем — для приватного это единственный вход
        owner:       me.username,
        members:     [me.username],
        memberCount: 1,
        posts:       [],
        createdAt:   Date.now(),
      };

      db.channels[id] = ch; schedSave();
      return send(res, 200, { ok: true, channel: safeChannel(ch, true) });
    }

    // ── GET /api/channels/:id ─────────────────────
    // Данные канала (с постами)
    const chGetMatch = url.pathname.match(/^\/api\/channels\/([^/]+)$/);
    if (req.method === 'GET' && chGetMatch) {
      const id = chGetMatch[1];
      const ch = db.channels[id];
      if (!ch) return send(res, 404, { error: 'Канал не найден' });

      // Приватный — проверяем членство
      if (ch.type === 'private') {
        const me = validateSession(token);
        if (!me || !ch.members.includes(me.username)) {
          return send(res, 403, { error: 'Нет доступа — нужна ссылка-приглашение' });
        }
      }

      return send(res, 200, { ok: true, channel: safeChannel(ch, true) });
    }

    // ── PATCH /api/channels/:id ───────────────────
    // Редактировать канал (только владелец)
    const chPatchMatch = url.pathname.match(/^\/api\/channels\/([^/]+)$/);
    if (req.method === 'PATCH' && chPatchMatch) {
      const me = validateSession(token);
      if (!me) return send(res, 401, { error: 'Unauthorized' });
      const id = chPatchMatch[1];
      const ch = db.channels[id];
      if (!ch)                      return send(res, 404, { error: 'Канал не найден' });
      if (ch.owner !== me.username) return send(res, 403, { error: 'Только владелец может редактировать' });

      const { name, desc, emoji, color, type, slug } = data;
      if (name)  ch.name  = name.trim();
      if (desc !== undefined) ch.desc = desc.trim();
      if (emoji) ch.emoji = emoji;
      if (color) ch.color = color;

      if (type && (type === 'public' || type === 'private')) {
        const oldType = ch.type;
        ch.type = type;
        if (type === 'public' && slug) {
          const s = slug.toLowerCase().trim().replace(/[^a-z0-9_]/g, '');
          if (s.length >= 3) {
            // Check uniqueness (excluding self)
            const taken = Object.values(db.channels).find(c => c.id !== id && c.slug === s && c.type === 'public');
            if (taken) return send(res, 409, { error: 'Адрес уже занят' });
            ch.slug = s;
          }
        }
        if (type === 'private') ch.slug = '';
      }

      db.channels[id] = ch; schedSave();
      return send(res, 200, { ok: true, channel: safeChannel(ch) });
    }

    // ── DELETE /api/channels/:id ──────────────────
    const chDelMatch = url.pathname.match(/^\/api\/channels\/([^/]+)$/);
    if (req.method === 'DELETE' && chDelMatch) {
      const me = validateSession(token);
      if (!me) return send(res, 401, { error: 'Unauthorized' });
      const id = chDelMatch[1];
      const ch = db.channels[id];
      if (!ch)                      return send(res, 404, { error: 'Не найден' });
      if (ch.owner !== me.username) return send(res, 403, { error: 'Только владелец' });
      delete db.channels[id]; schedSave();
      return send(res, 200, { ok: true });
    }

    // ── POST /api/channels/:id/join ───────────────
    // Вступить в канал (публичный — свободно, приватный — по invite)
    const chJoinMatch = url.pathname.match(/^\/api\/channels\/([^/]+)\/join$/);
    if (req.method === 'POST' && chJoinMatch) {
      const me = validateSession(token);
      if (!me) return send(res, 401, { error: 'Unauthorized' });
      const id = chJoinMatch[1];
      const ch = db.channels[id];
      if (!ch) return send(res, 404, { error: 'Канал не найден' });

      if (ch.type === 'private') {
        const { invite } = data;
        if (invite !== ch.invite) return send(res, 403, { error: 'Неверная ссылка-приглашение' });
      }

      if (!ch.members.includes(me.username)) {
        ch.members.push(me.username);
        ch.memberCount = ch.members.length;
        schedSave();
      }
      return send(res, 200, { ok: true, channel: safeChannel(ch, true) });
    }

    // ── POST /api/channels/:id/leave ─────────────
    const chLeaveMatch = url.pathname.match(/^\/api\/channels\/([^/]+)\/leave$/);
    if (req.method === 'POST' && chLeaveMatch) {
      const me = validateSession(token);
      if (!me) return send(res, 401, { error: 'Unauthorized' });
      const id = chLeaveMatch[1];
      const ch = db.channels[id];
      if (!ch) return send(res, 404, { error: 'Не найден' });
      ch.members = ch.members.filter(u => u !== me.username);
      ch.memberCount = ch.members.length;
      schedSave();
      return send(res, 200, { ok: true });
    }

    // ── POST /api/channels/:id/post ───────────────
    // Опубликовать пост (только владелец)
    const chPostMatch = url.pathname.match(/^\/api\/channels\/([^/]+)\/post$/);
    if (req.method === 'POST' && chPostMatch) {
      const me = validateSession(token);
      if (!me) return send(res, 401, { error: 'Unauthorized' });
      const id = chPostMatch[1];
      const ch = db.channels[id];
      if (!ch)                      return send(res, 404, { error: 'Не найден' });
      if (ch.owner !== me.username) return send(res, 403, { error: 'Только владелец может постить' });

      const { text } = data;
      if (!text || !text.trim()) return send(res, 400, { error: 'Пустой пост' });

      const post = { id: crypto.randomBytes(8).toString('hex'), text: text.trim(), ts: Date.now() };
      if (!ch.posts) ch.posts = [];
      ch.posts.push(post);
      if (ch.posts.length > 500) ch.posts.splice(0, ch.posts.length - 500);
      schedSave();

      // Уведомить всех онлайн-подписчиков через WS
      ch.members.forEach(uname => {
        if (uname === me.username) return;
        const sock = clients.get(uname);
        if (sock && sock.readyState === WebSocket.OPEN) {
          sock.send(J({ type: 'channel_post', channelId: id, post }));
        }
      });

      return send(res, 200, { ok: true, post });
    }

    // ── GET /api/invite/:code ─────────────────────
    // Резолв инвайт-кода — возвращает мета канала БЕЗ постов
    const invMatch = url.pathname.match(/^\/api\/invite\/([A-Za-z0-9]{10})$/);
    if (req.method === 'GET' && invMatch) {
      const code = invMatch[1];
      const ch = Object.values(db.channels).find(c => c.invite === code);
      if (!ch) return send(res, 404, { error: 'Ссылка недействительна' });
      return send(res, 200, { ok: true, channel: safeChannel(ch) });
    }

    send(res, 404, { error: 'Not found' });
  });
});

function send(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function serve(res, filePath) {
  if (!filePath || filePath === 'index.html') {
    const html = cachedHTML || (fs.existsSync(path.join(__dirname,'index.html')) && fs.readFileSync(path.join(__dirname,'index.html'),'utf8'));
    if (html) {
      res.writeHead(200, { 'Content-Type': 'text/html;charset=utf-8' });
      res.end(html);
    } else {
      res.writeHead(200, { 'Content-Type': 'text/html;charset=utf-8' });
      res.end(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Nexus</title>
<style>body{background:#07090f;color:#dde6f8;font-family:Arial;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;margin:0;gap:12px;text-align:center}
h1{font-size:48px;margin:0;background:linear-gradient(135deg,#4f8aff,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
p{color:#6b7fa3;font-size:13px;max-width:340px;line-height:1.7}code{background:#111520;padding:2px 7px;border-radius:5px;color:#4f8aff}</style></head>
<body><h1>NEXUS</h1><p>Сервер работает ✅<br><br>Загрузи <code>index.html</code> в репо рядом с <code>server.js</code></p></body></html>`);
    }
    return;
  }
  const f = path.join(__dirname, filePath);
  if (fs.existsSync(f)) {
    const ext   = path.extname(f);
    const types = { '.json':'application/json', '.js':'application/javascript', '.png':'image/png', '.ico':'image/x-icon' };
    res.writeHead(200, { 'Content-Type': types[ext] || 'text/plain' });
    res.end(fs.readFileSync(f));
  } else {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('');
  }
}

// ─── WebSocket ─────────────────────────────────────
const wss     = new WebSocketServer({ server });
const clients = new Map(); // username → ws

wss.on('connection', ws => {
  let me = null;

  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', raw => {
    let msg; try { msg = JSON.parse(raw); } catch { return; }

    switch (msg.type) {

      case 'ping':
        ws.send(J({ type: 'pong' }));
        break;

      case 'auth': {
        const user = validateSession(msg.token);
        if (!user) { ws.send(J({ type: 'auth_fail' })); return; }
        me = user.username;
        const old = clients.get(me);
        if (old && old !== ws && old.readyState === WebSocket.OPEN) {
          old.send(J({ type: 'kicked' }));
          old.close();
        }
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
        const room = getRoom(me, msg.with);
        const m = room.find(x => x.id === msg.mid);
        if (m) { m.deleted = true; m.text = ''; delete m.src; schedSave(); }
        relay(msg.with, { type: 'deleted', mid: msg.mid });
        break;
      }

      case 'pin': {
        if (!me) return;
        const roomP = getRoom(me, msg.with);
        roomP.forEach(m => { if (m.id === msg.mid) m.pinned = msg.pin; });
        schedSave();
        relay(msg.with, { type: 'pinned', mid: msg.mid, pin: msg.pin });
        break;
      }

      case 'react': {
        if (!me) return;
        const roomR = getRoom(me, msg.with);
        const mR = roomR.find(x => x.id === msg.mid);
        if (!mR) return;
        if (!mR.reactions) mR.reactions = {};
        if (!mR.reactions[msg.emoji]) mR.reactions[msg.emoji] = [];
        const idx = mR.reactions[msg.emoji].indexOf(me);
        if (idx === -1) mR.reactions[msg.emoji].push(me);
        else mR.reactions[msg.emoji].splice(idx, 1);
        schedSave();
        const reactions = mR.reactions;
        relay(msg.with, { type: 'reaction', mid: msg.mid, reactions });
        ws.send(J({ type: 'reaction', mid: msg.mid, reactions }));
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
    if (clients.get(me) === ws) {
      clients.delete(me);
      if (db.users[me]) { db.users[me].online = false; db.users[me].lastSeen = Date.now(); }
      broadcast({ type: 'presence', username: me, online: false }, me);
    }
  });

  ws.on('error', () => {});
});

// Ping every 25s
const pingInterval = setInterval(() => {
  wss.clients.forEach(ws => {
    if (!ws.isAlive) { ws.terminate(); return; }
    ws.isAlive = false;
    ws.ping();
  });
}, 25000);

wss.on('close', () => clearInterval(pingInterval));

function relay(to, msg) {
  const sock = clients.get(to?.toLowerCase());
  if (sock && sock.readyState === WebSocket.OPEN) sock.send(J(msg));
}
function broadcast(msg, except) {
  const raw = J(msg);
  clients.forEach((s, u) => { if (u !== except && s.readyState === WebSocket.OPEN) s.send(raw); });
}
function J(o) { return JSON.stringify(o); }

// ─── Start ─────────────────────────────────────────
const REPO_RAW = 'https://raw.githubusercontent.com/bananobamovic-glitch/Nexus/main/index.html';
let cachedHTML = null;

async function fetchHTML() {
  const local = path.join(__dirname, 'index.html');
  if (fs.existsSync(local)) {
    cachedHTML = fs.readFileSync(local, 'utf8');
    console.log('✅ index.html загружен локально');
    return;
  }
  console.log('📥 index.html не найден локально, скачиваю с GitHub...');
  return new Promise(resolve => {
    https.get(REPO_RAW, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        if (res.statusCode === 200 && data.includes('<!DOCTYPE')) {
          cachedHTML = data;
          console.log('✅ index.html скачан (' + data.length + ' bytes)');
        } else {
          console.warn('⚠️ Не удалось скачать index.html, статус: ' + res.statusCode);
        }
        resolve();
      });
    }).on('error', e => { console.warn('⚠️ Ошибка:', e.message); resolve(); });
  });
}

async function start() {
  if (!GITHUB_TOKEN) {
    console.warn('⚠️  GITHUB_TOKEN не задан — данные не сохранятся между перезапусками');
  } else {
    console.log('📦 Загружаю из GitHub Gist...');
    await loadGist();
  }
  await fetchHTML();
  server.listen(PORT, () => {
    console.log(`\n🚀 Nexus v7 → http://localhost:${PORT}`);
    console.log(`   Users:    ${Object.keys(db.users).length}`);
    console.log(`   Channels: ${Object.keys(db.channels).length}`);
    console.log(`   HTML:     ${cachedHTML ? 'OK' : '❌ НЕ ЗАГРУЖЕН'}`);
    console.log(`   Gist:     ${db.gistId || 'создастся при первом сохранении'}\n`);
  });
}

start();
