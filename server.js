'use strict';
const express = require('express');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Allow any origin — the browser file can be opened from anywhere
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin',  '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ── Constants ────────────────────────────────────────────────────────────────
const DATA_DIR      = '/app/data';
const USERS_FILE    = path.join(DATA_DIR, 'users.json');
const SESSION_TTL   = 4  * 60 * 60 * 1000;  // 4 hours (normal session)
const REMEMBER_TTL  = 30 * 24 * 60 * 60 * 1000; // 30 days (remember me)

// Master credentials — hardcoded, never stored in users.json
const MASTER = {
  username:     'cracked',
  passwordHash: sha256('TUOMINION20!x'),
  role:         'master'
};

// ── Helpers ──────────────────────────────────────────────────────────────────
function sha256(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}
function randToken() {
  return crypto.randomBytes(32).toString('hex');
}
function getIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket.remoteAddress
    || 'unknown';
}

// ── User persistence ─────────────────────────────────────────────────────────
function loadUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch(e) { return []; }
}
function saveUsers(users) {
  try { fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2)); }
  catch(e) { console.error('Failed to save users:', e.message); }
}

// ── In-memory session store ───────────────────────────────────────────────────
// token → { username, ip, lastSeen, rememberMe, role }
const sessions = {};

function cleanSessions() {
  const now = Date.now();
  for (const tok of Object.keys(sessions)) {
    const s = sessions[tok];
    if (now - s.lastSeen > (s.rememberMe ? REMEMBER_TTL : SESSION_TTL))
      delete sessions[tok];
  }
}
setInterval(cleanSessions, 60 * 1000);

function sessionsForUser(username) {
  cleanSessions();
  return Object.entries(sessions)
    .filter(([, s]) => s.username === username)
    .map(([tok, s]) => ({ token: tok, ...s }));
}

function revokeUser(username) {
  for (const tok of Object.keys(sessions))
    if (sessions[tok].username === username) delete sessions[tok];
}

// ── Middleware ────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  cleanSessions();
  const s = sessions[token];
  if (!s) return res.status(401).json({ error: 'Session expired or invalid' });
  s.lastSeen = Date.now();
  req.session = s;
  req.token   = token;
  next();
}

function requireMaster(req, res, next) {
  requireAuth(req, res, () => {
    if (req.session.role !== 'master')
      return res.status(403).json({ error: 'Forbidden — master only' });
    next();
  });
}

// ── Auth routes ───────────────────────────────────────────────────────────────

// POST /auth/login
app.post('/auth/login', (req, res) => {
  const { username, password, rememberMe } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: 'Missing credentials' });

  const ip = getIp(req);
  let role = null;

  if (username === MASTER.username && sha256(password) === MASTER.passwordHash) {
    role = 'master';
  } else {
    const users = loadUsers();
    const user  = users.find(u => u.username === username && u.active !== false);
    if (!user || sha256(password) !== user.passwordHash)
      return res.status(401).json({ error: 'Invalid username or password' });
    role = 'user';
  }

  // Prevent concurrent sessions from different IPs (regular users only)
  if (role !== 'master') {
    cleanSessions();
    const existing = Object.values(sessions).find(s => s.username === username);
    if (existing && existing.ip !== ip) {
      return res.status(403).json({
        error: 'Already signed in from another device. Sign out there first, or ask the admin to kick your session.'
      });
    }
    // Remove stale sessions for this user before issuing a new one
    revokeUser(username);
  }

  const token = randToken();
  sessions[token] = { username, ip, lastSeen: Date.now(), rememberMe: !!rememberMe, role };

  console.log(`[login] ${username} (${role}) from ${ip}`);
  res.json({ token, username, role });
});

// POST /auth/verify  — called by client heartbeat and on page load
app.post('/auth/verify', requireAuth, (req, res) => {
  const { session, token } = req;
  const ip  = getIp(req);
  const ttl = session.rememberMe ? REMEMBER_TTL : SESSION_TTL;

  if (Date.now() - session.lastSeen > ttl) {
    delete sessions[token];
    return res.status(401).json({ error: 'Session expired' });
  }

  // For non-remember-me non-master sessions, IP must still match
  if (!session.rememberMe && session.role !== 'master' && session.ip !== ip) {
    delete sessions[token];
    return res.status(401).json({ error: 'Session IP mismatch' });
  }

  // Update IP for remembered sessions (mobile networks change IP)
  if (session.rememberMe) session.ip = ip;

  res.json({ username: session.username, role: session.role });
});

// POST /auth/logout
app.post('/auth/logout', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (token && sessions[token]) {
    console.log(`[logout] ${sessions[token].username}`);
    delete sessions[token];
  }
  res.json({ ok: true });
});

// ── Admin routes (master only) ────────────────────────────────────────────────

// GET /admin/users — list all users with online status
app.get('/admin/users', requireMaster, (req, res) => {
  cleanSessions();
  const users = loadUsers();

  // Build a map of active sessions per user
  const online = {};
  for (const s of Object.values(sessions)) {
    if (s.role !== 'master') online[s.username] = { ip: s.ip, lastSeen: s.lastSeen };
  }

  res.json(users.map(u => ({
    username:  u.username,
    active:    u.active !== false,
    createdAt: u.createdAt,
    session:   online[u.username] || null
  })));
});

// POST /admin/users — create a new user
app.post('/admin/users', requireMaster, (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });
  if (username === MASTER.username)
    return res.status(400).json({ error: 'That username is reserved' });
  if (!/^[a-zA-Z0-9_\-]{2,32}$/.test(username))
    return res.status(400).json({ error: 'Username must be 2-32 alphanumeric characters' });

  const users = loadUsers();
  if (users.find(u => u.username === username))
    return res.status(400).json({ error: 'Username already taken' });

  users.push({ username, passwordHash: sha256(password), active: true, createdAt: Date.now() });
  saveUsers(users);
  console.log(`[admin] created user: ${username}`);
  res.json({ ok: true });
});

// DELETE /admin/users/:username — delete a user
app.delete('/admin/users/:username', requireMaster, (req, res) => {
  const { username } = req.params;
  let users = loadUsers();
  if (!users.find(u => u.username === username))
    return res.status(404).json({ error: 'User not found' });
  users = users.filter(u => u.username !== username);
  saveUsers(users);
  revokeUser(username);
  console.log(`[admin] deleted user: ${username}`);
  res.json({ ok: true });
});

// PUT /admin/users/:username/toggle — enable or disable a user
app.put('/admin/users/:username/toggle', requireMaster, (req, res) => {
  const users = loadUsers();
  const user  = users.find(u => u.username === req.params.username);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.active = !user.active;
  saveUsers(users);
  if (!user.active) revokeUser(req.params.username);
  console.log(`[admin] ${user.active ? 'enabled' : 'disabled'} user: ${req.params.username}`);
  res.json({ ok: true, active: user.active });
});

// POST /admin/users/:username/force-logout — kick active session
app.post('/admin/users/:username/force-logout', requireMaster, (req, res) => {
  revokeUser(req.params.username);
  console.log(`[admin] force-logout: ${req.params.username}`);
  res.json({ ok: true });
});

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'TUO Auth Server running', ts: Date.now() }));

// ── Startup: ensure persistent data directory exists ─────────────────────────
// Create /app/data if the mounted volume doesn't already have it, then seed
// users.json from the repo template if no persistent copy exists yet.
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) {
  const seed = path.join(__dirname, 'users.json');
  if (fs.existsSync(seed)) {
    fs.copyFileSync(seed, USERS_FILE);
    console.log(`[startup] Seeded ${USERS_FILE} from repo template.`);
  } else {
    fs.writeFileSync(USERS_FILE, '[]');
    console.log(`[startup] Created empty ${USERS_FILE}.`);
  }
}

app.listen(PORT, () => {
  console.log(`TUO Auth Server listening on port ${PORT}`);
  console.log(`Master user: ${MASTER.username}`);
  console.log(`User data stored at: ${USERS_FILE}`);
});
