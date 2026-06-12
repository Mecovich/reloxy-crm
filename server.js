require('dotenv').config();

if (!process.env.JWT_SECRET) {
  console.error('FATAL: JWT_SECRET is not set. Add it to your environment variables.');
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@libsql/client');
const { OAuth2Client } = require('google-auth-library');

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Turso returns BigInt for row IDs — teach JSON how to serialize them
BigInt.prototype.toJSON = function() { return Number(this); };

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 минут
  max: 20,
  message: { error: 'Too many attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

const app = express();

// Behind a reverse proxy (Render/Fly/Nginx) — needed for correct client IP in rate limiting
app.set('trust proxy', 1);

// Auto-wrap async route handlers so a rejected promise reaches the global error
// handler instead of hanging the request (Express 4 doesn't catch async throws).
['get', 'post', 'put', 'delete', 'patch'].forEach((method) => {
  const original = app[method].bind(app);
  app[method] = (path, ...handlers) =>
    original(
      path,
      ...handlers.map((h) =>
        typeof h === 'function' && h.length < 4
          ? (req, res, next) => Promise.resolve(h(req, res, next)).catch(next)
          : h
      )
    );
});

app.use(helmet({ contentSecurityPolicy: false })); // CSP отдельно при необходимости
app.use(cors({
  origin: process.env.APP_URL || 'https://reloxy.tech',
  credentials: true,
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Shared helpers ──────────────────────────────────────────────────────────
// Numeric coercion that preserves 0 (so a value/budget/amount of 0 is NOT lost)
function num(v) {
  if (v === '' || v === undefined || v === null) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}
// Escape user input before putting it into Telegram HTML messages
function tgEsc(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ─── Turso DB ───────────────────────────────────────────────────────────────
const db = createClient({
  url: process.env.TURSO_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// ─── Telegram ────────────────────────────────────────────────────────────────
async function sendTelegram(text) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return;
  try {
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML' }),
    });
  } catch (e) {
    console.error('Telegram error:', e.message);
  }
}

// ─── Init DB ─────────────────────────────────────────────────────────────────
async function initDB() {
  const tables = [
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      plan TEXT DEFAULT 'free',
      studio_name TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      industry TEXT,
      contact_name TEXT,
      email TEXT,
      phone TEXT,
      status TEXT DEFAULT 'active',
      notes TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`,
    `CREATE TABLE IF NOT EXISTS projects (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      client_id INTEGER,
      title TEXT NOT NULL,
      type TEXT,
      status TEXT DEFAULT 'queue',
      progress INTEGER DEFAULT 0,
      deadline TEXT,
      budget REAL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (client_id) REFERENCES clients(id)
    )`,
    `CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      project_id INTEGER,
      title TEXT NOT NULL,
      description TEXT,
      status TEXT DEFAULT 'todo',
      priority TEXT DEFAULT 'medium',
      due_date TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (project_id) REFERENCES projects(id)
    )`,
    `CREATE TABLE IF NOT EXISTS deals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      client_id INTEGER,
      title TEXT NOT NULL,
      value REAL,
      stage TEXT DEFAULT 'new',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (client_id) REFERENCES clients(id)
    )`,
    `CREATE TABLE IF NOT EXISTS invoices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      client_id INTEGER,
      number TEXT,
      amount REAL,
      issued_at TEXT,
      due_at TEXT,
      status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (client_id) REFERENCES clients(id)
    )`,
    `CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      date TEXT NOT NULL,
      time TEXT,
      color TEXT DEFAULT '#000000',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`,
    `CREATE TABLE IF NOT EXISTS project_stages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      project_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      status TEXT DEFAULT 'planned',
      position INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (project_id) REFERENCES projects(id)
    )`,
    `CREATE TABLE IF NOT EXISTS staff (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      position TEXT,
      email TEXT,
      phone TEXT,
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`,
  ];
  for (const sql of tables) {
    await db.execute({ sql, args: [] });
  }

  // ─── Migrations: add new columns to existing tables ───────────────────────
  const migrations = [
    `ALTER TABLE users ADD COLUMN plan TEXT DEFAULT 'free'`,
    `ALTER TABLE users ADD COLUMN trial_ends_at TEXT DEFAULT NULL`,
    `ALTER TABLE users ADD COLUMN studio_name TEXT DEFAULT ''`,
    `ALTER TABLE clients ADD COLUMN industry TEXT DEFAULT ''`,
    `ALTER TABLE clients ADD COLUMN contact_name TEXT DEFAULT ''`,
    `ALTER TABLE clients ADD COLUMN status TEXT DEFAULT 'active'`,
    `ALTER TABLE projects ADD COLUMN type TEXT DEFAULT ''`,
    `ALTER TABLE projects ADD COLUMN progress INTEGER DEFAULT 0`,
    `ALTER TABLE deals ADD COLUMN value REAL`,
    `ALTER TABLE deals ADD COLUMN stage TEXT DEFAULT 'new'`,
    `ALTER TABLE invoices ADD COLUMN issued_at TEXT`,
    `ALTER TABLE invoices ADD COLUMN due_at TEXT`,
    `ALTER TABLE invoices ADD COLUMN project_id INTEGER DEFAULT NULL`,
    `ALTER TABLE users ADD COLUMN invite_token TEXT DEFAULT ''`,
    `ALTER TABLE users ADD COLUMN owner_id INTEGER DEFAULT NULL`,
    `ALTER TABLE users ADD COLUMN google_id TEXT DEFAULT NULL`,
    `ALTER TABLE projects ADD COLUMN assigned_to INTEGER DEFAULT NULL`,
    `ALTER TABLE users ADD COLUMN telegram_chat_id TEXT DEFAULT NULL`,
    `ALTER TABLE users ADD COLUMN tg_link_code TEXT DEFAULT NULL`,
    `ALTER TABLE projects ADD COLUMN share_token TEXT DEFAULT NULL`,
  ];
  for (const sql of migrations) {
    try {
      await db.execute({ sql, args: [] });
    } catch (e) {
      // Ignore "duplicate column" (migration already applied); surface anything else.
      if (!/duplicate column/i.test(e.message || '')) {
        console.error('Migration warning:', sql, '→', e.message);
      }
    }
  }

  // ─── Indexes for the columns we filter/join on most ───────────────────────
  const indexes = [
    `CREATE INDEX IF NOT EXISTS idx_clients_user      ON clients(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_projects_user     ON projects(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_projects_assigned ON projects(assigned_to)`,
    `CREATE INDEX IF NOT EXISTS idx_projects_share    ON projects(share_token)`,
    `CREATE INDEX IF NOT EXISTS idx_tasks_user        ON tasks(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_deals_user        ON deals(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_invoices_user     ON invoices(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_events_user       ON events(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_staff_user        ON staff(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_stages_project    ON project_stages(project_id)`,
    `CREATE INDEX IF NOT EXISTS idx_users_owner       ON users(owner_id)`,
    `CREATE INDEX IF NOT EXISTS idx_users_google      ON users(google_id)`,
  ];
  for (const sql of indexes) {
    try { await db.execute({ sql, args: [] }); } catch (e) { console.error('Index warning:', e.message); }
  }

  console.log('✅ DB initialized');
}

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Verify admin role against the DB, not the (long-lived) JWT claim, so a demoted
// admin loses access immediately instead of keeping it until the token expires.
async function adminMiddleware(req, res, next) {
  const row = await db.execute({ sql: 'SELECT role FROM users WHERE id = ?', args: [req.user.id] });
  if (row.rows[0]?.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────
async function handleRegister(req, res) {
  try {
    const { name, email, password, studioName } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email format' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const existing = await db.execute({ sql: 'SELECT id FROM users WHERE email = ?', args: [email] });
    if (existing.rows.length > 0) return res.status(400).json({ error: 'Email already exists' });

    const hash = await bcrypt.hash(password, 10);
    const role = email === process.env.ADMIN_EMAIL ? 'admin' : 'user';

    const result = await db.execute({
      sql: 'INSERT INTO users (name, email, password, role, studio_name, trial_ends_at) VALUES (?, ?, ?, ?, ?, ?)',
      args: [name, email, hash, role, studioName || '', trialEnd()],
    });

    const token = jwt.sign(
      { id: result.lastInsertRowid, email, role, name },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    await sendTelegram(`🆕 <b>New user</b>\nName: ${tgEsc(name)}\nEmail: ${tgEsc(email)}`);

    res.json({ token, user: { id: result.lastInsertRowid, name, email, role, plan: 'free', trial_ends_at: trialEnd(), studioName: studioName || '' } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Internal server error' });
  }
}

async function handleLogin(req, res) {
  try {
    const { email, password } = req.body;
    const result = await db.execute({ sql: 'SELECT * FROM users WHERE email = ?', args: [email] });
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: 'User not found' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Wrong password' });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, name: user.name, owner_id: user.owner_id || null },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, plan: user.plan, trial_ends_at: user.trial_ends_at || null, owner_id: user.owner_id || null } });
  } catch (e) {
    res.status(500).json({ error: 'Internal server error' });
  }
}

app.post('/api/auth/register', authLimiter, handleRegister);
app.post('/api/auth/login',    authLimiter, handleLogin);

// ─── Google OAuth (redirect flow) ────────────────────────────────────────────
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT = process.env.GOOGLE_REDIRECT_URI || 'https://reloxy.tech/api/auth/google/callback';

// Short-lived one-time codes so the JWT never travels in the redirect URL
// (URLs leak via browser history, referrer headers and proxy/server logs).
const oauthCodes = new Map(); // code -> { payload, exp }
function putOAuthCode(payload) {
  const code = crypto.randomBytes(24).toString('hex');
  oauthCodes.set(code, { payload, exp: Date.now() + 60 * 1000 }); // 60s TTL
  return code;
}
setInterval(() => {
  const now = Date.now();
  for (const [c, v] of oauthCodes) if (v.exp < now) oauthCodes.delete(c);
}, 60 * 1000).unref?.();

// Frontend exchanges the one-time code for the actual JWT + user
app.post('/api/auth/exchange', (req, res) => {
  const { code } = req.body || {};
  const entry = code && oauthCodes.get(code);
  if (!entry || entry.exp < Date.now()) return res.status(400).json({ error: 'Invalid or expired code' });
  oauthCodes.delete(code); // single use
  res.json(entry.payload);
});

app.get('/api/auth/google', (req, res) => {
  const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  url.searchParams.set('client_id', GOOGLE_CLIENT_ID);
  url.searchParams.set('redirect_uri', GOOGLE_REDIRECT);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'openid email profile');
  url.searchParams.set('access_type', 'offline');
  url.searchParams.set('prompt', 'select_account');
  res.redirect(url.toString());
});

app.get('/api/auth/google/callback', async (req, res) => {
  try {
    const { code, error } = req.query;
    if (error || !code) return res.redirect('/login?error=google_denied');

    // Exchange code for tokens
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT,
        grant_type: 'authorization_code',
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.id_token) return res.redirect('/login?error=no_token');

    // Verify ID token to get user info
    const ticket = await googleClient.verifyIdToken({
      idToken: tokenData.id_token,
      audience: GOOGLE_CLIENT_ID,
    });
    const { sub: googleId, email, name } = ticket.getPayload();

    // Find or create user
    let result = await db.execute({ sql: 'SELECT * FROM users WHERE google_id = ? OR email = ?', args: [googleId, email] });
    let user = result.rows[0];

    if (!user) {
      const role = email === process.env.ADMIN_EMAIL ? 'admin' : 'user';
      const placeholder = await bcrypt.hash('google_oauth_' + googleId, 10);
      const ins = await db.execute({
        sql: 'INSERT INTO users (name, email, password, role, google_id, studio_name, trial_ends_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        args: [name, email, placeholder, role, googleId, '', trialEnd()],
      });
      user = { id: ins.lastInsertRowid, name, email, role, plan: 'free', trial_ends_at: trialEnd() };
      await sendTelegram(`🆕 <b>New Google user</b>\nName: ${tgEsc(name)}\nEmail: ${tgEsc(email)}`);
    } else if (!user.google_id) {
      await db.execute({ sql: 'UPDATE users SET google_id = ? WHERE id = ?', args: [googleId, user.id] });
    }

    const jwtToken = jwt.sign(
      { id: user.id, email: user.email || email, role: user.role, name: user.name || name },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    // Hand the frontend a one-time code (not the token) to exchange via POST
    const otc = putOAuthCode({
      token: jwtToken,
      user: {
        name: user.name || name,
        email: user.email || email,
        role: user.role,
        plan: user.plan || 'free',
        trial_ends_at: user.trial_ends_at || null,
      },
    });
    res.redirect(`/app?code=${otc}`);
  } catch (e) {
    console.error('Google callback error:', e.message);
    res.redirect('/login?error=google_failed');
  }
});
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  const result = await db.execute({ sql: 'SELECT id, name, email, role, plan, trial_ends_at, studio_name, owner_id, created_at FROM users WHERE id = ?', args: [req.user.id] });
  res.json(result.rows[0]);
});

app.post('/api/register', authLimiter, handleRegister);
app.post('/api/login',    authLimiter, handleLogin);
app.get('/api/me', authMiddleware, async (req, res) => {
  const result = await db.execute({ sql: 'SELECT id, name, email, role, plan, trial_ends_at, studio_name, owner_id, created_at FROM users WHERE id = ?', args: [req.user.id] });
  res.json(result.rows[0]);
});

app.post('/api/upgrade-request', authMiddleware, async (req, res) => {
  try {
    const { plan } = req.body;
    await sendTelegram(`💳 <b>Заявка на тариф</b>\nUser: ${tgEsc(req.user.name || '')} (${tgEsc(req.user.email || '')})\nПлан: ${tgEsc(String(plan || '?'))}`);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Internal server error' }); }
});

// ─── Role helpers ─────────────────────────────────────────────────────────────
function ownerId(req)  { return req.user.owner_id || req.user.id; }

// ─── Plans ───────────────────────────────────────────────────────────────────
const PLAN_STAFF_LIMITS = { free: 2, pro: 7, studio: Infinity };
function trialEnd() { const d = new Date(); d.setDate(d.getDate() + 14); return d.toISOString(); }
async function getEffectivePlan(userId) {
  const r = await db.execute({ sql: 'SELECT plan, trial_ends_at FROM users WHERE id = ?', args: [userId] });
  const u = r.rows[0] || {};
  if (u.trial_ends_at && new Date(u.trial_ends_at) > new Date()) return 'studio';
  return u.plan || 'free';
}
function isStaff(req)  { return req.user.role === 'staff'; }
function denyStaff(req, res) { if (isStaff(req)) { res.status(403).json({ error: 'Staff access denied' }); return true; } return false; }

// Resolve an assignee to a valid users.id that belongs to this workspace.
// Returns the numeric user id, or null if invalid (prevents cross-tenant
// assignment / notifications). The owner may also assign to themselves.
async function validAssignee(req, assignedTo) {
  if (!assignedTo) return null;
  const uid = ownerId(req);
  if (Number(assignedTo) === Number(uid)) return Number(assignedTo);
  const r = await db.execute({ sql: 'SELECT id FROM users WHERE id=? AND owner_id=?', args: [assignedTo, uid] });
  return r.rows.length ? Number(assignedTo) : null;
}

// ─── CLIENTS ─────────────────────────────────────────────────────────────────
app.get('/api/clients', authMiddleware, async (req, res) => {
  const result = await db.execute({ sql: 'SELECT * FROM clients WHERE user_id = ? ORDER BY created_at DESC', args: [ownerId(req)] });
  res.json(result.rows);
});

app.post('/api/clients', authMiddleware, async (req, res) => {
  const { name, industry, contact_name, email, phone, status, notes } = req.body;
  const result = await db.execute({
    sql: 'INSERT INTO clients (user_id, name, industry, contact_name, email, phone, status, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    args: [ownerId(req), name, industry||'', contact_name||'', email||'', phone||'', status||'active', notes||''],
  });
  const row = await db.execute({ sql: 'SELECT * FROM clients WHERE id = ?', args: [result.lastInsertRowid] });
  res.json(row.rows[0]);
});

app.put('/api/clients/:id', authMiddleware, async (req, res) => {
  const { name, industry, contact_name, email, phone, status, notes } = req.body;
  await db.execute({
    sql: 'UPDATE clients SET name=?, industry=?, contact_name=?, email=?, phone=?, status=?, notes=? WHERE id=? AND user_id=?',
    args: [name, industry||'', contact_name||'', email||'', phone||'', status||'active', notes||'', req.params.id, ownerId(req)],
  });
  const row = await db.execute({ sql: 'SELECT * FROM clients WHERE id = ?', args: [req.params.id] });
  res.json(row.rows[0]);
});

app.delete('/api/clients/:id', authMiddleware, async (req, res) => {
  const uid = ownerId(req);
  // Detach the client from anything that references it, then delete (SQLite has no
  // ON DELETE here, so we avoid dangling client_id values).
  await db.execute({ sql: 'UPDATE projects SET client_id=NULL WHERE client_id=? AND user_id=?', args: [req.params.id, uid] });
  await db.execute({ sql: 'UPDATE deals    SET client_id=NULL WHERE client_id=? AND user_id=?', args: [req.params.id, uid] });
  await db.execute({ sql: 'UPDATE invoices SET client_id=NULL WHERE client_id=? AND user_id=?', args: [req.params.id, uid] });
  await db.execute({ sql: 'DELETE FROM clients WHERE id=? AND user_id=?', args: [req.params.id, uid] });
  res.json({ ok: true });
});

// ─── PROJECTS ────────────────────────────────────────────────────────────────
app.get('/api/projects', authMiddleware, async (req, res) => {
  const uid = ownerId(req);
  let sql, args;
  if (isStaff(req)) {
    sql = `SELECT p.*, c.name as client_name FROM projects p
           LEFT JOIN clients c ON p.client_id = c.id
           WHERE p.user_id = ? AND p.assigned_to = ? ORDER BY p.created_at DESC`;
    args = [uid, req.user.id];
  } else {
    sql = `SELECT p.*, c.name as client_name FROM projects p
           LEFT JOIN clients c ON p.client_id = c.id
           WHERE p.user_id = ? ORDER BY p.created_at DESC`;
    args = [uid];
  }
  const result = await db.execute({ sql, args });
  res.json(result.rows);
});

app.post('/api/projects', authMiddleware, async (req, res) => {
  if (denyStaff(req, res)) return;
  const { title, type, client_id, status, progress, deadline, budget, assigned_to } = req.body;
  if (!title) return res.status(400).json({ error: 'Title is required' });
  const uid = ownerId(req);
  if (client_id) {
    const cl = await db.execute({ sql: 'SELECT id FROM clients WHERE id=? AND user_id=?', args: [client_id, uid] });
    if (!cl.rows.length) return res.status(403).json({ error: 'Invalid client' });
  }
  // assigned_to must be a real user account in this workspace (validated)
  const assignee = await validAssignee(req, assigned_to);
  const safeProgress = Math.max(0, Math.min(100, parseInt(progress) || 0));
  const result = await db.execute({
    sql: 'INSERT INTO projects (user_id, client_id, title, type, status, progress, deadline, budget, assigned_to) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    args: [uid, client_id||null, title, type||'', status||'queue', safeProgress, deadline||null, num(budget), assignee],
  });
  const row = await db.execute({ sql: 'SELECT * FROM projects WHERE id = ?', args: [result.lastInsertRowid] });
  // Notify assigned staff
  if (assignee) {
    const deadline_str = deadline ? `\n📅 Deadline: ${tgEsc(deadline)}` : '';
    await notifyUser(assignee,
      `🔔 <b>New project assigned to you</b>\n\n📁 <b>${tgEsc(title)}</b>${deadline_str}\n\nAssigned by: ${tgEsc(req.user.name)}\n\n→ <a href="https://reloxy.tech/app">Open Reloxy</a>`
    );
  }
  res.json(row.rows[0]);
});

app.put('/api/projects/:id', authMiddleware, async (req, res) => {
  if (denyStaff(req, res)) return;
  const { title, type, client_id, status, progress, deadline, budget, assigned_to } = req.body;
  if (!title) return res.status(400).json({ error: 'Title is required' });
  const uid = ownerId(req);
  if (client_id) {
    const cl = await db.execute({ sql: 'SELECT id FROM clients WHERE id=? AND user_id=?', args: [client_id, uid] });
    if (!cl.rows.length) return res.status(403).json({ error: 'Invalid client' });
  }
  const assignee = await validAssignee(req, assigned_to);
  const safeProgress = Math.max(0, Math.min(100, parseInt(progress) || 0));
  // Check previous assignee to detect reassignment
  const prev = await db.execute({ sql: 'SELECT assigned_to, title FROM projects WHERE id = ? AND user_id = ?', args: [req.params.id, uid] });
  const prevAssigned = prev.rows[0]?.assigned_to;
  await db.execute({
    sql: 'UPDATE projects SET title=?, type=?, client_id=?, status=?, progress=?, deadline=?, budget=?, assigned_to=? WHERE id=? AND user_id=?',
    args: [title, type||'', client_id||null, status||'queue', safeProgress, deadline||null, num(budget), assignee, req.params.id, uid],
  });
  const row = await db.execute({ sql: 'SELECT * FROM projects WHERE id = ?', args: [req.params.id] });
  // Notify if newly assigned or reassigned
  if (assignee && assignee != prevAssigned) {
    const deadline_str = deadline ? `\n📅 Deadline: ${tgEsc(deadline)}` : '';
    await notifyUser(assignee,
      `🔔 <b>Project assigned to you</b>\n\n📁 <b>${tgEsc(title)}</b>${deadline_str}\n\nAssigned by: ${tgEsc(req.user.name)}\n\n→ <a href="https://reloxy.tech/app">Open Reloxy</a>`
    );
  }
  res.json(row.rows[0]);
});

app.delete('/api/projects/:id', authMiddleware, async (req, res) => {
  if (denyStaff(req, res)) return;
  const uid = ownerId(req);
  // Only touch dependents if the project actually belongs to this workspace
  const own = await db.execute({ sql: 'SELECT id FROM projects WHERE id=? AND user_id=?', args: [req.params.id, uid] });
  if (!own.rows.length) return res.status(404).json({ error: 'Project not found' });
  await db.execute({ sql: 'DELETE FROM project_stages WHERE project_id=?', args: [req.params.id] });
  await db.execute({ sql: 'UPDATE tasks SET project_id=NULL WHERE project_id=? AND user_id=?', args: [req.params.id, uid] });
  await db.execute({ sql: 'UPDATE invoices SET project_id=NULL WHERE project_id=? AND user_id=?', args: [req.params.id, uid] });
  await db.execute({ sql: 'DELETE FROM projects WHERE id=? AND user_id=?', args: [req.params.id, uid] });
  res.json({ ok: true });
});

// ─── PROJECT STAGES ──────────────────────────────────────────────────────────
async function assertOwnsProject(req, projectId) {
  const uid = ownerId(req);
  const row = await db.execute({ sql: 'SELECT id FROM projects WHERE id=? AND user_id=?', args: [projectId, uid] });
  return row.rows.length > 0;
}

app.get('/api/projects/:id/stages', authMiddleware, async (req, res) => {
  if (!(await assertOwnsProject(req, req.params.id))) return res.status(404).json({ error: 'Project not found' });
  const result = await db.execute({
    sql: 'SELECT * FROM project_stages WHERE project_id=? ORDER BY position ASC, id ASC',
    args: [req.params.id],
  });
  res.json(result.rows);
});

app.post('/api/projects/:id/stages', authMiddleware, async (req, res) => {
  if (denyStaff(req, res)) return;
  if (!(await assertOwnsProject(req, req.params.id))) return res.status(404).json({ error: 'Project not found' });
  const { title, status } = req.body;
  if (!title) return res.status(400).json({ error: 'Title is required' });
  const posRow = await db.execute({ sql: 'SELECT COALESCE(MAX(position),-1)+1 as next FROM project_stages WHERE project_id=?', args: [req.params.id] });
  const position = posRow.rows[0]?.next || 0;
  const result = await db.execute({
    sql: 'INSERT INTO project_stages (project_id, title, status, position) VALUES (?, ?, ?, ?)',
    args: [req.params.id, title, status || 'planned', position],
  });
  const row = await db.execute({ sql: 'SELECT * FROM project_stages WHERE id=?', args: [result.lastInsertRowid] });
  res.json(row.rows[0]);
});

app.put('/api/projects/:id/stages/:stageId', authMiddleware, async (req, res) => {
  if (denyStaff(req, res)) return;
  if (!(await assertOwnsProject(req, req.params.id))) return res.status(404).json({ error: 'Project not found' });
  const { title, status, position } = req.body;
  const cur = await db.execute({ sql: 'SELECT * FROM project_stages WHERE id=? AND project_id=?', args: [req.params.stageId, req.params.id] });
  if (!cur.rows.length) return res.status(404).json({ error: 'Stage not found' });
  const c = cur.rows[0];
  await db.execute({
    sql: 'UPDATE project_stages SET title=?, status=?, position=? WHERE id=?',
    args: [title ?? c.title, status ?? c.status, position ?? c.position, req.params.stageId],
  });
  const row = await db.execute({ sql: 'SELECT * FROM project_stages WHERE id=?', args: [req.params.stageId] });
  res.json(row.rows[0]);
});

app.delete('/api/projects/:id/stages/:stageId', authMiddleware, async (req, res) => {
  if (denyStaff(req, res)) return;
  if (!(await assertOwnsProject(req, req.params.id))) return res.status(404).json({ error: 'Project not found' });
  await db.execute({ sql: 'DELETE FROM project_stages WHERE id=? AND project_id=?', args: [req.params.stageId, req.params.id] });
  res.json({ ok: true });
});

// Reorder stages — body: { order: [stageId1, stageId2, ...] }
app.put('/api/projects/:id/stages-reorder', authMiddleware, async (req, res) => {
  if (denyStaff(req, res)) return;
  if (!(await assertOwnsProject(req, req.params.id))) return res.status(404).json({ error: 'Project not found' });
  const { order } = req.body;
  if (!Array.isArray(order)) return res.status(400).json({ error: 'order must be an array' });
  for (let i = 0; i < order.length; i++) {
    await db.execute({ sql: 'UPDATE project_stages SET position=? WHERE id=? AND project_id=?', args: [i, order[i], req.params.id] });
  }
  const result = await db.execute({ sql: 'SELECT * FROM project_stages WHERE project_id=? ORDER BY position ASC, id ASC', args: [req.params.id] });
  res.json(result.rows);
});

// ─── PROJECT SHARE LINK (client-facing, read-only) ───────────────────────────
// POST /api/projects/:id/share — owner gets (or creates) a share token for the project
app.post('/api/projects/:id/share', authMiddleware, async (req, res) => {
  if (denyStaff(req, res)) return;
  if (!(await assertOwnsProject(req, req.params.id))) return res.status(404).json({ error: 'Project not found' });
  const row = await db.execute({ sql: 'SELECT share_token FROM projects WHERE id=?', args: [req.params.id] });
  let token = row.rows[0]?.share_token;
  if (!token) {
    token = crypto.randomBytes(20).toString('hex');
    await db.execute({ sql: 'UPDATE projects SET share_token=? WHERE id=?', args: [token, req.params.id] });
  }
  const base = process.env.APP_URL || `https://${req.hostname}`;
  res.json({ url: `${base}/share/${token}` });
});

// DELETE /api/projects/:id/share — owner revokes the share link
app.delete('/api/projects/:id/share', authMiddleware, async (req, res) => {
  if (denyStaff(req, res)) return;
  if (!(await assertOwnsProject(req, req.params.id))) return res.status(404).json({ error: 'Project not found' });
  await db.execute({ sql: 'UPDATE projects SET share_token=NULL WHERE id=?', args: [req.params.id] });
  res.json({ ok: true });
});

// GET /api/share/:token — public: read-only project info + stages for the client
app.get('/api/share/:token', async (req, res) => {
  const row = await db.execute({
    sql: `SELECT p.id, p.title, p.type, p.status, p.progress, p.deadline, p.created_at,
                 c.name as client_name, u.name as owner_name, u.studio_name as studio_name
          FROM projects p
          LEFT JOIN clients c ON p.client_id = c.id
          LEFT JOIN users u ON p.user_id = u.id
          WHERE p.share_token = ?`,
    args: [req.params.token],
  });
  if (!row.rows.length) return res.status(404).json({ error: 'Invalid or expired link' });
  const p = row.rows[0];
  const stages = await db.execute({
    sql: 'SELECT id, title, status, position FROM project_stages WHERE project_id=? ORDER BY position ASC, id ASC',
    args: [p.id],
  });
  res.json({
    title: p.title,
    type: p.type,
    status: p.status,
    progress: p.progress,
    deadline: p.deadline,
    created_at: p.created_at,
    client_name: p.client_name,
    studio_name: p.studio_name || p.owner_name,
    stages: stages.rows,
  });
});

// GET staff list with their user_ids (for assignment dropdown)
app.get('/api/staff-accounts', authMiddleware, async (req, res) => {
  if (denyStaff(req, res)) return;
  const result = await db.execute({
    sql: 'SELECT id, name, email FROM users WHERE owner_id = ? ORDER BY name ASC',
    args: [req.user.id],
  });
  res.json(result.rows);
});

// ─── TASKS (Kanban) ──────────────────────────────────────────────────────────
app.get('/api/tasks', authMiddleware, async (req, res) => {
  const result = await db.execute({
    sql: `SELECT t.*, p.title as project_title FROM tasks t
          LEFT JOIN projects p ON t.project_id = p.id
          WHERE t.user_id = ? ORDER BY t.created_at DESC`,
    args: [ownerId(req)],
  });
  res.json(result.rows);
});

app.post('/api/tasks', authMiddleware, async (req, res) => {
  const { title, description, project_id, status, priority, due_date } = req.body;
  const result = await db.execute({
    sql: 'INSERT INTO tasks (user_id, project_id, title, description, status, priority, due_date) VALUES (?, ?, ?, ?, ?, ?, ?)',
    args: [ownerId(req), project_id || null, title, description || '', status || 'todo', priority || 'medium', due_date || null],
  });
  const row = await db.execute({ sql: 'SELECT * FROM tasks WHERE id = ?', args: [result.lastInsertRowid] });
  res.json(row.rows[0]);
});

app.put('/api/tasks/:id', authMiddleware, async (req, res) => {
  const { title, description, project_id, status, priority, due_date } = req.body;
  await db.execute({
    sql: 'UPDATE tasks SET title=?, description=?, project_id=?, status=?, priority=?, due_date=? WHERE id=? AND user_id=?',
    args: [title, description || '', project_id || null, status || 'todo', priority || 'medium', due_date || null, req.params.id, ownerId(req)],
  });
  const row = await db.execute({ sql: 'SELECT * FROM tasks WHERE id = ?', args: [req.params.id] });
  res.json(row.rows[0]);
});

app.delete('/api/tasks/:id', authMiddleware, async (req, res) => {
  await db.execute({ sql: 'DELETE FROM tasks WHERE id=? AND user_id=?', args: [req.params.id, ownerId(req)] });
  res.json({ ok: true });
});

// ─── DEALS ───────────────────────────────────────────────────────────────────
app.get('/api/deals', authMiddleware, async (req, res) => {
  const result = await db.execute({
    sql: `SELECT d.*, c.name as client_name FROM deals d
          LEFT JOIN clients c ON d.client_id = c.id
          WHERE d.user_id = ? ORDER BY d.created_at DESC`,
    args: [ownerId(req)],
  });
  res.json(result.rows);
});

app.post('/api/deals', authMiddleware, async (req, res) => {
  const { title, client_id, value, stage } = req.body;
  if (!title) return res.status(400).json({ error: 'Title is required' });
  if (client_id) {
    const cl = await db.execute({ sql: 'SELECT id FROM clients WHERE id=? AND user_id=?', args: [client_id, ownerId(req)] });
    if (!cl.rows.length) return res.status(403).json({ error: 'Invalid client' });
  }
  const result = await db.execute({
    sql: 'INSERT INTO deals (user_id, client_id, title, value, stage) VALUES (?, ?, ?, ?, ?)',
    args: [ownerId(req), client_id||null, title, num(value), stage||'new'],
  });
  const row = await db.execute({ sql: 'SELECT * FROM deals WHERE id = ?', args: [result.lastInsertRowid] });
  res.json(row.rows[0]);
});

app.put('/api/deals/:id', authMiddleware, async (req, res) => {
  const { title, client_id, value, stage } = req.body;
  await db.execute({
    sql: 'UPDATE deals SET title=?, client_id=?, value=?, stage=? WHERE id=? AND user_id=?',
    args: [title, client_id||null, num(value), stage||'new', req.params.id, ownerId(req)],
  });
  const row = await db.execute({ sql: 'SELECT * FROM deals WHERE id = ?', args: [req.params.id] });
  res.json(row.rows[0]);
});

app.delete('/api/deals/:id', authMiddleware, async (req, res) => {
  await db.execute({ sql: 'DELETE FROM deals WHERE id=? AND user_id=?', args: [req.params.id, ownerId(req)] });
  res.json({ ok: true });
});

// ─── INVOICES ────────────────────────────────────────────────────────────────
app.get('/api/invoices', authMiddleware, async (req, res) => {
  if (denyStaff(req, res)) return;
  const result = await db.execute({
    sql: `SELECT i.*, c.name as client_name, p.title as project_title FROM invoices i
          LEFT JOIN clients c ON i.client_id = c.id
          LEFT JOIN projects p ON i.project_id = p.id
          WHERE i.user_id = ? ORDER BY i.created_at DESC`,
    args: [ownerId(req)],
  });
  res.json(result.rows);
});

app.post('/api/invoices', authMiddleware, async (req, res) => {
  const { number, client_id, amount, issued_at, due_at, status } = req.body;
  if (client_id) {
    const cl = await db.execute({ sql: 'SELECT id FROM clients WHERE id=? AND user_id=?', args: [client_id, ownerId(req)] });
    if (!cl.rows.length) return res.status(403).json({ error: 'Invalid client' });
  }
  const result = await db.execute({
    sql: 'INSERT INTO invoices (user_id, client_id, number, amount, issued_at, due_at, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
    args: [ownerId(req), client_id||null, number||'', num(amount), issued_at||null, due_at||null, status||'pending'],
  });
  const row = await db.execute({ sql: 'SELECT * FROM invoices WHERE id = ?', args: [result.lastInsertRowid] });
  res.json(row.rows[0]);
});

app.put('/api/invoices/:id', authMiddleware, async (req, res) => {
  const { number, client_id, amount, issued_at, due_at, status } = req.body;
  await db.execute({
    sql: 'UPDATE invoices SET number=?, client_id=?, amount=?, issued_at=?, due_at=?, status=? WHERE id=? AND user_id=?',
    args: [number||'', client_id||null, num(amount), issued_at||null, due_at||null, status||'pending', req.params.id, ownerId(req)],
  });
  const row = await db.execute({ sql: 'SELECT * FROM invoices WHERE id = ?', args: [req.params.id] });
  res.json(row.rows[0]);
});

app.delete('/api/invoices/:id', authMiddleware, async (req, res) => {
  await db.execute({ sql: 'DELETE FROM invoices WHERE id=? AND user_id=?', args: [req.params.id, ownerId(req)] });
  res.json({ ok: true });
});

app.put('/api/invoices/:id/pay', authMiddleware, async (req, res) => {
  if (denyStaff(req, res)) return;
  await db.execute({
    sql: 'UPDATE invoices SET status=? WHERE id=? AND user_id=?',
    args: ['paid', req.params.id, ownerId(req)],
  });
  const row = await db.execute({ sql: 'SELECT * FROM invoices WHERE id = ? AND user_id = ?', args: [req.params.id, ownerId(req)] });
  const inv = row.rows[0];
  if (!inv) return res.status(404).json({ error: 'Invoice not found' });
  await sendTelegram(`💰 <b>Payment received!</b>\nInvoice: ${tgEsc(inv.number)}\nAmount: ${tgEsc(inv.amount)}`);
  res.json(inv);
});

// ─── EVENTS (Calendar) ───────────────────────────────────────────────────────
app.get('/api/events', authMiddleware, async (req, res) => {
  const result = await db.execute({
    sql: 'SELECT * FROM events WHERE user_id = ? ORDER BY date ASC, time ASC',
    args: [ownerId(req)],
  });
  res.json(result.rows);
});

app.post('/api/events', authMiddleware, async (req, res) => {
  const { title, description, date, time, color } = req.body;
  const result = await db.execute({
    sql: 'INSERT INTO events (user_id, title, description, date, time, color) VALUES (?, ?, ?, ?, ?, ?)',
    args: [ownerId(req), title, description || '', date, time || '', color || '#000000'],
  });
  const row = await db.execute({ sql: 'SELECT * FROM events WHERE id = ?', args: [result.lastInsertRowid] });
  res.json(row.rows[0]);
});

app.put('/api/events/:id', authMiddleware, async (req, res) => {
  const { title, description, date, time, color } = req.body;
  await db.execute({
    sql: 'UPDATE events SET title=?, description=?, date=?, time=?, color=? WHERE id=? AND user_id=?',
    args: [title, description || '', date, time || '', color || '#000000', req.params.id, ownerId(req)],
  });
  const row = await db.execute({ sql: 'SELECT * FROM events WHERE id = ?', args: [req.params.id] });
  res.json(row.rows[0]);
});

app.delete('/api/events/:id', authMiddleware, async (req, res) => {
  await db.execute({ sql: 'DELETE FROM events WHERE id=? AND user_id=?', args: [req.params.id, ownerId(req)] });
  res.json({ ok: true });
});

// ─── USER STATS ──────────────────────────────────────────────────────────────
app.get('/api/stats', authMiddleware, async (req, res) => {
  try {
    const uid = ownerId(req);
    const [cls, prj, dls, invs] = await Promise.all([
      db.execute({ sql: 'SELECT COUNT(*) as n FROM clients WHERE user_id=?', args: [uid] }),
      db.execute({ sql: "SELECT COUNT(*) as n FROM projects WHERE user_id=? AND status != 'done'", args: [uid] }),
      db.execute({ sql: "SELECT COUNT(*) as n FROM deals WHERE user_id=? AND stage NOT IN ('won','lost')", args: [uid] }),
      db.execute({ sql: "SELECT SUM(amount) as total FROM invoices WHERE user_id=? AND status='paid'", args: [uid] }),
    ]);
    res.json({
      totalClients:   cls.rows[0].n,
      activeProjects: prj.rows[0].n,
      totalLeads:     dls.rows[0].n,
      revenue:        invs.rows[0].total || 0,
    });
  } catch (e) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── PROFILE UPDATE ──────────────────────────────────────────────────────────
app.put('/api/me', authMiddleware, async (req, res) => {
  try {
    const { name, studio_name } = req.body;
    if (!name) return res.status(400).json({ error: 'Name is required' });
    await db.execute({
      sql: 'UPDATE users SET name=?, studio_name=? WHERE id=?',
      args: [name, studio_name || '', req.user.id],
    });
    const row = await db.execute({ sql: 'SELECT id, name, email, role, plan, trial_ends_at, studio_name FROM users WHERE id=?', args: [req.user.id] });
    res.json(row.rows[0]);
  } catch(e) { res.status(500).json({ error: 'Internal server error' }); }
});

app.put('/api/me/password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const row = await db.execute({ sql: 'SELECT * FROM users WHERE id=?', args: [req.user.id] });
    const u = row.rows[0];
    if (!u) return res.status(404).json({ error: 'User not found' });
    const valid = await bcrypt.compare(currentPassword, u.password);
    if (!valid) return res.status(400).json({ error: 'Current password is wrong' });
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Min 6 characters' });
    const hash = await bcrypt.hash(newPassword, 10);
    await db.execute({ sql: 'UPDATE users SET password=? WHERE id=?', args: [hash, req.user.id] });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Internal server error' }); }
});

app.post('/api/telegram/test', authMiddleware, async (req, res) => {
  try {
    const { token, chatId } = req.body;
    const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text: '✅ Reloxy CRM connected!' }),
    });
    if (!r.ok) throw new Error('Telegram error');
    res.json({ ok: true });
  } catch(e) { res.status(400).json({ error: e.message }); }
});

// ─── STAFF ───────────────────────────────────────────────────────────────────
app.get('/api/staff', authMiddleware, async (req, res) => {
  const result = await db.execute({ sql: 'SELECT * FROM staff WHERE user_id = ? ORDER BY created_at DESC', args: [ownerId(req)] });
  res.json(result.rows);
});

app.post('/api/staff', authMiddleware, async (req, res) => {
  if (denyStaff(req, res)) return;
  const { name, position, email, phone, status } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  // Plan limit on team size
  const _plan = await getEffectivePlan(ownerId(req));
  const _limit = PLAN_STAFF_LIMITS[_plan] ?? 2;
  if (_limit !== Infinity) {
    const _cnt = await db.execute({ sql: 'SELECT COUNT(*) AS c FROM staff WHERE user_id = ?', args: [ownerId(req)] });
    if (Number(_cnt.rows[0].c) >= _limit) {
      return res.status(403).json({ error: _plan === 'free'
        ? 'Start plan limit: up to 2 team members. Open Plans to upgrade.'
        : 'Pro plan limit: up to 7 team members. Switch to Studio for an unlimited team.' });
    }
  }
  const result = await db.execute({
    sql: 'INSERT INTO staff (user_id, name, position, email, phone, status) VALUES (?, ?, ?, ?, ?, ?)',
    args: [ownerId(req), name, position || '', email || '', phone || '', status || 'active'],
  });
  const row = await db.execute({ sql: 'SELECT * FROM staff WHERE id = ?', args: [result.lastInsertRowid] });
  res.json(row.rows[0]);
});

app.put('/api/staff/:id', authMiddleware, async (req, res) => {
  if (denyStaff(req, res)) return;
  const { name, position, email, phone, status } = req.body;
  await db.execute({
    sql: 'UPDATE staff SET name=?, position=?, email=?, phone=?, status=? WHERE id=? AND user_id=?',
    args: [name, position || '', email || '', phone || '', status || 'active', req.params.id, ownerId(req)],
  });
  const row = await db.execute({ sql: 'SELECT * FROM staff WHERE id = ?', args: [req.params.id] });
  res.json(row.rows[0]);
});

app.delete('/api/staff/:id', authMiddleware, async (req, res) => {
  if (denyStaff(req, res)) return;
  await db.execute({ sql: 'DELETE FROM staff WHERE id=? AND user_id=?', args: [req.params.id, ownerId(req)] });
  res.json({ ok: true });
});

// ─── ADMIN ROUTES ────────────────────────────────────────────────────────────
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const result = await db.execute({ sql: 'SELECT id, name, email, role, plan, created_at FROM users ORDER BY created_at DESC', args: [] });
  res.json(result.rows);
});

app.put('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const { role, plan } = req.body;
  await db.execute({
    sql: 'UPDATE users SET role=?, plan=? WHERE id=?',
    args: [role, plan, req.params.id],
  });
  res.json({ ok: true });
});

app.put('/api/admin/users/:id/role', authMiddleware, adminMiddleware, async (req, res) => {
  const { role } = req.body;
  await db.execute({ sql: 'UPDATE users SET role=? WHERE id=?', args: [role, req.params.id] });
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  await db.execute({ sql: 'DELETE FROM users WHERE id=?', args: [req.params.id] });
  res.json({ ok: true });
});

app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  const [users, clients, projects, invoices, staff] = await Promise.all([
    db.execute({ sql: 'SELECT COUNT(*) as count FROM users', args: [] }),
    db.execute({ sql: 'SELECT COUNT(*) as count FROM clients', args: [] }),
    db.execute({ sql: 'SELECT COUNT(*) as count FROM projects', args: [] }),
    db.execute({ sql: 'SELECT SUM(amount) as total FROM invoices WHERE status=?', args: ['paid'] }),
    db.execute({ sql: 'SELECT COUNT(*) as count FROM staff', args: [] }),
  ]);
  res.json({
    totalUsers: users.rows[0].count,
    totalClients: clients.rows[0].count,
    totalProjects: projects.rows[0].count,
    totalRevenue: invoices.rows[0].total || 0,
    totalStaff: staff.rows[0].count,
  });
});

// ─── INVITE SYSTEM ───────────────────────────────────────────────────────────

// GET /api/invite-link — owner gets (or creates) their invite token
app.get('/api/invite-link', authMiddleware, async (req, res) => {
  const row = await db.execute({ sql: 'SELECT invite_token FROM users WHERE id=?', args: [req.user.id] });
  let token = row.rows[0]?.invite_token;
  if (!token) {
    token = crypto.randomBytes(24).toString('hex');
    await db.execute({ sql: 'UPDATE users SET invite_token=? WHERE id=?', args: [token, req.user.id] });
  }
  const base = process.env.APP_URL || `https://${req.hostname}`;
  res.json({ url: `${base}/invite/${token}` });
});

// GET /api/invite/:token — public: verify token, return studio info
app.get('/api/invite/:token', async (req, res) => {
  const row = await db.execute({
    sql: 'SELECT id, name, studio_name FROM users WHERE invite_token=?',
    args: [req.params.token],
  });
  if (!row.rows.length) return res.status(404).json({ error: 'Invalid or expired link' });
  const u = row.rows[0];
  res.json({ owner_name: u.name, studio_name: u.studio_name || u.name });
});

// POST /api/invite/:token — public: staff accepts invite, creates a real user account
app.post('/api/invite/:token', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const ownerRow = await db.execute({
      sql: 'SELECT id, name, studio_name FROM users WHERE invite_token=?',
      args: [req.params.token],
    });
    if (!ownerRow.rows.length) return res.status(404).json({ error: 'Invalid invite link' });
    const owner = ownerRow.rows[0];

    // Check email not already registered
    const exists = await db.execute({ sql: 'SELECT id FROM users WHERE email=?', args: [email] });
    if (exists.rows.length) return res.status(409).json({ error: 'This email is already registered' });

    const hash = await bcrypt.hash(password, 10);

    // Create user account with role='staff' and owner_id
    const result = await db.execute({
      sql: 'INSERT INTO users (name, email, password, role, owner_id, studio_name) VALUES (?,?,?,?,?,?)',
      args: [name, email, hash, 'staff', owner.id, owner.studio_name || owner.name],
    });

    // Also add to staff table so owner can see them in Team page
    await db.execute({
      sql: 'INSERT INTO staff (user_id, name, email, position, status) VALUES (?,?,?,?,?)',
      args: [owner.id, name, email, 'Staff', 'active'],
    });

    res.json({ ok: true });
  } catch(e) {
    console.error('Invite error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Telegram Bot ────────────────────────────────────────────────────────────
const TG_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TG_API   = TG_TOKEN ? `https://api.telegram.org/bot${TG_TOKEN}` : null;

async function tgSend(chatId, text) {
  if (!TG_API || !chatId) return;
  try {
    await fetch(`${TG_API}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML', disable_web_page_preview: true }),
    });
  } catch (e) { console.error('TG send error:', e.message); }
}

// Send notification to a user by their DB id
async function notifyUser(userId, text) {
  if (!userId) return;
  const r = await db.execute({ sql: 'SELECT telegram_chat_id FROM users WHERE id = ?', args: [userId] });
  const chatId = r.rows[0]?.telegram_chat_id;
  if (chatId) await tgSend(chatId, text);
}

// Generate a cryptographically-strong link code (8 hex chars)
function genCode() { return crypto.randomBytes(4).toString('hex').toUpperCase(); }

// In-memory brute-force guard for /start CODE attempts (per Telegram chat)
const tgCodeAttempts = new Map(); // chatId -> { count, ts }
function tgCodeBlocked(chatId) {
  const now = Date.now();
  const rec = tgCodeAttempts.get(chatId) || { count: 0, ts: now };
  if (now - rec.ts > 10 * 60 * 1000) { rec.count = 0; rec.ts = now; } // reset window
  tgCodeAttempts.set(chatId, rec);
  return rec.count >= 8;
}
function tgCodeFail(chatId) {
  const rec = tgCodeAttempts.get(chatId) || { count: 0, ts: Date.now() };
  rec.count++; tgCodeAttempts.set(chatId, rec);
}

// API: get or create link code for current user
app.get('/api/tg/link-code', authMiddleware, async (req, res) => {
  try {
    let r = await db.execute({ sql: 'SELECT tg_link_code, telegram_chat_id FROM users WHERE id = ?', args: [req.user.id] });
    let { tg_link_code, telegram_chat_id } = r.rows[0] || {};
    if (!tg_link_code) {
      tg_link_code = genCode();
      await db.execute({ sql: 'UPDATE users SET tg_link_code = ? WHERE id = ?', args: [tg_link_code, req.user.id] });
    }
    res.json({ code: tg_link_code, linked: !!telegram_chat_id });
  } catch(e) {
    console.error('TG link-code error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// API: unlink telegram
app.post('/api/tg/unlink', authMiddleware, async (req, res) => {
  await db.execute({ sql: 'UPDATE users SET telegram_chat_id = NULL, tg_link_code = NULL WHERE id = ?', args: [req.user.id] });
  res.json({ ok: true });
});

// Long-polling loop
let tgOffset = 0;
async function tgPoll() {
  if (!TG_API) return;
  try {
    const r = await fetch(`${TG_API}/getUpdates?timeout=25&offset=${tgOffset}&allowed_updates=["message"]`);
    const data = await r.json();
    if (!data.ok) { setTimeout(tgPoll, 5000); return; }
    for (const upd of data.result || []) {
      tgOffset = upd.update_id + 1;
      const msg = upd.message;
      if (!msg || !msg.text) continue;
      const chatId = String(msg.chat.id);
      const text   = msg.text.trim();
      const from   = msg.from;

      if (text.startsWith('/start')) {
        const parts = text.split(' ');
        const code  = parts[1]?.toUpperCase();
        if (!code) {
          await tgSend(chatId, `👋 <b>Welcome to Reloxy!</b>\n\nTo link your account, get your code from the CRM:\n<b>Team → your profile → Telegram</b>\n\nThen send: <code>/start YOUR_CODE</code>`);
          continue;
        }
        if (tgCodeBlocked(chatId)) {
          await tgSend(chatId, '⏳ Too many attempts. Please wait a few minutes and try again.');
          continue;
        }
        // Find user by code
        const ur = await db.execute({ sql: 'SELECT id, name FROM users WHERE tg_link_code = ?', args: [code] });
        if (!ur.rows.length) {
          tgCodeFail(chatId);
          await tgSend(chatId, '❌ Code not found. Please get a fresh code from Reloxy CRM.');
          continue;
        }
        const u = ur.rows[0];
        tgCodeAttempts.delete(chatId); // success — clear the counter
        await db.execute({ sql: 'UPDATE users SET telegram_chat_id = ?, tg_link_code = NULL WHERE id = ?', args: [chatId, u.id] });
        await tgSend(chatId, `✅ <b>Connected!</b>\n\nHi ${tgEsc(u.name)}, your Reloxy account is now linked.\n\nYou'll receive notifications here when tasks or projects are assigned to you.`);
        continue;
      }

      if (text === '/help' || text === '/status') {
        const ur2 = await db.execute({ sql: 'SELECT name FROM users WHERE telegram_chat_id = ?', args: [chatId] });
        if (ur2.rows.length) {
          await tgSend(chatId, `✅ Linked as <b>${tgEsc(ur2.rows[0].name)}</b>\n\nYou'll get notified about new tasks and projects.`);
        } else {
          await tgSend(chatId, '❌ Not linked. Get your code from Reloxy → Team → Telegram.');
        }
        continue;
      }
    }
  } catch (e) { console.error('TG poll error:', e.message); }
  setTimeout(tgPoll, 1000);
}

// ─── Global error handler ────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Static pages (MUST be last — catch-all intercepts everything) ───────────
app.get('/app',           (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/admin',         (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/invite/:token', (req, res) => res.sendFile(path.join(__dirname, 'public', 'invite.html')));
app.get('/share/:token',  (req, res) => res.sendFile(path.join(__dirname, 'public', 'share.html')));
app.get('*',              (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

// ─── Start ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
initDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 Reloxy CRM running on port ${PORT}`));
  // Telegram long-polling must run on ONE instance only. With multiple instances,
  // concurrent getUpdates calls cause 409 conflicts — disable with TELEGRAM_POLLING=false.
  if (process.env.TELEGRAM_POLLING !== 'false') {
    tgPoll();
  } else {
    console.log('ℹ️ Telegram polling disabled on this instance');
  }
}).catch(err => {
  console.error('DB init failed:', err);
  process.exit(1);
});
