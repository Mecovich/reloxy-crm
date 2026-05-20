require('dotenv').config();
const express    = require('express');
const Database   = require('better-sqlite3');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const path       = require('path');

const app        = express();
const PORT       = process.env.PORT || 3000;
const SECRET     = process.env.JWT_SECRET || 'studio-crm-dev-secret';
const DB_PATH    = process.env.DB_PATH || 'studio.db';

// ─── DATABASE ────────────────────────────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    email       TEXT    UNIQUE NOT NULL,
    password    TEXT    NOT NULL,
    studio_name TEXT    DEFAULT '',
    created_at  TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS clients (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT    NOT NULL,
    industry     TEXT    DEFAULT '',
    contact_name TEXT    DEFAULT '',
    email        TEXT    DEFAULT '',
    phone        TEXT    DEFAULT '',
    status       TEXT    DEFAULT 'active',
    notes        TEXT    DEFAULT '',
    created_at   TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS projects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id   INTEGER REFERENCES clients(id) ON DELETE SET NULL,
    title       TEXT    NOT NULL,
    type        TEXT    DEFAULT '',
    status      TEXT    DEFAULT 'queue',
    progress    INTEGER DEFAULT 0,
    deadline    TEXT    DEFAULT '',
    budget      REAL    DEFAULT 0,
    created_at  TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS deals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id   INTEGER REFERENCES clients(id) ON DELETE SET NULL,
    title       TEXT    NOT NULL,
    stage       TEXT    DEFAULT 'new',
    value       REAL    DEFAULT 0,
    created_at  TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS invoices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id   INTEGER REFERENCES clients(id) ON DELETE SET NULL,
    project_id  INTEGER REFERENCES projects(id) ON DELETE SET NULL,
    number      TEXT    DEFAULT '',
    amount      REAL    DEFAULT 0,
    status      TEXT    DEFAULT 'pending',
    issued_at   TEXT    DEFAULT '',
    due_at      TEXT    DEFAULT '',
    created_at  TEXT    DEFAULT (datetime('now'))
  );
`);

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Необходима авторизация' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Токен недействителен' });
  }
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, studioName } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'Заполните все обязательные поля' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Пароль должен быть минимум 6 символов' });

  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (exists) return res.status(400).json({ error: 'Email уже зарегистрирован' });

  const hash   = await bcrypt.hash(password, 10);
  const result = db.prepare(
    'INSERT INTO users (name, email, password, studio_name) VALUES (?, ?, ?, ?)'
  ).run(name, email.toLowerCase().trim(), hash, studioName || '');

  const user  = { id: result.lastInsertRowid, name, email, studioName: studioName || '' };
  const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, SECRET, { expiresIn: '30d' });
  res.json({ token, user });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Введите email и пароль' });

  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (!row) return res.status(401).json({ error: 'Неверный email или пароль' });

  const ok = await bcrypt.compare(password, row.password);
  if (!ok) return res.status(401).json({ error: 'Неверный email или пароль' });

  const user  = { id: row.id, name: row.name, email: row.email, studioName: row.studio_name };
  const token = jwt.sign({ id: row.id, email: row.email, name: row.name }, SECRET, { expiresIn: '30d' });
  res.json({ token, user });
});

app.get('/api/auth/me', auth, (req, res) => {
  const row = db.prepare('SELECT id, name, email, studio_name FROM users WHERE id = ?').get(req.user.id);
  if (!row) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json({ id: row.id, name: row.name, email: row.email, studioName: row.studio_name });
});

// ─── STATS ───────────────────────────────────────────────────────────────────
app.get('/api/stats', auth, (req, res) => {
  const uid  = req.user.id;
  const now  = new Date();
  const year = now.getFullYear();
  const m    = String(now.getMonth() + 1).padStart(2, '0');
  const from = `${year}-${m}-01`;

  const revenue        = db.prepare(`SELECT COALESCE(SUM(amount),0) AS v FROM invoices WHERE user_id=? AND status='paid' AND issued_at >= ?`).get(uid, from).v;
  const activeProjects = db.prepare(`SELECT COUNT(*) AS v FROM projects WHERE user_id=? AND status != 'done'`).get(uid).v;
  const totalClients   = db.prepare(`SELECT COUNT(*) AS v FROM clients WHERE user_id=?`).get(uid).v;
  const totalLeads     = db.prepare(`SELECT COUNT(*) AS v FROM deals WHERE user_id=? AND stage != 'closed'`).get(uid).v;

  const monthly = [];
  for (let i = 0; i < 12; i++) {
    const mm = String(i + 1).padStart(2, '0');
    const s  = `${year}-${mm}-01`;
    const e  = `${year}-${mm}-31`;
    monthly.push(
      db.prepare(`SELECT COALESCE(SUM(amount),0) AS v FROM invoices WHERE user_id=? AND status='paid' AND issued_at >= ? AND issued_at <= ?`).get(uid, s, e).v
    );
  }

  res.json({ revenue, activeProjects, totalClients, totalLeads, monthly });
});

// ─── CLIENTS ─────────────────────────────────────────────────────────────────
app.get('/api/clients', auth, (req, res) => {
  const rows = db.prepare(`
    SELECT c.*,
      (SELECT COUNT(*) FROM projects WHERE client_id = c.id) AS project_count,
      (SELECT COALESCE(SUM(amount),0) FROM invoices WHERE client_id = c.id AND status='paid') AS total_paid
    FROM clients c WHERE c.user_id = ? ORDER BY c.created_at DESC
  `).all(req.user.id);
  res.json(rows);
});

app.post('/api/clients', auth, (req, res) => {
  const { name, industry, contact_name, email, phone, status, notes } = req.body;
  if (!name) return res.status(400).json({ error: 'Укажите название компании' });
  const r = db.prepare(
    `INSERT INTO clients (user_id,name,industry,contact_name,email,phone,status,notes)
     VALUES (?,?,?,?,?,?,?,?)`
  ).run(req.user.id, name, industry||'', contact_name||'', email||'', phone||'', status||'active', notes||'');
  res.json({ id: r.lastInsertRowid, name, industry, contact_name, email, phone, status: status||'active', notes, project_count: 0, total_paid: 0 });
});

app.put('/api/clients/:id', auth, (req, res) => {
  const { name, industry, contact_name, email, phone, status, notes } = req.body;
  db.prepare(
    `UPDATE clients SET name=?,industry=?,contact_name=?,email=?,phone=?,status=?,notes=? WHERE id=? AND user_id=?`
  ).run(name, industry||'', contact_name||'', email||'', phone||'', status||'active', notes||'', req.params.id, req.user.id);
  res.json({ ok: true });
});

app.delete('/api/clients/:id', auth, (req, res) => {
  db.prepare('DELETE FROM clients WHERE id=? AND user_id=?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ─── PROJECTS ────────────────────────────────────────────────────────────────
app.get('/api/projects', auth, (req, res) => {
  const rows = db.prepare(`
    SELECT p.*, c.name AS client_name
    FROM projects p LEFT JOIN clients c ON p.client_id = c.id
    WHERE p.user_id = ? ORDER BY p.created_at DESC
  `).all(req.user.id);
  res.json(rows);
});

app.post('/api/projects', auth, (req, res) => {
  const { title, type, client_id, status, progress, deadline, budget } = req.body;
  if (!title) return res.status(400).json({ error: 'Укажите название проекта' });
  const r = db.prepare(
    `INSERT INTO projects (user_id,title,type,client_id,status,progress,deadline,budget)
     VALUES (?,?,?,?,?,?,?,?)`
  ).run(req.user.id, title, type||'', client_id||null, status||'queue', progress||0, deadline||'', budget||0);
  res.json({ id: r.lastInsertRowid, title, type, client_id, status: status||'queue', progress: progress||0, deadline, budget: budget||0 });
});

app.put('/api/projects/:id', auth, (req, res) => {
  const { title, type, client_id, status, progress, deadline, budget } = req.body;
  db.prepare(
    `UPDATE projects SET title=?,type=?,client_id=?,status=?,progress=?,deadline=?,budget=? WHERE id=? AND user_id=?`
  ).run(title, type||'', client_id||null, status||'queue', progress||0, deadline||'', budget||0, req.params.id, req.user.id);
  res.json({ ok: true });
});

app.delete('/api/projects/:id', auth, (req, res) => {
  db.prepare('DELETE FROM projects WHERE id=? AND user_id=?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ─── DEALS ───────────────────────────────────────────────────────────────────
app.get('/api/deals', auth, (req, res) => {
  const rows = db.prepare(`
    SELECT d.*, c.name AS client_name
    FROM deals d LEFT JOIN clients c ON d.client_id = c.id
    WHERE d.user_id = ? ORDER BY d.created_at DESC
  `).all(req.user.id);
  res.json(rows);
});

app.post('/api/deals', auth, (req, res) => {
  const { title, client_id, stage, value } = req.body;
  if (!title) return res.status(400).json({ error: 'Укажите название сделки' });
  const r = db.prepare(
    `INSERT INTO deals (user_id,title,client_id,stage,value) VALUES (?,?,?,?,?)`
  ).run(req.user.id, title, client_id||null, stage||'new', value||0);
  res.json({ id: r.lastInsertRowid, title, client_id, stage: stage||'new', value: value||0 });
});

app.put('/api/deals/:id', auth, (req, res) => {
  const { title, client_id, stage, value } = req.body;
  db.prepare(
    `UPDATE deals SET title=?,client_id=?,stage=?,value=? WHERE id=? AND user_id=?`
  ).run(title, client_id||null, stage||'new', value||0, req.params.id, req.user.id);
  res.json({ ok: true });
});

app.delete('/api/deals/:id', auth, (req, res) => {
  db.prepare('DELETE FROM deals WHERE id=? AND user_id=?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ─── INVOICES ────────────────────────────────────────────────────────────────
app.get('/api/invoices', auth, (req, res) => {
  const rows = db.prepare(`
    SELECT i.*, c.name AS client_name
    FROM invoices i LEFT JOIN clients c ON i.client_id = c.id
    WHERE i.user_id = ? ORDER BY i.created_at DESC
  `).all(req.user.id);
  res.json(rows);
});

app.post('/api/invoices', auth, (req, res) => {
  const { number, client_id, project_id, amount, status, issued_at, due_at } = req.body;
  const r = db.prepare(
    `INSERT INTO invoices (user_id,number,client_id,project_id,amount,status,issued_at,due_at)
     VALUES (?,?,?,?,?,?,?,?)`
  ).run(req.user.id, number||'', client_id||null, project_id||null, amount||0, status||'pending', issued_at||'', due_at||'');
  res.json({ id: r.lastInsertRowid, ...req.body });
});

app.put('/api/invoices/:id', auth, (req, res) => {
  const { number, client_id, project_id, amount, status, issued_at, due_at } = req.body;
  db.prepare(
    `UPDATE invoices SET number=?,client_id=?,project_id=?,amount=?,status=?,issued_at=?,due_at=? WHERE id=? AND user_id=?`
  ).run(number||'', client_id||null, project_id||null, amount||0, status||'pending', issued_at||'', due_at||'', req.params.id, req.user.id);
  res.json({ ok: true });
});

app.delete('/api/invoices/:id', auth, (req, res) => {
  db.prepare('DELETE FROM invoices WHERE id=? AND user_id=?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ─── FALLBACK ─────────────────────────────────────────────────────────────────
app.get('/app', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

app.listen(PORT, () => {
  console.log(`\n  Studio CRM → http://localhost:${PORT}\n`);
});
