const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const { createClient } = require('@libsql/client');

// Turso returns BigInt for row IDs — teach JSON how to serialize them
BigInt.prototype.toJSON = function() { return Number(this); };

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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
    `ALTER TABLE users ADD COLUMN invite_token TEXT DEFAULT ''`,
    `ALTER TABLE staff ADD COLUMN invite_email TEXT DEFAULT ''`,
  ];
  for (const sql of migrations) {
    try { await db.execute({ sql, args: [] }); } catch (_) { /* column already exists */ }
  }

  console.log('✅ DB initialized');
}

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function adminMiddleware(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────
async function handleRegister(req, res) {
  try {
    const { name, email, password, studioName } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });

    const existing = await db.execute({ sql: 'SELECT id FROM users WHERE email = ?', args: [email] });
    if (existing.rows.length > 0) return res.status(400).json({ error: 'Email already exists' });

    const hash = await bcrypt.hash(password, 10);
    const role = email === process.env.ADMIN_EMAIL ? 'admin' : 'user';

    const result = await db.execute({
      sql: 'INSERT INTO users (name, email, password, role, studio_name) VALUES (?, ?, ?, ?, ?)',
      args: [name, email, hash, role, studioName || ''],
    });

    const token = jwt.sign(
      { id: result.lastInsertRowid, email, role, name },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '30d' }
    );

    await sendTelegram(`🆕 <b>New user</b>\nName: ${name}\nEmail: ${email}`);

    res.json({ token, user: { id: result.lastInsertRowid, name, email, role, studioName: studioName || '' } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
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
      { id: user.id, email: user.email, role: user.role, name: user.name },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '30d' }
    );

    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, plan: user.plan } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

app.post('/api/auth/register', handleRegister);
app.post('/api/auth/login',    handleLogin);
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  const result = await db.execute({ sql: 'SELECT id, name, email, role, plan, studio_name, created_at FROM users WHERE id = ?', args: [req.user.id] });
  res.json(result.rows[0]);
});

app.post('/api/register', handleRegister);
app.post('/api/login',    handleLogin);
app.get('/api/me', authMiddleware, async (req, res) => {
  const result = await db.execute({ sql: 'SELECT id, name, email, role, plan, studio_name, created_at FROM users WHERE id = ?', args: [req.user.id] });
  res.json(result.rows[0]);
});

// ─── CLIENTS ─────────────────────────────────────────────────────────────────
app.get('/api/clients', authMiddleware, async (req, res) => {
  const result = await db.execute({ sql: 'SELECT * FROM clients WHERE user_id = ? ORDER BY created_at DESC', args: [req.user.id] });
  res.json(result.rows);
});

app.post('/api/clients', authMiddleware, async (req, res) => {
  const { name, industry, contact_name, email, phone, status, notes } = req.body;
  const result = await db.execute({
    sql: 'INSERT INTO clients (user_id, name, industry, contact_name, email, phone, status, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    args: [req.user.id, name, industry||'', contact_name||'', email||'', phone||'', status||'active', notes||''],
  });
  const row = await db.execute({ sql: 'SELECT * FROM clients WHERE id = ?', args: [result.lastInsertRowid] });
  res.json(row.rows[0]);
});

app.put('/api/clients/:id', authMiddleware, async (req, res) => {
  const { name, industry, contact_name, email, phone, status, notes } = req.body;
  await db.execute({
    sql: 'UPDATE clients SET name=?, industry=?, contact_name=?, email=?, phone=?, status=?, notes=? WHERE id=? AND user_id=?',
    args: [name, industry||'', contact_name||'', email||'', phone||'', status||'active', notes||'', req.params.id, req.user.id],
  });
  const row = await db.execute({ sql: 'SELECT * FROM clients WHERE id = ?', args: [req.params.id] });
  res.json(row.rows[0]);
});

app.delete('/api/clients/:id', authMiddleware, async (req, res) => {
  await db.execute({ sql: 'DELETE FROM clients WHERE id=? AND user_id=?', args: [req.params.id, req.user.id] });
  res.json({ ok: true });
});

// ─── PROJECTS ────────────────────────────────────────────────────────────────
app.get('/api/projects', authMiddleware, async (req, res) => {
  const result = await db.execute({
    sql: `SELECT p.*, c.name as client_name FROM projects p
          LEFT JOIN clients c ON p.client_id = c.id
          WHERE p.user_id = ? ORDER BY p.created_at DESC`,
    args: [req.user.id],
  });
  res.json(result.rows);
});

app.post('/api/projects', authMiddleware, async (req, res) => {
  const { title, type, client_id, status, progress, deadline, budget } = req.body;
  const result = await db.execute({
    sql: 'INSERT INTO projects (user_id, client_id, title, type, status, progress, deadline, budget) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    args: [req.user.id, client_id||null, title, type||'', status||'queue', progress||0, deadline||null, budget||null],
  });
  const row = await db.execute({ sql: 'SELECT * FROM projects WHERE id = ?', args: [result.lastInsertRowid] });
  res.json(row.rows[0]);
});

app.put('/api/projects/:id', authMiddleware, async (req, res) => {
  const { title, type, client_id, status, progress, deadline, budget } = req.body;
  await db.execute({
    sql: 'UPDATE projects SET title=?, type=?, client_id=?, status=?, progress=?, deadline=?, budget=? WHERE id=? AND user_id=?',
    args: [title, type||'', client_id||null, status||'queue', progress||0, deadline||null, budget||null, req.params.id, req.user.id],
  });
  const row = await db.execute({ sql: 'SELECT * FROM projects WHERE id = ?', args: [req.params.id] });
  res.json(row.rows[0]);
});

app.delete('/api/projects/:id', authMiddleware, async (req, res) => {
  await db.execute({ sql: 'DELETE FROM projects WHERE id=? AND user_id=?', args: [req.params.id, req.user.id] });
  res.json({ ok: true });
});

// ─── TASKS (Kanban) ──────────────────────────────────────────────────────────
app.get('/api/tasks', authMiddleware, async (req, res) => {
  const result = await db.execute({
    sql: `SELECT t.*, p.title as project_title FROM tasks t
          LEFT JOIN projects p ON t.project_id = p.id
          WHERE t.user_id = ? ORDER BY t.created_at DESC`,
    args: [req.user.id],
  });
  res.json(result.rows);
});

app.post('/api/tasks', authMiddleware, async (req, res) => {
  const { title, description, project_id, status, priority, due_date } = req.body;
  const result = await db.execute({
    sql: 'INSERT INTO tasks (user_id, project_id, title, description, status, priority, due_date) VALUES (?, ?, ?, ?, ?, ?, ?)',
    args: [req.user.id, project_id || null, title, description || '', status || 'todo', priority || 'medium', due_date || null],
  });
  const row = await db.execute({ sql: 'SELECT * FROM tasks WHERE id = ?', args: [result.lastInsertRowid] });
  res.json(row.rows[0]);
});

app.put('/api/tasks/:id', authMiddleware, async (req, res) => {
  const { title, description, project_id, status, priority, due_date } = req.body;
  await db.execute({
    sql: 'UPDATE tasks SET title=?, description=?, project_id=?, status=?, priority=?, due_date=? WHERE id=? AND user_id=?',
    args: [title, description || '', project_id || null, status || 'todo', priority || 'medium', due_date || null, req.params.id, req.user.id],
  });
  const row = await db.execute({ sql: 'SELECT * FROM tasks WHERE id = ?', args: [req.params.id] });
  res.json(row.rows[0]);
});

app.delete('/api/tasks/:id', authMiddleware, async (req, res) => {
  await db.execute({ sql: 'DELETE FROM tasks WHERE id=? AND user_id=?', args: [req.params.id, req.user.id] });
  res.json({ ok: true });
});

// ─── DEALS ───────────────────────────────────────────────────────────────────
app.get('/api/deals', authMiddleware, async (req, res) => {
  const result = await db.execute({
    sql: `SELECT d.*, c.name as client_name FROM deals d
          LEFT JOIN clients c ON d.client_id = c.id
          WHERE d.user_id = ? ORDER BY d.created_at DESC`,
    args: [req.user.id],
  });
  res.json(result.rows);
});

app.post('/api/deals', authMiddleware, async (req, res) => {
  const { title, client_id, value, stage } = req.body;
  const result = await db.execute({
    sql: 'INSERT INTO deals (user_id, client_id, title, value, stage) VALUES (?, ?, ?, ?, ?)',
    args: [req.user.id, client_id||null, title, value||null, stage||'new'],
  });
  const row = await db.execute({ sql: 'SELECT * FROM deals WHERE id = ?', args: [result.lastInsertRowid] });
  res.json(row.rows[0]);
});

app.put('/api/deals/:id', authMiddleware, async (req, res) => {
  const { title, client_id, value, stage } = req.body;
  await db.execute({
    sql: 'UPDATE deals SET title=?, client_id=?, value=?, stage=? WHERE id=? AND user_id=?',
    args: [title, client_id||null, value||null, stage||'new', req.params.id, req.user.id],
  });
  const row = await db.execute({ sql: 'SELECT * FROM deals WHERE id = ?', args: [req.params.id] });
  res.json(row.rows[0]);
});

app.delete('/api/deals/:id', authMiddleware, async (req, res) => {
  await db.execute({ sql: 'DELETE FROM deals WHERE id=? AND user_id=?', args: [req.params.id, req.user.id] });
  res.json({ ok: true });
});

// ─── INVOICES ────────────────────────────────────────────────────────────────
app.get('/api/invoices', authMiddleware, async (req, res) => {
  const result = await db.execute({
    sql: `SELECT i.*, c.name as client_name, p.title as project_title FROM invoices i
          LEFT JOIN clients c ON i.client_id = c.id
          LEFT JOIN projects p ON i.project_id = p.id
          WHERE i.user_id = ? ORDER BY i.created_at DESC`,
    args: [req.user.id],
  });
  res.json(result.rows);
});

app.post('/api/invoices', authMiddleware, async (req, res) => {
  const { number, client_id, amount, issued_at, due_at, status } = req.body;
  const result = await db.execute({
    sql: 'INSERT INTO invoices (user_id, client_id, number, amount, issued_at, due_at, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
    args: [req.user.id, client_id||null, number||'', amount||null, issued_at||null, due_at||null, status||'pending'],
  });
  const row = await db.execute({ sql: 'SELECT * FROM invoices WHERE id = ?', args: [result.lastInsertRowid] });
  res.json(row.rows[0]);
});

app.put('/api/invoices/:id', authMiddleware, async (req, res) => {
  const { number, client_id, amount, issued_at, due_at, status } = req.body;
  await db.execute({
    sql: 'UPDATE invoices SET number=?, client_id=?, amount=?, issued_at=?, due_at=?, status=? WHERE id=? AND user_id=?',
    args: [number||'', client_id||null, amount||null, issued_at||null, due_at||null, status||'pending', req.params.id, req.user.id],
  });
  const row = await db.execute({ sql: 'SELECT * FROM invoices WHERE id = ?', args: [req.params.id] });
  res.json(row.rows[0]);
});

app.delete('/api/invoices/:id', authMiddleware, async (req, res) => {
  await db.execute({ sql: 'DELETE FROM invoices WHERE id=? AND user_id=?', args: [req.params.id, req.user.id] });
  res.json({ ok: true });
});

app.put('/api/invoices/:id/pay', authMiddleware, async (req, res) => {
  await db.execute({
    sql: 'UPDATE invoices SET status=? WHERE id=? AND user_id=?',
    args: ['paid', req.params.id, req.user.id],
  });
  const row = await db.execute({ sql: 'SELECT * FROM invoices WHERE id = ?', args: [req.params.id] });
  const inv = row.rows[0];
  await sendTelegram(`💰 <b>Payment received!</b>\nInvoice: ${inv.number}\nAmount: ${inv.amount}`);
  res.json(inv);
});

// ─── EVENTS (Calendar) ───────────────────────────────────────────────────────
app.get('/api/events', authMiddleware, async (req, res) => {
  const result = await db.execute({
    sql: 'SELECT * FROM events WHERE user_id = ? ORDER BY date ASC, time ASC',
    args: [req.user.id],
  });
  res.json(result.rows);
});

app.post('/api/events', authMiddleware, async (req, res) => {
  const { title, description, date, time, color } = req.body;
  const result = await db.execute({
    sql: 'INSERT INTO events (user_id, title, description, date, time, color) VALUES (?, ?, ?, ?, ?, ?)',
    args: [req.user.id, title, description || '', date, time || '', color || '#000000'],
  });
  const row = await db.execute({ sql: 'SELECT * FROM events WHERE id = ?', args: [result.lastInsertRowid] });
  res.json(row.rows[0]);
});

app.put('/api/events/:id', authMiddleware, async (req, res) => {
  const { title, description, date, time, color } = req.body;
  await db.execute({
    sql: 'UPDATE events SET title=?, description=?, date=?, time=?, color=? WHERE id=? AND user_id=?',
    args: [title, description || '', date, time || '', color || '#000000', req.params.id, req.user.id],
  });
  const row = await db.execute({ sql: 'SELECT * FROM events WHERE id = ?', args: [req.params.id] });
  res.json(row.rows[0]);
});

app.delete('/api/events/:id', authMiddleware, async (req, res) => {
  await db.execute({ sql: 'DELETE FROM events WHERE id=? AND user_id=?', args: [req.params.id, req.user.id] });
  res.json({ ok: true });
});

// ─── USER STATS ──────────────────────────────────────────────────────────────
app.get('/api/stats', authMiddleware, async (req, res) => {
  try {
    const uid = req.user.id;
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
    res.status(500).json({ error: e.message });
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
    const row = await db.execute({ sql: 'SELECT id, name, email, role, plan, studio_name FROM users WHERE id=?', args: [req.user.id] });
    res.json(row.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
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
  } catch(e) { res.status(500).json({ error: e.message }); }
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
  const result = await db.execute({ sql: 'SELECT * FROM staff WHERE user_id = ? ORDER BY created_at DESC', args: [req.user.id] });
  res.json(result.rows);
});

app.post('/api/staff', authMiddleware, async (req, res) => {
  const { name, position, email, phone, status } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  const result = await db.execute({
    sql: 'INSERT INTO staff (user_id, name, position, email, phone, status) VALUES (?, ?, ?, ?, ?, ?)',
    args: [req.user.id, name, position || '', email || '', phone || '', status || 'active'],
  });
  const row = await db.execute({ sql: 'SELECT * FROM staff WHERE id = ?', args: [result.lastInsertRowid] });
  res.json(row.rows[0]);
});

app.put('/api/staff/:id', authMiddleware, async (req, res) => {
  const { name, position, email, phone, status } = req.body;
  await db.execute({
    sql: 'UPDATE staff SET name=?, position=?, email=?, phone=?, status=? WHERE id=? AND user_id=?',
    args: [name, position || '', email || '', phone || '', status || 'active', req.params.id, req.user.id],
  });
  const row = await db.execute({ sql: 'SELECT * FROM staff WHERE id = ?', args: [req.params.id] });
  res.json(row.rows[0]);
});

app.delete('/api/staff/:id', authMiddleware, async (req, res) => {
  await db.execute({ sql: 'DELETE FROM staff WHERE id=? AND user_id=?', args: [req.params.id, req.user.id] });
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
const crypto = require('crypto');

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

// POST /api/invite/:token — public: staff accepts invite and registers
app.post('/api/invite/:token', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password required' });

  const ownerRow = await db.execute({
    sql: 'SELECT id FROM users WHERE invite_token=?',
    args: [req.params.token],
  });
  if (!ownerRow.rows.length) return res.status(404).json({ error: 'Invalid invite link' });
  const ownerId = ownerRow.rows[0].id;

  // Check email not taken in staff
  const exists = await db.execute({ sql: 'SELECT id FROM staff WHERE email=? AND user_id=?', args: [email, ownerId] });
  if (exists.rows.length) return res.status(409).json({ error: 'This email is already in the team' });

  const hash = await bcrypt.hash(password, 10);
  await db.execute({
    sql: 'INSERT INTO staff (user_id, name, email, position, status, invite_email) VALUES (?,?,?,?,?,?)',
    args: [ownerId, name, email, 'Staff', 'active', email],
  });
  res.json({ ok: true });
});

// ─── Static pages ────────────────────────────────────────────────────────────
app.get('/app',        (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/admin',      (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/invite/:token', (req, res) => res.sendFile(path.join(__dirname, 'public', 'invite.html')));
app.get('*',           (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

// ─── Start ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
initDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 Reloxy CRM running on port ${PORT}`));
}).catch(err => {
  console.error('DB init failed:', err);
  process.exit(1);
});
