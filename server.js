require('dotenv').config();
const express  = require('express');
const { createClient } = require('@libsql/client');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const path     = require('path');

const app      = express();
const PORT     = process.env.PORT || 3000;
const SECRET   = process.env.JWT_SECRET || 'reloxy-dev-secret';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').toLowerCase().trim();

// ─── TELEGRAM ────────────────────────────────────────────────────────────────
async function tg(text) {
  const token  = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return;
  try {
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML' })
    });
  } catch (e) { console.error('Telegram error:', e.message); }
}

// ─── DATABASE ────────────────────────────────────────────────────────────────
const db = createClient({
  url:       process.env.TURSO_URL       || 'file:studio.db',
  authToken: process.env.TURSO_AUTH_TOKEN || undefined
});

// Helpers — mimic better-sqlite3 API but async
async function run(sql, args = []) {
  return await db.execute({ sql, args });
}
async function get(sql, args = []) {
  const r = await db.execute({ sql, args });
  return r.rows[0] || null;
}
async function all(sql, args = []) {
  const r = await db.execute({ sql, args });
  return r.rows;
}

async function initDB() {
  await db.batch([
    `CREATE TABLE IF NOT EXISTS users (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      name        TEXT    NOT NULL,
      email       TEXT    UNIQUE NOT NULL,
      password    TEXT    NOT NULL,
      studio_name TEXT    DEFAULT '',
      role        TEXT    DEFAULT 'user',
      created_at  TEXT    DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS clients (
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
    )`,
    `CREATE TABLE IF NOT EXISTS projects (
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
    )`,
    `CREATE TABLE IF NOT EXISTS deals (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      client_id   INTEGER REFERENCES clients(id) ON DELETE SET NULL,
      title       TEXT    NOT NULL,
      stage       TEXT    DEFAULT 'new',
      value       REAL    DEFAULT 0,
      created_at  TEXT    DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS invoices (
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
    )`
  ], 'write');

  // Migration: add role column if missing
  try { await run(`ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'`); } catch {}
}

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Необходима авторизация' });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: 'Токен недействителен' }); }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin')
    return res.status(403).json({ error: 'Доступ запрещён' });
  next();
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, studioName } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: 'Заполните все обязательные поля' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Пароль должен быть минимум 6 символов' });

    const emailClean = email.toLowerCase().trim();
    const exists = await get('SELECT id FROM users WHERE email = ?', [emailClean]);
    if (exists) return res.status(400).json({ error: 'Email уже зарегистрирован' });

    const hash = await bcrypt.hash(password, 10);
    const role = (ADMIN_EMAIL && emailClean === ADMIN_EMAIL) ? 'admin' : 'user';
    const result = await run(
      'INSERT INTO users (name, email, password, studio_name, role) VALUES (?, ?, ?, ?, ?)',
      [name, emailClean, hash, studioName || '', role]
    );

    const userId = Number(result.lastInsertRowid);
    const user   = { id: userId, name, email: emailClean, studioName: studioName || '', role };
    const token  = jwt.sign({ id: userId, email: emailClean, name, role }, SECRET, { expiresIn: '30d' });

    tg(`🆕 <b>Новая регистрация</b>\n👤 ${name}\n📧 ${emailClean}\n🏢 ${studioName || '—'}`);

    res.json({ token, user });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Введите email и пароль' });

    const emailClean = email.toLowerCase().trim();
    const row = await get('SELECT * FROM users WHERE email = ?', [emailClean]);
    if (!row) return res.status(401).json({ error: 'Неверный email или пароль' });

    const ok = await bcrypt.compare(password, row.password);
    if (!ok) return res.status(401).json({ error: 'Неверный email или пароль' });

    // Auto-upgrade to admin if email matches ADMIN_EMAIL
    let role = row.role || 'user';
    if (ADMIN_EMAIL && emailClean === ADMIN_EMAIL && role !== 'admin') {
      await run('UPDATE users SET role=? WHERE id=?', ['admin', row.id]);
      role = 'admin';
    }

    const user  = { id: row.id, name: row.name, email: row.email, studioName: row.studio_name, role };
    const token = jwt.sign({ id: row.id, email: row.email, name: row.name, role }, SECRET, { expiresIn: '30d' });
    res.json({ token, user });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const row = await get('SELECT id, name, email, studio_name, role FROM users WHERE id = ?', [req.user.id]);
    if (!row) return res.status(404).json({ error: 'Пользователь не найден' });
    res.json({ id: row.id, name: row.name, email: row.email, studioName: row.studio_name, role: row.role || 'user' });
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

// ─── ADMIN ────────────────────────────────────────────────────────────────────
app.get('/api/admin/stats', auth, adminOnly, async (req, res) => {
  try {
    const totalUsers    = (await get('SELECT COUNT(*) AS v FROM users')).v;
    const totalClients  = (await get('SELECT COUNT(*) AS v FROM clients')).v;
    const totalProjects = (await get('SELECT COUNT(*) AS v FROM projects')).v;
    const totalRevenue  = (await get(`SELECT COALESCE(SUM(amount),0) AS v FROM invoices WHERE status='paid'`)).v;
    res.json({ totalUsers, totalClients, totalProjects, totalRevenue });
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const rows = await all(`
      SELECT u.id, u.name, u.email, u.studio_name, u.role, u.created_at,
        (SELECT COUNT(*) FROM clients  WHERE user_id = u.id) AS clients_count,
        (SELECT COUNT(*) FROM projects WHERE user_id = u.id) AS projects_count,
        (SELECT COALESCE(SUM(amount),0) FROM invoices WHERE user_id = u.id AND status='paid') AS revenue
      FROM users u ORDER BY u.created_at DESC
    `);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.delete('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  try {
    if (Number(req.params.id) === req.user.id)
      return res.status(400).json({ error: 'Нельзя удалить себя' });
    await run('DELETE FROM users WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.put('/api/admin/users/:id/role', auth, adminOnly, async (req, res) => {
  try {
    const { role } = req.body;
    if (!['admin','user'].includes(role))
      return res.status(400).json({ error: 'Неверная роль' });
    await run('UPDATE users SET role=? WHERE id=?', [role, req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

// ─── STATS ───────────────────────────────────────────────────────────────────
app.get('/api/stats', auth, async (req, res) => {
  try {
    const uid  = req.user.id;
    const now  = new Date();
    const year = now.getFullYear();
    const m    = String(now.getMonth() + 1).padStart(2, '0');
    const from = `${year}-${m}-01`;

    const revenue        = (await get(`SELECT COALESCE(SUM(amount),0) AS v FROM invoices WHERE user_id=? AND status='paid' AND issued_at >= ?`, [uid, from])).v;
    const activeProjects = (await get(`SELECT COUNT(*) AS v FROM projects WHERE user_id=? AND status != 'done'`, [uid])).v;
    const totalClients   = (await get(`SELECT COUNT(*) AS v FROM clients WHERE user_id=?`, [uid])).v;
    const totalLeads     = (await get(`SELECT COUNT(*) AS v FROM deals WHERE user_id=? AND stage != 'closed'`, [uid])).v;

    const monthly = [];
    for (let i = 0; i < 12; i++) {
      const mm = String(i + 1).padStart(2, '0');
      const v = (await get(
        `SELECT COALESCE(SUM(amount),0) AS v FROM invoices WHERE user_id=? AND status='paid' AND issued_at >= ? AND issued_at <= ?`,
        [uid, `${year}-${mm}-01`, `${year}-${mm}-31`]
      )).v;
      monthly.push(v);
    }

    res.json({ revenue, activeProjects, totalClients, totalLeads, monthly });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

// ─── CLIENTS ─────────────────────────────────────────────────────────────────
app.get('/api/clients', auth, async (req, res) => {
  try {
    const rows = await all(`
      SELECT c.*,
        (SELECT COUNT(*) FROM projects WHERE client_id = c.id) AS project_count,
        (SELECT COALESCE(SUM(amount),0) FROM invoices WHERE client_id = c.id AND status='paid') AS total_paid
      FROM clients c WHERE c.user_id = ? ORDER BY c.created_at DESC
    `, [req.user.id]);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/clients', auth, async (req, res) => {
  try {
    const { name, industry, contact_name, email, phone, status, notes } = req.body;
    if (!name) return res.status(400).json({ error: 'Укажите название компании' });
    const r = await run(
      `INSERT INTO clients (user_id,name,industry,contact_name,email,phone,status,notes) VALUES (?,?,?,?,?,?,?,?)`,
      [req.user.id, name, industry||'', contact_name||'', email||'', phone||'', status||'active', notes||'']
    );
    res.json({ id: Number(r.lastInsertRowid), name, industry, contact_name, email, phone, status: status||'active', notes, project_count: 0, total_paid: 0 });
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.put('/api/clients/:id', auth, async (req, res) => {
  try {
    const { name, industry, contact_name, email, phone, status, notes } = req.body;
    await run(
      `UPDATE clients SET name=?,industry=?,contact_name=?,email=?,phone=?,status=?,notes=? WHERE id=? AND user_id=?`,
      [name, industry||'', contact_name||'', email||'', phone||'', status||'active', notes||'', req.params.id, req.user.id]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.delete('/api/clients/:id', auth, async (req, res) => {
  try {
    await run('DELETE FROM clients WHERE id=? AND user_id=?', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

// ─── PROJECTS ────────────────────────────────────────────────────────────────
app.get('/api/projects', auth, async (req, res) => {
  try {
    const rows = await all(
      `SELECT p.*, c.name AS client_name FROM projects p LEFT JOIN clients c ON p.client_id = c.id WHERE p.user_id = ? ORDER BY p.created_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/projects', auth, async (req, res) => {
  try {
    const { title, type, client_id, status, progress, deadline, budget } = req.body;
    if (!title) return res.status(400).json({ error: 'Укажите название проекта' });
    const r = await run(
      `INSERT INTO projects (user_id,title,type,client_id,status,progress,deadline,budget) VALUES (?,?,?,?,?,?,?,?)`,
      [req.user.id, title, type||'', client_id||null, status||'queue', progress||0, deadline||'', budget||0]
    );
    res.json({ id: Number(r.lastInsertRowid), title, type, client_id, status: status||'queue', progress: progress||0, deadline, budget: budget||0 });
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.put('/api/projects/:id', auth, async (req, res) => {
  try {
    const { title, type, client_id, status, progress, deadline, budget } = req.body;
    await run(
      `UPDATE projects SET title=?,type=?,client_id=?,status=?,progress=?,deadline=?,budget=? WHERE id=? AND user_id=?`,
      [title, type||'', client_id||null, status||'queue', progress||0, deadline||'', budget||0, req.params.id, req.user.id]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.delete('/api/projects/:id', auth, async (req, res) => {
  try {
    await run('DELETE FROM projects WHERE id=? AND user_id=?', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

// ─── DEALS ───────────────────────────────────────────────────────────────────
app.get('/api/deals', auth, async (req, res) => {
  try {
    const rows = await all(
      `SELECT d.*, c.name AS client_name FROM deals d LEFT JOIN clients c ON d.client_id = c.id WHERE d.user_id = ? ORDER BY d.created_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/deals', auth, async (req, res) => {
  try {
    const { title, client_id, stage, value } = req.body;
    if (!title) return res.status(400).json({ error: 'Укажите название сделки' });
    const r = await run(
      `INSERT INTO deals (user_id,title,client_id,stage,value) VALUES (?,?,?,?,?)`,
      [req.user.id, title, client_id||null, stage||'new', value||0]
    );
    res.json({ id: Number(r.lastInsertRowid), title, client_id, stage: stage||'new', value: value||0 });
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.put('/api/deals/:id', auth, async (req, res) => {
  try {
    const { title, client_id, stage, value } = req.body;
    await run(
      `UPDATE deals SET title=?,client_id=?,stage=?,value=? WHERE id=? AND user_id=?`,
      [title, client_id||null, stage||'new', value||0, req.params.id, req.user.id]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.delete('/api/deals/:id', auth, async (req, res) => {
  try {
    await run('DELETE FROM deals WHERE id=? AND user_id=?', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

// ─── INVOICES ────────────────────────────────────────────────────────────────
app.get('/api/invoices', auth, async (req, res) => {
  try {
    const rows = await all(
      `SELECT i.*, c.name AS client_name FROM invoices i LEFT JOIN clients c ON i.client_id = c.id WHERE i.user_id = ? ORDER BY i.created_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/invoices', auth, async (req, res) => {
  try {
    const { number, client_id, project_id, amount, status, issued_at, due_at } = req.body;
    const r = await run(
      `INSERT INTO invoices (user_id,number,client_id,project_id,amount,status,issued_at,due_at) VALUES (?,?,?,?,?,?,?,?)`,
      [req.user.id, number||'', client_id||null, project_id||null, amount||0, status||'pending', issued_at||'', due_at||'']
    );

    if (status === 'paid') {
      const u = await get('SELECT name FROM users WHERE id=?', [req.user.id]);
      tg(`💰 <b>Оплачен счёт</b>\n👤 ${u?.name || req.user.email}\n🧾 ${number || '—'}\n💵 ₽${amount || 0}`);
    }

    res.json({ id: Number(r.lastInsertRowid), ...req.body });
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.put('/api/invoices/:id', auth, async (req, res) => {
  try {
    const { number, client_id, project_id, amount, status, issued_at, due_at } = req.body;
    const prev = await get('SELECT status FROM invoices WHERE id=? AND user_id=?', [req.params.id, req.user.id]);
    await run(
      `UPDATE invoices SET number=?,client_id=?,project_id=?,amount=?,status=?,issued_at=?,due_at=? WHERE id=? AND user_id=?`,
      [number||'', client_id||null, project_id||null, amount||0, status||'pending', issued_at||'', due_at||'', req.params.id, req.user.id]
    );

    if (prev && prev.status !== 'paid' && status === 'paid') {
      const u = await get('SELECT name FROM users WHERE id=?', [req.user.id]);
      tg(`💰 <b>Оплачен счёт</b>\n👤 ${u?.name || req.user.email}\n🧾 ${number || '—'}\n💵 ₽${amount || 0}`);
    }

    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.delete('/api/invoices/:id', auth, async (req, res) => {
  try {
    await run('DELETE FROM invoices WHERE id=? AND user_id=?', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

// ─── ROUTES ──────────────────────────────────────────────────────────────────
app.get('/app',   (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('*',      (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

// ─── START ───────────────────────────────────────────────────────────────────
async function start() {
  await initDB();
  app.listen(PORT, () => console.log(`\n  Reloxy CRM → http://localhost:${PORT}\n`));
}

start().catch(e => { console.error('Startup error:', e); process.exit(1); });
