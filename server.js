// ============================================================
// server.js — Maaref Herat Backend
// Node.js 20 + Express + PostgreSQL (Neon) + Render
// ============================================================

'use strict';

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const multer = require('multer');

// ============================================================
// ENV CHECK
// ============================================================
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_RECOVERY_KEY = process.env.ADMIN_RECOVERY_KEY;

if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET is not set');
  process.exit(1);
}
if (!DATABASE_URL) {
  console.error('FATAL: DATABASE_URL is not set');
  process.exit(1);
}

// ============================================================
// DATABASE (Neon / PostgreSQL)
// ============================================================
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on('error', (err) => {
  console.error('Unexpected PG pool error:', err);
});

// helper: query
const q = (text, params) => pool.query(text, params);

// ============================================================
// APP
// ============================================================
const app = express();

app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// ============================================================
// asyncRoute wrapper
// ============================================================
const asyncRoute = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

// ============================================================
// AUTH MIDDLEWARE
// ============================================================
function authRequired(req, res, next) {
  const header = req.get('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'توکن ارسال نشده است' });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'توکن نامعتبر یا منقضی است' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'دسترسی فقط برای مدیر' });
  }
  next();
}

// ============================================================
// HEALTH
// ============================================================
app.get('/api/health', asyncRoute(async (req, res) => {
  const r = await q('SELECT 1 AS ok');
  res.json({ ok: r.rows[0].ok === 1, time: new Date().toISOString() });
}));

// ============================================================
// LOGIN — ورود مدیر و کاربران مکاتب
// ============================================================
app.post('/api/login', asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({
      error: 'نام کاربری و رمز الزامی است'
    });
  }

  const result = await q(
    'SELECT * FROM users WHERE username = $1',
    [String(username).trim()]
  );

  const user = result.rows[0];

  if (!user) {
    return res.status(401).json({
      error: 'نام کاربری یا رمز اشتباه است'
    });
  }

  const match = await bcrypt.compare(
    String(password),
    user.password
  );

  if (!match) {
    return res.status(401).json({
      error: 'نام کاربری یا رمز اشتباه است'
    });
  }

  const token = jwt.sign(
    {
      id: user.id,
      username: user.username,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  return res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      schoolname: user.schoolname,
      district: user.district,
      role: user.role,
      school_first_code: user.school_first_code,
      school_last_code: user.school_last_code,
      madaris_first_code: user.madaris_first_code,
      madaris_last_code: user.madaris_last_code
    }
  });
}));

// ============================================================
// ME — اطلاعات کاربر جاری
// ============================================================
app.get('/api/me', authRequired, asyncRoute(async (req, res) => {
  const result = await q(
    `SELECT id, username, role, schoolname, district,
            school_first_code, school_last_code,
            madaris_first_code, madaris_last_code
       FROM users WHERE id = $1`,
    [req.user.id]
  );

  if (result.rows.length === 0) {
    return res.status(404).json({ error: 'کاربر یافت نشد' });
  }

  res.json({ user: result.rows[0] });
}));

// ============================================================
// RECOVER ADMIN ONCE
// این بخش پس از ایجاد حساب مدیر باید حذف شود
// ============================================================
app.post('/api/recover-admin-once', asyncRoute(async (req, res) => {
  const recoveryKey = req.get('x-admin-recovery-key');

  if (
    !ADMIN_RECOVERY_KEY ||
    recoveryKey !== ADMIN_RECOVERY_KEY
  ) {
    return res.status(403).json({
      error: 'دسترسی غیرمجاز'
    });
  }

  const { password } = req.body || {};

  if (
    typeof password !== 'string' ||
    password.length < 8 ||
    password.length > 128
  ) {
    return res.status(400).json({
      error: 'رمز باید حداقل ۸ و حداکثر ۱۲۸ حرف باشد'
    });
  }

  const existing = await q(
    'SELECT id FROM users WHERE username = $1',
    ['admin']
  );

  if (existing.rows.length > 0) {
    return res.status(409).json({
      error: 'حساب مدیر از قبل موجود است'
    });
  }

  const hashedPassword = await bcrypt.hash(password, 12);

  await q(
    `INSERT INTO users
      (username, password, role, schoolname, district)
     VALUES ($1, $2, $3, NULL, NULL)`,
    ['admin', hashedPassword, 'admin']
  );

  return res.json({
    success: true,
    message: 'حساب مدیر با موفقیت ایجاد شد'
  });
}));

// ============================================================
// USERS — مدیریت کاربران (فقط ادمین)
// ============================================================
app.get('/api/users', authRequired, adminOnly, asyncRoute(async (req, res) => {
  const result = await q(
    `SELECT id, username, role, schoolname, district,
            school_first_code, school_last_code,
            madaris_first_code, madaris_last_code
       FROM users
      ORDER BY id ASC`
  );
  res.json({ users: result.rows });
}));

app.post('/api/users', authRequired, adminOnly, asyncRoute(async (req, res) => {
  const {
    username, password, role,
    schoolname, district,
    school_first_code, school_last_code,
    madaris_first_code, madaris_last_code
  } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'نام کاربری و رمز الزامی است' });
  }
  if (String(password).length < 8) {
    return res.status(400).json({ error: 'رمز باید حداقل ۸ حرف باشد' });
  }

  const exists = await q(
    'SELECT 1 FROM users WHERE username = $1',
    [String(username).trim()]
  );
  if (exists.rows.length > 0) {
    return res.status(409).json({ error: 'نام کاربری تکراری است' });
  }

  const hash = await bcrypt.hash(String(password), 12);

  const inserted = await q(
    `INSERT INTO users
      (username, password, role, schoolname, district,
       school_first_code, school_last_code,
       madaris_first_code, madaris_last_code)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
     RETURNING id, username, role, schoolname, district,
               school_first_code, school_last_code,
               madaris_first_code, madaris_last_code`,
    [
      String(username).trim(),
      hash,
      role || 'school',
      schoolname || null,
      district || null,
      school_first_code || null,
      school_last_code || null,
      madaris_first_code || null,
      madaris_last_code || null
    ]
  );

  res.status(201).json({ user: inserted.rows[0] });
}));

app.put('/api/users/:id', authRequired, adminOnly, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) {
    return res.status(400).json({ error: 'شناسه نامعتبر' });
  }

  const {
    password, role,
    schoolname, district,
    school_first_code, school_last_code,
    madaris_first_code, madaris_last_code
  } = req.body || {};

  let hash = null;
  if (password) {
    if (String(password).length < 8) {
      return res.status(400).json({ error: 'رمز باید حداقل ۸ حرف باشد' });
    }
    hash = await bcrypt.hash(String(password), 12);
  }

  const updated = await q(
    `UPDATE users SET
       password            = COALESCE($2, password),
       role                = COALESCE($3, role),
       schoolname          = COALESCE($4, schoolname),
       district            = COALESCE($5, district),
       school_first_code   = COALESCE($6, school_first_code),
       school_last_code    = COALESCE($7, school_last_code),
       madaris_first_code  = COALESCE($8, madaris_first_code),
       madaris_last_code   = COALESCE($9, madaris_last_code)
     WHERE id = $1
     RETURNING id, username, role, schoolname, district,
               school_first_code, school_last_code,
               madaris_first_code, madaris_last_code`,
    [
      id, hash,
      role || null,
      schoolname || null,
      district || null,
      school_first_code || null,
      school_last_code || null,
      madaris_first_code || null,
      madaris_last_code || null
    ]
  );

  if (updated.rows.length === 0) {
    return res.status(404).json({ error: 'کاربر یافت نشد' });
  }

  res.json({ user: updated.rows[0] });
}));

app.delete('/api/users/:id', authRequired, adminOnly, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) {
    return res.status(400).json({ error: 'شناسه نامعتبر' });
  }
  if (id === req.user.id) {
    return res.status(400).json({ error: 'حساب خود را نمی‌توانید حذف کنید' });
  }

  const del = await q('DELETE FROM users WHERE id = $1 RETURNING id', [id]);
  if (del.rows.length === 0) {
    return res.status(404).json({ error: 'کاربر یافت نشد' });
  }

  res.json({ success: true });
}));

// ============================================================
// 404 + ERROR HANDLER
// ============================================================
app.use((req, res) => {
  res.status(404).json({ error: 'مسیر یافت نشد' });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'خطای داخلی سرور' });
});

// ============================================================
// START
// ============================================================
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
