// ============================================================
// server.js — Maaref Herat Backend
// Node 20 + Express + PostgreSQL (Neon) + Render
// ============================================================
'use strict';

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

// ============================================================
// ENV
// ============================================================
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_RECOVERY_KEY = process.env.ADMIN_RECOVERY_KEY;

if (!JWT_SECRET) { console.error('FATAL: JWT_SECRET not set'); process.exit(1); }
if (!DATABASE_URL) { console.error('FATAL: DATABASE_URL not set'); process.exit(1); }

// ============================================================
// DB
// ============================================================
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});
pool.on('error', (e) => console.error('PG pool error:', e));
const q = (text, params) => pool.query(text, params);

// ============================================================
// APP
// ============================================================
const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '4mb' }));
app.use(express.urlencoded({ extended: true }));

const asyncRoute = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

// ============================================================
// AUTH
// ============================================================
function authRequired(req, res, next) {
  const h = req.get('authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'توکن ارسال نشده است' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'توکن نامعتبر یا منقضی است' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== 'admin')
    return res.status(403).json({ error: 'دسترسی فقط برای مدیر' });
  next();
}

// ============================================================
// HELPERS
// ============================================================
const num = (v, def = 0) => (v === undefined || v === null || v === '' ? def : Number(v));

async function logAttempt(ip, username, success) {
  try {
    await q(
      'INSERT INTO login_attempts (ip, username, success) VALUES ($1,$2,$3)',
      [ip || 'unknown', username || null, !!success]
    );
  } catch (e) { console.error('logAttempt error:', e.message); }
}

async function tooManyFailures(ip) {
  const r = await q(
    `SELECT COUNT(*)::int AS c
       FROM login_attempts
      WHERE ip = $1 AND success = false
        AND createdat > NOW() - INTERVAL '15 minutes'`,
    [ip]
  );
  return r.rows[0].c >= 10;
}

// ============================================================
// HEALTH
// ============================================================
app.get('/api/health', asyncRoute(async (_req, res) => {
  const r = await q('SELECT 1 AS ok');
  res.json({ ok: r.rows[0].ok === 1, time: new Date().toISOString() });
}));

// ============================================================
// LOGIN
// ============================================================
app.post('/api/login', asyncRoute(async (req, res) => {
  const ip = req.ip;
  const { username, password } = req.body || {};

  if (!username || !password)
    return res.status(400).json({ error: 'نام کاربری و رمز الزامی است' });

  if (await tooManyFailures(ip))
    return res.status(429).json({ error: 'تلاش‌های ناموفق زیاد. بعداً دوباره امتحان کنید.' });

  const result = await q(
    'SELECT * FROM users WHERE username = $1',
    [String(username).trim()]
  );
  const user = result.rows[0];

  if (!user) {
    await logAttempt(ip, username, false);
    return res.status(401).json({ error: 'نام کاربری یا رمز اشتباه است' });
  }

  const match = await bcrypt.compare(String(password), user.password);
  if (!match) {
    await logAttempt(ip, username, false);
    return res.status(401).json({ error: 'نام کاربری یا رمز اشتباه است' });
  }

  await logAttempt(ip, username, true);

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({
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
// ME
// ============================================================
app.get('/api/me', authRequired, asyncRoute(async (req, res) => {
  const r = await q(
    `SELECT id, username, role, schoolname, district,
            school_first_code, school_last_code,
            madaris_first_code, madaris_last_code
       FROM users WHERE id = $1`,
    [req.user.id]
  );
  if (!r.rows[0]) return res.status(404).json({ error: 'کاربر یافت نشد' });
  res.json({ user: r.rows[0] });
}));

// ============================================================
// RECOVER ADMIN ONCE
// ============================================================
app.post('/api/recover-admin-once', asyncRoute(async (req, res) => {
  const key = req.get('x-admin-recovery-key');
  if (!ADMIN_RECOVERY_KEY || key !== ADMIN_RECOVERY_KEY)
    return res.status(403).json({ error: 'دسترسی غیرمجاز' });

  const { password } = req.body || {};
  if (typeof password !== 'string' || password.length < 8 || password.length > 128)
    return res.status(400).json({ error: 'رمز باید حداقل ۸ و حداکثر ۱۲۸ حرف باشد' });

  const exists = await q('SELECT id FROM users WHERE username=$1', ['admin']);
  if (exists.rows.length) return res.status(409).json({ error: 'حساب مدیر از قبل موجود است' });

  const hash = await bcrypt.hash(password, 12);
  await q(
    `INSERT INTO users (username, password, role)
     VALUES ('admin', $1, 'admin')`,
    [hash]
  );
  res.json({ success: true, message: 'حساب مدیر ایجاد شد' });
}));

// ============================================================
// USERS (admin)
// ============================================================
app.get('/api/users', authRequired, adminOnly, asyncRoute(async (_req, res) => {
  const r = await q(
    `SELECT id, username, role, schoolname, district,
            school_first_code, school_last_code,
            madaris_first_code, madaris_last_code
       FROM users ORDER BY id`
  );
  res.json({ users: r.rows });
}));

app.post('/api/users', authRequired, adminOnly, asyncRoute(async (req, res) => {
  const b = req.body || {};
  if (!b.username || !b.password)
    return res.status(400).json({ error: 'نام کاربری و رمز الزامی است' });
  if (String(b.password).length < 8)
    return res.status(400).json({ error: 'رمز باید حداقل ۸ حرف باشد' });

  const exists = await q('SELECT 1 FROM users WHERE username=$1', [String(b.username).trim()]);
  if (exists.rows.length) return res.status(409).json({ error: 'نام کاربری تکراری است' });

  const hash = await bcrypt.hash(String(b.password), 12);
  const r = await q(
    `INSERT INTO users
      (username, password, role, schoolname, district,
       school_first_code, school_last_code,
       madaris_first_code, madaris_last_code)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
     RETURNING id, username, role, schoolname, district,
               school_first_code, school_last_code,
               madaris_first_code, madaris_last_code`,
    [
      String(b.username).trim(), hash, b.role || 'school',
      b.schoolname || null, b.district || null,
      b.school_first_code || null, b.school_last_code || null,
      b.madaris_first_code || null, b.madaris_last_code || null
    ]
  );
  res.status(201).json({ user: r.rows[0] });
}));

app.put('/api/users/:id', authRequired, adminOnly, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const b = req.body || {};
  let hash = null;
  if (b.password) {
    if (String(b.password).length < 8)
      return res.status(400).json({ error: 'رمز باید حداقل ۸ حرف باشد' });
    hash = await bcrypt.hash(String(b.password), 12);
  }
  const r = await q(
    `UPDATE users SET
       password = COALESCE($2, password),
       role = COALESCE($3, role),
       schoolname = COALESCE($4, schoolname),
       district = COALESCE($5, district),
       school_first_code = COALESCE($6, school_first_code),
       school_last_code = COALESCE($7, school_last_code),
       madaris_first_code = COALESCE($8, madaris_first_code),
       madaris_last_code = COALESCE($9, madaris_last_code)
     WHERE id = $1
     RETURNING id, username, role, schoolname, district,
               school_first_code, school_last_code,
               madaris_first_code, madaris_last_code`,
    [id, hash, b.role || null, b.schoolname || null, b.district || null,
     b.school_first_code || null, b.school_last_code || null,
     b.madaris_first_code || null, b.madaris_last_code || null]
  );
  if (!r.rows[0]) return res.status(404).json({ error: 'کاربر یافت نشد' });
  res.json({ user: r.rows[0] });
}));

app.delete('/api/users/:id', authRequired, adminOnly, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) return res.status(400).json({ error: 'حساب خود را حذف نکنید' });
  const r = await q('DELETE FROM users WHERE id=$1 RETURNING id', [id]);
  if (!r.rows[0]) return res.status(404).json({ error: 'کاربر یافت نشد' });
  res.json({ success: true });
}));

// ============================================================
// APP SETTINGS (key/value)
// ============================================================
app.get('/api/app-settings', asyncRoute(async (_req, res) => {
  const r = await q('SELECT key, value, updatedat FROM app_settings ORDER BY key');
  res.json({ settings: r.rows });
}));

app.get('/api/app-settings/:key', asyncRoute(async (req, res) => {
  const r = await q('SELECT key, value FROM app_settings WHERE key=$1', [req.params.key]);
  if (!r.rows[0]) return res.status(404).json({ error: 'یافت نشد' });
  res.json({ setting: r.rows[0] });
}));

app.put('/api/app-settings/:key', authRequired, adminOnly, asyncRoute(async (req, res) => {
  const { value } = req.body || {};
  if (value === undefined) return res.status(400).json({ error: 'value الزامی است' });
  const r = await q(
    `INSERT INTO app_settings (key, value, updatedat)
     VALUES ($1,$2,NOW())
     ON CONFLICT (key) DO UPDATE
       SET value = EXCLUDED.value, updatedat = NOW()
     RETURNING key, value, updatedat`,
    [req.params.key, String(value)]
  );
  res.json({ setting: r.rows[0] });
}));

// ============================================================
// SCHOOL SETTINGS
// ============================================================
app.get('/api/school-settings', authRequired, asyncRoute(async (req, res) => {
  const r = await q(
    'SELECT * FROM school_settings WHERE userid=$1 ORDER BY id',
    [req.user.id]
  );
  res.json({ settings: r.rows });
}));

app.post('/api/school-settings', authRequired, asyncRoute(async (req, res) => {
  const b = req.body || {};
  // فقط ستون‌های موجود: userid, schoolname (+ هر ستون دیگری که در جدول هست)
  const r = await q(
    `INSERT INTO school_settings (userid, schoolname)
     VALUES ($1,$2) RETURNING *`,
    [req.user.id, b.schoolname || null]
  );
  res.status(201).json({ setting: r.rows[0] });
}));

// ============================================================
// RECORDS
// ============================================================
app.get('/api/records', authRequired, asyncRoute(async (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const r = await q(
    isAdmin
      ? `SELECT * FROM records ORDER BY createdat DESC LIMIT 500`
      : `SELECT * FROM records WHERE userid=$1 ORDER BY createdat DESC LIMIT 500`,
    isAdmin ? [] : [req.user.id]
  );
  res.json({ records: r.rows });
}));

app.get('/api/records/:id', authRequired, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const r = await q('SELECT * FROM records WHERE id=$1', [id]);
  const rec = r.rows[0];
  if (!rec) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role !== 'admin' && rec.userid !== req.user.id)
    return res.status(403).json({ error: 'دسترسی ندارید' });
  res.json({ record: rec });
}));

app.post('/api/records', authRequired, asyncRoute(async (req, res) => {
  const b = req.body || {};
  const r = await q(
    `INSERT INTO records (userid, schoolname, district, data, status, editallowed)
     VALUES ($1,$2,$3,$4,$5,$6)
     RETURNING *`,
    [
      req.user.id,
      b.schoolname || null,
      b.district || null,
      b.data ? (typeof b.data === 'string' ? b.data : JSON.stringify(b.data)) : null,
      b.status || 'pending',
      num(b.editallowed, 0)
    ]
  );
  res.status(201).json({ record: r.rows[0] });
}));

app.put('/api/records/:id', authRequired, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const r0 = await q('SELECT * FROM records WHERE id=$1', [id]);
  const rec = r0.rows[0];
  if (!rec) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role !== 'admin' && rec.userid !== req.user.id)
    return res.status(403).json({ error: 'دسترسی ندارید' });

  const b = req.body || {};
  const r = await q(
    `UPDATE records SET
       schoolname = COALESCE($2, schoolname),
       district   = COALESCE($3, district),
       data       = COALESCE($4, data),
       status     = COALESCE($5, status),
       editallowed= COALESCE($6, editallowed),
       updatedat  = NOW()
     WHERE id=$1 RETURNING *`,
    [
      id,
      b.schoolname || null,
      b.district || null,
      b.data === undefined ? null : (typeof b.data === 'string' ? b.data : JSON.stringify(b.data)),
      b.status || null,
      b.editallowed === undefined ? null : num(b.editallowed)
    ]
  );
  res.json({ record: r.rows[0] });
}));

app.delete('/api/records/:id', authRequired, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const r0 = await q('SELECT * FROM records WHERE id=$1', [id]);
  const rec = r0.rows[0];
  if (!rec) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role !== 'admin' && rec.userid !== req.user.id)
    return res.status(403).json({ error: 'دسترسی ندارید' });

  await q('DELETE FROM records WHERE id=$1', [id]);
  res.json({ success: true });
}));

// ============================================================
// SALARIES
// ============================================================
const SALARY_COLS = [
  'bank_number','appointment_letter','base_salary','other_base',
  'professional','other_professional','food','other_food',
  'allowance','other_allowance','other_increase','total_entitlement',
  'absence','tax','other_tax','tax_10','deductions','other_deductions',
  'total_deductions','net_pay','status','first_name','last_name',
  'father_name','job_title','job_code','attendance'
];

app.get('/api/salaries', authRequired, asyncRoute(async (req, res) => {
  const { year, month } = req.query;
  const isAdmin = req.user.role === 'admin';
  const params = [];
  const conds = [];
  if (!isAdmin) { params.push(req.user.id); conds.push(`userid=$${params.length}`); }
  if (year)  { params.push(String(year));  conds.push(`year=$${params.length}`); }
  if (month) { params.push(String(month)); conds.push(`month=$${params.length}`); }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  const r = await q(
    `SELECT * FROM salaries ${where} ORDER BY createdat DESC LIMIT 1000`,
    params
  );
  res.json({ salaries: r.rows });
}));

app.get('/api/salaries/:id', authRequired, asyncRoute(async (req, res) => {
  const r = await q('SELECT * FROM salaries WHERE id=$1', [Number(req.params.id)]);
  const s = r.rows[0];
  if (!s) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role !== 'admin' && s.userid !== req.user.id)
    return res.status(403).json({ error: 'دسترسی ندارید' });
  res.json({ salary: s });
}));

app.post('/api/salaries', authRequired, asyncRoute(async (req, res) => {
  const b = req.body || {};
  if (!b.record_id || !b.year || !b.month)
    return res.status(400).json({ error: 'record_id, year, month الزامی است' });

  const cols = ['record_id','userid','schoolname','district','year','month', ...SALARY_COLS];
  const vals = [
    Number(b.record_id),
    req.user.role === 'admin' && b.userid ? Number(b.userid) : req.user.id,
    b.schoolname || null,
    b.district || null,
    String(b.year),
    String(b.month),
    ...SALARY_COLS.map(c => {
      if (c === 'status') return b.status || 'draft';
      if (['first_name','last_name','father_name','job_title','job_code','bank_number','appointment_letter','attendance'].includes(c))
        return b[c] || null;
      return num(b[c], 0);
    })
  ];

  const placeholders = cols.map((_, i) => `$${i + 1}`).join(',');
  const r = await q(
    `INSERT INTO salaries (${cols.join(',')}) VALUES (${placeholders}) RETURNING *`,
    vals
  );
  res.status(201).json({ salary: r.rows[0] });
}));

app.put('/api/salaries/:id', authRequired, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const r0 = await q('SELECT * FROM salaries WHERE id=$1', [id]);
  const s = r0.rows[0];
  if (!s) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role !== 'admin' && s.userid !== req.user.id)
    return res.status(403).json({ error: 'دسترسی ندارید' });

  const b = req.body || {};
  const updates = [];
  const params = [];
  for (const c of SALARY_COLS) {
    if (b[c] === undefined) continue;
    params.push(
      ['first_name','last_name','father_name','job_title','job_code','bank_number','appointment_letter','attendance','status'].includes(c)
        ? (b[c] || null)
        : num(b[c], 0)
    );
    updates.push(`${c}=$${params.length}`);
  }
  if (!updates.length) return res.status(400).json({ error: 'چیزی برای به‌روزرسانی نیست' });

  updates.push('updatedat=NOW()');
  params.push(id);
  const r = await q(
    `UPDATE salaries SET ${updates.join(',')} WHERE id=$${params.length} RETURNING *`,
    params
  );
  res.json({ salary: r.rows[0] });
}));

app.delete('/api/salaries/:id', authRequired, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const r0 = await q('SELECT * FROM salaries WHERE id=$1', [id]);
  const s = r0.rows[0];
  if (!s) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role !== 'admin' && s.userid !== req.user.id)
    return res.status(403).json({ error: 'دسترسی ندارید' });

  await q('DELETE FROM attendance WHERE salary_id=$1', [id]);
  await q('DELETE FROM salaries WHERE id=$1', [id]);
  res.json({ success: true });
}));

// ============================================================
// ATTENDANCE (وابسته به salary)
// ============================================================
app.get('/api/attendance/:salary_id', authRequired, asyncRoute(async (req, res) => {
  const salary_id = Number(req.params.salary_id);
  const r = await q('SELECT * FROM attendance WHERE salary_id=$1', [salary_id]);
  res.json({ attendance: r.rows[0] || null });
}));

app.post('/api/attendance', authRequired, asyncRoute(async (req, res) => {
  const b = req.body || {};
  if (!b.salary_id) return res.status(400).json({ error: 'salary_id الزامی است' });

  const fields = ['salary_id','present','absent','vacation','sick','essential',
    'maternity','service_center','service_province','hajj','holidays','other','total_days'];
  const vals = fields.map(f => f === 'salary_id' ? Number(b.salary_id) : num(b[f], 0));
  const ph = fields.map((_, i) => `$${i + 1}`).join(',');

  const r = await q(
    `INSERT INTO attendance (${fields.join(',')}) VALUES (${ph}) RETURNING *`,
    vals
  );
  res.status(201).json({ attendance: r.rows[0] });
}));

app.put('/api/attendance/:id', authRequired, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const b = req.body || {};
  const fields = ['present','absent','vacation','sick','essential',
    'maternity','service_center','service_province','hajj','holidays','other','total_days'];
  const updates = [];
  const params = [];
  for (const f of fields) {
    if (b[f] === undefined) continue;
    params.push(num(b[f], 0));
    updates.push(`${f}=$${params.length}`);
  }
  if (!updates.length) return res.status(400).json({ error: 'چیزی برای به‌روزرسانی نیست' });
  updates.push('updatedat=NOW()');
  params.push(id);
  const r = await q(
    `UPDATE attendance SET ${updates.join(',')} WHERE id=$${params.length} RETURNING *`,
    params
  );
  if (!r.rows[0]) return res.status(404).json({ error: 'یافت نشد' });
  res.json({ attendance: r.rows[0] });
}));

// ============================================================
// EVALUATIONS
// ============================================================
app.get('/api/evaluations', authRequired, asyncRoute(async (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const r = await q(
    isAdmin
      ? `SELECT * FROM evaluations ORDER BY createdat DESC LIMIT 500`
      : `SELECT * FROM evaluations WHERE userid=$1 ORDER BY createdat DESC LIMIT 500`,
    isAdmin ? [] : [req.user.id]
  );
  res.json({ evaluations: r.rows });
}));

app.get('/api/evaluations/:id', authRequired, asyncRoute(async (req, res) => {
  const r = await q('SELECT * FROM evaluations WHERE id=$1', [Number(req.params.id)]);
  const e = r.rows[0];
  if (!e) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role !== 'admin' && e.userid !== req.user.id)
    return res.status(403).json({ error: 'دسترسی ندارید' });
  res.json({ evaluation: e });
}));

const EVAL_TEXT = [
  'schoolname','district','first_name','last_name','father_name','grandfather_name',
  'job_code','employment_type','birth_year','service_duration','degree','gender',
  'job_title','appointment_date','eval_date_prev','bust','grade','eval_date','eval_result','remarks'
];

app.post('/api/evaluations', authRequired, asyncRoute(async (req, res) => {
  const b = req.body || {};
  if (!b.record_id || !b.eval_date || b.eval_score === undefined || !b.eval_result)
    return res.status(400).json({ error: 'record_id, eval_date, eval_score, eval_result الزامی است' });

  const cols = ['record_id','userid','eval_score', ...EVAL_TEXT];
  const vals = [
    Number(b.record_id),
    req.user.role === 'admin' && b.userid ? Number(b.userid) : req.user.id,
    Number(b.eval_score),
    ...EVAL_TEXT.map(c => b[c] !== undefined ? (b[c] === null ? null : String(b[c])) : null)
  ];
  const ph = cols.map((_, i) => `$${i + 1}`).join(',');
  const r = await q(
    `INSERT INTO evaluations (${cols.join(',')}) VALUES (${ph}) RETURNING *`,
    vals
  );
  res.status(201).json({ evaluation: r.rows[0] });
}));

app.put('/api/evaluations/:id', authRequired, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const r0 = await q('SELECT * FROM evaluations WHERE id=$1', [id]);
  const e = r0.rows[0];
  if (!e) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role !== 'admin' && e.userid !== req.user.id)
    return res.status(403).json({ error: 'دسترسی ندارید' });

  const b = req.body || {};
  const updates = [];
  const params = [];
  if (b.eval_score !== undefined) { params.push(Number(b.eval_score)); updates.push(`eval_score=$${params.length}`); }
  for (const c of EVAL_TEXT) {
    if (b[c] === undefined) continue;
    params.push(b[c] === null ? null : String(b[c]));
    updates.push(`${c}=$${params.length}`);
  }
  if (!updates.length) return res.status(400).json({ error: 'چیزی برای به‌روزرسانی نیست' });
  params.push(id);
  const r = await q(
    `UPDATE evaluations SET ${updates.join(',')} WHERE id=$${params.length} RETURNING *`,
    params
  );
  res.json({ evaluation: r.rows[0] });
}));

app.delete('/api/evaluations/:id', authRequired, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const r0 = await q('SELECT * FROM evaluations WHERE id=$1', [id]);
  const e = r0.rows[0];
  if (!e) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role !== 'admin' && e.userid !== req.user.id)
    return res.status(403).json({ error: 'دسترسی ندارید' });
  await q('DELETE FROM evaluations WHERE id=$1', [id]);
  res.json({ success: true });
}));

// ============================================================
// EVALUATION PERMISSION (single row toggle)
// ============================================================
app.get('/api/evaluation-permission', asyncRoute(async (_req, res) => {
  const r = await q('SELECT * FROM evaluation_permission ORDER BY id LIMIT 1');
  res.json({ permission: r.rows[0] || { allowed: 0 } });
}));

app.put('/api/evaluation-permission', authRequired, adminOnly, asyncRoute(async (req, res) => {
  const allowed = num(req.body?.allowed, 0) ? 1 : 0;
  const existing = await q('SELECT id FROM evaluation_permission ORDER BY id LIMIT 1');
  if (existing.rows[0]) {
    const r = await q(
      `UPDATE evaluation_permission SET allowed=$1, updated_at=NOW() WHERE id=$2 RETURNING *`,
      [allowed, existing.rows[0].id]
    );
    return res.json({ permission: r.rows[0] });
  }
  const r = await q(
    `INSERT INTO evaluation_permission (allowed) VALUES ($1) RETURNING *`,
    [allowed]
  );
  res.json({ permission: r.rows[0] });
}));

// ============================================================
// 404 + ERROR
// ============================================================
app.use((_req, res) => res.status(404).json({ error: 'مسیر یافت نشد' }));
app.use((err, _req, res, _next) => {
  console.error('Unhandled:', err);
  res.status(500).json({ error: 'خطای داخلی سرور', detail: err.message });
});

// ============================================================
// START
// ============================================================
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
