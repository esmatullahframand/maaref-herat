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
app.use(express.json({ limit: '8mb' }));
app.use(express.urlencoded({ extended: true, limit: '8mb' }));
app.use(express.static('public'));

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
const txt = (v) => (v === undefined || v === null || v === '' ? null : String(v));

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
    return res.status(429).json({ error: 'تلاش‌های ناموفق زیاد. بعداً امتحان کنید.' });

  const result = await q('SELECT * FROM users WHERE username=$1', [String(username).trim()]);
  const user = result.rows[0];
  if (!user) { await logAttempt(ip, username, false); return res.status(401).json({ error: 'نام کاربری یا رمز اشتباه است' }); }

  const match = await bcrypt.compare(String(password), user.password);
  if (!match) { await logAttempt(ip, username, false); return res.status(401).json({ error: 'نام کاربری یا رمز اشتباه است' }); }

  await logAttempt(ip, username, true);

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET, { expiresIn: '7d' }
  );
  res.json({
    token,
    user: {
      id: user.id, username: user.username,
      schoolname: user.schoolname, district: user.district, role: user.role,
      school_first_code: user.school_first_code, school_last_code: user.school_last_code,
      madaris_first_code: user.madaris_first_code, madaris_last_code: user.madaris_last_code
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
       FROM users WHERE id=$1`,
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
  await q(`INSERT INTO users (username,password,role) VALUES ('admin',$1,'admin')`, [hash]);
  res.json({ success: true, message: 'حساب مدیر ایجاد شد' });
}));

// ============================================================
// USERS
// ============================================================
app.get('/api/users', authRequired, adminOnly, asyncRoute(async (_req, res) => {
  const r = await q(
    `SELECT id, username, role, schoolname, district,
            school_first_code, school_last_code,
            madaris_first_code, madaris_last_code
       FROM users ORDER BY id`
  );
  res.json(r.rows);
}));

app.post('/api/users', authRequired, adminOnly, asyncRoute(async (req, res) => {
  const b = req.body || {};
  if (!b.username || !b.password)
    return res.status(400).json({ error: 'نام کاربری و رمز الزامی است' });
  if (String(b.password).length < 8)
    return res.status(400).json({ error: 'رمز باید حداقل ۸ حرف باشد' });

  const exists = await q('SELECT 1 FROM users WHERE username=$1', [String(b.username).trim()]);
  if (exists.rows.length) return res.status(409).json({ error: 'نام کاربری تکراری است' });

  const schoolFirstCode = b.school_first_code ?? b.schoolFirstCode ?? null;
  const schoolLastCode  = b.school_last_code  ?? b.schoolLastCode  ?? null;
  const madarisFirstCode = b.madaris_first_code ?? b.madarisFirstCode ?? null;
  const madarisLastCode  = b.madaris_last_code  ?? b.madarisLastCode  ?? null;

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
      txt(b.schoolname), txt(b.district),
      txt(schoolFirstCode), txt(schoolLastCode),
      txt(madarisFirstCode), txt(madarisLastCode)
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

  const schoolFirstCode = b.school_first_code ?? b.schoolFirstCode ?? null;
  const schoolLastCode  = b.school_last_code  ?? b.schoolLastCode  ?? null;
  const madarisFirstCode = b.madaris_first_code ?? b.madarisFirstCode ?? null;
  const madarisLastCode  = b.madaris_last_code  ?? b.madarisLastCode  ?? null;

  const r = await q(
    `UPDATE users SET
       password = COALESCE($2, password),
       role = COALESCE($3, role),
       schoolname = COALESCE($4, schoolname),
       district = COALESCE($5, district),
       school_first_code = COALESCE($6, school_first_code),
       school_last_code = COALESCE($7, school_last_code),
       madaris_first_code = COALESCE($8, madaris_first_code),
       madaris_last_code = COALESCE($9, madaris_last_code),
       username = COALESCE($10, username)
     WHERE id=$1
     RETURNING id, username, role, schoolname, district,
               school_first_code, school_last_code,
               madaris_first_code, madaris_last_code`,
    [id, hash, txt(b.role), txt(b.schoolname), txt(b.district),
     txt(schoolFirstCode), txt(schoolLastCode),
     txt(madarisFirstCode), txt(madarisLastCode),
     txt(b.username)]
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
// ALL SCHOOL SETTINGS
// ============================================================
app.get('/api/all-school-settings', authRequired, adminOnly, asyncRoute(async (_req, res) => {
  try {
    const r = await q(
      `SELECT u.id, u.schoolname, u.district,
              u.school_first_code, u.school_last_code,
              u.madaris_first_code, u.madaris_last_code,
              ss.id AS setting_id, ss.schoolname AS setting_schoolname
         FROM users u
         LEFT JOIN school_settings ss ON ss.userid = u.id
         WHERE u.role = 'school'
         ORDER BY u.id`
    );
    res.json(r.rows);
  } catch (e) {
    const r = await q(
      `SELECT id, schoolname, district,
              school_first_code, school_last_code,
              madaris_first_code, madaris_last_code
         FROM users WHERE role = 'school' ORDER BY id`
    );
    res.json(r.rows);
  }
}));

// ============================================================
// APP SETTINGS
// ============================================================
app.get('/api/app-settings', asyncRoute(async (_req, res) => {
  const r = await q('SELECT key, value, updatedat FROM app_settings ORDER BY key');
  res.json({ settings: r.rows });
}));
app.get('/api/app-settings/:key', asyncRoute(async (req, res) => {
  const r = await q('SELECT key, value, updatedat FROM app_settings WHERE key=$1', [req.params.key]);
  if (!r.rows[0]) return res.status(404).json({ error: 'یافت نشد' });
  res.json({ setting: r.rows[0] });
}));
app.put('/api/app-settings/:key', authRequired, adminOnly, asyncRoute(async (req, res) => {
  const { value } = req.body || {};
  if (value === undefined) return res.status(400).json({ error: 'value الزامی است' });
  const r = await q(
    `INSERT INTO app_settings (key, value, updatedat)
     VALUES ($1,$2,NOW())
     ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updatedat=NOW()
     RETURNING key, value, updatedat`,
    [req.params.key, String(value)]
  );
  res.json({ setting: r.rows[0] });
}));

// ============================================================
// SCHOOL SETTINGS
// ============================================================
const SCHOOL_FIELDS = ['schoolname'];

app.get('/api/school-settings', authRequired, asyncRoute(async (req, res) => {
  const r = await q('SELECT * FROM school_settings WHERE userid=$1 ORDER BY id', [req.user.id]);
  res.json({ settings: r.rows });
}));
app.post('/api/school-settings', authRequired, asyncRoute(async (req, res) => {
  const b = req.body || {};
  const cols = ['userid', ...SCHOOL_FIELDS];
  const vals = [req.user.id, ...SCHOOL_FIELDS.map(f => txt(b[f]))];
  const ph = cols.map((_, i) => `$${i + 1}`).join(',');
  const r = await q(
    `INSERT INTO school_settings (${cols.join(',')}) VALUES (${ph}) RETURNING *`,
    vals
  );
  res.status(201).json({ setting: r.rows[0] });
}));
app.put('/api/school-settings/:id', authRequired, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const b = req.body || {};
  const updates = [];
  const params = [];
  for (const f of SCHOOL_FIELDS) {
    if (b[f] === undefined) continue;
    params.push(txt(b[f]));
    updates.push(`${f}=$${params.length}`);
  }
  if (!updates.length) return res.status(400).json({ error: 'چیزی برای به‌روزرسانی نیست' });
  params.push(id);
  params.push(req.user.role === 'admin' ? null : req.user.id);
  const r = await q(
    `UPDATE school_settings SET ${updates.join(',')}
      WHERE id=$${params.length - 1}
        AND ($${params.length}::int IS NULL OR userid=$${params.length})
      RETURNING *`,
    params
  );
  if (!r.rows[0]) return res.status(404).json({ error: 'یافت نشد' });
  res.json({ setting: r.rows[0] });
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
  res.json(r.rows);
}));
app.get('/api/records/:id', authRequired, asyncRoute(async (req, res) => {
  const r = await q('SELECT * FROM records WHERE id=$1', [Number(req.params.id)]);
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
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [
      req.user.role === 'admin' && b.userid ? Number(b.userid) : req.user.id,
      txt(b.schoolname), txt(b.district),
      b.data === undefined || b.data === null ? null : (typeof b.data === 'string' ? b.data : JSON.stringify(b.data)),
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
  const editAllowed = b.editAllowed !== undefined ? b.editAllowed : b.editallowed;
  const r = await q(
    `UPDATE records SET
       schoolname  = COALESCE($2, schoolname),
       district    = COALESCE($3, district),
       data        = COALESCE($4, data),
       status      = COALESCE($5, status),
       editallowed = COALESCE($6, editallowed),
       updatedat   = NOW()
     WHERE id=$1 RETURNING *`,
    [
      id,
      txt(b.schoolname), txt(b.district),
      b.data === undefined ? null : (b.data === null ? null : (typeof b.data === 'string' ? b.data : JSON.stringify(b.data))),
      txt(b.status),
      editAllowed === undefined ? null : num(editAllowed)
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
// APPROVE RECORD
// ============================================================
app.post('/api/records/:id/approve', authRequired, adminOnly, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const r = await q(
    `UPDATE records SET status='approved', updatedat=NOW() WHERE id=$1 RETURNING *`,
    [id]
  );
  if (!r.rows[0]) return res.status(404).json({ error: 'یافت نشد' });
  res.json({ success: true, record: r.rows[0] });
}));

// ============================================================
// SALARIES
// ============================================================
const SALARY_TEXT_COLS = ['bank_number','appointment_letter','first_name','last_name','father_name','job_title','job_code','attendance','status'];
const SALARY_NUM_COLS = [
  'base_salary','other_base','professional','other_professional',
  'food','other_food','allowance','other_allowance','other_increase','total_entitlement',
  'absence','tax','other_tax','tax_10','deductions','other_deductions',
  'total_deductions','net_pay'
];

app.get('/api/salaries', authRequired, asyncRoute(async (req, res) => {
  const { year, month } = req.query;
  const isAdmin = req.user.role === 'admin';
  const params = []; const conds = [];
  if (!isAdmin) { params.push(req.user.id); conds.push(`userid=$${params.length}`); }
  if (year)  { params.push(String(year));  conds.push(`year=$${params.length}`); }
  if (month) { params.push(String(month)); conds.push(`month=$${params.length}`); }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  const r = await q(`SELECT * FROM salaries ${where} ORDER BY createdat DESC LIMIT 1000`, params);
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

  const cols = ['record_id','userid','schoolname','district','year','month',
                ...SALARY_TEXT_COLS, ...SALARY_NUM_COLS];
  const vals = [
    Number(b.record_id),
    req.user.role === 'admin' && b.userid ? Number(b.userid) : req.user.id,
    txt(b.schoolname), txt(b.district),
    String(b.year), String(b.month),
    ...SALARY_TEXT_COLS.map(c => c === 'status' ? (b.status || 'draft') : txt(b[c])),
    ...SALARY_NUM_COLS.map(c => num(b[c], 0))
  ];
  const ph = cols.map((_, i) => `$${i + 1}`).join(',');
  const r = await q(
    `INSERT INTO salaries (${cols.join(',')}) VALUES (${ph}) RETURNING *`,
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
  const updates = []; const params = [];
  for (const c of [...SALARY_TEXT_COLS, ...SALARY_NUM_COLS]) {
    if (b[c] === undefined) continue;
    params.push(SALARY_TEXT_COLS.includes(c) ? txt(b[c]) : num(b[c], 0));
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
// ATTENDANCE
// ============================================================
const ATT_NUM_COLS = ['present','absent','vacation','sick','essential','maternity',
  'service_center','service_province','hajj','holidays','other','total_days'];

app.get('/api/attendance/:salary_id', authRequired, asyncRoute(async (req, res) => {
  const r = await q('SELECT * FROM attendance WHERE salary_id=$1', [Number(req.params.salary_id)]);
  res.json({ attendance: r.rows[0] || null });
}));
app.post('/api/attendance', authRequired, asyncRoute(async (req, res) => {
  const b = req.body || {};
  if (!b.salary_id) return res.status(400).json({ error: 'salary_id الزامی است' });
  const cols = ['salary_id', ...ATT_NUM_COLS];
  const vals = [Number(b.salary_id), ...ATT_NUM_COLS.map(c => num(b[c], 0))];
  const ph = cols.map((_, i) => `$${i + 1}`).join(',');
  const r = await q(`INSERT INTO attendance (${cols.join(',')}) VALUES (${ph}) RETURNING *`, vals);
  res.status(201).json({ attendance: r.rows[0] });
}));
app.put('/api/attendance/:id', authRequired, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const b = req.body || {};
  const updates = []; const params = [];
  for (const c of ATT_NUM_COLS) {
    if (b[c] === undefined) continue;
    params.push(num(b[c], 0));
    updates.push(`${c}=$${params.length}`);
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
app.delete('/api/attendance/:id', authRequired, asyncRoute(async (req, res) => {
  const r = await q('DELETE FROM attendance WHERE id=$1 RETURNING id', [Number(req.params.id)]);
  if (!r.rows[0]) return res.status(404).json({ error: 'یافت نشد' });
  res.json({ success: true });
}));

// ============================================================
// EVALUATIONS
// ============================================================
const EVAL_TEXT = [
  'schoolname','district','first_name','last_name','father_name','grandfather_name',
  'job_code','employment_type','birth_year','service_duration','degree','gender',
  'job_title','appointment_date','eval_date_prev','bust','grade','eval_date','eval_result','remarks'
];

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
app.post('/api/evaluations', authRequired, asyncRoute(async (req, res) => {
  const b = req.body || {};
  if (!b.record_id || !b.eval_date || b.eval_score === undefined || !b.eval_result)
    return res.status(400).json({ error: 'record_id, eval_date, eval_score, eval_result الزامی است' });

  const cols = ['record_id','userid','eval_score', ...EVAL_TEXT];
  const vals = [
    Number(b.record_id),
    req.user.role === 'admin' && b.userid ? Number(b.userid) : req.user.id,
    Number(b.eval_score),
    ...EVAL_TEXT.map(c => txt(b[c]))
  ];
  const ph = cols.map((_, i) => `$${i + 1}`).join(',');
  const r = await q(`INSERT INTO evaluations (${cols.join(',')}) VALUES (${ph}) RETURNING *`, vals);
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
  const updates = []; const params = [];
  if (b.eval_score !== undefined) { params.push(Number(b.eval_score)); updates.push(`eval_score=$${params.length}`); }
  for (const c of EVAL_TEXT) {
    if (b[c] === undefined) continue;
    params.push(txt(b[c]));
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
// EVALUATION PERMISSION
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
  const r = await q('INSERT INTO evaluation_permission (allowed) VALUES ($1) RETURNING *', [allowed]);
  res.json({ permission: r.rows[0] });
}));

// ============================================================
// TASHKEEL
// ============================================================
app.get('/api/tashkeel', authRequired, asyncRoute(async (req, res) => {
  const { section, place, amariat, q: search, mine } = req.query;
  const isAdmin = req.user.role === 'admin';
  const conds = []; const params = [];

  if (!isAdmin || mine === '1') {
    params.push(req.user.id);
    conds.push(`userid = $${params.length}`);
  }
  if (section)  { params.push(String(section));  conds.push(`section = $${params.length}`); }
  if (place)    { params.push(String(place));    conds.push(`place = $${params.length}`); }
  if (amariat)  { params.push(String(amariat));  conds.push(`amariat = $${params.length}`); }
  if (search) {
    params.push(`%${String(search).trim()}%`);
    conds.push(`(title ILIKE $${params.length} OR place ILIKE $${params.length} OR code ILIKE $${params.length})`);
  }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  const r = await q(
    `SELECT id, userid, pub, priv, title, place, code, section, amariat, created_at
       FROM tashkeel
       ${where}
       ORDER BY section, place,
                NULLIF(priv,'')::int NULLS LAST,
                NULLIF(pub,'')::int
       LIMIT 5000`,
    params
  );
  res.json({ tashkeel: r.rows, count: r.rows.length });
}));

app.get('/api/tashkeel/:id', authRequired, asyncRoute(async (req, res) => {
  const r = await q('SELECT * FROM tashkeel WHERE id=$1', [Number(req.params.id)]);
  const t = r.rows[0];
  if (!t) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role !== 'admin' && t.userid !== req.user.id)
    return res.status(403).json({ error: 'دسترسی ندارید' });
  res.json({ tashkeel: t });
}));

app.post('/api/tashkeel', authRequired, asyncRoute(async (req, res) => {
  const b = req.body || {};
  if (!b.title || !b.place || !b.code)
    return res.status(400).json({ error: 'title, place, code الزامی است' });
  const owner = req.user.role === 'admin' && b.userid ? Number(b.userid) : req.user.id;
  const r = await q(
    `INSERT INTO tashkeel (userid, pub, priv, title, place, code, section, amariat)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [
      owner, txt(b.pub), txt(b.priv),
      String(b.title), String(b.place), String(b.code),
      b.section || 'amariat', txt(b.amariat)
    ]
  );
  res.status(201).json({ tashkeel: r.rows[0] });
}));

app.put('/api/tashkeel/:id', authRequired, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const r0 = await q('SELECT * FROM tashkeel WHERE id=$1', [id]);
  const t = r0.rows[0];
  if (!t) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role !== 'admin' && t.userid !== req.user.id)
    return res.status(403).json({ error: 'دسترسی ندارید' });

  const b = req.body || {};
  const r = await q(
    `UPDATE tashkeel SET
       pub = COALESCE($2, pub),
       priv = COALESCE($3, priv),
       title = COALESCE($4, title),
       place = COALESCE($5, place),
       code = COALESCE($6, code),
       section = COALESCE($7, section),
       amariat = COALESCE($8, amariat)
     WHERE id=$1 RETURNING *`,
    [id, txt(b.pub), txt(b.priv), txt(b.title), txt(b.place), txt(b.code), txt(b.section), txt(b.amariat)]
  );
  res.json({ tashkeel: r.rows[0] });
}));

app.delete('/api/tashkeel/:id', authRequired, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const r0 = await q('SELECT * FROM tashkeel WHERE id=$1', [id]);
  const t = r0.rows[0];
  if (!t) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role !== 'admin' && t.userid !== req.user.id)
    return res.status(403).json({ error: 'دسترسی ندارید' });
  await q('DELETE FROM tashkeel WHERE id=$1', [id]);
  res.json({ success: true });
}));

// import گروهی (فقط ادمین)
app.post('/api/tashkeel/import', authRequired, adminOnly, asyncRoute(async (req, res) => {
  const { records, ownerUserId } = req.body || {};
  if (!Array.isArray(records) || records.length === 0)
    return res.status(400).json({ error: 'records آرایه الزامی است' });

  const owner = ownerUserId ? Number(ownerUserId) : null;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let inserted = 0;
    for (const r of records) {
      if (!r.title || !r.place || !r.code) continue;
      await client.query(
        `INSERT INTO tashkeel (userid, pub, priv, title, place, code, section, amariat)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [
          owner, txt(r.pub), txt(r.priv),
          String(r.title), String(r.place), String(r.code),
          r.section || 'amariat', txt(r.amariat)
        ]
      );
      inserted++;
    }
    await client.query('COMMIT');
    res.json({ success: true, inserted });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}));

// ============================================================
// SEED TASHKEEL — یک‌بار برای پر کردن tashkeel از tashkeel-data.js
// ============================================================
app.post('/api/tashkeel/seed', authRequired, adminOnly, asyncRoute(async (req, res) => {
  let buildTashkeelRecords;
  try {
    ({ buildTashkeelRecords } = require('./tashkeel-data'));
  } catch (e) {
    return res.status(500).json({
      error: 'فایل tashkeel-data.js در سرور پیدا نشد',
      detail: e.message
    });
  }
  if (typeof buildTashkeelRecords !== 'function') {
    return res.status(500).json({ error: 'buildTashkeelRecords در tashkeel-data.js نیست' });
  }

  const records = buildTashkeelRecords();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let inserted = 0;
    let skipped = 0;
    for (const r of records) {
   const exists = await client.query('SELECT 1 FROM tashkeel WHERE code=$1 AND section=$2', [r.code, r.section]);
      if (exists.rows.length) { skipped++; continue; }
      await client.query(
        `INSERT INTO tashkeel (userid, pub, priv, title, place, code, section, amariat)
         VALUES (NULL,$1,$2,$3,$4,$5,$6,$7)`,
        [
          r.pub === null || r.pub === undefined ? null : String(r.pub),
          r.priv === null || r.priv === undefined ? null : String(r.priv),
          String(r.title), String(r.place), String(r.code),
          r.section || 'amariat', r.amariat || null
        ]
      );
      inserted++;
    }
    await client.query('COMMIT');
    res.json({ success: true, inserted, skipped, total_in_file: records.length });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}));

// آمار
app.get('/api/tashkeel/stats/summary', authRequired, asyncRoute(async (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const params = []; let where = '';
  if (!isAdmin) { params.push(req.user.id); where = 'WHERE userid = $1'; }

  const bySection = await q(
    `SELECT section, COUNT(*)::int AS count FROM tashkeel ${where} GROUP BY section ORDER BY section`,
    params
  );
  const byAmariat = await q(
    `SELECT amariat, COUNT(*)::int AS count FROM tashkeel ${where} GROUP BY amariat ORDER BY count DESC`,
    params
  );
  const byPlace = await q(
    `SELECT place, COUNT(*)::int AS count FROM tashkeel ${where} GROUP BY place ORDER BY count DESC LIMIT 100`,
    params
  );
  const total = await q(`SELECT COUNT(*)::int AS c FROM tashkeel ${where}`, params);

  res.json({ total: total.rows[0].c, by_section: bySection.rows, by_amariat: byAmariat.rows, by_place: byPlace.rows });
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
