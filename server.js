const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'maaref-secret-key-12345';
console.log("✅✅✅ VERSION 200 IS RUNNING ✅✅✅");

app.set('trust proxy', 1);
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false, checkServerIdentity: () => undefined },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'admin123';

async function initDB() {
  try {
    const client = await pool.connect();
    await client.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL, schoolname TEXT, district TEXT, createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    await client.query(`CREATE TABLE IF NOT EXISTS records (id SERIAL PRIMARY KEY, userid INTEGER, schoolname TEXT, district TEXT, data TEXT, status TEXT DEFAULT 'pending', createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    await client.query(`CREATE TABLE IF NOT EXISTS login_attempts (id SERIAL PRIMARY KEY, ip TEXT NOT NULL, username TEXT, success BOOLEAN DEFAULT FALSE, createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    await client.query(`CREATE TABLE IF NOT EXISTS school_settings (id SERIAL PRIMARY KEY, userid INTEGER UNIQUE NOT NULL, schoolname TEXT, district TEXT, time_type TEXT DEFAULT 'یک تایم', academic_member TEXT, branches_total INTEGER DEFAULT 0, budget_status TEXT DEFAULT 'عادی', extra_bust_count INTEGER DEFAULT 0, extra_bust_field TEXT, lack_bust_count INTEGER DEFAULT 0, lack_bust_field TEXT, createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updatedat TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    await client.query(`CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updatedat TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    await client.query(`INSERT INTO app_settings (key, value) VALUES ('evaluation_allowed', 'false') ON CONFLICT (key) DO NOTHING;`);
    await client.query(`CREATE TABLE IF NOT EXISTS evaluations (id SERIAL PRIMARY KEY, record_id INTEGER NOT NULL, userid INTEGER NOT NULL, schoolname TEXT, district TEXT, first_name TEXT, last_name TEXT, father_name TEXT, grandfather_name TEXT, job_code TEXT, employment_type TEXT, birth_year TEXT, service_duration TEXT, degree TEXT, gender TEXT, job_title TEXT, appointment_date TEXT, eval_date_prev TEXT, bust TEXT, grade TEXT, eval_date TEXT NOT NULL, eval_score INTEGER NOT NULL, eval_result TEXT NOT NULL, createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    await client.query(`CREATE TABLE IF NOT EXISTS salaries (id SERIAL PRIMARY KEY, record_id INTEGER NOT NULL, userid INTEGER NOT NULL, schoolname TEXT, district TEXT, year TEXT NOT NULL, month TEXT NOT NULL, bank_number TEXT, appointment_letter TEXT, base_salary REAL DEFAULT 0, other_base REAL DEFAULT 0, professional REAL DEFAULT 0, other_professional REAL DEFAULT 0, food REAL DEFAULT 0, other_food REAL DEFAULT 0, allowance REAL DEFAULT 0, other_allowance REAL DEFAULT 0, other_increase REAL DEFAULT 0, total_entitlement REAL DEFAULT 0, absence REAL DEFAULT 0, tax REAL DEFAULT 0, other_tax REAL DEFAULT 0, tax_10 REAL DEFAULT 0, deductions REAL DEFAULT 0, other_deductions REAL DEFAULT 0, total_deductions REAL DEFAULT 0, net_pay REAL DEFAULT 0, status TEXT DEFAULT 'draft', createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updatedat TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(record_id, year, month));`);
    await client.query(`CREATE TABLE IF NOT EXISTS attendance (id SERIAL PRIMARY KEY, salary_id INTEGER NOT NULL UNIQUE, present REAL DEFAULT 0, absent REAL DEFAULT 0, vacation REAL DEFAULT 0, sick REAL DEFAULT 0, essential REAL DEFAULT 0, maternity REAL DEFAULT 0, service_center REAL DEFAULT 0, service_province REAL DEFAULT 0, hajj REAL DEFAULT 0, holidays REAL DEFAULT 0, other REAL DEFAULT 0, total_days REAL DEFAULT 0, createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updatedat TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    await client.query(`ALTER TABLE school_settings ADD COLUMN IF NOT EXISTS branches_f_1_3 INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS branches_f_4_6 INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS branches_f_7_9 INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS branches_f_10_12 INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS branches_m_1_3 INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS branches_m_4_6 INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS branches_m_7_9 INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS branches_m_10_12 INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS branches_x_1_3 INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS branches_x_4_6 INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS branches_x_7_9 INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS branches_x_10_12 INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS total_in_female INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS total_in_male INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS total_present_female INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS total_present_male INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c1_in_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c1_in_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c1_pr_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c1_pr_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c2_in_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c2_in_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c2_pr_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c2_pr_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c3_in_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c3_in_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c3_pr_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c3_pr_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c4_in_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c4_in_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c4_pr_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c4_pr_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c5_in_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c5_in_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c5_pr_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c5_pr_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c6_in_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c6_in_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c6_pr_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c6_pr_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c7_in_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c7_in_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c7_pr_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c7_pr_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c8_in_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c8_in_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c8_pr_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c8_pr_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c9_in_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c9_in_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c9_pr_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c9_pr_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c10_in_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c10_in_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c10_pr_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c10_pr_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c11_in_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c11_in_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c11_pr_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c11_pr_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c12_in_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c12_in_m INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c12_pr_f INTEGER DEFAULT 0, ADD COLUMN IF NOT EXISTS c12_pr_m INTEGER DEFAULT 0;`);
    client.release();
    console.log('✅ جداول دیتابیس آماده شدند.');
  } catch (err) { console.error('⚠️ خطا در اتصال اولیه به دیتابیس:', err.message); }
}
initDB();

app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => { res.header('Access-Control-Allow-Origin', req.headers.origin || '*'); res.header('Access-Control-Allow-Credentials', 'true'); res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization'); res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS'); if (req.method === 'OPTIONS') return res.sendStatus(200); next(); });

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: '❌ تعداد تلاش‌های شما بیش از حد مجاز است.' } });

function authRequired(req, res, next) {
  let token = req.cookies?.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'وارد نشده‌اید' });
  token = String(token).trim().replace(/^["']|["']$/g, '');
  try { const decoded = jwt.verify(token, JWT_SECRET); req.user = decoded; next(); } catch (e) { res.status(401).json({ error: 'توکن نامعتبر است' }); }
}

async function logLoginAttempt(ip, username, success) { try { await pool.query('INSERT INTO login_attempts (ip, username, success) VALUES ($1, $2, $3)', [ip || 'unknown', username || 'unknown', success]); } catch (e) { console.error('Log attempt error:', e.message); } }

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
      await logLoginAttempt(req.ip, username, true);
      const token = jwt.sign({ id: 0, username: 'admin', role: 'admin' }, JWT_SECRET, { expiresIn: '7d' });
      return res.json({ token, user: { id: 0, username: 'admin', role: 'admin', schoolname: 'ریاست معارف', district: 'مرکز هرات' }, redirect: '/admin-main.html' });
    }
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) { await logLoginAttempt(req.ip, username, false); return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است' }); }
    const user = result.rows[0];
    if (!bcrypt.compareSync(password, user.password)) { await logLoginAttempt(req.ip, username, false); return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است' }); }
    await logLoginAttempt(req.ip, username, true);
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, schoolname: user.schoolname || '', district: user.district || '' }, redirect: '/school-settings.html' });
  } catch (e) { res.status(500).json({ error: 'خطای سرور' }); }
});

app.get('/api/school-settings', authRequired, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM school_settings WHERE userid = $1', [req.user.id]);
    if (result.rows.length === 0) return res.json({ exists: false, settings: null });
    res.json({ exists: true, settings: result.rows[0] });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.post('/api/school-settings', authRequired, async (req, res) => {
  try {
    const body = req.body || {};
    const toNum = (val) => { if (val === null || val === undefined || val === '') return 0; const num = Number(val); return isNaN(num) ? 0 : num; };
    const academicMember = String(body.academicMember || '').trim();
    if (!academicMember) return res.status(400).json({ error: 'نام عضو علمی الزامی است' });
    const schoolName = req.user.schoolname || '';
    const district = req.user.district || '';
    const check = await pool.query('SELECT id FROM school_settings WHERE userid = $1', [req.user.id]);
    
    const columns = [
      'schoolname', 'district', 'academic_member',
      'branches_f_1_3', 'branches_f_4_6', 'branches_f_7_9', 'branches_f_10_12',
      'branches_m_1_3', 'branches_m_4_6', 'branches_m_7_9', 'branches_m_10_12',
      'branches_x_1_3', 'branches_x_4_6', 'branches_x_7_9', 'branches_x_10_12',
      'branches_total',
      'total_in_female', 'total_in_male', 'total_present_female', 'total_present_male',
      'c1_in_f', 'c1_in_m', 'c1_pr_f', 'c1_pr_m', 'c2_in_f', 'c2_in_m', 'c2_pr_f', 'c2_pr_m',
      'c3_in_f', 'c3_in_m', 'c3_pr_f', 'c3_pr_m', 'c4_in_f', 'c4_in_m', 'c4_pr_f', 'c4_pr_m',
      'c5_in_f', 'c5_in_m', 'c5_pr_f', 'c5_pr_m', 'c6_in_f', 'c6_in_m', 'c6_pr_f', 'c6_pr_m',
      'c7_in_f', 'c7_in_m', 'c7_pr_f', 'c7_pr_m', 'c8_in_f', 'c8_in_m', 'c8_pr_f', 'c8_pr_m',
      'c9_in_f', 'c9_in_m', 'c9_pr_f', 'c9_pr_m', 'c10_in_f', 'c10_in_m', 'c10_pr_f', 'c10_pr_m',
      'c11_in_f', 'c11_in_m', 'c11_pr_f', 'c11_pr_m', 'c12_in_f', 'c12_in_m', 'c12_pr_f', 'c12_pr_m',
      'budget_status', 'extra_bust_count', 'extra_bust_field', 'lack_bust_count', 'lack_bust_field'
    ];
    
    const values = [
      schoolName, district, academicMember,
      toNum(body.branchesF13), toNum(body.branchesF46), toNum(body.branchesF79), toNum(body.branchesF1012),
      toNum(body.branchesM13), toNum(body.branchesM46), toNum(body.branchesM79), toNum(body.branchesM1012),
      toNum(body.branchesX13), toNum(body.branchesX46), toNum(body.branchesX79), toNum(body.branchesX1012),
      toNum(body.branchesTotal),
      toNum(body.totalInFemale), toNum(body.totalInMale), toNum(body.totalPresentFemale), toNum(body.totalPresentMale),
      toNum(body.c1_in_f), toNum(body.c1_in_m), toNum(body.c1_pr_f), toNum(body.c1_pr_m),
      toNum(body.c2_in_f), toNum(body.c2_in_m), toNum(body.c2_pr_f), toNum(body.c2_pr_m),
      toNum(body.c3_in_f), toNum(body.c3_in_m), toNum(body.c3_pr_f), toNum(body.c3_pr_m),
      toNum(body.c4_in_f), toNum(body.c4_in_m), toNum(body.c4_pr_f), toNum(body.c4_pr_m),
      toNum(body.c5_in_f), toNum(body.c5_in_m), toNum(body.c5_pr_f), toNum(body.c5_pr_m),
      toNum(body.c6_in_f), toNum(body.c6_in_m), toNum(body.c6_pr_f), toNum(body.c6_pr_m),
      toNum(body.c7_in_f), toNum(body.c7_in_m), toNum(body.c7_pr_f), toNum(body.c7_pr_m),
      toNum(body.c8_in_f), toNum(body.c8_in_m), toNum(body.c8_pr_f), toNum(body.c8_pr_m),
      toNum(body.c9_in_f), toNum(body.c9_in_m), toNum(body.c9_pr_f), toNum(body.c9_pr_m),
      toNum(body.c10_in_f), toNum(body.c10_in_m), toNum(body.c10_pr_f), toNum(body.c10_pr_m),
      toNum(body.c11_in_f), toNum(body.c11_in_m), toNum(body.c11_pr_f), toNum(body.c11_pr_m),
      toNum(body.c12_in_f), toNum(body.c12_in_m), toNum(body.c12_pr_f), toNum(body.c12_pr_m),
      body.budgetStatus || 'عادی', toNum(body.extraBustCount), body.extraBustField || '', toNum(body.lackBustCount), body.lackBustField || ''
    ];
    
    if (check.rows.length > 0) {
      const setClauses = columns.map((col, i) => `${col} = $${i + 1}`).join(', ');
      await pool.query(`UPDATE school_settings SET ${setClauses}, updatedat = CURRENT_TIMESTAMP WHERE userid = $${columns.length + 1}`, [...values, req.user.id]);
    } else {
      const placeholders = columns.map((_, i) => `$${i + 1}`).join(', ');
      await pool.query(`INSERT INTO school_settings (userid, ${columns.join(', ')}) VALUES ($${columns.length + 1}, ${placeholders})`, [req.user.id, ...values]);
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطا در ذخیره تنظیمات: ' + err.message }); }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, '0.0.0.0', () => console.log('🚀 Server live on port ' + PORT));
