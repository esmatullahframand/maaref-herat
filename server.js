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

console.log('═══════════════════════════════════════');
console.log('🔐 Server V23.0 starting...');
console.log('═══════════════════════════════════════');

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
    await client.query(`CREATE TABLE IF NOT EXISTS school_settings_new (id SERIAL PRIMARY KEY, userid INTEGER UNIQUE NOT NULL, schoolname TEXT, district TEXT, time_type TEXT DEFAULT 'یک تایم', academic_member TEXT, budget_status TEXT DEFAULT 'عادی', extra_bust_count INTEGER DEFAULT 0, extra_bust_field TEXT, lack_bust_count INTEGER DEFAULT 0, lack_bust_field TEXT, branches_data TEXT, createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updatedat TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    await client.query(`CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updatedat TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    await client.query(`INSERT INTO app_settings (key, value) VALUES ('evaluation_allowed', 'false') ON CONFLICT (key) DO NOTHING;`);
    await client.query(`CREATE TABLE IF NOT EXISTS evaluations (id SERIAL PRIMARY KEY, record_id INTEGER NOT NULL, userid INTEGER NOT NULL, schoolname TEXT, district TEXT, first_name TEXT, last_name TEXT, father_name TEXT, grandfather_name TEXT, job_code TEXT, employment_type TEXT, birth_year TEXT, service_duration TEXT, degree TEXT, gender TEXT, job_title TEXT, appointment_date TEXT, eval_date_prev TEXT, bust TEXT, grade TEXT, eval_date TEXT NOT NULL, eval_score INTEGER NOT NULL, eval_result TEXT NOT NULL, createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    await client.query(`CREATE TABLE IF NOT EXISTS salaries (id SERIAL PRIMARY KEY, record_id INTEGER NOT NULL, userid INTEGER NOT NULL, schoolname TEXT, district TEXT, year TEXT NOT NULL, month TEXT NOT NULL, bank_number TEXT, appointment_letter TEXT, base_salary REAL DEFAULT 0, other_base REAL DEFAULT 0, professional REAL DEFAULT 0, other_professional REAL DEFAULT 0, food REAL DEFAULT 0, other_food REAL DEFAULT 0, allowance REAL DEFAULT 0, other_allowance REAL DEFAULT 0, other_increase REAL DEFAULT 0, total_entitlement REAL DEFAULT 0, absence REAL DEFAULT 0, tax REAL DEFAULT 0, other_tax REAL DEFAULT 0, tax_10 REAL DEFAULT 0, deductions REAL DEFAULT 0, other_deductions REAL DEFAULT 0, total_deductions REAL DEFAULT 0, net_pay REAL DEFAULT 0, status TEXT DEFAULT 'draft', createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updatedat TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(record_id, year, month));`);
    await client.query(`CREATE TABLE IF NOT EXISTS attendance (id SERIAL PRIMARY KEY, salary_id INTEGER NOT NULL UNIQUE, present REAL DEFAULT 0, absent REAL DEFAULT 0, vacation REAL DEFAULT 0, sick REAL DEFAULT 0, essential REAL DEFAULT 0, maternity REAL DEFAULT 0, service_center REAL DEFAULT 0, service_province REAL DEFAULT 0, hajj REAL DEFAULT 0, holidays REAL DEFAULT 0, other REAL DEFAULT 0, total_days REAL DEFAULT 0, createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updatedat TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
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
    if (req.user.role !== 'school') return res.status(403).json({ error: 'فقط مکتب دسترسی دارد' });
    const result = await pool.query('SELECT * FROM school_settings_new WHERE userid = $1', [req.user.id]);
    if (result.rows.length === 0) return res.json({ exists: false, settings: null });
    
    const row = result.rows[0];
    let branchesData = {};
    try { branchesData = JSON.parse(row.branches_data || '{}'); } catch (e) {}
    
    const settings = { ...row, ...branchesData };
    res.json({ exists: true, settings });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.post('/api/school-settings', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'school') return res.status(403).json({ error: 'فقط مکتب دسترسی دارد' });
    const body = req.body || {};
    
    const academicMember = String(body.academicMember || '').trim();
    if (!academicMember) return res.status(400).json({ error: 'نام عضو علمی الزامی است' });
    
    const schoolName = req.user.schoolname || '';
    const district = req.user.district || '';
    
    const branchesData = {
      branchesF13: Number(body.branchesF13) || 0,
      branchesF46: Number(body.branchesF46) || 0,
      branchesF79: Number(body.branchesF79) || 0,
      branchesF1012: Number(body.branchesF1012) || 0,
      branchesM13: Number(body.branchesM13) || 0,
      branchesM46: Number(body.branchesM46) || 0,
      branchesM79: Number(body.branchesM79) || 0,
      branchesM1012: Number(body.branchesM1012) || 0,
      branchesX13: Number(body.branchesX13) || 0,
      branchesX46: Number(body.branchesX46) || 0,
      branchesX79: Number(body.branchesX79) || 0,
      branchesX1012: Number(body.branchesX1012) || 0,
      branchesTotal: Number(body.branchesTotal) || 0,
      totalInFemale: Number(body.totalInFemale) || 0,
      totalInMale: Number(body.totalInMale) || 0,
      totalPresentFemale: Number(body.totalPresentFemale) || 0,
      totalPresentMale: Number(body.totalPresentMale) || 0,
      c1_in_f: Number(body.c1_in_f) || 0, c1_in_m: Number(body.c1_in_m) || 0, c1_pr_f: Number(body.c1_pr_f) || 0, c1_pr_m: Number(body.c1_pr_m) || 0,
      c2_in_f: Number(body.c2_in_f) || 0, c2_in_m: Number(body.c2_in_m) || 0, c2_pr_f: Number(body.c2_pr_f) || 0, c2_pr_m: Number(body.c2_pr_m) || 0,
      c3_in_f: Number(body.c3_in_f) || 0, c3_in_m: Number(body.c3_in_m) || 0, c3_pr_f: Number(body.c3_pr_f) || 0, c3_pr_m: Number(body.c3_pr_m) || 0,
      c4_in_f: Number(body.c4_in_f) || 0, c4_in_m: Number(body.c4_in_m) || 0, c4_pr_f: Number(body.c4_pr_f) || 0, c4_pr_m: Number(body.c4_pr_m) || 0,
      c5_in_f: Number(body.c5_in_f) || 0, c5_in_m: Number(body.c5_in_m) || 0, c5_pr_f: Number(body.c5_pr_f) || 0, c5_pr_m: Number(body.c5_pr_m) || 0,
      c6_in_f: Number(body.c6_in_f) || 0, c6_in_m: Number(body.c6_in_m) || 0, c6_pr_f: Number(body.c6_pr_f) || 0, c6_pr_m: Number(body.c6_pr_m) || 0,
      c7_in_f: Number(body.c7_in_f) || 0, c7_in_m: Number(body.c7_in_m) || 0, c7_pr_f: Number(body.c7_pr_f) || 0, c7_pr_m: Number(body.c7_pr_m) || 0,
      c8_in_f: Number(body.c8_in_f) || 0, c8_in_m: Number(body.c8_in_m) || 0, c8_pr_f: Number(body.c8_pr_f) || 0, c8_pr_m: Number(body.c8_pr_m) || 0,
      c9_in_f: Number(body.c9_in_f) || 0, c9_in_m: Number(body.c9_in_m) || 0, c9_pr_f: Number(body.c9_pr_f) || 0, c9_pr_m: Number(body.c9_pr_m) || 0,
      c10_in_f: Number(body.c10_in_f) || 0, c10_in_m: Number(body.c10_in_m) || 0, c10_pr_f: Number(body.c10_pr_f) || 0, c10_pr_m: Number(body.c10_pr_m) || 0,
      c11_in_f: Number(body.c11_in_f) || 0, c11_in_m: Number(body.c11_in_m) || 0, c11_pr_f: Number(body.c11_pr_f) || 0, c11_pr_m: Number(body.c11_pr_m) || 0,
      c12_in_f: Number(body.c12_in_f) || 0, c12_in_m: Number(body.c12_in_m) || 0, c12_pr_f: Number(body.c12_pr_f) || 0, c12_pr_m: Number(body.c12_pr_m) || 0
    };

    const check = await pool.query('SELECT id FROM school_settings_new WHERE userid = $1', [req.user.id]);
    
    if (check.rows.length > 0) {
      await pool.query(
        `UPDATE school_settings_new SET schoolname=$1, district=$2, time_type=$3, academic_member=$4, budget_status=$5, extra_bust_count=$6, extra_bust_field=$7, lack_bust_count=$8, lack_bust_field=$9, branches_data=$10, updatedat=CURRENT_TIMESTAMP WHERE userid=$11`,
        [schoolName, district, body.timeType || 'یک تایم', academicMember, body.budgetStatus || 'عادی', Number(body.extraBustCount) || 0, body.extraBustField || '', Number(body.lackBustCount) || 0, body.lackBustField || '', JSON.stringify(branchesData), req.user.id]
      );
    } else {
      await pool.query(
        `INSERT INTO school_settings_new (userid, schoolname, district, time_type, academic_member, budget_status, extra_bust_count, extra_bust_field, lack_bust_count, lack_bust_field, branches_data) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [req.user.id, schoolName, district, body.timeType || 'یک تایم', academicMember, body.budgetStatus || 'عادی', Number(body.extraBustCount) || 0, body.extraBustField || '', Number(body.lackBustCount) || 0, body.lackBustField || '', JSON.stringify(branchesData)]
      );
    }
    res.json({ ok: true });
  } catch (err) { 
    console.error('POST /api/school-settings error:', err.message);
    res.status(500).json({ error: 'خطا در ذخیره تنظیمات: ' + err.message }); 
  }
});
app.get('*', (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('═══════════════════════════════════════');
  console.log('🚀 Server live on port ' + PORT);
  console.log('═══════════════════════════════════════');
});
