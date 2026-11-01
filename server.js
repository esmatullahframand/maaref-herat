const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET_CONSTANT = 'maaref-secret-key-12345';
const JWT_ALGORITHM = 'HS256';

console.log('═══════════════════════════════════════');
console.log('🔐 Server V22.0 starting (Ultimate Edition)...');
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

const JOB_TITLES = ['آمر', 'مدیر', 'مدیر اجرائیه', 'معلم', 'سر معلم', 'معلم همکار', 'معلم سپورت', 'معلم لابرانت', 'عضو علمی معلمان', 'عضو علمی مدرسین', 'عضو مسلکی امور مالی و کارکنان', 'عضو مسلکی نظارت احصاییه و گزارش', 'عضو مسلکی تاسیسات و ترمیمات', 'عضو مسلکی شوراها', 'کارکن خدماتی', 'معتمد جنسی (تحویلدار)', 'سایر'];
const NO_CODE_TITLES = [];
const SERVICE_TITLES = ['کارکن خدماتی', 'معتمد جنسی (تحویلدار)'];
const EDUCATION_EXEMPT_JOBS = ['کارکن خدماتی', 'معتمد جنسی (تحویلدار)', 'سایر'];
const MONTHS_SHAMSI = ['حمل', 'ثور', 'جوزا', 'سرطان', 'اسد', 'سنبله', 'میزان', 'عقرب', 'قوس', 'جدی', 'دلو', 'حوت'];
const JOBCODE_REGEX = /^27-\d{1,3}-\d{1,3}-\d{3,6}$/;
const ETAZKIRA_REGEX = /^\d+-\d+-\d+$/;
const PAPER_TAZKIRA_NUMERIC_REGEX = /^\d{1,20}$/;

async function initDB() {
  try {
    const client = await pool.connect();
    try {
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
      console.log('✅ جداول دیتابیس آماده شدند.');
    } finally { client.release(); }
  } catch (err) { console.error('⚠️ خطا در اتصال اولیه به دیتابیس:', err.message); }
}
initDB();

app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use((req, res, next) => { if (req.url.endsWith('.html') || req.url === '/' || req.url.startsWith('/?')) { res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private'); res.setHeader('Pragma', 'no-cache'); res.setHeader('Expires', '0'); } next(); });
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => { res.header('Access-Control-Allow-Origin', req.headers.origin || '*'); res.header('Access-Control-Allow-Credentials', 'true'); res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization'); res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS'); if (req.method === 'OPTIONS') return res.sendStatus(200); next(); });

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, validate: { xForwardedForHeader: false, trustProxy: false }, message: { error: '❌ تعداد تلاش‌های شما بیش از حد مجاز است.' } });

function authRequired(req, res, next) { let token = req.cookies?.token || req.headers.authorization?.replace('Bearer ', ''); if (!token && req.query.token) token = req.query.token; if (!token) return res.status(401).json({ error: 'وارد نشده‌اید' }); token = String(token).trim().replace(/^["']|["']$/g, ''); try { const decoded = jwt.verify(token, JWT_SECRET_CONSTANT, { algorithms: [JWT_ALGORITHM] }); req.user = decoded; next(); } catch (e) { res.status(401).json({ error: 'توکن نامعتبر است' }); } }

async function logLoginAttempt(ip, username, success) { try { await pool.query('INSERT INTO login_attempts (ip, username, success) VALUES ($1, $2, $3)', [ip || 'unknown', username || 'unknown', success]); } catch (e) { console.error('Log attempt error:', e.message); } }

function normalizeDigits(str) { if (!str) return ''; const p = '۰۱۲۳۴۵۶۷۸۹', a = '٠١٢٣٤٥٦٧٨٩'; return String(str).split('').map(ch => { const pi = p.indexOf(ch); if (pi !== -1) return pi; const ai = a.indexOf(ch); if (ai !== -1) return ai; return ch; }).join(''); }
function validateShamsiDateServer(dateStr, fieldName) { if (!dateStr) return null; const cleaned = normalizeDigits(dateStr).trim().replace(/[.\-]/g, '/'); const parts = cleaned.split('/').map(p => p.trim()); if (parts.length !== 3) return `${fieldName} باید فرمت YYYY/MM/DD داشته باشد`; const p1 = parseInt(parts[0]), p2 = parseInt(parts[1]), p3 = parseInt(parts[2]); if (isNaN(p1) || isNaN(p2) || isNaN(p3)) return `${fieldName} باید فقط شامل اعداد باشد`; let year, month, day; if (parts[0].length === 4 || (p1 >= 1300 && p1 <= 1450)) { year = p1; month = p2; day = p3; } else if (parts[2].length === 4 || (p3 >= 1300 && p3 <= 1450)) { year = p3; month = p2; day = p1; } else return `${fieldName}: سال باید بین ۱۳۰۰ تا ۱۴۵۰ باشد`; if (year < 1300 || year > 1450) return `${fieldName}: سال نامعتبر`; if (month < 1 || month > 12) return `${fieldName}: ماه نامعتبر`; let maxDay = 31; if (month >= 7 && month <= 11) maxDay = 30; if (month === 12) maxDay = 29; if (day < 1 || day > maxDay) return `${fieldName}: روز نامعتبر`; return null; }
function validateTazkiraServer(s) { if (!s) return null; const c = normalizeDigits(s).trim(); if (!ETAZKIRA_REGEX.test(c)) return 'فرمت تذکره الکترونیکی اشتباه است'; return null; }
function validatePaperTazkiraServer(s) { if (!s) return null; const c = normalizeDigits(s).trim().replace(/\s+/g, ''); if (!PAPER_TAZKIRA_NUMERIC_REGEX.test(c)) return 'فرمت تذکره کاغذی اشتباه است (فقط عدد)'; return null; }
function validateJobCodeServer(s) { if (!s) return null; const c = normalizeDigits(s).trim().replace(/\s+/g, ''); if (!JOBCODE_REGEX.test(c)) return 'فرمت کُد بست اشتباه است'; return null; }
function isValidJobCode(s) { if (!s) return false; const c = normalizeDigits(s).trim().replace(/\s+/g, ''); return JOBCODE_REGEX.test(c); }
function isNoCodeTitle(t) { return NO_CODE_TITLES.some(x => x === t); }
function isServiceOrSupport(t) { return SERVICE_TITLES.includes(t); }
function isEducationExemptJob(t) { return EDUCATION_EXEMPT_JOBS.includes(String(t || '').trim()); }

async function checkJobCodeExact(jobCode, excludeRecordId = null) {
  if (!jobCode) return { exists: false };
  try {
    const normalizedCode = normalizeDigits(jobCode).trim().replace(/\s+/g, '');
    let sql = `SELECT r.id, r.userid, r.data, COALESCE(NULLIF(r.schoolname, ''), u.schoolname) AS schoolname, COALESCE(NULLIF(r.district, ''), u.district) AS district FROM records r LEFT JOIN users u ON u.id = r.userid WHERE (CAST(r.data AS JSON)->>'jobCode') = $1`;
    const params = [normalizedCode];
    if (excludeRecordId) { params.push(excludeRecordId); sql += ` AND r.id <> $${params.length}`; }
    sql += ' LIMIT 1';
    const result = await pool.query(sql, params);
    if (result.rows.length === 0) return { exists: false };
    const row = result.rows[0]; let info = {}; try { info = JSON.parse(row.data || '{}'); } catch (e) {}
    return { exists: true, recordId: row.id, userid: row.userid, schoolname: row.schoolname || 'نامشخص', district: row.district || '', employeeName: `${info.firstName || ''} ${info.lastName || ''}`.trim() || 'نامشخص' };
  } catch (err) { return { exists: false }; }
}
async function checkETazkiraExact(eTazkira, excludeRecordId = null) {
  if (!eTazkira) return { exists: false };
  try {
    const cleaned = normalizeDigits(eTazkira).trim().replace(/\s+/g, '');
    let sql = `SELECT r.id, r.userid, r.data, COALESCE(NULLIF(r.schoolname, ''), u.schoolname) AS schoolname, COALESCE(NULLIF(r.district, ''), u.district) AS district FROM records r LEFT JOIN users u ON u.id = r.userid WHERE (CAST(r.data AS JSON)->>'eTazkira') = $1`;
    const params = [cleaned];
    if (excludeRecordId) { params.push(excludeRecordId); sql += ` AND r.id <> $${params.length}`; }
    sql += ' LIMIT 1';
    const result = await pool.query(sql, params);
    if (result.rows.length === 0) return { exists: false };
    const row = result.rows[0]; let info = {}; try { info = JSON.parse(row.data || '{}'); } catch (e) {}
    return { exists: true, recordId: row.id, userid: row.userid, schoolname: row.schoolname || 'نامشخص', district: row.district || '', employeeName: `${info.firstName || ''} ${info.lastName || ''}`.trim() || 'نامشخص' };
  } catch (err) { return { exists: false }; }
}
async function checkPaperTazkiraExact(tazkiraCode, excludeRecordId = null) {
  if (!tazkiraCode) return { exists: false };
  try {
    const cleaned = normalizeDigits(tazkiraCode).trim().replace(/\s+/g, '');
    let sql = `SELECT r.id, r.userid, r.data, COALESCE(NULLIF(r.schoolname, ''), u.schoolname) AS schoolname, COALESCE(NULLIF(r.district, ''), u.district) AS district FROM records r LEFT JOIN users u ON u.id = r.userid WHERE (CAST(r.data AS JSON)->>'paperTazkira') = $1`;
    const params = [cleaned];
    if (excludeRecordId) { params.push(excludeRecordId); sql += ` AND r.id <> $${params.length}`; }
    sql += ' LIMIT 1';
    const result = await pool.query(sql, params);
    if (result.rows.length === 0) return { exists: false };
    const row = result.rows[0]; let info = {}; try { info = JSON.parse(row.data || '{}'); } catch (e) {}
    return { exists: true, recordId: row.id, userid: row.userid, schoolname: row.schoolname || 'نامشخص', district: row.district || '', employeeName: `${info.firstName || ''} ${info.lastName || ''}`.trim() || 'نامشخص' };
  } catch (err) { return { exists: false }; }
}
function buildDuplicateResponse(kind, dup, currentUserId) {
  const isSameSchool = String(dup.userid) === String(currentUserId);
  const label = kind === 'jobcode' ? 'کد بست' : kind === 'etazkira' ? 'تذکره الکترونیکی' : 'کد تذکره کاغذی';
  return { error: `${label} تکراری است`, code: kind === 'jobcode' ? 'DUPLICATE_JOBCODE' : kind === 'etazkira' ? 'DUPLICATE_ETAZKIRA' : 'DUPLICATE_TAZKIRA', isSameSchool, schoolname: isSameSchool ? null : dup.schoolname, district: isSameSchool ? null : dup.district, employeeName: isSameSchool ? dup.employeeName : null, recordId: dup.recordId };
}

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const clientIp = req.ip || 'unknown';
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'نام کاربری و رمز عبور الزامی است' });
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
      await logLoginAttempt(clientIp, username, true);
      const payload = { id: 0, username: 'admin', role: 'admin' };
      const token = jwt.sign(payload, JWT_SECRET_CONSTANT, { expiresIn: '7d', algorithm: JWT_ALGORITHM });
      return res.json({ token, user: { id: 0, username: 'admin', role: 'admin', schoolname: 'ریاست معارف', district: 'مرکز هرات' }, redirect: '/admin-main.html' });
    }
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) { await logLoginAttempt(clientIp, username, false); return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است' }); }
    const user = result.rows[0];
    if (!bcrypt.compareSync(password, user.password)) { await logLoginAttempt(clientIp, username, false); return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است' }); }
    await logLoginAttempt(clientIp, username, true);
    const payload = { id: user.id, username: user.username, role: user.role };
    const token = jwt.sign(payload, JWT_SECRET_CONSTANT, { expiresIn: '7d', algorithm: JWT_ALGORITHM });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, schoolname: user.schoolname || '', district: user.district || '' }, redirect: '/school-settings.html' });
  } catch (e) { res.status(500).json({ error: 'خطای سرور' }); }
});

app.get('/api/school-settings', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'school') return res.status(403).json({ error: 'فقط مکتب دسترسی دارد' });
    const result = await pool.query('SELECT * FROM school_settings WHERE userid = $1', [req.user.id]);
    if (result.rows.length === 0) return res.json({ exists: false, settings: null });
    res.json({ exists: true, settings: result.rows[0] });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.post('/api/school-settings', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'school') return res.status(403).json({ error: 'فقط مکتب دسترسی دارد' });
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
      'c1_in_f', 'c1_in_m', 'c1_pr_f', 'c1_pr_m',
      'c2_in_f', 'c2_in_m', 'c2_pr_f', 'c2_pr_m',
      'c3_in_f', 'c3_in_m', 'c3_pr_f', 'c3_pr_m',
      'c4_in_f', 'c4_in_m', 'c4_pr_f', 'c4_pr_m',
      'c5_in_f', 'c5_in_m', 'c5_pr_f', 'c5_pr_m',
      'c6_in_f', 'c6_in_m', 'c6_pr_f', 'c6_pr_m',
      'c7_in_f', 'c7_in_m', 'c7_pr_f', 'c7_pr_m',
      'c8_in_f', 'c8_in_m', 'c8_pr_f', 'c8_pr_m',
      'c9_in_f', 'c9_in_m', 'c9_pr_f', 'c9_pr_m',
      'c10_in_f', 'c10_in_m', 'c10_pr_f', 'c10_pr_m',
      'c11_in_f', 'c11_in_m', 'c11_pr_f', 'c11_pr_m',
      'c12_in_f', 'c12_in_m', 'c12_pr_f', 'c12_pr_m',
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
      const query = `UPDATE school_settings SET ${setClauses}, updatedat = CURRENT_TIMESTAMP WHERE userid = $${columns.length + 1}`;
      await pool.query(query, [...values, req.user.id]);
    } else {
      const placeholders = columns.map((_, i) => `$${i + 1}`).join(', ');
      const query = `INSERT INTO school_settings (userid, ${columns.join(', ')}) VALUES ($${columns.length + 1}, ${placeholders})`;
      await pool.query(query, [req.user.id, ...values]);
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
  console.log('🚀 Server V22.0 live on port ' + PORT);
  console.log('═══════════════════════════════════════');
});
