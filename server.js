const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// ═══════════════════════════════════════════════════════════
// 🔐 امنیت: الزام به env (مورد ۸ و ۹)
// ═══════════════════════════════════════════════════════════
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('❌ JWT_SECRET باید تنظیم شود و حداقل ۳۲ کاراکتر باشد. سرور متوقف شد.');
  process.exit(1);
}

const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
  console.error('❌ ADMIN_USERNAME و ADMIN_PASSWORD باید در env تنظیم شوند. سرور متوقف شد.');
  process.exit(1);
}
if (ADMIN_PASSWORD.length < 8) {
  console.error('❌ ADMIN_PASSWORD باید حداقل ۸ کاراکتر باشد.');
  process.exit(1);
}

// ═══════════════════════════════════════════════════════════
// CORS محدود (مورد ۱۲)
// ═══════════════════════════════════════════════════════════
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

console.log('═══════════════════════════════════════');
console.log('🔐 Server V27.0 starting...');
console.log('═══════════════════════════════════════');

app.set('trust proxy', 1);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false, checkServerIdentity: () => undefined },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const JOB_TITLES = ['آمر', 'مدیر', 'مدیر اجرائیه', 'معلم', 'سر معلم', 'معلم همکار', 'معلم سپورت', 'معلم لابرانت', 'عضو علمی معلمان', 'عضو علمی مدرسین', 'عضو مسلکی امور مالی و کارکنان', 'عضو مسلکی نظارت احصاییه و گزارش', 'عضو مسلکی تاسیسات و ترمیمات', 'عضو مسلکی شوراها', 'کارکن خدماتی', 'معتمد جنسی (تحویلدار)', 'سایر'];
const NO_CODE_TITLES = [];
const SERVICE_TITLES = ['کارکن خدماتی', 'معتمد جنسی (تحویلدار)'];
const EDUCATION_EXEMPT_JOBS = ['کارکن خدماتی', 'معتمد جنسی (تحویلدار)', 'سایر'];
const MONTHS_SHAMSI = ['حمل', 'ثور', 'جوزا', 'سرطان', 'اسد', 'سنبله', 'میزان', 'عقرب', 'قوس', 'جدی', 'دلو', 'حوت'];
const JOBCODE_REGEX = /^27-\d{1,3}-\d{1,3}-\d{3,6}$/;
const ETAZKIRA_REGEX = /^\d+-\d+-\d+$/;
const PAPER_TAZKIRA_NUMERIC_REGEX = /^\d{1,20}$/;

const MIN_YEAR = 1300;
const MAX_YEAR = 1500;
const DEFAULT_YEAR = 1405;

function isValidYear(y) {
  const n = Number(y);
  return Number.isInteger(n) && n >= MIN_YEAR && n <= MAX_YEAR;
}

// ═══════════════════════════════════════════════════════════
// normalizeDigits و toNum (مورد ۳)
// ═══════════════════════════════════════════════════════════
function normalizeDigits(str) {
  if (str === null || str === undefined) return '';
  const p = '۰۱۲۳۴۵۶۷۸۹', a = '٠١٢٣٤٥٦٧٨٩';
  return String(str).split('').map(ch => {
    const pi = p.indexOf(ch); if (pi !== -1) return pi;
    const ai = a.indexOf(ch); if (ai !== -1) return ai;
    return ch;
  }).join('');
}

function toNum(val, fallback = 0) {
  if (val === null || val === undefined || val === '') return fallback;
  const cleaned = normalizeDigits(String(val)).replace(/[^0-9.\-]/g, '');
  const num = Number(cleaned);
  return Number.isFinite(num) ? num : fallback;
}

// ═══════════════════════════════════════════════════════════
// initDB با Migration جامع (مورد ۵)
// ═══════════════════════════════════════════════════════════
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL, schoolname TEXT, district TEXT, createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    await client.query(`CREATE TABLE IF NOT EXISTS records (id SERIAL PRIMARY KEY, userid INTEGER, schoolname TEXT, district TEXT, data TEXT, status TEXT DEFAULT 'pending', createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    await client.query(`CREATE TABLE IF NOT EXISTS login_attempts (id SERIAL PRIMARY KEY, ip TEXT NOT NULL, username TEXT, success BOOLEAN DEFAULT FALSE, createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);

    await client.query(`CREATE TABLE IF NOT EXISTS school_settings_new (
      id SERIAL PRIMARY KEY,
      userid INTEGER NOT NULL,
      school_year INTEGER NOT NULL DEFAULT ${DEFAULT_YEAR},
      schoolname TEXT,
      district TEXT,
      time_type TEXT DEFAULT 'یک تایم',
      academic_member TEXT,
      budget_status TEXT DEFAULT 'عادی',
      extra_bust_count INTEGER DEFAULT 0,
      extra_bust_field TEXT,
      lack_bust_count INTEGER DEFAULT 0,
      lack_bust_field TEXT,
      branches_data TEXT,
      createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updatedat TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`);

    // Migration جامع: بررسی همه ستون‌ها
    const requiredColumns = {
      school_year: `INTEGER NOT NULL DEFAULT ${DEFAULT_YEAR}`,
      schoolname: 'TEXT',
      district: 'TEXT',
      time_type: "TEXT DEFAULT 'یک تایم'",
      academic_member: 'TEXT',
      budget_status: "TEXT DEFAULT 'عادی'",
      extra_bust_count: 'INTEGER DEFAULT 0',
      extra_bust_field: 'TEXT',
      lack_bust_count: 'INTEGER DEFAULT 0',
      lack_bust_field: 'TEXT',
      branches_data: 'TEXT',
      createdat: 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
      updatedat: 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'
    };
    for (const [col, type] of Object.entries(requiredColumns)) {
      await client.query(`ALTER TABLE school_settings_new ADD COLUMN IF NOT EXISTS ${col} ${type};`);
    }

    // Migration UNIQUE
    await client.query(`
      DO $$
      BEGIN
        IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'school_settings_new_userid_key') THEN
          ALTER TABLE school_settings_new DROP CONSTRAINT school_settings_new_userid_key;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'school_settings_new_userid_year_key') THEN
          ALTER TABLE school_settings_new ADD CONSTRAINT school_settings_new_userid_year_key UNIQUE (userid, school_year);
        END IF;
      END $$;
    `);

    await client.query(`CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updatedat TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    await client.query(`INSERT INTO app_settings (key, value) VALUES ('evaluation_allowed', 'false') ON CONFLICT (key) DO NOTHING;`);
    await client.query(`CREATE TABLE IF NOT EXISTS evaluations (id SERIAL PRIMARY KEY, record_id INTEGER NOT NULL, userid INTEGER NOT NULL, schoolname TEXT, district TEXT, first_name TEXT, last_name TEXT, father_name TEXT, grandfather_name TEXT, job_code TEXT, employment_type TEXT, birth_year TEXT, service_duration TEXT, degree TEXT, gender TEXT, job_title TEXT, appointment_date TEXT, eval_date_prev TEXT, bust TEXT, grade TEXT, eval_date TEXT NOT NULL, eval_score INTEGER NOT NULL, eval_result TEXT NOT NULL, remarks TEXT DEFAULT '', createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    await client.query(`CREATE TABLE IF NOT EXISTS salaries (id SERIAL PRIMARY KEY, record_id INTEGER NOT NULL, userid INTEGER NOT NULL, schoolname TEXT, district TEXT, year TEXT NOT NULL, month TEXT NOT NULL, bank_number TEXT, appointment_letter TEXT, base_salary REAL DEFAULT 0, other_base REAL DEFAULT 0, professional REAL DEFAULT 0, other_professional REAL DEFAULT 0, food REAL DEFAULT 0, other_food REAL DEFAULT 0, allowance REAL DEFAULT 0, other_allowance REAL DEFAULT 0, other_increase REAL DEFAULT 0, total_entitlement REAL DEFAULT 0, absence REAL DEFAULT 0, tax REAL DEFAULT 0, other_tax REAL DEFAULT 0, tax_10 REAL DEFAULT 0, deductions REAL DEFAULT 0, other_deductions REAL DEFAULT 0, total_deductions REAL DEFAULT 0, net_pay REAL DEFAULT 0, status TEXT DEFAULT 'draft', createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updatedat TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(record_id, year, month));`);
    await client.query(`CREATE TABLE IF NOT EXISTS attendance (id SERIAL PRIMARY KEY, salary_id INTEGER NOT NULL UNIQUE, present REAL DEFAULT 0, absent REAL DEFAULT 0, vacation REAL DEFAULT 0, sick REAL DEFAULT 0, essential REAL DEFAULT 0, maternity REAL DEFAULT 0, service_center REAL DEFAULT 0, service_province REAL DEFAULT 0, hajj REAL DEFAULT 0, holidays REAL DEFAULT 0, other REAL DEFAULT 0, total_days REAL DEFAULT 0, createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updatedat TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    console.log('✅ جداول دیتابیس آماده شدند.');
  } finally { client.release(); }
}

// ═══════════════════════════════════════════════════════════
// میدل‌ورها
// ═══════════════════════════════════════════════════════════
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => {
  if (req.url.endsWith('.html') || req.url === '/' || req.url.startsWith('/?')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  next();
});

// CORS محدود (مورد ۱۲)
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin))) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
  }
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: '❌ تعداد تلاش‌های شما بیش از حد مجاز است.' }
});

function authRequired(req, res, next) {
  let token = req.cookies?.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token && req.query.token) token = req.query.token;
  if (!token) return res.status(401).json({ error: 'وارد نشده‌اید' });
  token = String(token).trim().replace(/^["']|["']$/g, '');
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    res.status(401).json({ error: 'توکن نامعتبر است' });
  }
}

async function logLoginAttempt(ip, username, success) {
  try { await pool.query('INSERT INTO login_attempts (ip, username, success) VALUES ($1, $2, $3)', [ip || 'unknown', username || 'unknown', success]); } catch (e) {}
}

// ═══════════════════════════════════════════════════════════
// توابع کمکی
// ═══════════════════════════════════════════════════════════
function validateShamsiDateServer(dateStr, fieldName) {
  if (!dateStr) return null;
  const cleaned = normalizeDigits(dateStr).trim().replace(/[.\-]/g, '/');
  const parts = cleaned.split('/').map(p => p.trim());
  if (parts.length !== 3) return `${fieldName} باید فرمت YYYY/MM/DD داشته باشد`;
  const p1 = parseInt(parts[0]), p2 = parseInt(parts[1]), p3 = parseInt(parts[2]);
  if (isNaN(p1) || isNaN(p2) || isNaN(p3)) return `${fieldName} باید فقط شامل اعداد باشد`;
  let year, month, day;
  if (parts[0].length === 4 || (p1 >= 1300 && p1 <= 1450)) { year = p1; month = p2; day = p3; }
  else if (parts[2].length === 4 || (p3 >= 1300 && p3 <= 1450)) { year = p3; month = p2; day = p1; }
  else return `${fieldName}: سال باید بین ۱۳۰۰ تا ۱۴۵۰ باشد`;
  if (year < 1300 || year > 1450) return `${fieldName}: سال نامعتبر`;
  if (month < 1 || month > 12) return `${fieldName}: ماه نامعتبر`;
  let maxDay = 31;
  if (month >= 7 && month <= 11) maxDay = 30;
  if (month === 12) maxDay = 29;
  if (day < 1 || day > maxDay) return `${fieldName}: روز نامعتبر`;
  return null;
}

function validateTazkiraServer(s) { if (!s) return null; const c = normalizeDigits(s).trim(); if (!ETAZKIRA_REGEX.test(c)) return 'فرمت تذکره الکترونیکی اشتباه است'; return null; }
function validatePaperTazkiraServer(s) { if (!s) return null; const c = normalizeDigits(s).trim().replace(/\s+/g, ''); if (!PAPER_TAZKIRA_NUMERIC_REGEX.test(c)) return 'فرمت تذکره کاغذی اشتباه است'; return null; }
function validateJobCodeServer(s) { if (!s) return null; const c = normalizeDigits(s).trim().replace(/\s+/g, ''); if (!JOBCODE_REGEX.test(c)) return 'فرمت کُد بست اشتباه است'; return null; }
function isValidJobCode(s) { if (!s) return false; const c = normalizeDigits(s).trim().replace(/\s+/g, ''); return JOBCODE_REGEX.test(c); }
function isNoCodeTitle(t) { return NO_CODE_TITLES.some(x => x === t); }
function isEducationExemptJob(t) { return EDUCATION_EXEMPT_JOBS.includes(String(t || '').trim()); }

async function checkJobCodeExact(jobCode, excludeRecordId = null) {
  if (!jobCode) return { exists: false };
  const normalizedCode = normalizeDigits(jobCode).trim().replace(/\s+/g, '');
  let sql = `SELECT r.id, r.userid, r.data, COALESCE(NULLIF(r.schoolname, ''), u.schoolname) AS schoolname, COALESCE(NULLIF(r.district, ''), u.district) AS district FROM records r LEFT JOIN users u ON u.id = r.userid WHERE (CAST(r.data AS JSON)->>'jobCode') = $1`;
  const params = [normalizedCode];
  if (excludeRecordId) { params.push(excludeRecordId); sql += ` AND r.id <> $${params.length}`; }
  sql += ' LIMIT 1';
  const result = await pool.query(sql, params);
  if (result.rows.length === 0) return { exists: false };
  const row = result.rows[0]; let info = {}; try { info = JSON.parse(row.data || '{}'); } catch (e) {}
  return { exists: true, recordId: row.id, userid: row.userid, schoolname: row.schoolname || 'نامشخص', district: row.district || '', employeeName: `${info.firstName || ''} ${info.lastName || ''}`.trim() || 'نامشخص' };
}

async function checkETazkiraExact(eTazkira, excludeRecordId = null) {
  if (!eTazkira) return { exists: false };
  const cleaned = normalizeDigits(eTazkira).trim().replace(/\s+/g, '');
  let sql = `SELECT r.id, r.userid, r.data, COALESCE(NULLIF(r.schoolname, ''), u.schoolname) AS schoolname, COALESCE(NULLIF(r.district, ''), u.district) AS district FROM records r LEFT JOIN users u ON u.id = r.userid WHERE (CAST(r.data AS JSON)->>'eTazkira') = $1`;
  const params = [cleaned];
  if (excludeRecordId) { params.push(excludeRecordId); sql += ` AND r.id <> $${params.length}`; }
  sql += ' LIMIT 1';
  const result = await pool.query(sql, params);
  if (result.rows.length === 0) return { exists: false };
  const row = result.rows[0]; let info = {}; try { info = JSON.parse(row.data || '{}'); } catch (e) {}
  return { exists: true, recordId: row.id, userid: row.userid, schoolname: row.schoolname || 'نامشخص', district: row.district || '', employeeName: `${info.firstName || ''} ${info.lastName || ''}`.trim() || 'نامشخص' };
}

async function checkPaperTazkiraExact(tazkiraCode, excludeRecordId = null) {
  if (!tazkiraCode) return { exists: false };
  const cleaned = normalizeDigits(tazkiraCode).trim().replace(/\s+/g, '');
  let sql = `SELECT r.id, r.userid, r.data, COALESCE(NULLIF(r.schoolname, ''), u.schoolname) AS schoolname, COALESCE(NULLIF(r.district, ''), u.district) AS district FROM records r LEFT JOIN users u ON u.id = r.userid WHERE (CAST(r.data AS JSON)->>'paperTazkira') = $1`;
  const params = [cleaned];
  if (excludeRecordId) { params.push(excludeRecordId); sql += ` AND r.id <> $${params.length}`; }
  sql += ' LIMIT 1';
  const result = await pool.query(sql, params);
  if (result.rows.length === 0) return { exists: false };
  const row = result.rows[0]; let info = {}; try { info = JSON.parse(row.data || '{}'); } catch (e) {}
  return { exists: true, recordId: row.id, userid: row.userid, schoolname: row.schoolname || 'نامشخص', district: row.district || '', employeeName: `${info.firstName || ''} ${info.lastName || ''}`.trim() || 'نامشخص' };
}

function buildDuplicateResponse(kind, dup, currentUserId) {
  const isSameSchool = String(dup.userid) === String(currentUserId);
  const label = kind === 'jobcode' ? 'کد بست' : kind === 'etazkira' ? 'تذکره الکترونیکی' : 'کد تذکره کاغذی';
  return { error: `${label} تکراری است`, code: kind === 'jobcode' ? 'DUPLICATE_JOBCODE' : kind === 'etazkira' ? 'DUPLICATE_ETAZKIRA' : 'DUPLICATE_TAZKIRA', isSameSchool, schoolname: isSameSchool ? null : dup.schoolname, district: isSameSchool ? null : dup.district, employeeName: isSameSchool ? dup.employeeName : null, recordId: dup.recordId };
}

// ═══════════════════════════════════════════════════════════
// API: احراز هویت
// ═══════════════════════════════════════════════════════════
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const clientIp = req.ip || 'unknown';
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'نام کاربری و رمز عبور الزامی است' });
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
      await logLoginAttempt(clientIp, username, true);
      const token = jwt.sign({ id: 0, username: ADMIN_USERNAME, role: 'admin' }, JWT_SECRET, { expiresIn: '7d' });
      return res.json({ token, user: { id: 0, username: ADMIN_USERNAME, role: 'admin', schoolname: 'ریاست معارف', district: 'مرکز هرات' }, redirect: '/admin-main.html' });
    }
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) { await logLoginAttempt(clientIp, username, false); return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است' }); }
    const user = result.rows[0];
    if (!bcrypt.compareSync(password, user.password)) { await logLoginAttempt(clientIp, username, false); return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است' }); }
    await logLoginAttempt(clientIp, username, true);
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, schoolname: user.schoolname || '', district: user.district || '' }, redirect: '/school-settings.html' });
  } catch (e) { res.status(500).json({ error: 'خطای سرور' }); }
});

// ═══════════════════════════════════════════════════════════
// API: رکوردها (کارمندان)
// ═══════════════════════════════════════════════════════════
app.get('/api/records', authRequired, async (req, res) => {
  try {
    const search = (req.query.search || '').trim();
    const statusFilter = (req.query.status || '').trim();
    const schoolnameFilter = (req.query.schoolname || '').trim();
    let result;
    if (req.user.role === 'admin') {
      const conditions = []; const params = [];
      if (search) { params.push(`%${search}%`); const i = params.length; conditions.push(`(schoolname ILIKE $${i} OR district ILIKE $${i} OR CAST(data AS TEXT) ILIKE $${i})`); }
      if (statusFilter === 'pending' || statusFilter === 'approved') { params.push(statusFilter); conditions.push(`status = $${params.length}`); }
      if (schoolnameFilter) { params.push(schoolnameFilter); conditions.push(`schoolname = $${params.length}`); }
      const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
      result = await pool.query(`SELECT * FROM records ${where} ORDER BY id DESC`, params);
    } else if (req.user.role === 'school') {
      const conditions = ['userid = $1']; const params = [req.user.id];
      if (search) { params.push(`%${search}%`); const i = params.length; conditions.push(`(schoolname ILIKE $${i} OR district ILIKE $${i} OR CAST(data AS TEXT) ILIKE $${i})`); }
      if (statusFilter === 'pending' || statusFilter === 'approved') { params.push(statusFilter); conditions.push(`status = $${params.length}`); }
      const where = 'WHERE ' + conditions.join(' AND ');
      result = await pool.query(`SELECT * FROM records ${where} ORDER BY id DESC`, params);
    } else {
      return res.status(403).json({ error: 'دسترسی غیرمجاز' });
    }
    const rows = result.rows.map((r) => { let parsed = {}; try { parsed = JSON.parse(r.data); } catch (e) {} return { ...r, data: parsed, status: r.status }; });
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطا در واکشی اطلاعات' }); }
});

app.get('/api/check-jobcode', authRequired, async (req, res) => {
  try {
    const code = (req.query.code || '').trim(); const excludeId = req.query.excludeId ? parseInt(req.query.excludeId) : null;
    if (!code) return res.json({ exists: false });
    const dup = await checkJobCodeExact(code, excludeId);
    if (!dup.exists) return res.json({ exists: false });
    const isSameSchool = String(dup.userid) === String(req.user.id);
    res.json({ exists: true, isSameSchool, recordId: dup.recordId, schoolname: isSameSchool ? null : dup.schoolname, district: isSameSchool ? null : dup.district, employeeName: isSameSchool ? dup.employeeName : null });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.get('/api/check-etazkira', authRequired, async (req, res) => {
  try {
    const code = (req.query.code || '').trim(); const excludeId = req.query.excludeId ? parseInt(req.query.excludeId) : null;
    if (!code) return res.json({ exists: false });
    const fmtErr = validateTazkiraServer(code); if (fmtErr) return res.status(400).json({ error: fmtErr });
    const dup = await checkETazkiraExact(code, excludeId);
    if (!dup.exists) return res.json({ exists: false });
    const isSameSchool = String(dup.userid) === String(req.user.id);
    res.json({ exists: true, isSameSchool, recordId: dup.recordId, schoolname: isSameSchool ? null : dup.schoolname, district: isSameSchool ? null : dup.district, employeeName: isSameSchool ? dup.employeeName : null });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.get('/api/check-tazkira', authRequired, async (req, res) => {
  try {
    const code = (req.query.code || '').trim(); const excludeId = req.query.excludeId ? parseInt(req.query.excludeId) : null;
    if (!code) return res.json({ exists: false });
    const fmtErr = validatePaperTazkiraServer(code); if (fmtErr) return res.status(400).json({ error: fmtErr });
    const dup = await checkPaperTazkiraExact(code, excludeId);
    if (!dup.exists) return res.json({ exists: false });
    const isSameSchool = String(dup.userid) === String(req.user.id);
    res.json({ exists: true, isSameSchool, recordId: dup.recordId, schoolname: isSameSchool ? null : dup.schoolname, district: isSameSchool ? null : dup.district, employeeName: isSameSchool ? dup.employeeName : null });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

async function validateRecordBody(body, excludeId = null) {
  const job = String(body.jobTitle || '').trim();
  const firstName = String(body.firstName || '').trim();
  const fatherName = String(body.fatherName || '').trim();
  const grandfatherName = String(body.grandfatherName || '').trim();
  const jobCode = String(body.jobCode || '').trim();
  const eTazkira = String(body.eTazkira || '').trim();
  const paperTazkira = String(body.paperTazkira || '').trim();
  const degree = String(body.degree || '').trim();
  const majorVal = String(body.major || '').trim();
  const eduInstituteVal = String(body.eduInstitute || '').trim();
  const eduInstituteLocationVal = String(body.eduInstituteLocation || '').trim();
  const birthDate = String(body.birthDate || '').trim();
  const firstAppointmentDate = String(body.firstAppointmentDate || '').trim();
  const currentPositionDate = String(body.currentPositionDate || '').trim();
  const ethnicity = String(body.ethnicity || '').trim();
  const phone = String(body.phone || '').trim();
  const enrollmentDate = String(body.enrollmentDate || '').trim();
  const graduationDate = String(body.graduationDate || '').trim();
  const maritalStatus = String(body.maritalStatus || '').trim();
  const teachingField = String(body.teachingField || body.subjectTeaching || '').trim();

  if (!job) return 'عنوان بست الزامی است';
  if (!JOB_TITLES.includes(job)) return '❌ عنوان بست انتخابی معتبر نیست';
  if (!firstName) return 'اسم الزامی است';
  if (!fatherName) return 'ولد الزامی است';
  if (!grandfatherName) return 'ولدیت الزامی است';
  if (maritalStatus && !['مجرد', 'متاهل'].includes(maritalStatus)) return '❌ حالت مدنی معتبر نیست';

  const isContract = isNoCodeTitle(job);
  const isEducationExempt = isEducationExemptJob(job);

  if (isContract) {
    if (!eTazkira && !paperTazkira) return 'حداقل یکی از تذکره‌ها الزامی است';
    if (!birthDate) return 'تاریخ تولد الزامی است';
  } else {
    if (!ethnicity) return 'قومیت الزامی است';
    if (!phone) return 'شماره تماس الزامی است';
    if (!eTazkira && !paperTazkira) return 'حداقل یکی از تذکره‌ها الزامی است';
    if (!jobCode) return 'کُد بست الزامی است';
    if (!isValidJobCode(jobCode)) return '❌ فرمت کُد بست اشتباه است';
    if (!birthDate) return 'تاریخ تولد الزامی است';
    if (!firstAppointmentDate) return 'تاریخ اولین تقرر الزامی است';
    if (!currentPositionDate) return 'تاریخ تقرر فعلی الزامی است';
    if (!isEducationExempt) {
      if (!degree) return 'درجه تحصیلی الزامی است';
      if (!majorVal) return 'رشته تحصیلی الزامی است';
      if (majorVal.length < 2) return 'رشته تحصیلی حداقل ۲ حرف';
      if (!eduInstituteVal) return 'مرجع تعلیمی الزامی است';
      if (!eduInstituteLocationVal) return 'موقعیت مرجع الزامی است';
      if (!enrollmentDate) return 'تاریخ شمولیت الزامی است';
      if (!graduationDate) return 'تاریخ فراغت الزامی است';
    }
  }

  if (jobCode) { const err = validateJobCodeServer(jobCode); if (err) return '❌ ' + err; }
  if (eTazkira) { const err = validateTazkiraServer(eTazkira); if (err) return '❌ ' + err; }
  if (paperTazkira) { const err = validatePaperTazkiraServer(paperTazkira); if (err) return '❌ ' + err; }
  if (birthDate) { const err = validateShamsiDateServer(birthDate, 'تاریخ تولد'); if (err) return '❌ ' + err; }
  if (firstAppointmentDate) { const err = validateShamsiDateServer(firstAppointmentDate, 'تاریخ اولین تقرر'); if (err) return '❌ ' + err; }
  if (currentPositionDate) { const err = validateShamsiDateServer(currentPositionDate, 'تاریخ تقرر فعلی'); if (err) return '❌ ' + err; }
  if (enrollmentDate) { const err = validateShamsiDateServer(enrollmentDate, 'تاریخ شمولیت'); if (err) return '❌ ' + err; }
  if (graduationDate) { const err = validateShamsiDateServer(graduationDate, 'تاریخ فراغت'); if (err) return '❌ ' + err; }

  const workshopStatus = String(body.workshopStatus || '').trim();
  if (workshopStatus === 'بلی') {
    if (!String(body.workshopTitle || '').trim()) return '❌ عنوان ورکشاپ الزامی است';
    if (!String(body.workshopDuration || '').trim()) return '❌ مدت ورکشاپ الزامی است';
  }

  const serviceStatus = String(body.serviceStatus || '').trim();
  if (serviceStatus === 'بلی') {
    if (!String(body.serviceDistrict || '').trim()) return '❌ نام ولسوالی خدمتی الزامی است';
    if (!String(body.serviceSchool || '').trim()) return '❌ نام مکتب خدمتی الزامی است';
    if (!String(body.serviceDate || '').trim()) return '❌ تاریخ خدمتی الزامی است';
    const dateErr = validateShamsiDateServer(body.serviceDate, 'تاریخ خدمتی'); if (dateErr) return '❌ ' + dateErr;
  }

  const totalTeachingHours = String(body.totalTeachingHours || '').trim();
  if (totalTeachingHours) { const num = toNum(totalTeachingHours); if (num < 0) return '❌ مجموعه ساعت درسی باید عددی مثبت باشد'; }
  if (teachingField && teachingField.length < 2) return '❌ رشته تدریس حداقل ۲ حرف';
  if (excludeId === null && !body.agreement) return '❌ شما باید موافقت خود را اعلام کنید';
  return null;
}

app.post('/api/records', authRequired, async (req, res) => {
  try {
    const body = req.body || {};
    const schoolName = body.schoolName || req.user.schoolname || '';
    const district = body.district || req.user.district || '';

    const settingsCheck = await pool.query('SELECT id FROM school_settings_new WHERE userid = $1 LIMIT 1', [req.user.id]);
    if (settingsCheck.rows.length === 0) return res.status(400).json({ error: '❌ لطفاً ابتدا اطلاعات مکتب خود را ثبت کنید' });

    const jobCode = String(body.jobCode || '').trim();
    if (jobCode) { const dup = await checkJobCodeExact(jobCode, null); if (dup.exists) return res.status(409).json(buildDuplicateResponse('jobcode', dup, req.user.id)); }

    const eTazkira = String(body.eTazkira || '').trim();
    if (eTazkira) { const fmtErr = validateTazkiraServer(eTazkira); if (fmtErr) return res.status(400).json({ error: '❌ ' + fmtErr }); const dupE = await checkETazkiraExact(eTazkira, null); if (dupE.exists) return res.status(409).json(buildDuplicateResponse('etazkira', dupE, req.user.id)); }

    const paperTazkira = String(body.paperTazkira || '').trim();
    if (paperTazkira) { const fmtErr = validatePaperTazkiraServer(paperTazkira); if (fmtErr) return res.status(400).json({ error: '❌ ' + fmtErr }); const dupT = await checkPaperTazkiraExact(paperTazkira, null); if (dupT.exists) return res.status(409).json(buildDuplicateResponse('tazkira', dupT, req.user.id)); }

    const error = await validateRecordBody(body, null);
    if (error) return res.status(400).json({ error });

    const dataToSave = { ...body };
    delete dataToSave.subjectTeaching;
    if (body.teachingField || body.subjectTeaching) dataToSave.teachingField = String(body.teachingField || body.subjectTeaching).trim();

    await pool.query(`INSERT INTO records (userid, schoolname, district, data, status) VALUES ($1, $2, $3, $4, 'pending')`, [req.user.id, schoolName, district, JSON.stringify(dataToSave)]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطا در ثبت رکورد' }); }
});

app.put('/api/records/:id', authRequired, async (req, res) => {
  try {
    const id = req.params.id;
    const body = req.body || {};
    let check;

    if (req.user.role === 'admin') {
      check = await pool.query('SELECT * FROM records WHERE id = $1', [id]);
    } else if (req.user.role === 'school') {
      check = await pool.query('SELECT * FROM records WHERE id = $1 AND userid = $2', [id, req.user.id]);
    } else {
      return res.status(403).json({ error: 'دسترسی غیرمجاز' });
    }

    if (check.rows.length === 0) return res.status(404).json({ error: 'رکورد یافت نشد' });

    const originalData = JSON.parse(check.rows[0].data || '{}');
    const bodyKeys = Object.keys(body || {});
    const isOnlyEditAllowed = req.user.role === 'admin' && bodyKeys.length === 1 && bodyKeys[0] === 'editAllowed';

    if (isOnlyEditAllowed) {
      const allowed = body.editAllowed === true || body.editAllowed === 'true';
      const updatedData = { ...originalData, editAllowed: allowed };
      await pool.query('UPDATE records SET data = $1 WHERE id = $2', [JSON.stringify(updatedData), id]);
      return res.json({ ok: true, editAllowed: allowed });
    }

    let finalBody;
    if (req.user.role === 'school') {
      if (originalData.editAllowed !== true) {
        return res.status(403).json({ error: '❌ ویرایش این کارمند هنوز از طرف ادمین اجازه داده نشده است' });
      }
      finalBody = { ...originalData, ...body, editAllowed: true, agreement: true };
    } else {
      finalBody = { ...originalData, ...body };
    }

    if (finalBody.jobCode) {
      const dup = await checkJobCodeExact(finalBody.jobCode, id);
      if (dup.exists) return res.status(409).json(buildDuplicateResponse('jobcode', dup, req.user.id));
    }
    if (finalBody.eTazkira) {
      const dupE = await checkETazkiraExact(finalBody.eTazkira, id);
      if (dupE.exists) return res.status(409).json(buildDuplicateResponse('etazkira', dupE, req.user.id));
    }
    if (finalBody.paperTazkira) {
      const dupT = await checkPaperTazkiraExact(finalBody.paperTazkira, id);
      if (dupT.exists) return res.status(409).json(buildDuplicateResponse('tazkira', dupT, req.user.id));
    }

    const error = await validateRecordBody(finalBody, id);
    if (error) return res.status(400).json({ error });

    await pool.query(`UPDATE records SET data = $1 WHERE id = $2`, [JSON.stringify(finalBody), id]);
    res.json({ ok: true });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: '❌ این کد بست یا تذکره قبلاً ثبت شده است', code: 'DUPLICATE_INDEX' });
    res.status(500).json({ error: 'خطا در ویرایش' });
  }
});

app.post('/api/records/:id/approve', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین' });
    const result = await pool.query("UPDATE records SET status = 'approved' WHERE id = $1", [req.params.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'یافت نشد' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.delete('/api/records/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین' });
    const result = await pool.query('DELETE FROM records WHERE id = $1', [req.params.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'یافت نشد' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

// ═══════════════════════════════════════════════════════════
// API: تنظیمات مکتب — سالانه با رفع همه مشکلات
// ═══════════════════════════════════════════════════════════

// GET تنظیمات یک سال (مورد ۱ برای single هم مشابه)
app.get('/api/school-settings', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'school') return res.status(403).json({ error: 'فقط مکتب دسترسی دارد' });
    const year = req.query.year ? Number(req.query.year) : DEFAULT_YEAR;
    if (!isValidYear(year)) return res.status(400).json({ error: 'سال تعلیمی نامعتبر است' });

    const result = await pool.query(
      'SELECT * FROM school_settings_new WHERE userid = $1 AND school_year = $2',
      [req.user.id, year]
    );
    if (result.rows.length === 0) return res.json({ exists: false, settings: null, schoolYear: year });

    const row = result.rows[0];
    let branchesData = {};
    try { branchesData = JSON.parse(row.branches_data || '{}'); } catch (e) {
      console.warn(`branches_data نامعتبر برای user ${req.user.id}، سال ${year}`);
    }
    const { userid, branches_data, ...safeRow } = row;
    res.json({
      exists: true,
      settings: { ...safeRow, ...branchesData, schoolYear: row.school_year },
      schoolYear: year
    });
  } catch (err) {
    console.error('GET /api/school-settings:', err.message);
    res.status(500).json({ error: 'خطا در دریافت تنظیمات' });
  }
});

// GET لیست سال‌ها
app.get('/api/school-settings/years', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'school') return res.status(403).json({ error: 'فقط مکتب دسترسی دارد' });
    const result = await pool.query(
      `SELECT school_year, updatedat FROM school_settings_new WHERE userid = $1 ORDER BY school_year DESC`,
      [req.user.id]
    );
    res.json(result.rows.map(r => ({ year: r.school_year, updatedAt: r.updatedat })));
  } catch (err) {
    console.error('GET /api/school-settings/years:', err.message);
    res.status(500).json({ error: 'خطا' });
  }
});

// GET همه (ادمین) — مورد ۱: پارس و ادغام branches_data
app.get('/api/all-school-settings', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین دسترسی دارد' });
    const year = req.query.year ? Number(req.query.year) : null;
    if (req.query.year && !isValidYear(year)) return res.status(400).json({ error: 'سال تعلیمی نامعتبر است' });

    const params = year ? [year] : [];
    const where = year ? 'WHERE s.school_year = $1' : '';
    const result = await pool.query(`
      SELECT s.*, s.school_year AS "schoolYear", u.username,
        COALESCE(NULLIF(s.schoolname, ''), u.schoolname) AS schoolname,
        COALESCE(NULLIF(s.district, ''), u.district) AS district
      FROM school_settings_new s
      LEFT JOIN users u ON u.id = s.userid
      ${where}
      ORDER BY s.school_year DESC, s.id DESC
    `, params);

    // ✅ مورد ۱: پارس و ادغام branches_data
    const rows = result.rows.map(r => {
      let branches = {};
      try { branches = JSON.parse(r.branches_data || '{}'); } catch (e) {
        console.warn(`branches_data نامعتبر برای settings id=${r.id}`);
      }
      const { branches_data, ...rest } = r;
      return { ...rest, ...branches, branches_data: branches };
    });
    res.json(rows);
  } catch (err) {
    console.error('GET /api/all-school-settings:', err.message);
    res.status(500).json({ error: 'خطا در دریافت آمار مکاتب' });
  }
});

// POST تنظیمات — مورد ۲: حفظ مقادیر قبلی برای فیلدهای ارسال‌نشده
app.post('/api/school-settings', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'school') return res.status(403).json({ error: 'فقط مکتب دسترسی دارد' });

    const body = req.body || {};
    const year = Number(body.schoolYear || body.school_year || DEFAULT_YEAR);
    if (!isValidYear(year)) return res.status(400).json({ error: 'سال تعلیمی نامعتبر است' });

    // ✅ مورد ۲: خواندن مقدار قبلی
    const existing = await pool.query(
      'SELECT * FROM school_settings_new WHERE userid = $1 AND school_year = $2',
      [req.user.id, year]
    );
    const oldRow = existing.rows[0] || null;
    let oldBranches = {};
    if (oldRow) { try { oldBranches = JSON.parse(oldRow.branches_data || '{}'); } catch (e) {} }

    // toNumSafe: اگر body[key] ارسال نشده بود، از قبلی استفاده کن
    const val = (key, fallback = 0) => {
      if (body[key] === undefined || body[key] === null || body[key] === '') {
        return toNum(oldBranches[key], fallback);
      }
      return toNum(body[key], fallback);
    };
    const strVal = (bodyKey, oldKey, fallback = '') => {
      if (body[bodyKey] === undefined || body[bodyKey] === null || body[bodyKey] === '') {
        return oldRow ? (oldRow[oldKey] ?? fallback) : fallback;
      }
      return body[bodyKey];
    };

    const academicMember = String(strVal('academicMember', 'academic_member', '')).trim();
    if (!academicMember) return res.status(400).json({ error: 'نام عضو علمی الزامی است' });

    const schoolName = req.user.schoolname || '';
    const district = req.user.district || '';

    const branchesData = {
      branchesF13: val('branchesF13'), branchesF46: val('branchesF46'), branchesF79: val('branchesF79'), branchesF1012: val('branchesF1012'),
      branchesM13: val('branchesM13'), branchesM46: val('branchesM46'), branchesM79: val('branchesM79'), branchesM1012: val('branchesM1012'),
      branchesX13: val('branchesX13'), branchesX46: val('branchesX46'), branchesX79: val('branchesX79'), branchesX1012: val('branchesX1012'),
      branchesTotal: val('branchesTotal'),
      totalInFemale: val('totalInFemale'), totalInMale: val('totalInMale'),
      totalPresentFemale: val('totalPresentFemale'), totalPresentMale: val('totalPresentMale'),
      gradFemale: val('gradFemale'), gradMale: val('gradMale')
    };
    for (let i = 1; i <= 12; i++) {
      for (const k of ['in_f', 'in_m', 'pr_f', 'pr_m']) {
        branchesData[`c${i}_${k}`] = val(`c${i}_${k}`);
      }
      branchesData[`e${i}_f`] = val(`e${i}_f`);
      branchesData[`e${i}_m`] = val(`e${i}_m`);
    }

    const result = await pool.query(`
      INSERT INTO school_settings_new (
        userid, school_year, schoolname, district,
        time_type, academic_member, budget_status,
        extra_bust_count, extra_bust_field,
        lack_bust_count, lack_bust_field, branches_data
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      ON CONFLICT (userid, school_year) DO UPDATE SET
        schoolname = EXCLUDED.schoolname,
        district = EXCLUDED.district,
        time_type = EXCLUDED.time_type,
        academic_member = EXCLUDED.academic_member,
        budget_status = EXCLUDED.budget_status,
        extra_bust_count = EXCLUDED.extra_bust_count,
        extra_bust_field = EXCLUDED.extra_bust_field,
        lack_bust_count = EXCLUDED.lack_bust_count,
        lack_bust_field = EXCLUDED.lack_bust_field,
        branches_data = EXCLUDED.branches_data,
        updatedat = CURRENT_TIMESTAMP
      RETURNING id
    `, [
      req.user.id, year, schoolName, district,
      strVal('timeType', 'time_type', 'یک تایم'),
      academicMember,
      strVal('budgetStatus', 'budget_status', 'عادی'),
      val('extraBustCount', toNum(oldRow?.extra_bust_count)),
      strVal('extraBustField', 'extra_bust_field', ''),
      val('lackBustCount', toNum(oldRow?.lack_bust_count)),
      strVal('lackBustField', 'lack_bust_field', ''),
      JSON.stringify(branchesData)
    ]);

    res.json({ ok: true, schoolYear: year, id: result.rows[0].id });
  } catch (err) {
    console.error('POST /api/school-settings:', err.message);
    res.status(500).json({ error: 'خطا در ذخیره تنظیمات: ' + err.message });
  }
});

// DELETE یک سال
app.delete('/api/school-settings/:year', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'school') return res.status(403).json({ error: 'فقط مکتب دسترسی دارد' });
    const year = Number(req.params.year);
    if (!isValidYear(year)) return res.status(400).json({ error: 'سال تعلیمی نامعتبر است' });
    const result = await pool.query(
      'DELETE FROM school_settings_new WHERE userid = $1 AND school_year = $2 RETURNING id',
      [req.user.id, year]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'برای این سال اطلاعاتی یافت نشد' });
    res.json({ ok: true, deletedYear: year });
  } catch (err) {
    console.error('DELETE /api/school-settings:', err.message);
    res.status(500).json({ error: 'خطا در حذف' });
  }
});

// POST کپی سال — مورد ۱۱: تأیید overwrite
app.post('/api/school-settings/copy', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'school') return res.status(403).json({ error: 'فقط مکتب دسترسی دارد' });
    const fromYear = Number(req.body.fromYear);
    const toYear = Number(req.body.toYear);
    if (!isValidYear(fromYear) || !isValidYear(toYear)) return res.status(400).json({ error: 'سال تعلیمی نامعتبر است' });
    if (fromYear === toYear) return res.status(400).json({ error: 'سال مبدأ و مقصد یکسان است' });

    // ✅ مورد ۱۱: چک وجود سال مقصد و نیاز به overwrite
    const toCheck = await pool.query(
      'SELECT id FROM school_settings_new WHERE userid = $1 AND school_year = $2',
      [req.user.id, toYear]
    );
    if (toCheck.rows.length > 0 && req.body.overwrite !== true) {
      return res.status(409).json({
        error: 'برای سال مقصد اطلاعاتی وجود دارد. برای جایگزینی، overwrite=true بفرستید.',
        code: 'TARGET_EXISTS',
        toYear
      });
    }

    const src = await pool.query(
      'SELECT * FROM school_settings_new WHERE userid = $1 AND school_year = $2',
      [req.user.id, fromYear]
    );
    if (src.rows.length === 0) return res.status(404).json({ error: 'اطلاعات سال مبدأ یافت نشد' });

    const s = src.rows[0];
    await pool.query(`
      INSERT INTO school_settings_new (
        userid, school_year, schoolname, district,
        time_type, academic_member, budget_status,
        extra_bust_count, extra_bust_field,
        lack_bust_count, lack_bust_field, branches_data
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      ON CONFLICT (userid, school_year) DO UPDATE SET
        schoolname = EXCLUDED.schoolname, district = EXCLUDED.district,
        time_type = EXCLUDED.time_type, academic_member = EXCLUDED.academic_member,
        budget_status = EXCLUDED.budget_status,
        extra_bust_count = EXCLUDED.extra_bust_count,
        extra_bust_field = EXCLUDED.extra_bust_field,
        lack_bust_count = EXCLUDED.lack_bust_count,
        lack_bust_field = EXCLUDED.lack_bust_field,
        branches_data = EXCLUDED.branches_data,
        updatedat = CURRENT_TIMESTAMP
    `, [
      req.user.id, toYear, s.schoolname, s.district,
      s.time_type, s.academic_member, s.budget_status,
      s.extra_bust_count, s.extra_bust_field,
      s.lack_bust_count, s.lack_bust_field, s.branches_data
    ]);

    res.json({ ok: true, fromYear, toYear });
  } catch (err) {
    console.error('POST /api/school-settings/copy:', err.message);
    res.status(500).json({ error: 'خطا در کپی' });
  }
});

// ═══════════════════════════════════════════════════════════
// API: ارزیابی‌ها — مورد ۷: محدودیت دسترسی
// ═══════════════════════════════════════════════════════════
app.get('/api/evaluation-permission', authRequired, async (req, res) => {
  try { const result = await pool.query("SELECT value FROM app_settings WHERE key = 'evaluation_allowed'"); res.json({ allowed: result.rows.length > 0 && result.rows[0].value === 'true' }); } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.post('/api/evaluation-permission', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین' });
    const value = req.body.allowed ? 'true' : 'false';
    await pool.query(`INSERT INTO app_settings (key, value, updatedat) VALUES ('evaluation_allowed', $1, CURRENT_TIMESTAMP) ON CONFLICT (key) DO UPDATE SET value = $1, updatedat = CURRENT_TIMESTAMP`, [value]);
    res.json({ ok: true, allowed: req.body.allowed });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.get('/api/evaluations', authRequired, async (req, res) => {
  try {
    // ✅ مورد ۷
    if (req.user.role !== 'admin' && req.user.role !== 'school') return res.status(403).json({ error: 'دسترسی غیرمجاز' });
    const conditions = []; const params = [];
    if (req.user.role === 'school') { conditions.push(`userid = $${params.length + 1}`); params.push(req.user.id); }
    const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
    const result = await pool.query(`SELECT * FROM evaluations ${where} ORDER BY id DESC`, params);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.post('/api/evaluations', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'school') return res.status(403).json({ error: 'فقط مکتب' });
    const permResult = await pool.query("SELECT value FROM app_settings WHERE key = 'evaluation_allowed'");
    if (!(permResult.rows.length > 0 && permResult.rows[0].value === 'true')) return res.status(403).json({ error: '❌ هنوز از طرف آمریت اجازه داده نشده است' });
    const body = req.body || {};
    if (!body.record_id || !body.eval_date || !body.eval_score || !body.eval_result) return res.status(400).json({ error: 'فیلدهای الزامی' });

    const recCheck = await pool.query('SELECT id FROM records WHERE id = $1 AND userid = $2', [body.record_id, req.user.id]);
    if (recCheck.rows.length === 0) return res.status(403).json({ error: 'این کارمند متعلق به مکتب شما نیست' });

    await pool.query(
      `INSERT INTO evaluations (record_id, userid, schoolname, district, first_name, last_name, father_name, grandfather_name, job_code, employment_type, birth_year, service_duration, degree, gender, job_title, appointment_date, eval_date_prev, bust, grade, eval_date, eval_score, eval_result, remarks) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)`,
      [body.record_id, req.user.id, req.user.schoolname || '', req.user.district || '', body.first_name || '', body.last_name || '', body.father_name || '', body.grandfather_name || '', body.job_code || '', body.appointment_type || '', '', '', body.degree || '', body.gender || '', body.job_title || '', body.appointment_date || '', body.eval_date_prev || '', body.bust || '', body.grade || '', body.eval_date, body.eval_score, body.eval_result, body.remarks || '']
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطا در ثبت ارزیابی' }); }
});

app.delete('/api/evaluations/:id', authRequired, async (req, res) => {
  try {
    // ✅ مورد ۷: چک مالکیت
    if (req.user.role !== 'admin') {
      const check = await pool.query('SELECT userid FROM evaluations WHERE id = $1', [req.params.id]);
      if (check.rows.length === 0) return res.status(404).json({ error: 'یافت نشد' });
      if (String(check.rows[0].userid) !== String(req.user.id))
        return res.status(403).json({ error: 'دسترسی غیرمجاز' });
    }
    const result = await pool.query('DELETE FROM evaluations WHERE id = $1', [req.params.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'یافت نشد' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

// ═══════════════════════════════════════════════════════════
// API: معاشات و حاضری — مورد ۷: محدودیت دسترسی
// ═══════════════════════════════════════════════════════════
app.get('/api/salaries', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin' && req.user.role !== 'school') return res.status(403).json({ error: 'دسترسی غیرمجاز' });
    const conditions = []; const params = [];
    if (req.user.role === 'school') { conditions.push(`s.userid = $${params.length + 1}`); params.push(req.user.id); }
    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
    const result = await pool.query(
      `SELECT s.*, (CAST(r.data AS JSON)->>'firstName') AS first_name, (CAST(r.data AS JSON)->>'lastName') AS last_name, (CAST(r.data AS JSON)->>'fatherName') AS father_name, (CAST(r.data AS JSON)->>'jobCode') AS job_code, (CAST(r.data AS JSON)->>'jobTitle') AS job_title, a.present AS att_present, a.absent AS att_absent, a.sick AS att_sick 
       FROM salaries s LEFT JOIN records r ON r.id = s.record_id LEFT JOIN attendance a ON a.salary_id = s.id ${where} ORDER BY s.year DESC, s.id DESC`, params);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.get('/api/salaries/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin' && req.user.role !== 'school') return res.status(403).json({ error: 'دسترسی غیرمجاز' });
    const conditions = ['s.id = $1']; const params = [req.params.id];
    if (req.user.role === 'school') { conditions.push('s.userid = $2'); params.push(req.user.id); }

    const result = await pool.query(
      `SELECT s.*, (CAST(r.data AS JSON)->>'firstName') AS first_name, (CAST(r.data AS JSON)->>'lastName') AS last_name, (CAST(r.data AS JSON)->>'fatherName') AS father_name, (CAST(r.data AS JSON)->>'jobCode') AS job_code, (CAST(r.data AS JSON)->>'jobTitle') AS job_title 
       FROM salaries s LEFT JOIN records r ON r.id = s.record_id WHERE ${conditions.join(' AND ')}`, params);
    if (result.rows.length === 0) return res.status(404).json({ error: 'یافت نشد یا دسترسی ندارید' });
    const salary = result.rows[0];
    const attResult = await pool.query('SELECT * FROM attendance WHERE salary_id = $1', [req.params.id]);
    salary.attendance = attResult.rows[0] || {};
    res.json(salary);
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.post('/api/salaries', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'school') return res.status(403).json({ error: 'فقط مکتب' });
    const b = req.body || {};
    const recCheck = await pool.query('SELECT id FROM records WHERE id = $1 AND userid = $2', [b.record_id, req.user.id]);
    if (recCheck.rows.length === 0) return res.status(403).json({ error: 'این کارمند متعلق به مکتب شما نیست' });

    const totalEnt = toNum(b.total_entitlement), totalDed = toNum(b.total_deductions);
    const net = toNum(b.net_pay) || (totalEnt - totalDed);
    const result = await pool.query(
      `INSERT INTO salaries (record_id, userid, schoolname, district, year, month, bank_number, appointment_letter, base_salary, other_base, professional, other_professional, food, other_food, allowance, other_allowance, other_increase, total_entitlement, absence, tax, other_tax, tax_10, deductions, other_deductions, total_deductions, net_pay, status) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, 'draft') RETURNING id`,
      [parseInt(b.record_id), req.user.id, req.user.schoolname || '', req.user.district || '', b.year, b.month, b.bank_number || '', b.appointment_letter || '', toNum(b.base_salary), toNum(b.other_base), toNum(b.professional), toNum(b.other_professional), toNum(b.food), toNum(b.other_food), toNum(b.allowance), toNum(b.other_allowance), toNum(b.other_increase), totalEnt, toNum(b.absence), toNum(b.tax), toNum(b.other_tax), toNum(b.tax_10), toNum(b.deductions), toNum(b.other_deductions), totalDed, net]
    );
    res.json({ ok: true, id: result.rows[0].id });
  } catch (err) { console.error('POST salaries:', err.message); res.status(500).json({ error: 'خطا' }); }
});

app.delete('/api/salaries/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین' });
    await pool.query('DELETE FROM salaries WHERE id = $1', [req.params.id]);
    await pool.query('DELETE FROM attendance WHERE salary_id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.get('/api/attendance/:salary_id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin' && req.user.role !== 'school') return res.status(403).json({ error: 'دسترسی غیرمجاز' });
    const salaryId = parseInt(req.params.salary_id);
    if (req.user.role === 'school') {
      const check = await pool.query('SELECT id FROM salaries WHERE id = $1 AND userid = $2', [salaryId, req.user.id]);
      if (check.rows.length === 0) return res.status(404).json({ error: 'یافت نشد یا دسترسی ندارید' });
    }
    const result = await pool.query('SELECT * FROM attendance WHERE salary_id = $1', [salaryId]);
    res.json(result.rows[0] || null);
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.post('/api/attendance', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin' && req.user.role !== 'school') return res.status(403).json({ error: 'دسترسی غیرمجاز' });
    const b = req.body || {}; const salary_id = parseInt(b.salary_id);
    if (!salary_id) return res.status(400).json({ error: 'salary_id الزامی است' });

    if (req.user.role === 'school') {
      const check = await pool.query('SELECT id FROM salaries WHERE id = $1 AND userid = $2', [salary_id, req.user.id]);
      if (check.rows.length === 0) return res.status(403).json({ error: 'این حقوق متعلق به مکتب شما نیست' });
    }

    const total_days = toNum(b.present) + toNum(b.absent) + toNum(b.vacation) + toNum(b.sick) + toNum(b.essential) + toNum(b.maternity) + toNum(b.service_center) + toNum(b.service_province) + toNum(b.hajj) + toNum(b.holidays) + toNum(b.other);
    const existing = await pool.query('SELECT id FROM attendance WHERE salary_id = $1', [salary_id]);
    if (existing.rows.length > 0) {
      await pool.query(
        `UPDATE attendance SET present=$1, absent=$2, vacation=$3, sick=$4, essential=$5, maternity=$6, service_center=$7, service_province=$8, hajj=$9, holidays=$10, other=$11, total_days=$12, updatedat=CURRENT_TIMESTAMP WHERE salary_id=$13`,
        [toNum(b.present), toNum(b.absent), toNum(b.vacation), toNum(b.sick), toNum(b.essential), toNum(b.maternity), toNum(b.service_center), toNum(b.service_province), toNum(b.hajj), toNum(b.holidays), toNum(b.other), total_days, salary_id]
      );
    } else {
      await pool.query(
        `INSERT INTO attendance (salary_id, present, absent, vacation, sick, essential, maternity, service_center, service_province, hajj, holidays, other, total_days) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
        [salary_id, toNum(b.present), toNum(b.absent), toNum(b.vacation), toNum(b.sick), toNum(b.essential), toNum(b.maternity), toNum(b.service_center), toNum(b.service_province), toNum(b.hajj), toNum(b.holidays), toNum(b.other), total_days]
      );
    }
    res.json({ ok: true, total_days });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

// ═══════════════════════════════════════════════════════════
// API: مدیریت کاربران (مکاتب) — مورد ۱۰: حذف یکپارچه
// ═══════════════════════════════════════════════════════════
app.get('/api/users', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین' });
    const result = await pool.query("SELECT id, username, schoolname, district FROM users WHERE role = 'school' ORDER BY id DESC");
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.post('/api/users', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین' });
    const { username, password, district } = req.body || {};
    const schoolName = req.body.schoolName || req.body.schoolname;
    if (!username || !password || !schoolName) return res.status(400).json({ error: 'فیلدها الزامی است' });
    const hash = bcrypt.hashSync(password, 10);
    await pool.query(`INSERT INTO users (username, password, role, schoolname, district) VALUES ($1, $2, 'school', $3, $4)`, [username.trim(), hash, schoolName.trim(), (district || '').trim()]);
    res.json({ ok: true });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'نام کاربری تکراری است' });
    res.status(500).json({ error: 'خطا' });
  }
});

app.put('/api/users/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین' });
    const id = parseInt(req.params.id);
    const { username, password, district } = req.body || {};
    const schoolName = req.body.schoolName || req.body.schoolname;
    if (!username || !schoolName) return res.status(400).json({ error: 'فیلدها الزامی است' });

    let updateQuery = 'UPDATE users SET username = $1, schoolname = $2, district = $3';
    let params = [username.trim(), schoolName.trim(), (district || '').trim()];
    if (password && password.trim() !== '') {
      const hash = bcrypt.hashSync(password, 10);
      updateQuery += ', password = $' + (params.length + 1);
      params.push(hash);
    }
    updateQuery += ' WHERE id = $' + (params.length + 1);
    params.push(id);

    await pool.query(updateQuery, params);
    res.json({ ok: true });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'نام کاربری تکراری است' });
    res.status(500).json({ error: 'خطا در ویرایش مکتب' });
  }
});

// ✅ مورد ۱۰: حذف یکپارچه در Transaction
app.delete('/api/users/:id', authRequired, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین' });
  const id = parseInt(req.params.id);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`DELETE FROM attendance WHERE salary_id IN (SELECT id FROM salaries WHERE userid = $1)`, [id]);
    await client.query('DELETE FROM salaries WHERE userid = $1', [id]);
    await client.query('DELETE FROM evaluations WHERE userid = $1', [id]);
    await client.query('DELETE FROM school_settings_new WHERE userid = $1', [id]);
    await client.query('DELETE FROM records WHERE userid = $1', [id]);
    await client.query('DELETE FROM users WHERE id = $1', [id]);
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('DELETE /api/users:', err.message);
    res.status(500).json({ error: 'خطا در حذف یکپارچه' });
  } finally {
    client.release();
  }
});

// ═══════════════════════════════════════════════════════════
// مسیر پیش‌فرض
// ═══════════════════════════════════════════════════════════
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ═══════════════════════════════════════════════════════════
// ✅ مورد ۴: انتظار برای initDB قبل از listen
// ═══════════════════════════════════════════════════════════
(async () => {
  try {
    await initDB();
    app.listen(PORT, '0.0.0.0', () => {
      console.log('═══════════════════════════════════════');
      console.log('🚀 Server live on port ' + PORT);
      console.log('═══════════════════════════════════════');
    });
  } catch (err) {
    console.error('❌ خطای بحرانی در راه‌اندازی:', err);
    process.exit(1);
  }
})();
