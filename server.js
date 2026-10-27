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
console.log('🔐 Server V21.2 starting...');
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

const JOB_TITLES = [
  'آمر', 'مدیر', 'مدیر اجرائیه', 'معلم', 'سر معلم', 'معلم همکار',
  'معلم سپورت', 'معلم لابرانت', 'عضو علمی معلمان', 'عضو علمی مدرسین',
  'عضو مسلکی امور مالی و کارکنان', 'عضو مسلکی نظارت احصاییه و گزارش',
  'عضو مسلکی تاسیسات و ترمیمات', 'عضو مسلکی شوراها', 'کارکن خدماتی',
  'معتمد جنسی (تحویلدار)', 'سایر'
];
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
      await client.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          username TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          role TEXT NOT NULL,
          schoolname TEXT,
          district TEXT,
          createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      await client.query(`
        CREATE TABLE IF NOT EXISTS records (
          id SERIAL PRIMARY KEY,
          userid INTEGER,
          schoolname TEXT,
          district TEXT,
          data TEXT,
          status TEXT DEFAULT 'pending',
          createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      await client.query(`
        CREATE TABLE IF NOT EXISTS login_attempts (
          id SERIAL PRIMARY KEY,
          ip TEXT NOT NULL,
          username TEXT,
          success BOOLEAN DEFAULT FALSE,
          createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      await client.query(`
        CREATE TABLE IF NOT EXISTS school_settings (
          id SERIAL PRIMARY KEY,
          userid INTEGER UNIQUE NOT NULL,
          schoolname TEXT,
          district TEXT,
          time_type TEXT DEFAULT 'یک تایم',
          academic_member TEXT,
          branches_total INTEGER DEFAULT 0,
          branches_1_3 INTEGER DEFAULT 0,
          branches_4_6 INTEGER DEFAULT 0,
          branches_7_9 INTEGER DEFAULT 0,
          branches_10_12 INTEGER DEFAULT 0,
          budget_status TEXT DEFAULT 'عادی',
          extra_bust_count INTEGER DEFAULT 0,
          extra_bust_field TEXT,
          lack_bust_count INTEGER DEFAULT 0,
          lack_bust_field TEXT,
          createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updatedat TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      await client.query(`
        CREATE TABLE IF NOT EXISTS app_settings (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL,
          updatedat TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      await client.query(`
        INSERT INTO app_settings (key, value)
        VALUES ('evaluation_allowed', 'false')
        ON CONFLICT (key) DO NOTHING;
      `);
      await client.query(`
        CREATE TABLE IF NOT EXISTS evaluations (
          id SERIAL PRIMARY KEY,
          record_id INTEGER NOT NULL,
          userid INTEGER NOT NULL,
          schoolname TEXT,
          district TEXT,
          first_name TEXT,
          last_name TEXT,
          father_name TEXT,
          grandfather_name TEXT,
          job_code TEXT,
          employment_type TEXT,
          birth_year TEXT,
          service_duration TEXT,
          degree TEXT,
          gender TEXT,
          job_title TEXT,
          appointment_date TEXT,
          eval_date_prev TEXT,
          bust TEXT,
          grade TEXT,
          eval_date TEXT NOT NULL, 
          eval_score INTEGER NOT NULL,
          eval_result TEXT NOT NULL,
          createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      await client.query(`
        CREATE TABLE IF NOT EXISTS salaries (
          id SERIAL PRIMARY KEY,
          record_id INTEGER NOT NULL,
          userid INTEGER NOT NULL,
          schoolname TEXT,
          district TEXT,
          year TEXT NOT NULL,
          month TEXT NOT NULL,
          bank_number TEXT,
          appointment_letter TEXT,
          base_salary REAL DEFAULT 0,
          other_base REAL DEFAULT 0,
          professional REAL DEFAULT 0,
          other_professional REAL DEFAULT 0,
          food REAL DEFAULT 0,
          other_food REAL DEFAULT 0,
          allowance REAL DEFAULT 0,
          other_allowance REAL DEFAULT 0,
          other_increase REAL DEFAULT 0,
          total_entitlement REAL DEFAULT 0,
          absence REAL DEFAULT 0,
          tax REAL DEFAULT 0,
          other_tax REAL DEFAULT 0,
          tax_10 REAL DEFAULT 0,
          deductions REAL DEFAULT 0,
          other_deductions REAL DEFAULT 0,
          total_deductions REAL DEFAULT 0,
          net_pay REAL DEFAULT 0,
          status TEXT DEFAULT 'draft',
          createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updatedat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(record_id, year, month)
        );
      `);
      await client.query(`
        CREATE TABLE IF NOT EXISTS attendance (
          id SERIAL PRIMARY KEY,
          salary_id INTEGER NOT NULL UNIQUE,
          present REAL DEFAULT 0,
          absent REAL DEFAULT 0,
          vacation REAL DEFAULT 0,
          sick REAL DEFAULT 0,
          essential REAL DEFAULT 0,
          maternity REAL DEFAULT 0,
          service_center REAL DEFAULT 0,
          service_province REAL DEFAULT 0,
          hajj REAL DEFAULT 0,
          holidays REAL DEFAULT 0,
          other REAL DEFAULT 0,
          total_days REAL DEFAULT 0,
          createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updatedat TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      await client.query(`
        ALTER TABLE attendance ADD COLUMN IF NOT EXISTS holidays REAL DEFAULT 0;
      `);

      await client.query(`
        CREATE UNIQUE INDEX IF NOT EXISTS idx_records_jobcode
          ON records ((data::json->>'jobCode'))
          WHERE (data::json->>'jobCode') IS NOT NULL
            AND (data::json->>'jobCode') <> '';
      `).catch(e => console.log('⚠️ idx_records_jobcode:', e.message));

      await client.query(`
        CREATE UNIQUE INDEX IF NOT EXISTS idx_records_papertazkira
          ON records ((data::json->>'paperTazkira'))
          WHERE (data::json->>'paperTazkira') IS NOT NULL
            AND (data::json->>'paperTazkira') <> '';
      `).catch(e => console.log('⚠️ idx_records_papertazkira:', e.message));

      await client.query(`
        CREATE UNIQUE INDEX IF NOT EXISTS idx_records_etazkira
          ON records ((data::json->>'eTazkira'))
          WHERE (data::json->>'eTazkira') IS NOT NULL
            AND (data::json->>'eTazkira') <> '';
      `).catch(e => console.log('⚠️ idx_records_etazkira:', e.message));

      console.log('✅ جداول دیتابیس آماده شدند.');
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('⚠️ خطا در اتصال اولیه به دیتابیس:', err.message);
  }
}
initDB();

app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use((req, res, next) => {
  if (req.url.endsWith('.html') || req.url === '/' || req.url.startsWith('/?')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
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
  validate: { xForwardedForHeader: false, trustProxy: false },
  message: { error: '❌ تعداد تلاش‌های شما بیش از حد مجاز است.' }
});

function authRequired(req, res, next) {
  let token = req.cookies?.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token && req.query.token) token = req.query.token;
  if (!token) return res.status(401).json({ error: 'وارد نشده‌اید' });

  token = String(token).trim().replace(/^["']|["']$/g, '');

  try {
    const decoded = jwt.verify(token, JWT_SECRET_CONSTANT, {
      algorithms: [JWT_ALGORITHM]
    });
    req.user = decoded;
    next();
  } catch (e) {
    console.error('❌ Token verify error:', e.message);
    res.status(401).json({ error: 'توکن نامعتبر است' });
  }
}

async function logLoginAttempt(ip, username, success) {
  try {
    await pool.query(
      'INSERT INTO login_attempts (ip, username, success) VALUES ($1, $2, $3)',
      [ip || 'unknown', username || 'unknown', success]
    );
  } catch (e) {
    console.error('Log attempt error:', e.message);
  }
}

function normalizeDigits(str) {
  if (!str) return '';
  const p = '۰۱۲۳۴۵۶۷۸۹', a = '٠١٢٣٤٥٦٧٨٩';
  return String(str).split('').map(ch => {
    const pi = p.indexOf(ch); if (pi !== -1) return pi;
    const ai = a.indexOf(ch); if (ai !== -1) return ai;
    return ch;
  }).join('');
}

function validateShamsiDateServer(dateStr, fieldName) {
  if (!dateStr) return null;
  const cleaned = normalizeDigits(dateStr).trim().replace(/[.\-]/g, '/');
  const parts = cleaned.split('/').map(p => p.trim());
  if (parts.length !== 3) return `${fieldName} باید فرمت YYYY/MM/DD داشته باشد`;
  const p1 = parseInt(parts[0]);
  const p2 = parseInt(parts[1]);
  const p3 = parseInt(parts[2]);
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

function validateTazkiraServer(tazkiraStr) {
  if (!tazkiraStr) return null;
  const cleaned = normalizeDigits(tazkiraStr).trim();
  if (!ETAZKIRA_REGEX.test(cleaned)) return 'فرمت تذکره الکترونیکی اشتباه است';
  return null;
}

function validatePaperTazkiraServer(tazkiraStr) {
  if (!tazkiraStr) return null;
  const cleaned = normalizeDigits(tazkiraStr).trim().replace(/\s+/g, '');
  if (!PAPER_TAZKIRA_NUMERIC_REGEX.test(cleaned)) return 'فرمت تذکره کاغذی اشتباه است (فقط عدد)';
  return null;
}

function validateJobCodeServer(jobCode) {
  if (!jobCode) return null;
  const cleaned = normalizeDigits(jobCode).trim().replace(/\s+/g, '');
  if (!JOBCODE_REGEX.test(cleaned)) return 'فرمت کُد بست اشتباه است';
  return null;
}

function isValidJobCode(jobCode) {
  if (!jobCode) return false;
  const cleaned = normalizeDigits(jobCode).trim().replace(/\s+/g, '');
  return JOBCODE_REGEX.test(cleaned);
}

function isNoCodeTitle(jobTitle) { return NO_CODE_TITLES.some(t => jobTitle === t); }
function isServiceOrSupport(jobTitle) { return SERVICE_TITLES.includes(jobTitle); }
function isEducationExemptJob(jobTitle) { return EDUCATION_EXEMPT_JOBS.includes(String(jobTitle || '').trim()); }

async function checkJobCodeExact(jobCode, excludeRecordId = null) {
  if (!jobCode) return { exists: false };
  try {
    const normalizedCode = normalizeDigits(jobCode).trim().replace(/\s+/g, '');
    let sql = `SELECT r.id, r.userid, r.data, COALESCE(NULLIF(r.schoolname, ''), u.schoolname) AS schoolname, COALESCE(NULLIF(r.district, ''), u.district) AS district FROM records r LEFT JOIN users u ON u.id = r.userid WHERE r.data::json->>'jobCode' = $1`;
    const params = [normalizedCode];
    if (excludeRecordId) { params.push(excludeRecordId); sql += ` AND r.id <> $${params.length}`; }
    sql += ' LIMIT 1';
    const result = await pool.query(sql, params);
    if (result.rows.length === 0) return { exists: false };
    const row = result.rows[0];
    let info = {}; try { info = JSON.parse(row.data || '{}'); } catch (e) {}
    return { exists: true, recordId: row.id, userid: row.userid, schoolname: row.schoolname || 'نامشخص', district: row.district || '', employeeName: `${info.firstName || ''} ${info.lastName || ''}`.trim() || 'نامشخص' };
  } catch (err) { return { exists: false }; }
}

async function checkETazkiraExact(eTazkira, excludeRecordId = null) {
  if (!eTazkira) return { exists: false };
  try {
    const cleaned = normalizeDigits(eTazkira).trim().replace(/\s+/g, '');
    let sql = `SELECT r.id, r.userid, r.data, COALESCE(NULLIF(r.schoolname, ''), u.schoolname) AS schoolname, COALESCE(NULLIF(r.district, ''), u.district) AS district FROM records r LEFT JOIN users u ON u.id = r.userid WHERE r.data::json->>'eTazkira' = $1`;
    const params = [cleaned];
    if (excludeRecordId) { params.push(excludeRecordId); sql += ` AND r.id <> $${params.length}`; }
    sql += ' LIMIT 1';
    const result = await pool.query(sql, params);
    if (result.rows.length === 0) return { exists: false };
    const row = result.rows[0];
    let info = {}; try { info = JSON.parse(row.data || '{}'); } catch (e) {}
    return { exists: true, recordId: row.id, userid: row.userid, schoolname: row.schoolname || 'نامشخص', district: row.district || '', employeeName: `${info.firstName || ''} ${info.lastName || ''}`.trim() || 'نامشخص' };
  } catch (err) { return { exists: false }; }
}

async function checkPaperTazkiraExact(tazkiraCode, excludeRecordId = null) {
  if (!tazkiraCode) return { exists: false };
  try {
    const cleaned = normalizeDigits(tazkiraCode).trim().replace(/\s+/g, '');
    let sql = `SELECT r.id, r.userid, r.data, COALESCE(NULLIF(r.schoolname, ''), u.schoolname) AS schoolname, COALESCE(NULLIF(r.district, ''), u.district) AS district FROM records r LEFT JOIN users u ON u.id = r.userid WHERE r.data::json->>'paperTazkira' = $1`;
    const params = [cleaned];
    if (excludeRecordId) { params.push(excludeRecordId); sql += ` AND r.id <> $${params.length}`; }
    sql += ' LIMIT 1';
    const result = await pool.query(sql, params);
    if (result.rows.length === 0) return { exists: false };
    const row = result.rows[0];
    let info = {}; try { info = JSON.parse(row.data || '{}'); } catch (e) {}
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
      return res.json({ token, user: { id: 0, username: 'admin', role: 'admin', schoolname: 'ریاست معارف', district: 'مرکز هرات' }, redirect: '/admin.html' });
    }
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) { await logLoginAttempt(clientIp, username, false); return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است' }); }
    const user = result.rows[0];
    if (!bcrypt.compareSync(password, user.password)) { await logLoginAttempt(clientIp, username, false); return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است' }); }
    await logLoginAttempt(clientIp, username, true);
    const payload = { id: user.id, username: user.username, role: user.role };
    const token = jwt.sign(payload, JWT_SECRET_CONSTANT, { expiresIn: '7d', algorithm: JWT_ALGORITHM });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, schoolname: user.schoolname || '', district: user.district || '' }, redirect: '/school.html' });
  } catch (e) { res.status(500).json({ error: 'خطای سرور' }); }
});

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
    } else {
      const conditions = ['userid = $1']; const params = [req.user.id];
      if (search) { params.push(`%${search}%`); const i = params.length; conditions.push(`(schoolname ILIKE $${i} OR district ILIKE $${i} OR CAST(data AS TEXT) ILIKE $${i})`); }
      if (statusFilter === 'pending' || statusFilter === 'approved') { params.push(statusFilter); conditions.push(`status = $${params.length}`); }
      const where = 'WHERE ' + conditions.join(' AND ');
      result = await pool.query(`SELECT * FROM records ${where} ORDER BY id DESC`, params);
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

  if (enrollmentDate && graduationDate) {
    const en = validateShamsiDateServer(enrollmentDate, 'تاریخ شمولیت');
    const gr = validateShamsiDateServer(graduationDate, 'تاریخ فراغت');
    if (!en && !gr) {
      const normalize = (s) => normalizeDigits(s).trim().replace(/[.\-]/g, '/');
      const enParts = normalize(enrollmentDate).split('/').map(p => parseInt(p.trim()));
      const grParts = normalize(graduationDate).split('/').map(p => parseInt(p.trim()));
      let enYear, enMonth, enDay, grYear, grMonth, grDay;
      if (enParts[0] > 1000) { enYear = enParts[0]; enMonth = enParts[1]; enDay = enParts[2]; } else { enYear = enParts[2]; enMonth = enParts[1]; enDay = enParts[0]; }
      if (grParts[0] > 1000) { grYear = grParts[0]; grMonth = grParts[1]; grDay = grParts[2]; } else { grYear = grParts[2]; grMonth = grParts[1]; grDay = grParts[0]; }
      if (enYear > grYear || (enYear === grYear && enMonth > grMonth) || (enYear === grYear && enMonth === grMonth && enDay > grDay)) return '❌ تاریخ شمولیت نمی‌تواند بعد از تاریخ فراغت باشد';
    }
  }

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
  if (totalTeachingHours) { const num = Number(normalizeDigits(totalTeachingHours)); if (isNaN(num) || num < 0) return '❌ مجموعه ساعت درسی باید عددی مثبت باشد'; }
  if (teachingField && teachingField.length < 2) return '❌ رشته تدریس حداقل ۲ حرف';
  if (excludeId === null && !body.agreement) return '❌ شما باید موافقت خود را اعلام کنید';
  return null;
}

app.post('/api/records', authRequired, async (req, res) => {
  try {
    const body = req.body || {};
    const schoolName = body.schoolName || req.user.schoolname || '';
    const district = body.district || req.user.district || '';
    const settingsCheck = await pool.query('SELECT id FROM school_settings WHERE userid = $1', [req.user.id]);
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

// ⭐⭐⭐ تغییر مهم ۱: اضافه کردن PATCH برای اجازه ویرایش ⭐⭐⭐
app.patch('/api/records/:id/edit-permission', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین دسترسی دارد' });
    const id = req.params.id;
    const allowed = req.body?.editAllowed === true || req.body?.editAllowed === 'true';

    const check = await pool.query('SELECT * FROM records WHERE id = $1', [id]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'رکورد یافت نشد' });

    let info = {};
    try { info = JSON.parse(check.rows[0].data || '{}'); } catch (e) {}

    info.editAllowed = allowed;

    await pool.query('UPDATE records SET data = $1 WHERE id = $2', [JSON.stringify(info), id]);
    res.json({ ok: true, editAllowed: allowed });
  } catch (err) {
    console.error('edit-permission PATCH error:', err.message);
    res.status(500).json({ error: 'خطا در تغییر اجازه ویرایش' });
  }
});

// ⭐⭐⭐ تغییر مهم ۲: اصلاح PUT برای جلوگیری از خطای 400 ⭐⭐⭐
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

    // اگر ادمین فقط editAllowed فرستاده باشد، بدون اعتبارسنجی کل فیلدها آن را ذخیره کن
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
      if (originalData.editAllowed !== true && check.rows[0].editAllowed !== true) {
        return res.status(403).json({ error: '❌ ویرایش این کارمند هنوز از طرف ادمین اجازه داده نشده است' });
      }
      finalBody = {
        ...originalData,
        jobTitle: body.jobTitle !== undefined ? String(body.jobTitle).trim() : originalData.jobTitle,
        jobCode: body.jobCode !== undefined ? String(body.jobCode).trim() : originalData.jobCode,
        bust: body.bust !== undefined ? String(body.bust).trim() : originalData.bust,
        grade: body.grade !== undefined ? String(body.grade).trim() : originalData.grade,
        teachingField: body.teachingField !== undefined ? String(body.teachingField).trim() : (originalData.teachingField || originalData.subjectTeaching || ''),
        workshopStatus: body.workshopStatus !== undefined ? body.workshopStatus : originalData.workshopStatus,
        workshopTitle: body.workshopTitle !== undefined ? String(body.workshopTitle).trim() : originalData.workshopTitle,
        workshopDuration: body.workshopDuration !== undefined ? String(body.workshopDuration).trim() : originalData.workshopDuration,
        degree: body.degree !== undefined ? String(body.degree).trim() : originalData.degree,
        totalTeachingHours: body.totalTeachingHours !== undefined ? String(body.totalTeachingHours).trim() : originalData.totalTeachingHours,
        currentPositionDate: body.currentPositionDate !== undefined ? String(body.currentPositionDate).trim() : originalData.currentPositionDate,
        serviceStatus: body.serviceStatus !== undefined ? body.serviceStatus : (originalData.serviceStatus || 'نخیر'),
        serviceDistrict: body.serviceDistrict !== undefined ? String(body.serviceDistrict).trim() : (originalData.serviceDistrict || ''),
        serviceSchool: body.serviceSchool !== undefined ? String(body.serviceSchool).trim() : (originalData.serviceSchool || ''),
        serviceDate: body.serviceDate !== undefined ? String(body.serviceDate).trim() : (originalData.serviceDate || ''),
        editAllowed: originalData.editAllowed === true,
        agreement: true
      };
      delete finalBody.subjectTeaching;
    } else {
      finalBody = body;
      if (finalBody.subjectTeaching && !finalBody.teachingField) {
        finalBody.teachingField = finalBody.subjectTeaching;
        delete finalBody.subjectTeaching;
      }
      if (finalBody.editAllowed === undefined) finalBody.editAllowed = originalData.editAllowed === true;
    }

    if (finalBody.jobCode) {
      const dup = await checkJobCodeExact(finalBody.jobCode, id);
      if (dup.exists) return res.status(409).json(buildDuplicateResponse('jobcode', dup, req.user.id));
    }
    if (finalBody.eTazkira) {
      const fmtErr = validateTazkiraServer(finalBody.eTazkira); if (fmtErr) return res.status(400).json({ error: '❌ ' + fmtErr });
      const dupE = await checkETazkiraExact(finalBody.eTazkira, id); if (dupE.exists) return res.status(409).json(buildDuplicateResponse('etazkira', dupE, req.user.id));
    }
    if (finalBody.paperTazkira) {
      const fmtErr = validatePaperTazkiraServer(finalBody.paperTazkira); if (fmtErr) return res.status(400).json({ error: '❌ ' + fmtErr });
      const dupT = await checkPaperTazkiraExact(finalBody.paperTazkira, id); if (dupT.exists) return res.status(409).json(buildDuplicateResponse('tazkira', dupT, req.user.id));
    }

    const error = await validateRecordBody(finalBody, id);
    if (error) return res.status(400).json({ error });

    const schoolName = check.rows[0].schoolname || '';
    const district = check.rows[0].district || '';

    if (req.user.role === 'admin') {
      await pool.query(`UPDATE records SET schoolname = $1, district = $2, data = $3 WHERE id = $4`, [schoolName, district, JSON.stringify(finalBody), id]);
    } else {
      await pool.query(`UPDATE records SET schoolname = $1, district = $2, data = $3 WHERE id = $4 AND userid = $5`, [schoolName, district, JSON.stringify(finalBody), id, req.user.id]);
    }
    res.json({ ok: true });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: '❌ این کد بست یا تذکره قبلاً ثبت شده است', code: 'DUPLICATE_INDEX' });
    res.status(500).json({ error: 'خطا در ویرایش' });
  }
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
    const academicMember = String(body.academicMember || '').trim();
    if (!academicMember) return res.status(400).json({ error: 'نام عضو علمی الزامی است' });
    const schoolName = req.user.schoolname || '';
    const district = req.user.district || '';
    const check = await pool.query('SELECT id FROM school_settings WHERE userid = $1', [req.user.id]);
    if (check.rows.length > 0) {
      await pool.query(`UPDATE school_settings SET schoolname = $1, district = $2, academic_member = $3, updatedat = CURRENT_TIMESTAMP WHERE userid = $4`, [schoolName, district, academicMember, req.user.id]);
    } else {
      await pool.query(`INSERT INTO school_settings (userid, schoolname, district, academic_member) VALUES ($1, $2, $3, $4)`, [req.user.id, schoolName, district, academicMember]);
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.get('/api/all-school-settings', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین دسترسی دارد' });
    const result = await pool.query(`SELECT s.id, s.userid, s.time_type, s.academic_member, s.branches_total, s.budget_status, s.extra_bust_count, s.lack_bust_count, u.username, COALESCE(NULLIF(s.schoolname, ''), u.schoolname) AS schoolname, COALESCE(NULLIF(s.district, ''), u.district) AS district FROM school_settings s LEFT JOIN users u ON u.id = s.userid ORDER BY s.id DESC`);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.get('/api/evaluation-permission', authRequired, async (req, res) => {
  try {
    const result = await pool.query("SELECT value FROM app_settings WHERE key = 'evaluation_allowed'");
    const allowed = result.rows.length > 0 && result.rows[0].value === 'true';
    res.json({ allowed });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.post('/api/evaluation-permission', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین دسترسی دارد' });
    const { allowed } = req.body;
    const value = allowed ? 'true' : 'false';
    await pool.query(`INSERT INTO app_settings (key, value, updatedat) VALUES ('evaluation_allowed', $1, CURRENT_TIMESTAMP) ON CONFLICT (key) DO UPDATE SET value = $1, updatedat = CURRENT_TIMESTAMP`, [value]);
    res.json({ ok: true, allowed: allowed });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.get('/api/evaluations', authRequired, async (req, res) => {
  try {
    const conditions = []; const params = [];
    if (req.user.role === 'school') {
      conditions.push(`userid = $${params.length + 1}`); params.push(req.user.id);
    } else if (req.user.role === 'admin') {
      const { record_id, school, job_code, date_from, date_to } = req.query;
      if (record_id) { conditions.push(`record_id = $${params.length + 1}`); params.push(record_id); }
      if (school) { conditions.push(`schoolname = $${params.length + 1}`); params.push(school); }
      if (job_code) { conditions.push(`job_code ILIKE $${params.length + 1}`); params.push(`%${job_code}%`); }
      if (date_from) { conditions.push(`eval_date >= $${params.length + 1}`); params.push(date_from); }
      if (date_to) { conditions.push(`eval_date <= $${params.length + 1}`); params.push(date_to); }
    } else { return res.status(403).json({ error: 'دسترسی غیرمجاز' }); }
    const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
    const result = await pool.query(`SELECT * FROM evaluations ${where} ORDER BY id DESC`, params);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.post('/api/evaluations', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'school') return res.status(403).json({ error: 'فقط مکتب دسترسی دارد' });
    const permResult = await pool.query("SELECT value FROM app_settings WHERE key = 'evaluation_allowed'");
    const allowed = permResult.rows.length > 0 && permResult.rows[0].value === 'true';
    if (!allowed) return res.status(403).json({ error: '❌ هنوز از طرف آمریت اجازه داده نشده است' });

    const body = req.body || {};
    const { record_id, eval_date_prev, bust, grade, eval_date, eval_score, eval_result } = body;
    if (!record_id) return res.status(400).json({ error: 'کارمند انتخاب نشده است' });
    if (!bust) return res.status(400).json({ error: 'بست الزامی است' });
    if (!grade) return res.status(400).json({ error: 'قدم الزامی است' });
    if (!eval_date) return res.status(400).json({ error: 'تاریخ ارزیابی الزامی است' });
    if (!eval_score) return res.status(400).json({ error: 'نمره الزامی است' });
    if (!eval_result) return res.status(400).json({ error: 'نتیجه الزامی است' });

    const dateErr = validateShamsiDateServer(eval_date, 'تاریخ ارزیابی'); if (dateErr) return res.status(400).json({ error: dateErr });
    const cleanDate = normalizeDigits(eval_date).trim().replace(/[.\-]/g, '/');
    const scoreNum = Number(normalizeDigits(eval_score));
    if (isNaN(scoreNum) || scoreNum < 0 || scoreNum > 100) return res.status(400).json({ error: 'نمره باید بین ۰ تا ۱۰۰ باشد' });
    if (!['عالی', 'خوب', 'ضعیف'].includes(eval_result)) return res.status(400).json({ error: 'نتیجه معتبر نیست' });

    const recResult = await pool.query('SELECT * FROM records WHERE id = $1 AND userid = $2', [record_id, req.user.id]);
    if (recResult.rows.length === 0) return res.status(404).json({ error: 'کارمند یافت نشد' });
    const rec = recResult.rows[0];
    let info = {}; try { info = JSON.parse(rec.data); } catch (e) {}

    await pool.query(
      `INSERT INTO evaluations (record_id, userid, schoolname, district, first_name, last_name, father_name, grandfather_name, job_code, employment_type, birth_year, service_duration, degree, gender, job_title, appointment_date, eval_date_prev, bust, grade, eval_date, eval_score, eval_result) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)`,
      [record_id, req.user.id, rec.schoolname || '', rec.district || '', info.firstName || '', info.lastName || '', info.fatherName || '', info.grandfatherName || '', info.jobCode || '', info.employmentType || '', '', '', info.degree || '', info.gender || '', info.jobTitle || '', info.currentPositionDate || '', eval_date_prev || '', bust, grade, cleanDate, scoreNum, eval_result]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطا در ثبت ارزیابی' }); }
});

app.delete('/api/evaluations/:id', authRequired, async (req, res) => {
  try {
    const id = req.params.id;
    let check;
    if (req.user.role === 'admin') check = await pool.query('SELECT id FROM evaluations WHERE id = $1', [id]);
    else if (req.user.role === 'school') check = await pool.query('SELECT id FROM evaluations WHERE id = $1 AND userid = $2', [id, req.user.id]);
    else return res.status(403).json({ error: 'دسترسی غیرمجاز' });
    if (check.rows.length === 0) return res.status(404).json({ error: 'یافت نشد' });
    await pool.query('DELETE FROM evaluations WHERE id = $1', [id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.get('/api/salaries', authRequired, async (req, res) => {
  try {
    const { record_id, year, search } = req.query;
    const conditions = []; const params = [];
    if (req.user.role === 'school') { conditions.push(`s.userid = $${params.length + 1}`); params.push(req.user.id); }
    else if (req.user.role === 'admin') { /* admin: همه */ }
    else return res.status(403).json({ error: 'دسترسی غیرمجاز' });

    if (record_id) { conditions.push(`s.record_id = $${params.length + 1}`); params.push(record_id); }
    if (year) { conditions.push(`s.year = $${params.length + 1}`); params.push(year); }
    if (search && search.trim()) {
      const q = `%${search.trim()}%`; params.push(q); const i = params.length;
      conditions.push(`(s.schoolname ILIKE $${i} OR s.district ILIKE $${i} OR CAST(r.data AS TEXT) ILIKE $${i})`);
    }
    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
    const result = await pool.query(
      `SELECT s.*, r.data::json->>'firstName' AS first_name, r.data::json->>'lastName' AS last_name, r.data::json->>'fatherName' AS father_name, r.data::json->>'jobCode' AS job_code, r.data::json->>'jobTitle' AS job_title, a.present AS att_present, a.absent AS att_absent, a.sick AS att_sick 
       FROM salaries s LEFT JOIN records r ON r.id = s.record_id LEFT JOIN attendance a ON a.salary_id = s.id ${where} ORDER BY s.year DESC, s.id DESC`, params);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.post('/api/salaries', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'school') return res.status(403).json({ error: 'فقط مکتب' });
    const body = req.body || {};
    const record_id = parseInt(body.record_id);
    const year = String(body.year || '').trim();
    const month = String(body.month || '').trim();
    if (!record_id || !year || !month) return res.status(400).json({ error: 'فیلدها الزامی است' });
    const recCheck = await pool.query('SELECT * FROM records WHERE id = $1 AND userid = $2', [record_id, req.user.id]);
    if (recCheck.rows.length === 0) return res.status(404).json({ error: 'کارمند یافت نشد' });
    
    const num = (v) => Number(normalizeDigits(v || 0)) || 0;
    const totalEnt = num(body.total_entitlement);
    const totalDed = num(body.total_deductions);
    const net = num(body.net_pay) || (totalEnt - totalDed);

    const result = await pool.query(
      `INSERT INTO salaries (record_id, userid, schoolname, district, year, month, bank_number, appointment_letter, base_salary, other_base, professional, other_professional, food, other_food, allowance, other_allowance, other_increase, total_entitlement, absence, tax, other_tax, tax_10, deductions, other_deductions, total_deductions, net_pay, status) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, 'draft') RETURNING id`,
      [record_id, req.user.id, recCheck.rows[0].schoolname || '', recCheck.rows[0].district || '', year, month, String(body.bank_number || '').trim(), String(body.appointment_letter || '').trim(), num(body.base_salary), num(body.other_base), num(body.professional), num(body.other_professional), num(body.food), num(body.other_food), num(body.allowance), num(body.other_allowance), num(body.other_increase), totalEnt, num(body.absence), num(body.tax), num(body.other_tax), num(body.tax_10), num(body.deductions), num(body.other_deductions), totalDed, net]
    );
    res.json({ ok: true, id: result.rows[0].id });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.post('/api/attendance', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'school' && req.user.role !== 'admin') return res.status(403).json({ error: 'دسترسی غیرمجاز' });
    const body = req.body || {};
    const salary_id = parseInt(body.salary_id);
    if (!salary_id) return res.status(400).json({ error: 'salary_id الزامی است' });
    const sc = await pool.query('SELECT * FROM salaries WHERE id = $1', [salary_id]);
    if (sc.rows.length === 0) return res.status(404).json({ error: 'یافت نشد' });
    
    const num = (v) => Number(normalizeDigits(v || 0)) || 0;
    const total_days = num(body.present) + num(body.absent) + num(body.vacation) + num(body.sick) + num(body.essential) + num(body.maternity) + num(body.service_center) + num(body.service_province) + num(body.hajj) + num(body.holidays) + num(body.other);

    const existing = await pool.query('SELECT id FROM attendance WHERE salary_id = $1', [salary_id]);
    if (existing.rows.length > 0) {
      await pool.query(`UPDATE attendance SET present = $1, absent = $2, vacation = $3, sick = $4, essential = $5, maternity = $6, service_center = $7, service_province = $8, hajj = $9, holidays = $10, other = $11, total_days = $12, updatedat = CURRENT_TIMESTAMP WHERE salary_id = $13`,
        [num(body.present), num(body.absent), num(body.vacation), num(body.sick), num(body.essential), num(body.maternity), num(body.service_center), num(body.service_province), num(body.hajj), num(body.holidays), num(body.other), total_days, salary_id]);
    } else {
      await pool.query(`INSERT INTO attendance (salary_id, present, absent, vacation, sick, essential, maternity, service_center, service_province, hajj, holidays, other, total_days) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
        [salary_id, num(body.present), num(body.absent), num(body.vacation), num(body.sick), num(body.essential), num(body.maternity), num(body.service_center), num(body.service_province), num(body.hajj), num(body.holidays), num(body.other), total_days]);
    }
    res.json({ ok: true, total_days });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
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
    await pool.query('DELETE FROM evaluations WHERE record_id = $1', [req.params.id]);
    await pool.query('DELETE FROM salaries WHERE record_id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

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
    const { username, password, schoolName, district } = req.body || {};
    if (!username || !password || !schoolName) return res.status(400).json({ error: 'فیلدها الزامی است' });
    const hash = bcrypt.hashSync(password, 10);
    await pool.query(`INSERT INTO users (username, password, role, schoolname, district) VALUES ($1, $2, 'school', $3, $4)`, [username.trim(), hash, schoolName.trim(), (district || '').trim()]);
    res.json({ ok: true });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'نام کاربری تکراری است' });
    res.status(500).json({ error: 'خطا' });
  }
});

app.delete('/api/users/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین' });
    const result = await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'یافت نشد' });
    const userRecords = await pool.query('SELECT id FROM records WHERE userid = $1', [req.params.id]);
    for (const r of userRecords.rows) {
      await pool.query('DELETE FROM evaluations WHERE record_id = $1', [r.id]);
      await pool.query('DELETE FROM salaries WHERE record_id = $1', [r.id]);
    }
    await pool.query('DELETE FROM records WHERE userid = $1', [req.params.id]);
    await pool.query('DELETE FROM school_settings WHERE userid = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطا' }); }
});

app.get('*', (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('═══════════════════════════════════════');
  console.log('🚀 Server V21.2 live on port ' + PORT);
  console.log('═══════════════════════════════════════');
});
