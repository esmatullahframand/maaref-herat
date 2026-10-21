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
console.log('🔐 Server V17.2 starting...');
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
const SERVICE_KEYWORDS = ['ملازم', 'شب باش', 'شب‌باش', 'شبباش', 'معتمد جنسی', 'معتمد', 'اجیر خدماتی', 'اجیر', 'خدماتی', 'خدمه', 'نگهبان', 'آشپز', 'کارگر', 'راننده', 'باغبان', 'سرایدار'];

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
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
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
  if (parts.length !== 3) {
    return `${fieldName} باید فرمت YYYY/MM/DD یا DD/MM/YYYY داشته باشد`;
  }
  const p1 = parseInt(parts[0]);
  const p2 = parseInt(parts[1]);
  const p3 = parseInt(parts[2]);
  if (isNaN(p1) || isNaN(p2) || isNaN(p3)) {
    return `${fieldName} باید فقط شامل اعداد باشد`;
  }
  let year, month, day;
  if (parts[0].length === 4 || (p1 >= 1300 && p1 <= 1450)) {
    year = p1; month = p2; day = p3;
  } else if (parts[2].length === 4 || (p3 >= 1300 && p3 <= 1450)) {
    year = p3; month = p2; day = p1;
  } else {
    return `${fieldName}: سال باید بین ۱۳۰۰ تا ۱۴۵۰ باشد`;
  }
  if (year < 1300 || year > 1450) return `${fieldName}: سال باید بین ۱۳۰۰ تا ۱۴۵۰ باشد`;
  if (month < 1 || month > 12) return `${fieldName}: ماه باید بین ۱ تا ۱۲ باشد`;
  let maxDay = 31;
  if (month >= 7 && month <= 11) maxDay = 30;
  if (month === 12) maxDay = 29;
  if (day < 1 || day > maxDay) return `${fieldName}: روز باید بین ۱ تا ${maxDay} باشد`;
  return null;
}

function validateTazkiraServer(tazkiraStr) {
  if (!tazkiraStr) return null;
  const cleaned = normalizeDigits(tazkiraStr).trim();
  const pattern = /^\d+-\d+-\d+$/;
  if (!pattern.test(cleaned)) {
    return 'فرمت تذکره الکترونیکی باید XXXXX-XXXXX-XXXX باشد';
  }
  return null;
}

function validateJobCodeServer(jobCode) {
  if (!jobCode) return null;
  const cleaned = normalizeDigits(jobCode).trim().replace(/\s+/g, '');
  const pattern = /^27-\d{1,3}-\d{1,3}-\d{3,6}$/;
  if (!pattern.test(cleaned)) {
    return 'فرمت کُد بست باید 27-XX-XX-XXXXX باشد';
  }
  return null;
}

function isValidJobCode(jobCode) {
  if (!jobCode) return false;
  const cleaned = normalizeDigits(jobCode).trim().replace(/\s+/g, '');
  return /^27-\d{1,3}-\d{1,3}-\d{3,6}$/.test(cleaned);
}

function isNoCodeTitle(jobTitle) {
  return NO_CODE_TITLES.some(t => jobTitle === t);
}

function isServiceOrSupport(jobTitle) {
  if (!jobTitle) return false;
  return SERVICE_TITLES.includes(jobTitle);
}

async function isJobCodeDuplicate(jobCode, excludeRecordId = null) {
  if (!jobCode) return { duplicate: false, schoolname: null };
  try {
    const normalizedCode = normalizeDigits(jobCode).trim().replace(/\s+/g, '');
    let result;
    if (excludeRecordId) {
      result = await pool.query(
        `SELECT r.id, COALESCE(NULLIF(r.schoolname, ''), u.schoolname) AS schoolname
         FROM records r LEFT JOIN users u ON u.id = r.userid
         WHERE CAST(r.data AS TEXT) LIKE $1 AND r.id != $2 LIMIT 1`,
        [`%"jobCode":"${normalizedCode}"%`, excludeRecordId]
      );
    } else {
      result = await pool.query(
        `SELECT r.id, COALESCE(NULLIF(r.schoolname, ''), u.schoolname) AS schoolname
         FROM records r LEFT JOIN users u ON u.id = r.userid
         WHERE CAST(r.data AS TEXT) LIKE $1 LIMIT 1`,
        [`%"jobCode":"${normalizedCode}"%`]
      );
    }
    if (result.rows.length > 0) {
      return { duplicate: true, schoolname: result.rows[0].schoolname || 'نامشخص' };
    }
    return { duplicate: false, schoolname: null };
  } catch (err) {
    console.error('Duplicate check error:', err.message);
    return { duplicate: false, schoolname: null };
  }
}

// ═══════════════════════════════════════════════════════════
// لاگین
// ═══════════════════════════════════════════════════════════
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const clientIp = req.ip || 'unknown';
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'نام کاربری و رمز عبور الزامی است' });
    }

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
      await logLoginAttempt(clientIp, username, true);
      const payload = { id: 0, username: 'admin', role: 'admin' };
      const token = jwt.sign(payload, JWT_SECRET_CONSTANT, { expiresIn: '7d', algorithm: JWT_ALGORITHM });
      return res.json({
        token,
        user: { id: 0, username: 'admin', role: 'admin', schoolname: 'ریاست معارف', district: 'مرکز هرات' },
        redirect: '/admin.html'
      });
    }

    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      await logLoginAttempt(clientIp, username, false);
      return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است' });
    }
    const user = result.rows[0];
    if (!bcrypt.compareSync(password, user.password)) {
      await logLoginAttempt(clientIp, username, false);
      return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است' });
    }
    await logLoginAttempt(clientIp, username, true);
    const payload = { id: user.id, username: user.username, role: user.role };
    const token = jwt.sign(payload, JWT_SECRET_CONSTANT, { expiresIn: '7d', algorithm: JWT_ALGORITHM });
    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role, schoolname: user.schoolname || '', district: user.district || '' },
      redirect: '/school.html'
    });
  } catch (e) {
    console.error('Login Error:', e);
    res.status(500).json({ error: 'خطای سرور در فرآیند ورود' });
  }
});

// ═══════════════════════════════════════════════════════════
// GET /api/records (با قابلیت جستجوی کد بست و جستجوی عمومی)
// ═══════════════════════════════════════════════════════════
app.get('/api/records', authRequired, async (req, res) => {
  try {
    const search = (req.query.search || '').trim();
    const statusFilter = (req.query.status || '').trim();
    const schoolnameFilter = (req.query.schoolname || '').trim();
    let result;

    if (req.user.role === 'admin') {
      const conditions = [];
      const params = [];
      if (search) {
        params.push(`%${search}%`);
        const i = params.length;
        conditions.push(`(schoolname ILIKE $${i} OR district ILIKE $${i} OR CAST(data AS TEXT) ILIKE $${i})`);
      }
      if (statusFilter === 'pending' || statusFilter === 'approved') {
        params.push(statusFilter);
        conditions.push(`status = $${params.length}`);
      }
      if (schoolnameFilter) {
        params.push(schoolnameFilter);
        conditions.push(`schoolname = $${params.length}`);
      }
      const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
      result = await pool.query(`SELECT * FROM records ${where} ORDER BY id DESC`, params);
    } else {
      const conditions = ['userid = $1'];
      const params = [req.user.id];
      if (search) {
        params.push(`%${search}%`);
        const i = params.length;
        conditions.push(`(schoolname ILIKE $${i} OR district ILIKE $${i} OR CAST(data AS TEXT) ILIKE $${i})`);
      }
      if (statusFilter === 'pending' || statusFilter === 'approved') {
        params.push(statusFilter);
        conditions.push(`status = $${params.length}`);
      }
      const where = 'WHERE ' + conditions.join(' AND ');
      result = await pool.query(`SELECT * FROM records ${where} ORDER BY id DESC`, params);
    }

    const rows = result.rows.map((r) => {
      let parsed = {};
      try { parsed = JSON.parse(r.data); } catch (e) {}
      return { ...r, data: parsed, status: r.status };
    });
    res.json(rows);
  } catch (err) {
    console.error('Records GET Error:', err.message);
    res.status(500).json({ error: 'خطا در واکشی اطلاعات دیتابیس' });
  }
});

// ═══════════════════════════════════════════════════════════
// اعتبارسنجی رکورد
// ═══════════════════════════════════════════════════════════
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

  if (!job) return 'عنوان بست الزامی است';
  if (!JOB_TITLES.includes(job)) return '❌ عنوان بست انتخابی معتبر نیست';
  if (!firstName) return 'اسم الزامی است';
  if (!fatherName) return 'ولد الزامی است';
  if (!grandfatherName) return 'ولدیت الزامی است';

  const isContract = isNoCodeTitle(job);
  const isService = isServiceOrSupport(job);

  if (isContract) {
    if (!eTazkira && !paperTazkira) return 'حداقل یکی از تذکره‌ها الزامی است';
    if (!birthDate) return 'تاریخ تولد الزامی است';
  } else {
    if (!ethnicity) return 'قومیت الزامی است';
    if (!phone) return 'شماره تماس الزامی است';
    if (!eTazkira && !paperTazkira) return 'حداقل یکی از تذکره‌ها الزامی است';
    if (!jobCode) return 'کُد بست الزامی است';
    if (!isValidJobCode(jobCode)) return '❌ فرمت کُد بست اشتباه است';
    const dupResult = await isJobCodeDuplicate(jobCode, excludeId);
    if (dupResult.duplicate) {
      return `❌ کُد بست قبلاً در مکتب «${dupResult.schoolname}» ثبت شده است.`;
    }
    if (!birthDate) return 'تاریخ تولد الزامی است';
    if (!firstAppointmentDate) return 'تاریخ اولین تقرر الزامی است';
    if (!currentPositionDate) return 'تاریخ تقرر فعلی الزامی است';
    if (!isService) {
      if (!degree) return 'درجه تحصیلی الزامی است';
      if (!majorVal) return 'رشته تحصیلی الزامی است';
      if (majorVal.length < 2) return 'رشته تحصیلی حداقل ۲ حرف';
      if (!eduInstituteVal) return 'مرجع تعلیمی الزامی است';
      if (!eduInstituteLocationVal) return 'موقعیت مرجع الزامی است';
      if (!enrollmentDate) return 'تاریخ شمولیت الزامی است';
      if (!graduationDate) return 'تاریخ فراغت الزامی است';
    }
  }

  if (jobCode) {
    const err = validateJobCodeServer(jobCode);
    if (err) return '❌ ' + err;
  }
  if (eTazkira) {
    const err = validateTazkiraServer(eTazkira);
    if (err) return '❌ ' + err;
  }
  if (birthDate) {
    const err = validateShamsiDateServer(birthDate, 'تاریخ تولد');
    if (err) return '❌ ' + err;
  }
  if (firstAppointmentDate) {
    const err = validateShamsiDateServer(firstAppointmentDate, 'تاریخ اولین تقرر');
    if (err) return '❌ ' + err;
  }
  if (currentPositionDate) {
    const err = validateShamsiDateServer(currentPositionDate, 'تاریخ تقرر فعلی');
    if (err) return '❌ ' + err;
  }
  if (enrollmentDate) {
    const err = validateShamsiDateServer(enrollmentDate, 'تاریخ شمولیت');
    if (err) return '❌ ' + err;
  }
  if (graduationDate) {
    const err = validateShamsiDateServer(graduationDate, 'تاریخ فراغت');
    if (err) return '❌ ' + err;
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
    const dateErr = validateShamsiDateServer(body.serviceDate, 'تاریخ خدمتی');
    if (dateErr) return '❌ ' + dateErr;
  }

  const totalTeachingHours = String(body.totalTeachingHours || '').trim();
  if (totalTeachingHours) {
    const num = Number(normalizeDigits(totalTeachingHours));
    if (isNaN(num) || num < 0) return '❌ مجموعه ساعت درسی باید عددی مثبت باشد';
  }

  if (excludeId === null && !body.agreement) return '❌ شما باید موافقت خود را اعلام کنید';
  return null;
}

// ═══════════════════════════════════════════════════════════
// POST /api/records
// ═══════════════════════════════════════════════════════════
app.post('/api/records', authRequired, async (req, res) => {
  try {
    const body = req.body || {};
    const schoolName = body.schoolName || req.user.schoolname || '';
    const district = body.district || req.user.district || '';

    const settingsCheck = await pool.query('SELECT id FROM school_settings WHERE userid = $1', [req.user.id]);
    if (settingsCheck.rows.length === 0) {
      return res.status(400).json({ error: '❌ لطفاً ابتدا اطلاعات مکتب خود را ثبت کنید' });
    }

    const error = await validateRecordBody(body, null);
    if (error) return res.status(400).json({ error });

    await pool.query(
      `INSERT INTO records (userid, schoolname, district, data, status)
       VALUES ($1, $2, $3, $4, 'pending')`,
      [req.user.id, schoolName, district, JSON.stringify(body)]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('Records POST Error:', err.message);
    res.status(500).json({ error: 'خطا در ثبت رکورد: ' + err.message });
  }
});

app.post('/api/check-jobcode', authRequired, async (req, res) => {
  try {
    const { jobCode } = req.body || {};
    if (!jobCode) return res.json({ exists: false });
    const normalizedCode = normalizeDigits(jobCode).trim().replace(/\s+/g, '');
    const result = await pool.query(
      `SELECT r.id, COALESCE(NULLIF(r.schoolname, ''), u.schoolname) AS schoolname
       FROM records r LEFT JOIN users u ON u.id = r.userid
       WHERE CAST(r.data AS TEXT) LIKE $1 LIMIT 1`,
      [`%"jobCode":"${normalizedCode}"%`]
    );
    if (result.rows.length > 0) {
      return res.json({ exists: true, schoolname: result.rows[0].schoolname || 'نامشخص' });
    }
    res.json({ exists: false });
  } catch (err) {
    console.error('Check jobcode error:', err.message);
    res.status(500).json({ error: 'خطا در بررسی کد بست' });
  }
});

// ═══════════════════════════════════════════════════════════
// PUT /api/records/:id
// ═══════════════════════════════════════════════════════════
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

    let finalBody;
    if (req.user.role === 'school') {
      const originalData = JSON.parse(check.rows[0].data || '{}');
      finalBody = {
        jobTitle: body.jobTitle !== undefined ? String(body.jobTitle).trim() : originalData.jobTitle,
        bust: body.bust !== undefined ? String(body.bust).trim() : originalData.bust,
        grade: body.grade !== undefined ? String(body.grade).trim() : originalData.grade,
        subjectTeaching: body.subjectTeaching !== undefined ? String(body.subjectTeaching).trim() : originalData.subjectTeaching,
        workshopStatus: body.workshopStatus !== undefined ? body.workshopStatus : originalData.workshopStatus,
        workshopTitle: body.workshopTitle !== undefined ? String(body.workshopTitle).trim() : originalData.workshopTitle,
        workshopDuration: body.workshopDuration !== undefined ? String(body.workshopDuration).trim() : originalData.workshopDuration,
        totalTeachingHours: body.totalTeachingHours !== undefined ? String(body.totalTeachingHours).trim() : originalData.totalTeachingHours,
        serviceStatus: body.serviceStatus !== undefined ? body.serviceStatus : (originalData.serviceStatus || 'نخیر'),
        serviceDistrict: body.serviceDistrict !== undefined ? String(body.serviceDistrict).trim() : (originalData.serviceDistrict || ''),
        serviceSchool: body.serviceSchool !== undefined ? String(body.serviceSchool).trim() : (originalData.serviceSchool || ''),
        serviceDate: body.serviceDate !== undefined ? String(body.serviceDate).trim() : (originalData.serviceDate || ''),
        firstName: originalData.firstName,
        lastName: originalData.lastName,
        fatherName: originalData.fatherName,
        grandfatherName: originalData.grandfatherName,
        eTazkira: originalData.eTazkira,
        paperTazkira: originalData.paperTazkira,
        tazkiraPage: originalData.tazkiraPage,
        tazkiraVolume: originalData.tazkiraVolume,
        ethnicity: originalData.ethnicity,
        gender: originalData.gender,
        birthDate: originalData.birthDate,
        birthPlace: originalData.birthPlace,
        originAddress: originalData.originAddress,
        currentAddress: originalData.currentAddress,
        firstAppointmentDate: originalData.firstAppointmentDate,
        phone: originalData.phone,
        disability: originalData.disability,
        positionType: originalData.positionType,
        employmentType: originalData.employmentType,
        jobCode: originalData.jobCode,
        degree: originalData.degree,
        major: originalData.major,
        eduInstitute: originalData.eduInstitute,
        eduInstituteLocation: originalData.eduInstituteLocation,
        enrollmentDate: originalData.enrollmentDate,
        graduationDate: originalData.graduationDate,
        agreement: true
      };
    } else {
      finalBody = body;
    }

    const error = await validateRecordBody(finalBody, id);
    if (error) return res.status(400).json({ error });

    const schoolName = check.rows[0].schoolname || '';
    const district = check.rows[0].district || '';

    if (req.user.role === 'admin') {
      await pool.query(`UPDATE records SET schoolname = $1, district = $2, data = $3 WHERE id = $4`,
        [schoolName, district, JSON.stringify(finalBody), id]);
    } else {
      await pool.query(`UPDATE records SET schoolname = $1, district = $2, data = $3 WHERE id = $4 AND userid = $5`,
        [schoolName, district, JSON.stringify(finalBody), id, req.user.id]);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('Records PUT Error:', err.message);
    res.status(500).json({ error: 'خطا در ویرایش: ' + err.message });
  }
});

// ═══════════════════════════════════════════════════════════
// school_settings
// ═══════════════════════════════════════════════════════════
app.get('/api/school-settings', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'school') return res.status(403).json({ error: 'فقط مکتب دسترسی دارد' });
    const result = await pool.query('SELECT * FROM school_settings WHERE userid = $1', [req.user.id]);
    if (result.rows.length === 0) return res.json({ exists: false, settings: null });
    res.json({ exists: true, settings: result.rows[0] });
  } catch (err) {
    console.error('School settings GET Error:', err.message);
    res.status(500).json({ error: 'خطا در دریافت تنظیمات' });
  }
});

app.post('/api/school-settings', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'school') return res.status(403).json({ error: 'فقط مکتب دسترسی دارد' });
    const body = req.body || {};
    const timeType = String(body.timeType || 'یک تایم').trim();
    const academicMember = String(body.academicMember || '').trim();
    const branchesTotal = parseInt(normalizeDigits(body.branchesTotal || 0)) || 0;
    const branches13 = parseInt(normalizeDigits(body.branches13 || 0)) || 0;
    const branches46 = parseInt(normalizeDigits(body.branches46 || 0)) || 0;
    const branches79 = parseInt(normalizeDigits(body.branches79 || 0)) || 0;
    const branches1012 = parseInt(normalizeDigits(body.branches1012 || 0)) || 0;
    const budgetStatus = String(body.budgetStatus || 'عادی').trim();
    const extraBustCount = parseInt(normalizeDigits(body.extraBustCount || 0)) || 0;
    const extraBustField = String(body.extraBustField || '').trim();
    const lackBustCount = parseInt(normalizeDigits(body.lackBustCount || 0)) || 0;
    const lackBustField = String(body.lackBustField || '').trim();

    if (!academicMember) return res.status(400).json({ error: 'نام و تخلص عضو علمی الزامی است' });
    if (!['یک تایم', 'دو تایم', 'سه تایم'].includes(timeType)) return res.status(400).json({ error: 'نوع تایم معتبر نیست' });
    if (!['عادی', 'اضافه بست', 'کمبود بست'].includes(budgetStatus)) return res.status(400).json({ error: 'وضعیت بست معتبر نیست' });
    if (budgetStatus === 'اضافه بست') {
      if (!extraBustCount || extraBustCount <= 0) return res.status(400).json({ error: 'تعداد اضافه بست الزامی است' });
      if (!extraBustField) return res.status(400).json({ error: 'رشته اضافه بست الزامی است' });
    }
    if (budgetStatus === 'کمبود بست') {
      if (!lackBustCount || lackBustCount <= 0) return res.status(400).json({ error: 'تعداد کمبود بست الزامی است' });
      if (!lackBustField) return res.status(400).json({ error: 'رشته کمبود بست الزامی است' });
    }

    const schoolName = req.user.schoolname || '';
    const district = req.user.district || '';
    const check = await pool.query('SELECT id FROM school_settings WHERE userid = $1', [req.user.id]);

    if (check.rows.length > 0) {
      await pool.query(
        `UPDATE school_settings SET
          schoolname = $1, district = $2, time_type = $3, academic_member = $4,
          branches_total = $5, branches_1_3 = $6, branches_4_6 = $7,
          branches_7_9 = $8, branches_10_12 = $9,
          budget_status = $10, extra_bust_count = $11, extra_bust_field = $12,
          lack_bust_count = $13, lack_bust_field = $14,
          updatedat = CURRENT_TIMESTAMP WHERE userid = $15`,
        [schoolName, district, timeType, academicMember,
         branchesTotal, branches13, branches46, branches79, branches1012,
         budgetStatus, extraBustCount, extraBustField,
         lackBustCount, lackBustField, req.user.id]
      );
    } else {
      await pool.query(
        `INSERT INTO school_settings (
          userid, schoolname, district, time_type, academic_member,
          branches_total, branches_1_3, branches_4_6, branches_7_9, branches_10_12,
          budget_status, extra_bust_count, extra_bust_field,
          lack_bust_count, lack_bust_field
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
        [req.user.id, schoolName, district, timeType, academicMember,
         branchesTotal, branches13, branches46, branches79, branches1012,
         budgetStatus, extraBustCount, extraBustField, lackBustCount, lackBustField]
      );
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('School settings POST Error:', err.message);
    res.status(500).json({ error: 'خطا در ذخیره: ' + err.message });
  }
});

app.get('/api/all-school-settings', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین دسترسی دارد' });
    const result = await pool.query(
      `SELECT 
         s.id, s.userid, s.time_type, s.academic_member,
         s.branches_total, s.branches_1_3, s.branches_4_6, s.branches_7_9, s.branches_10_12,
         s.budget_status, s.extra_bust_count, s.extra_bust_field,
         s.lack_bust_count, s.lack_bust_field, s.createdat, s.updatedat,
         u.username,
         COALESCE(NULLIF(s.schoolname, ''), u.schoolname) AS schoolname,
         COALESCE(NULLIF(s.district, ''), u.district) AS district
       FROM school_settings s LEFT JOIN users u ON u.id = s.userid ORDER BY s.id DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('All school settings Error:', err.message);
    res.status(500).json({ error: 'خطا در دریافت' });
  }
});

// ═══════════════════════════════════════════════════════════
// ⭐ تنظیمات عمومی (اجازه ارزیابی)
// ═══════════════════════════════════════════════════════════
app.get('/api/evaluation-permission', authRequired, async (req, res) => {
  try {
    const result = await pool.query("SELECT value FROM app_settings WHERE key = 'evaluation_allowed'");
    const allowed = result.rows.length > 0 && result.rows[0].value === 'true';
    res.json({ allowed });
  } catch (err) {
    console.error('Eval permission GET error:', err.message);
    res.status(500).json({ error: 'خطا' });
  }
});

app.post('/api/evaluation-permission', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین دسترسی دارد' });
    const { allowed } = req.body;
    const value = allowed ? 'true' : 'false';
    await pool.query(
      `INSERT INTO app_settings (key, value, updatedat) 
       VALUES ('evaluation_allowed', $1, CURRENT_TIMESTAMP)
       ON CONFLICT (key) DO UPDATE SET value = $1, updatedat = CURRENT_TIMESTAMP`,
      [value]
    );
    res.json({ ok: true, allowed: allowed });
  } catch (err) {
    console.error('Eval permission POST error:', err.message);
    res.status(500).json({ error: 'خطا' });
  }
});

// ═══════════════════════════════════════════════════════════
// ⭐ ارزیابی‌ها
// ═══════════════════════════════════════════════════════════
app.get('/api/evaluations', authRequired, async (req, res) => {
  try {
    const conditions = [];
    const params = [];

    if (req.user.role === 'school') {
      conditions.push(`userid = $${params.length + 1}`);
      params.push(req.user.id);
    } else if (req.user.role === 'admin') {
      const recordId = req.query.record_id;
      const schoolFilter = req.query.school;
      const jobCodeSearch = req.query.job_code;
      const dateFrom = req.query.date_from;
      const dateTo = req.query.date_to;

      if (recordId) {
        conditions.push(`record_id = $${params.length + 1}`);
        params.push(recordId);
      }
      if (schoolFilter) {
        conditions.push(`schoolname = $${params.length + 1}`);
        params.push(schoolFilter);
      }
      if (jobCodeSearch) {
        conditions.push(`job_code ILIKE $${params.length + 1}`);
        params.push(`%${jobCodeSearch}%`);
      }
      if (dateFrom) {
        conditions.push(`eval_date >= $${params.length + 1}`);
        params.push(dateFrom);
      }
      if (dateTo) {
        conditions.push(`eval_date <= $${params.length + 1}`);
        params.push(dateTo);
      }
    } else {
      return res.status(403).json({ error: 'دسترسی غیرمجاز' });
    }

    const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
    const result = await pool.query(
      `SELECT * FROM evaluations ${where} ORDER BY id DESC`,
      params
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Evaluations GET error:', err.message);
    res.status(500).json({ error: 'خطا در دریافت ارزیابی‌ها' });
  }
});

app.post('/api/evaluations', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'school') return res.status(403).json({ error: 'فقط مکتب دسترسی دارد' });

    const permResult = await pool.query("SELECT value FROM app_settings WHERE key = 'evaluation_allowed'");
    const allowed = permResult.rows.length > 0 && permResult.rows[0].value === 'true';
    if (!allowed) {
      return res.status(403).json({ error: '❌ هنوز از طرف آمریت اجازه داده نشده است' });
    }

    const body = req.body || {};
    const { record_id, eval_date_prev, bust, grade, eval_date, eval_score, eval_result } = body;

    if (!record_id) return res.status(400).json({ error: 'کارمند انتخاب نشده است' });
    if (!bust) return res.status(400).json({ error: 'بست الزامی است' });
    if (!grade) return res.status(400).json({ error: 'قدم الزامی است' });
    if (!eval_date) return res.status(400).json({ error: 'تاریخ ارزیابی الزامی است' });
    if (!eval_score) return res.status(400).json({ error: 'نمره الزامی است' });
    if (!eval_result) return res.status(400).json({ error: 'نتیجه الزامی است' });

    // ⭐ اعتبارسنجی تاریخ کامل (تغییر جدید)
    const dateErr = validateShamsiDateServer(eval_date, 'تاریخ ارزیابی');
    if (dateErr) return res.status(400).json({ error: dateErr });
    const cleanDate = normalizeDigits(eval_date).trim().replace(/[.\-]/g, '/');

    const scoreNum = Number(normalizeDigits(eval_score));
    if (isNaN(scoreNum) || scoreNum < 0 || scoreNum > 100) {
      return res.status(400).json({ error: 'نمره باید بین ۰ تا ۱۰۰ باشد' });
    }

    if (!['عالی', 'خوب', 'ضعیف'].includes(eval_result)) {
      return res.status(400).json({ error: 'نتیجه ارزیابی معتبر نیست' });
    }

    const recResult = await pool.query('SELECT * FROM records WHERE id = $1 AND userid = $2', [record_id, req.user.id]);
    if (recResult.rows.length === 0) {
      return res.status(404).json({ error: 'کارمند یافت نشد' });
    }
    const rec = recResult.rows[0];
    let info = {};
    try { info = JSON.parse(rec.data); } catch (e) {}

    let birthYear = '';
    if (info.birthDate) {
      const cleaned = normalizeDigits(info.birthDate).replace(/[.\-]/g, '/').trim();
      const parts = cleaned.split('/');
      if (parts.length === 3) {
        const p1 = parseInt(parts[0]), p3 = parseInt(parts[2]);
        if (parts[0].length === 4 || (p1 >= 1300 && p1 <= 1450)) birthYear = String(p1);
        else if (parts[2].length === 4 || (p3 >= 1300 && p3 <= 1450)) birthYear = String(p3);
      }
    }

    // محاسبه مدت خدمت (سال)
    let serviceDuration = '';
    if (info.firstAppointmentDate) {
      const cleaned = normalizeDigits(info.firstAppointmentDate).replace(/[.\-]/g, '/').trim();
      const parts = cleaned.split('/').map(p => parseInt(p.trim()));
      if (parts.length === 3 && !isNaN(parts[0]) && !isNaN(parts[1]) && !isNaN(parts[2])) {
        let startYear, startMonth, startDay;
        if (parts[0].length === 4 || (parts[0] >= 1300 && parts[0] <= 1450)) {
          startYear = parts[0]; startMonth = parts[1]; startDay = parts[2];
        } else {
          startYear = parts[2]; startMonth = parts[1]; startDay = parts[0];
        }
        
        const now = new Date();
        const gy = now.getFullYear();
        const gm = now.getMonth() + 1;
        const gd = now.getDate();
        const g_d_m = [0,31,59,90,120,151,181,212,243,273,304,334];
        let jy = (gy <= 1600) ? 0 : 979;
        let _gy = gy - ((gy <= 1600) ? 621 : 1600);
        const gy2 = (gm > 2) ? (_gy + 1) : _gy;
        let days = (365*_gy) + Math.floor((gy2+3)/4) - Math.floor((gy2+99)/100) + Math.floor((gy2+399)/400) - 80 + gd + g_d_m[gm-1];
        jy += 33 * Math.floor(days/12053); days %= 12053;
        jy += 4 * Math.floor(days/1461); days %= 1461;
        if (days > 365) { jy += Math.floor((days-1)/365); days = (days-1) % 365; }
        const jm = (days < 186) ? 1 + Math.floor(days/31) : 7 + Math.floor((days-186)/30);
        const jd = 1 + ((days < 186) ? (days%31) : ((days-186)%30));
        
        let years = jy - startYear;
        if (jm < startMonth || (jm === startMonth && jd < startDay)) years--;
        if (years >= 0) serviceDuration = `${years} سال`;
      }
    }

    const insertResult = await pool.query(
      `INSERT INTO evaluations (
        record_id, userid, schoolname, district,
        first_name, last_name, father_name, grandfather_name,
        job_code, employment_type, birth_year, service_duration,
        degree, gender, job_title, appointment_date,
        eval_date_prev, bust, grade, eval_date, eval_score, eval_result
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
      RETURNING id`,
      [
        record_id, req.user.id, rec.schoolname || '', rec.district || '',
        info.firstName || '', info.lastName || '', info.fatherName || '', info.grandfatherName || '',
        info.jobCode || '', info.employmentType || '', birthYear, serviceDuration,
        info.degree || '', info.gender || '', info.jobTitle || info.job || '', info.currentPositionDate || '',
        eval_date_prev || '', bust, grade, cleanDate, scoreNum, eval_result
      ]
    );

    res.json({ ok: true, id: insertResult.rows[0].id });
  } catch (err) {
    console.error('Evaluation POST error:', err.message);
    res.status(500).json({ error: 'خطا در ثبت ارزیابی: ' + err.message });
  }
});

app.delete('/api/evaluations/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین دسترسی دارد' });
    const result = await pool.query('DELETE FROM evaluations WHERE id = $1', [req.params.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'یافت نشد' });
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete evaluation error:', err.message);
    res.status(500).json({ error: 'خطا' });
  }
});

// ═══════════════════════════════════════════════════════════
// تایید / حذف رکوردها
// ═══════════════════════════════════════════════════════════
app.post('/api/records/:id/approve', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین' });
    const result = await pool.query("UPDATE records SET status = 'approved' WHERE id = $1", [req.params.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'رکورد یافت نشد' });
    res.json({ ok: true });
  } catch (err) {
    console.error('Approve Error:', err.message);
    res.status(500).json({ error: 'خطا در تایید' });
  }
});

app.delete('/api/records/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین' });
    const result = await pool.query('DELETE FROM records WHERE id = $1', [req.params.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'رکورد یافت نشد' });
    await pool.query('DELETE FROM evaluations WHERE record_id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete record error:', err.message);
    res.status(500).json({ error: 'خطا در حذف: ' + err.message });
  }
});

// ═══════════════════════════════════════════════════════════
// کاربران (مکاتب)
// ═══════════════════════════════════════════════════════════
app.post('/api/users', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین' });
    const { username, password, schoolName, district } = req.body || {};
    if (!username || !password || !schoolName) return res.status(400).json({ error: 'فیلدها الزامی است' });
    const hash = bcrypt.hashSync(password, 10);
    await pool.query(
      `INSERT INTO users (username, password, role, schoolname, district) VALUES ($1, $2, 'school', $3, $4)`,
      [username.trim(), hash, schoolName.trim(), (district || '').trim()]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('Add School Error:', err.message);
    if (err.code === '23505') return res.status(400).json({ error: 'این نام کاربری قبلاً ثبت شده' });
    res.status(500).json({ error: 'خطا در ثبت: ' + err.message });
  }
});

app.put('/api/users/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین' });
    const id = req.params.id;
    const { username, password, schoolName, district } = req.body || {};
    if (!username || !schoolName) return res.status(400).json({ error: 'نام کاربری و نام مکتب الزامی است' });
    const check = await pool.query("SELECT * FROM users WHERE id = $1 AND role = 'school'", [id]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'مکتب یافت نشد' });
    const dup = await pool.query("SELECT id FROM users WHERE username = $1 AND id != $2", [username.trim(), id]);
    if (dup.rows.length > 0) return res.status(400).json({ error: 'این نام کاربری قبلاً استفاده شده' });
    if (password && password.trim()) {
      const hash = bcrypt.hashSync(password.trim(), 10);
      await pool.query(`UPDATE users SET username = $1, password = $2, schoolname = $3, district = $4 WHERE id = $5 AND role = 'school'`,
        [username.trim(), hash, schoolName.trim(), (district || '').trim(), id]);
    } else {
      await pool.query(`UPDATE users SET username = $1, schoolname = $2, district = $3 WHERE id = $4 AND role = 'school'`,
        [username.trim(), schoolName.trim(), (district || '').trim(), id]);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('Edit School Error:', err.message);
    res.status(500).json({ error: 'خطا در ویرایش: ' + err.message });
  }
});

app.get('/api/users', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین' });
    const result = await pool.query("SELECT id, username, schoolname, district FROM users WHERE role = 'school' ORDER BY id DESC");
    res.json(result.rows);
  } catch (err) {
    console.error('Users GET Error:', err.message);
    res.status(500).json({ error: 'خطا در دریافت' });
  }
});

app.delete('/api/users/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین' });
    const result = await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'مکتب یافت نشد' });
    const userRecords = await pool.query('SELECT id FROM records WHERE userid = $1', [req.params.id]);
    for (const r of userRecords.rows) {
      await pool.query('DELETE FROM evaluations WHERE record_id = $1', [r.id]);
    }
    await pool.query('DELETE FROM records WHERE userid = $1', [req.params.id]);
    await pool.query('DELETE FROM school_settings WHERE userid = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete school error:', err.message);
    res.status(500).json({ error: 'خطا در حذف: ' + err.message });
  }
});

app.get('/api/login-attempts', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین' });
    const result = await pool.query('SELECT * FROM login_attempts ORDER BY id DESC LIMIT 100');
    res.json(result.rows);
  } catch (err) {
    console.error('Login attempts error:', err.message);
    res.status(500).json({ error: 'خطا' });
  }
});

app.get('/api/test', (req, res) => {
  res.json({ ok: true, version: '17.2.0', timestamp: new Date().toISOString() });
});

app.get('*', (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('═══════════════════════════════════════');
  console.log('🚀 Server V17.2 live on port ' + PORT);
  console.log('═══════════════════════════════════════');
});
