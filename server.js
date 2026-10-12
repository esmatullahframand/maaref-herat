const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'maaref-secret-key-12345';

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false, checkServerIdentity: () => undefined },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

// ═══════════════════════════════════════════════════════════
// عناوین بست
// ═══════════════════════════════════════════════════════════
const JOB_TITLES = [
  'آمر',
  'مدیر',
  'مدیر اجرائیه',
  'معلم',
  'سر معلم',
  'معلم همکار',
  'معلم سپورت',
  'معلم لابرانت',
  'عضو علمی معلمان',
  'عضو علمی مدرسین',
  'عضو مسلکی امور مالی و کارکنان',
  'عضو مسلکی نظارت احصاییه و گزارش',
  'عضو مسلکی تاسیسات و ترمیمات',
  'عضو مسلکی شوراها',
  'کارکن خدماتی',
  'معتمد جنسی (تحویلدار)',
  'معلم قراردادی',
  'معلم افتخاری',
  'سایر'
];

// عناوینی که کد بست الزامی نیست
const NO_CODE_TITLES = ['معلم قراردادی', 'معلم افتخاری'];

// کلمات کلیدی کارکن خدماتی
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
  message: { error: '❌ تعداد تلاش‌های شما بیش از حد مجاز است. لطفاً ۱۵ دقیقه بعد تلاش کنید.' }
});

function authRequired(req, res, next) {
  let token = req.cookies?.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token && req.query.token) token = req.query.token;
  if (!token) return res.status(401).json({ error: 'وارد نشده‌اید' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch (e) {
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

// ═══════════════════════════════════════════════════════════
// توابع اعتبارسنجی
// ═══════════════════════════════════════════════════════════
function isValidJobCode(jobCode) {
  if (!jobCode) return false;
  return /^27-32-02-\d+$/.test(jobCode.trim());
}

function isValidETazkira(eTazkira) {
  if (!eTazkira) return false;
  return /^\d+-\d+-\d+$/.test(eTazkira.trim());
}

function isNoCodeTitle(jobTitle) {
  return NO_CODE_TITLES.some(t => jobTitle === t);
}

function isServiceStaff(jobTitle) {
  if (!jobTitle) return false;
  return SERVICE_KEYWORDS.some(kw => jobTitle.includes(kw)) || jobTitle === 'کارکن خدماتی';
}

async function isJobCodeDuplicate(jobCode, excludeRecordId = null) {
  if (!jobCode) return false;
  try {
    const searchPattern = `%"jobCode":"${jobCode}"%`;
    let result;
    if (excludeRecordId) {
      result = await pool.query(
        `SELECT id FROM records WHERE CAST(data AS TEXT) LIKE $1 AND id != $2 LIMIT 1`,
        [searchPattern, excludeRecordId]
      );
    } else {
      result = await pool.query(
        `SELECT id FROM records WHERE CAST(data AS TEXT) LIKE $1 LIMIT 1`,
        [searchPattern]
      );
    }
    return result.rows.length > 0;
  } catch (err) {
    console.error('Duplicate check error:', err.message);
    return false;
  }
}

// ═══════════════════════════════════════════════════════════
// لاگین
// ═══════════════════════════════════════════════════════════
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const clientIp = req.headers['x-forwarded-for'] || req.ip || 'unknown';
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'نام کاربری و رمز عبور الزامی است' });
    }

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
      await logLoginAttempt(clientIp, username, true);
      const adminUser = { id: 0, username: 'admin', role: 'admin', schoolname: 'ریاست معارف', district: 'مرکز هرات' };
      const token = jwt.sign(adminUser, SECRET, { expiresIn: '7d' });
      return res.json({ token, user: adminUser, redirect: '/admin.html' });
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
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, schoolname: user.schoolname, district: user.district },
      SECRET,
      { expiresIn: '7d' }
    );
    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role, schoolname: user.schoolname, district: user.district },
      redirect: '/school.html'
    });
  } catch (e) {
    console.error('Login Error:', e);
    res.status(500).json({ error: 'خطای سرور در فرآیند ورود' });
  }
});

// ═══════════════════════════════════════════════════════════
// GET /api/records
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
// اعتبارسنجی مشترک برای POST و PUT
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
  const birthDate = String(body.birthDate || '').trim();
  const firstAppointmentDate = String(body.firstAppointmentDate || '').trim();
  const currentPositionDate = String(body.currentPositionDate || '').trim();
  const ethnicity = String(body.ethnicity || '').trim();
  const phone = String(body.phone || '').trim();

  // الزامیات پایه
  if (!job) return 'عنوان بست الزامی است';
  if (!JOB_TITLES.includes(job)) return '❌ عنوان بست انتخابی معتبر نیست';
  if (!firstName) return 'اسم الزامی است';
  if (!fatherName) return 'ولد الزامی است';
  if (!grandfatherName) return 'ولدیت الزامی است';

  const isContract = isNoCodeTitle(job);

  if (isContract) {
    // ═══ معلم قراردادی/افتخاری: فقط اسم، تخلص، ولد، ولدیت، تاریخ تولد، تذکره ═══
    if (!eTazkira && !paperTazkira) return 'حداقل یکی از تذکره‌ها الزامی است';
    if (eTazkira && !isValidETazkira(eTazkira)) return '❌ فرمت تذکره برقی اشتباه است (مثال: 1399-1200-2434)';
    if (!birthDate) return 'تاریخ تولد الزامی است';
  } else {
    // ═══ بقیه: همه فیلدهای اصلی الزامی ═══
    if (!ethnicity) return 'قومیت الزامی است';
    if (!phone) return 'شماره تماس الزامی است';
    if (!eTazkira && !paperTazkira) return 'حداقل یکی از تذکره‌ها الزامی است';
    if (eTazkira && !isValidETazkira(eTazkira)) return '❌ فرمت تذکره برقی اشتباه است (مثال: 1399-1200-2434)';

    if (!jobCode) return 'کُد بست الزامی است';
    if (!isValidJobCode(jobCode)) return '❌ فرمت کُد بست اشتباه است. باید به شکل 27-32-02-XXXXX باشد';
    const isDuplicate = await isJobCodeDuplicate(jobCode, excludeId);
    if (isDuplicate) return `❌ کُد بست «${jobCode}» قبلاً در سیستم ثبت شده است`;

    if (!birthDate) return 'تاریخ تولد الزامی است';
    if (!firstAppointmentDate) return 'تاریخ اولین تقرر الزامی است';
    if (!currentPositionDate) return 'تاریخ تقرر فعلی الزامی است';

    if (!isServiceStaff(job) && !degree) return 'درجه تحصیلی برای این عنوان الزامی است';
  }

  // ═══ بررسی ورکشاپ ═══
  const workshopStatus = String(body.workshopStatus || '').trim();
  if (workshopStatus === 'بلی') {
    const workshopTitle = String(body.workshopTitle || '').trim();
    const workshopDuration = String(body.workshopDuration || '').trim();
    if (!workshopTitle) return '❌ عنوان ورکشاپ الزامی است (چون ورکشاپ اخذ کرده‌اید)';
    if (!workshopDuration) return '❌ مدت ورکشاپ الزامی است (چون ورکشاپ اخذ کرده‌اید)';
  }

  // ═══ بررسی نمره ارزیابی ═══
  const evaluationScore = String(body.evaluationScore || '').trim();
  if (evaluationScore) {
    const num = Number(evaluationScore);
    if (isNaN(num) || num < 0 || num > 100) {
      return '❌ نمره ارزیابی باید عددی بین ۰ تا ۱۰۰ باشد';
    }
  }

  // ═══ بررسی مجموعه ساعت درسی ═══
  const totalTeachingHours = String(body.totalTeachingHours || '').trim();
  if (totalTeachingHours) {
    const num = Number(totalTeachingHours);
    if (isNaN(num) || num < 0) {
      return '❌ مجموعه ساعت درسی باید عددی مثبت باشد';
    }
  }

  // ═══ بررسی دکمه موافقت ═══
  if (excludeId === null && !body.agreement) {
    return '❌ شما باید موافقت خود را اعلام کنید';
  }

  return null; // بدون خطا
}

// ═══════════════════════════════════════════════════════════
// POST /api/records — ثبت رکورد جدید
// ═══════════════════════════════════════════════════════════
app.post('/api/records', authRequired, async (req, res) => {
  try {
    const body = req.body || {};
    const schoolName = body.schoolName || req.user.schoolname || '';
    const district = body.district || req.user.district || '';

    const error = await validateRecordBody(body, null);
    if (error) {
      return res.status(400).json({ error });
    }

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

// ═══════════════════════════════════════════════════════════
// PUT /api/records/:id — ویرایش رکورد
// ═══════════════════════════════════════════════════════════
app.put('/api/records/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'school') {
      return res.status(403).json({ error: 'فقط مکتب اجازه ویرایش دارد' });
    }
    const id = req.params.id;
    const body = req.body || {};

    const check = await pool.query('SELECT * FROM records WHERE id = $1 AND userid = $2', [id, req.user.id]);
    if (check.rows.length === 0) {
      return res.status(404).json({ error: 'رکورد یافت نشد یا به شما تعلق ندارد' });
    }
    if (check.rows[0].status === 'approved') {
      return res.status(403).json({ error: 'رکورد تایید شده قابل ویرایش نیست' });
    }

    const error = await validateRecordBody(body, id);
    if (error) {
      return res.status(400).json({ error });
    }

    const schoolName = body.schoolName || req.user.schoolname || '';
    const district = body.district || req.user.district || '';

    await pool.query(
      `UPDATE records SET schoolname = $1, district = $2, data = $3
       WHERE id = $4 AND userid = $5`,
      [schoolName, district, JSON.stringify(body), id, req.user.id]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('Records PUT Error:', err.message);
    res.status(500).json({ error: 'خطا در ویرایش: ' + err.message });
  }
});

// ═══════════════════════════════════════════════════════════
// تایید رکورد (فقط ادمین)
// ═══════════════════════════════════════════════════════════
app.post('/api/records/:id/approve', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین اجازه تایید دارد' });
    const result = await pool.query("UPDATE records SET status = 'approved' WHERE id = $1", [req.params.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'رکورد یافت نشد' });
    res.json({ ok: true });
  } catch (err) {
    console.error('Approve Error:', err.message);
    res.status(500).json({ error: 'خطا در تایید رکورد' });
  }
});

// ═══════════════════════════════════════════════════════════
// حذف رکورد (فقط ادمین)
// ═══════════════════════════════════════════════════════════
app.delete('/api/records/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین اجازه حذف دارد' });
    const result = await pool.query('DELETE FROM records WHERE id = $1', [req.params.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'رکورد یافت نشد' });
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete record error:', err.message);
    res.status(500).json({ error: 'خطا در حذف رکورد: ' + err.message });
  }
});

// ═══════════════════════════════════════════════════════════
// افزودن مکتب (فقط ادمین)
// ═══════════════════════════════════════════════════════════
app.post('/api/users', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین اجازه افزودن مکتب دارد' });
    const { username, password, schoolName, district } = req.body || {};
    if (!username || !password || !schoolName) {
      return res.status(400).json({ error: 'پر کردن فیلدهای اصلی الزامی است' });
    }
    const hash = bcrypt.hashSync(password, 10);
    await pool.query(
      `INSERT INTO users (username, password, role, schoolname, district)
       VALUES ($1, $2, 'school', $3, $4)`,
      [username.trim(), hash, schoolName.trim(), (district || '').trim()]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('Add School Error:', err.message);
    if (err.code === '23505') return res.status(400).json({ error: 'این نام کاربری قبلا ثبت شده است' });
    res.status(500).json({ error: 'خطا در ثبت مکتب: ' + err.message });
  }
});

// ═══════════════════════════════════════════════════════════
// لیست مکاتب (فقط ادمین)
// ═══════════════════════════════════════════════════════════
app.get('/api/users', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین دسترسی دارد' });
    const result = await pool.query("SELECT id, username, schoolname, district FROM users WHERE role = 'school' ORDER BY id DESC");
    res.json(result.rows);
  } catch (err) {
    console.error('Users GET Error:', err.message);
    res.status(500).json({ error: 'خطا در دریافت لیست مکاتب' });
  }
});

// ═══════════════════════════════════════════════════════════
// حذف مکتب (فقط ادمین)
// ═══════════════════════════════════════════════════════════
app.delete('/api/users/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین اجازه حذف دارد' });
    const result = await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'مکتب یافت نشد' });
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete school error:', err.message);
    res.status(500).json({ error: 'خطا در حذف مکتب: ' + err.message });
  }
});

// ═══════════════════════════════════════════════════════════
// لاگ تلاش‌های ورود (فقط ادمین)
// ═══════════════════════════════════════════════════════════
app.get('/api/login-attempts', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین دسترسی دارد' });
    const result = await pool.query('SELECT * FROM login_attempts ORDER BY id DESC LIMIT 100');
    res.json(result.rows);
  } catch (err) {
    console.error('Login attempts error:', err.message);
    res.status(500).json({ error: 'خطا در دریافت لاگ' });
  }
});

// ═══════════════════════════════════════════════════════════
// Fallback
// ═══════════════════════════════════════════════════════════
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔒 Rate limiting: 10 login attempts per 15 minutes`);
});
