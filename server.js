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

// ============================================================
// ایجاد جدول‌ها
// ============================================================
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
          userid INTEGER NOT NULL,
          schoolname TEXT NOT NULL,
          district TEXT NOT NULL,
          data TEXT NOT NULL,
          status TEXT DEFAULT 'pending',
          createdat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(userid) REFERENCES users(id) ON DELETE CASCADE
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

// ============================================================
// Middleware
// ============================================================
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

// ============================================================
// Rate Limiting
// ============================================================
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: '❌ تعداد تلاش‌های شما بیش از حد مجاز است. لطفاً ۱۵ دقیقه بعد تلاش کنید.' }
});

// ============================================================
// احراز هویت
// ============================================================
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

// ============================================================
// ⭐ اعتبارسنجی کد بست
// فرمت: 27-32-02-XXXXX (شروع با 27-32-02-)
// ============================================================
function isValidJobCode(jobCode) {
  if (!jobCode) return false;
  const cleaned = String(jobCode).trim();
  // الگو: 27-32-02- و بعد ۳ تا ۶ رقم
  const pattern = /^27-32-02-\d{3,6}$/;
  return pattern.test(cleaned);
}

// ============================================================
// ⭐ اعتبارسنجی تذکره برقی
// فرمت: 1399-1200-63538 (سه بخش با خط تیره)
// ============================================================
function isValidETazkira(eTazkira) {
  if (!eTazkira) return false;
  const cleaned = String(eTazkira).trim();
  // الگو: 4 رقم - 4 رقم - 5 رقم
  const pattern = /^\d{4}-\d{4}-\d{5}$/;
  return pattern.test(cleaned);
}

// ============================================================
// ⭐ بررسی تکراری بودن کد بست
// ============================================================
async function isJobCodeDuplicate(jobCode, excludeRecordId = null) {
  if (!jobCode) return false;
  try {
    const searchPattern = `%"jobCode":"${jobCode}"%`;
    let result;
    if (excludeRecordId) {
      result = await pool.query(
        `SELECT id FROM records 
         WHERE CAST(data AS TEXT) LIKE $1 AND id != $2 
         LIMIT 1`,
        [searchPattern, excludeRecordId]
      );
    } else {
      result = await pool.query(
        `SELECT id FROM records 
         WHERE CAST(data AS TEXT) LIKE $1 
         LIMIT 1`,
        [searchPattern]
      );
    }
    return result.rows.length > 0;
  } catch (err) {
    console.error('Duplicate check error:', err.message);
    return false;
  }
}

// ============================================================
// لاگین
// ============================================================
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

// ============================================================
// GET /api/records
// ============================================================
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

// ============================================================
// POST /api/records — با اعتبارسنجی کد بست و تذکره
// ============================================================
app.post('/api/records', authRequired, async (req, res) => {
  try {
    const body = req.body || {};
    const schoolName = body.schoolName || req.user.schoolname || '';
    const district = body.district || req.user.district || '';

    const job = String(body.jobTitle || body.job || '').trim();
    const firstName = String(body.firstName || '').trim();
    const fatherName = String(body.fatherName || '').trim();
    const name = String(body.name || (firstName ? firstName + ' ' + (body.lastName || '') : '')).trim();

    if (!name || !fatherName || !job) {
      return res.status(400).json({ error: 'نام، نام پدر و وظیفه الزامی است' });
    }

    // ═══ اعتبارسنجی کد بست ═══
    const jobCode = String(body.jobCode || '').trim();
    if (!jobCode) {
      return res.status(400).json({ error: 'کُد بست الزامی است' });
    }
    if (!isValidJobCode(jobCode)) {
      return res.status(400).json({
        error: '❌ فرمت کُد بست اشتباه است. باید به شکل 27-32-02-XXXXX باشد (مثال: 27-32-02-13056)'
      });
    }
    // ═══ بررسی تکراری بودن کد بست ═══
    const isDuplicate = await isJobCodeDuplicate(jobCode);
    if (isDuplicate) {
      return res.status(400).json({
        error: `❌ کُد بست «${jobCode}» قبلاً در سیستم ثبت شده است. لطفاً کُد بست دیگری وارد کنید.`
      });
    }

    // ═══ اعتبارسنجی تذکره برقی ═══
    const eTazkira = String(body.eTazkira || '').trim();
    if (eTazkira && !isValidETazkira(eTazkira)) {
      return res.status(400).json({
        error: '❌ فرمت تذکره الکترونیکی اشتباه است. باید به شکل 1399-1200-63538 باشد (با خط تیره)'
      });
    }

    // ═══ کارکن خدماتی: درجه اختیاری ═══
    const SERVICE_KEYWORDS = ['ملازم', 'شب باش', 'شب‌باش', 'شبباش', 'معتمد جنسی', 'معتمد', 'اجیر خدماتی', 'اجیر', 'خدماتی', 'خدمه', 'نگهبان', 'آشپز', 'کارگر', 'راننده', 'باغبان', 'سرایدار'];
    const isServiceStaff = SERVICE_KEYWORDS.some(kw => job.includes(kw));
    const degree = String(body.degree || '').trim();

    if (!isServiceStaff && (!degree || degree.replace(/\s/g, '') === '')) {
      return res.status(400).json({
        error: 'درجه تحصیلی برای معلمان، مدیران و کارمندان دفتری الزامی است'
      });
    }

    if (!body.birthDate) return res.status(400).json({ error: 'تاریخ تولد الزامی است' });
    if (!body.firstAppointmentDate) return res.status(400).json({ error: 'تاریخ اولین تقرر الزامی است' });
    if (!body.currentPositionDate) return res.status(400).json({ error: 'تاریخ تقرر فعلی الزامی است' });

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

// ============================================================
// PUT /api/records/:id — ویرایش با اعتبارسنجی
// ============================================================
app.put('/api/records/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'school') {
      return res.status(403).json({ error: 'فقط مکتب اجازه ویرایش دارد' });
    }

    const id = req.params.id;
    const body = req.body || {};

    const check = await pool.query(
      'SELECT * FROM records WHERE id = $1 AND userid = $2',
      [id, req.user.id]
    );
    if (check.rows.length === 0) {
      return res.status(404).json({ error: 'رکورد یافت نشد یا به شما تعلق ندارد' });
    }
    if (check.rows[0].status === 'approved') {
      return res.status(403).json({ error: 'رکورد تایید شده قابل ویرایش نیست' });
    }

    // ═══ اعتبارسنجی کد بست ═══
    const jobCode = String(body.jobCode || '').trim();
    if (!jobCode) {
      return res.status(400).json({ error: 'کُد بست الزامی است' });
    }
    if (!isValidJobCode(jobCode)) {
      return res.status(400).json({
        error: '❌ فرمت کُد بست اشتباه است. باید به شکل 27-32-02-XXXXX باشد'
      });
    }
    const isDuplicate = await isJobCodeDuplicate(jobCode, id);
    if (isDuplicate) {
      return res.status(400).json({
        error: `❌ کُد بست «${jobCode}» قبلاً در سیستم ثبت شده است.`
      });
    }

    // ═══ اعتبارسنجی تذکره برقی ═══
    const eTazkira = String(body.eTazkira || '').trim();
    if (eTazkira && !isValidETazkira(eTazkira)) {
      return res.status(400).json({
        error: '❌ فرمت تذکره الکترونیکی اشتباه است. باید به شکل 1399-1200-63538 باشد'
      });
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

// ============================================================
// تایید / حذف / کاربران
// ============================================================
app.post('/api/records/:id/approve', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'فقط ادمین اجازه تایید دارد' });
    }
    const result = await pool.query(
      "UPDATE records SET status = 'approved' WHERE id = $1",
      [req.params.id]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'رکورد یافت نشد' });
    res.json({ ok: true });
  } catch (err) {
    console.error('Approve Error:', err.message);
    res.status(500).json({ error: 'خطا در تایید رکورد' });
  }
});

app.delete('/api/records/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'فقط ادمین اجازه حذف دارد' });
    }
    const result = await pool.query('DELETE FROM records WHERE id = $1', [req.params.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'رکورد یافت نشد' });
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete record error:', err.message);
    res.status(500).json({ error: 'خطا در حذف رکورد: ' + err.message });
  }
});

app.post('/api/users', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'فقط ادمین اجازه افزودن مکتب دارد' });
    }
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

app.get('/api/users', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین دسترسی دارد' });
    const result = await pool.query(
      "SELECT id, username, schoolname, district FROM users WHERE role = 'school' ORDER BY id DESC"
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Users GET Error:', err.message);
    res.status(500).json({ error: 'خطا در دریافت لیست مکاتب' });
  }
});

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

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
