const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'maaref-secret-key-12345';

// ============================================================
// 🔧 حل مشکل SSL: غیرفعال کردن بررسی گواهی self-signed
// ============================================================
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// ============================================================
// اتصال به دیتابیس Supabase
// ============================================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
    checkServerIdentity: () => undefined
  },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

// ============================================================
// ایجاد خودکار جدول‌ها
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

// سرو فایل‌های استاتیک از پوشه public
app.use(express.static(path.join(__dirname, 'public')));

// CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
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

// ============================================================
// مسیر لاگین
// ============================================================
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'نام کاربری و رمز عبور الزامی است' });
    }

    // لاگین ادمین (سخت‌کد)
    if (username === 'admin' && password === 'admin123') {
      const adminUser = {
        id: 0,
        username: 'admin',
        role: 'admin',
        schoolname: 'ریاست معارف',
        district: 'مرکز هرات'
      };
      const token = jwt.sign(adminUser, SECRET, { expiresIn: '30d' });
      return res.json({ token, user: adminUser, redirect: '/admin.html' });
    }

    // لاگین مکاتب از دیتابیس
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است' });
    }

    const user = result.rows[0];
    const passOk = bcrypt.compareSync(password, user.password);
    if (!passOk) {
      return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است' });
    }

    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        role: user.role,
        schoolname: user.schoolname,
        district: user.district
      },
      SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        schoolname: user.schoolname,
        district: user.district
      },
      redirect: '/school.html'
    });
  } catch (e) {
    console.error('Login Error:', e);
    res.status(500).json({ error: 'خطای سرور در فرآیند ورود' });
  }
});

// ============================================================
// دریافت لیست رکوردها
// ============================================================
app.get('/api/records', authRequired, async (req, res) => {
  try {
    const search = (req.query.search || '').trim();
    let result;

    if (req.user.role === 'admin') {
      if (search) {
        result = await pool.query(
          `SELECT * FROM records
           WHERE schoolname ILIKE $1
              OR district ILIKE $1
              OR CAST(data AS TEXT) ILIKE $1
           ORDER BY id DESC`,
          [`%${search}%`]
        );
      } else {
        result = await pool.query('SELECT * FROM records ORDER BY id DESC');
      }
    } else {
      if (search) {
        result = await pool.query(
          `SELECT * FROM records
           WHERE userid = $1
             AND (schoolname ILIKE $2 OR district ILIKE $2 OR CAST(data AS TEXT) ILIKE $2)
           ORDER BY id DESC`,
          [req.user.id, `%${search}%`]
        );
      } else {
        result = await pool.query(
          'SELECT * FROM records WHERE userid = $1 ORDER BY id DESC',
          [req.user.id]
        );
      }
    }

    const rows = result.rows.map((r) => {
      let parsed = {};
      try {
        parsed = JSON.parse(r.data);
      } catch (e) {
        parsed = {};
      }
      return { ...r, data: parsed, status: r.status };
    });

    res.json(rows);
  } catch (err) {
    console.error('Records GET Error:', err.message);
    res.status(500).json({ error: 'خطا در واکشی اطلاعات دیتابیس' });
  }
});

// ============================================================
// ثبت رکورد جدید (کارمند)
// ============================================================
app.post('/api/records', authRequired, async (req, res) => {
  try {
    const body = req.body || {};
    const schoolName = body.schoolName || req.user.schoolname || '';
    const district = body.district || req.user.district || '';
    const job = String(body.job || '').trim();
    const degree = String(body.degree || '').trim();

    if (!body.name || !body.fatherName || !job) {
      return res.status(400).json({ error: 'نام، نام پدر و وظیفه الزامی است' });
    }

    const isServiceStaff =
      job.includes('خدماتی') || job.includes('معتمد') || job.includes('ملازم');

    if (!isServiceStaff && (!degree || degree.replace(/\s/g, '') === '')) {
      return res.status(400).json({
        error: 'وارد کردن فیلد تحصیلات برای معلمان، مدیران و کارمندان دفتری الزامی است.'
      });
    }

    await pool.query(
      `INSERT INTO records (userid, schoolname, district, data, status)
       VALUES ($1, $2, $3, $4, 'pending')`,
      [req.user.id, schoolName, district, JSON.stringify(body)]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error('Records POST Error:', err.message);
    res.status(500).json({ error: 'خطا در ثبت رکورد کارمند' });
  }
});

// ============================================================
// تایید رکورد توسط ادمین
// ============================================================
app.post('/api/records/:id/approve', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'فقط ادمین اجازه تایید دارد' });
    }
    await pool.query("UPDATE records SET status = 'approved' WHERE id = $1", [
      req.params.id
    ]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Approve Error:', err.message);
    res.status(500).json({ error: 'خطا در تایید رکورد' });
  }
});

// ============================================================
// افزودن مکتب جدید
// ============================================================
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
    console.error('❌ Add School Error Details:');
    console.error('   Message:', err.message);
    console.error('   Code:', err.code);
    console.error('   Detail:', err.detail);

    if (err.code === '23505') {
      return res.status(400).json({ error: 'این نام کاربری قبلا ثبت شده است' });
    }
    res.status(500).json({
      error: 'خطا در ثبت مکتب جدید: ' + err.message
    });
  }
});

// ============================================================
// دریافت لیست مکاتب
// ============================================================
app.get('/api/users', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'فقط ادمین دسترسی دارد' });
    }
    const result = await pool.query(
      "SELECT id, username, schoolname, district FROM users WHERE role = 'school' ORDER BY id DESC"
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Users GET Error:', err.message);
    res.status(500).json({ error: 'خطا در دریافت لیست مکاتب' });
  }
});

// ============================================================
// حذف مکتب
// ============================================================
app.delete('/api/users/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'فقط ادمین اجازه حذف دارد' });
    }
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete Error:', err.message);
    res.status(500).json({ error: 'خطا در حذف مکتب' });
  }
});

// ============================================================
// Fallback: هر مسیر ناشناخته → index.html
// ============================================================
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================================
// اجرای سرور
// ============================================================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
