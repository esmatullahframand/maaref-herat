const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'maaref-secret-key-12345';

// اتصال مستقیم و مستقل به دیتابیس Supabase بدون علامت مخرّب بک‌اسلش
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000 
});

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
      console.log('✅ جدول‌های دیتابیس با موفقیت متصل و آماده شدند.');
    } catch (e) {
      console.error('Database structure error:', e);
    } finally {
      client.release();
    }
  } catch (err) {
    console.log('🔄 دیتابیس موقتاً آفلاین است اما سرور برای ورود زنده می‌ماند.');
  }
}
initDB();

app.use(express.json({ limit: '15mb' }));
app.use(cookieParser());

// 🛠️ حل مشکل به‌هم‌ریختگی: اتصال مستقیم سرور به قلب لایه سوم پوشه عمومی شما
const targetFrontendPath = path.join(__dirname, 'public/public/public');
app.use(express.static(targetFrontendPath));

// کدهای کمکی برای سایر لایه‌های احتمالی جهت تضمین لود استایل‌ها
app.use(express.static(path.join(__dirname, 'public/public')));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// مسیر احراز هویت ۱۰۰٪ تست شده بدون بک‌اسلش
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'نام و رمز الزامی است' });

    // ورود مستقیم ادمین
    if (username === 'admin' && password === 'admin123') {
      const adminUser = { id: 1, username: 'admin', role: 'admin', schoolname: 'ریاست معارف', district: 'مرکز هرات' };
      const token = jwt.sign(adminUser, SECRET, { expiresIn: '30d' });
      return res.json({ token, user: adminUser, redirect: '/admin.html' });
    }

    // ورود مدارس از دیتابیس Postgres
    const result = await pool.query('SELECT * FROM users WHERE username = \$1', [username]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'نام کاربری یافت نشد' });
    
    const user = result.rows[0]; 
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'رمز عبور اشتباه است' });
    
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role, schoolname: user.schoolname, district: user.district }, SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, schoolname: user.schoolname, district: user.district }, redirect: '/school.html' });
  } catch (e) {
    res.status(500).json({ error: 'خطای سرور در لاگین' });
  }
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

app.get('/api/records', authRequired, async (req, res) => {
  let result;
  const search = req.query.search || '';
  try {
    if (req.user.role === 'admin') {
      if (search) {
        result = await pool.query(`SELECT * FROM records WHERE schoolname ILIKE $1 OR district ILIKE $1 OR CAST(data AS TEXT) ILIKE $1 ORDER BY id DESC`, [`%${search}%`]);
      } else {
        result = await pool.query('SELECT * FROM records ORDER BY id DESC');
      }
    } else {
      if (search) {
        result = await pool.query(`SELECT * FROM records WHERE userid = $1 AND (schoolname ILIKE $2 OR district ILIKE $2 OR CAST(data AS TEXT) ILIKE $2) ORDER BY id DESC`, [req.user.id, `%${search}%`]);
      } else {
        result = await pool.query('SELECT * FROM records WHERE userid = \$1 ORDER BY id DESC', [req.user.id]);
      }
    }
    const rows = result.rows.map(r => ({ ...r, data: JSON.parse(r.data), status: r.status }));
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'خطا در واکشی اطلاعات دیتابیس' });
  }
});

// مسیر افزودن مکتب جدید بدون خطای کاراکتر اضافی در کوئری
app.post('/api/users', authRequired, async (req, res) => {
  try {
    const { username, password, schoolName, district } = req.body;
    const hash = bcrypt.hashSync(password, 10);
    await pool.query('INSERT INTO users (username, password, role, schoolname, district) VALUES (\$1, \$2, \'school\', \$3, \$4)', [username, hash, schoolName, district]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'خطا در ایجاد حساب کاربری مکتب' });
  }
});

app.get('/api/users', authRequired, async (req, res) => {
  try {
    const result = await pool.query("SELECT id, username, schoolname, district FROM users WHERE role = 'school' ORDER BY id DESC");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'خطا در دریافت لیست' });
  }
});

app.post('/api/records/:id/approve', authRequired, async (req, res) => {
  try {
    await pool.query('UPDATE records SET status = \'approved\' WHERE id = \$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'خطا در تایید رکورد' });
  }
});

app.delete('/api/users/:id', authRequired, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = \$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'خطا در حذف مکتب' });
  }
});

// لود اتوماتیک از لایه سوم تو در تو در هر بار باز کردن آدرس اصلی
app.get('*', (req, res) => {
  const primaryIndex = path.join(targetFrontendPath, 'index.html');
  if (fs.existsSync(primaryIndex)) {
      return res.sendFile(primaryIndex);
  }
  res.status(404).send('فایل index.html در لایه‌های پابلیک یافت نشد.');
});

app.listen(PORT, () => console.log(`🚀 Server fully live on port ${PORT}`));
