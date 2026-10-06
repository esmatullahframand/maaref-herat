const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'maaref-secret-key-12345';

// اتصال استاندارد به دیتابیس آنلاین پستگرس رندر
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000
});

// ساخت جدول‌ها بدون کوچک‌ترین خطای نگارشی
async function initDB() {
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

    // بررسی و ساخت ادمین پیش‌فرض
    const res = await client.query('SELECT * FROM users WHERE username = \$1', ['admin']);
    if (res.rows.length === 0) {
      const hash = bcrypt.hashSync('admin123', 10);
      await client.query('INSERT INTO users (username, password, role) VALUES (\$1, \$2, \$3)', ['admin', hash, 'admin']);
      console.log('✅ ادمین اصلی سیستم آماده شد: admin / admin123');
    }
  } catch (err) {
    console.error('Database Initialization Error:', err);
  } finally {
    client.release();
  }
}
initDB();

app.use(express.json({ limit: '15mb' }));
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

function sign(user) {
  return jwt.sign({ id: user.id, username: user.username, role: user.role, schoolName: user.schoolname, district: user.district }, SECRET, { expiresIn: '30d' });
}

function authRequired(req, res, next) {
  let token = req.cookies?.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token && req.query.token) token = req.query.token;
  if (!token) return res.status(401).json({ error: 'وارد نشده‌اید' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'توکن نامعتبر' });
  }
}

// مسیر احراز هویت و لاگین صحیح کاربران و ادمین
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'نام و رمز الزامی' });
    const result = await pool.query('SELECT * FROM users WHERE username = \$1', [username]);
    const user = result.rows[0]; // تصحیح خواندن سطر اول برای باز شدن قفل ورود
    if (!user) return res.status(401).json({ error: 'نام کاربری یافت نشد' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'رمز عبور اشتباه' });
    const token = sign(user);
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, schoolName: user.schoolname, district: user.district } });
  } catch (e) {
    res.status(500).json({ error: 'خطای سرور در لاگین' });
  }
});

app.post('/api/auth/logout', (req, res) => res.json({ ok: true }));
app.get('/api/auth/me', authRequired, (req, res) => res.json(req.user));

// سیستم جستجوی فوق‌العاده سریع و هوشمند متنیِ دیتابیس آنلاین
app.get('/api/records', authRequired, async (req, res) => {
  let result;
  const search = req.query.search || '';
  try {
    if (req.user.role === 'admin') {
      if (search) {
        result = await pool.query(
          `SELECT r.*, u.schoolname as "userSchool", u.district as "userDistrict" 
           FROM records r LEFT JOIN users u ON r.userid = u.id 
           WHERE r.schoolname ILIKE $1 OR r.district ILIKE $1 OR CAST(r.data AS TEXT) ILIKE $1 OR r.status ILIKE $1
           ORDER BY r.id DESC`, [`%${search}%`]
        );
      } else {
        result = await pool.query('SELECT r.*, u.schoolname as "userSchool", u.district as "userDistrict" FROM records r LEFT JOIN users u ON r.userid = u.id ORDER BY r.id DESC');
      }
    } else {
      if (search) {
        result = await pool.query(
          `SELECT * FROM records 
           WHERE userid = $1 AND (schoolname ILIKE $2 OR district ILIKE $2 OR CAST(data AS TEXT) ILIKE $2) 
           ORDER BY id DESC`, [req.user.id, `%${search}%`]
        );
      } else {
        result = await pool.query('SELECT * FROM records WHERE userid = \$1 ORDER BY id DESC', [req.user.id]);
      }
    }
    const rows = result.rows.map(r => ({ ...r, data: JSON.parse(r.data), status: r.status }));
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'خطا در خواندن اطلاعات سریع' });
  }
});

app.post('/api/records', authRequired, async (req, res) => {
  const body = req.body || {};
  const schoolName = body.schoolName || req.user.schoolName || '';
  const district = body.district || req.user.district || '';
  
  const job = String(body.job || '').trim();
  const degree = String(body.degree || '').trim();
  const isServiceStaff = job.includes('خدماتی') || job.includes('معتمد') || job.includes('ملازم');
  
  if (!isServiceStaff && (!degree || degree.replace(/\s/g, '') === '')) {
    return res.status(400).json({ error: 'وارد کردن فیلد تحصیلات برای معلمان، مدیران و سایر اعضا الزامی است.' });
  }

  await pool.query('INSERT INTO records (userid, schoolname, district, data, status) VALUES (\$1, \$2, \$3, \$4, \'pending\')', [req.user.id, schoolName, district, JSON.stringify(body)]);
  res.json({ ok: true });
});

// مسیر ویرایش دقیق اطلاعات کارمندان بر اساس آی‌دی
app.put('/api/records/:id', authRequired, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM records WHERE id = \$1', [req.params.id]);
    const rec = result.rows[0];
    if (!rec) return res.status(404).json({ error: 'یافت نشد' });
    if (req.user.role !== 'admin' && rec.userid !== req.user.id) return res.status(403).json({ error: 'دسترسی ندارید' });
    
    const body = req.body || {};
    const job = String(body.job || '').trim();
    const degree = String(body.degree || '').trim();
    const isServiceStaff = job.includes('خدماتی') || job.includes('معتمد') || job.includes('ملازم');
    
    if (!isServiceStaff && (!degree || degree.replace(/\s/g, '') === '')) {
      return res.status(400).json({ error: 'وارد کردن فیلد تحصیلات برای معلمان، مدیران و سایر اعضا الزامی است.' });
    }

    await pool.query('UPDATE records SET schoolname=\$1, district=\$2, data=\$3 WHERE id=\$4', [body.schoolName || rec.schoolname, body.district || rec.district, JSON.stringify(body), req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'خطای سرور در ویرایش معلومات' });
  }
});

app.post('/api/records/:id/approve', authRequired, async (req, res) => {
  await pool.query("UPDATE records SET status = 'approved' WHERE id = \$1", [req.params.id]);
  res.json({ ok: true });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`🚀 Fast Server running on port ${PORT}`));
