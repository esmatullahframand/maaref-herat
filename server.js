const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'maaref-secret-key-12345';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000
});

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

// مسیر ورود مستقیم و بدون خطا برای ادمین و مدارس
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  
  // تعریف مستقیم حساب کاربری ادمین
  if (username === 'admin' && password === 'admin123') {
    const user = { id: 1, username: 'admin', role: 'admin', schoolname: 'ریاست معارف', district: 'مرکز هرات' };
    const token = jwt.sign(user, SECRET, { expiresIn: '30d' });
    return res.json({ token, user });
  }
  
  // تعریف یک حساب نمونه برای مکتب (جهت تست)
  if (username === 'school1' && password === 'school123') {
    const user = { id: 2, username: 'school1', role: 'school', schoolname: 'لیسه سطان غیاث الدین', district: 'ناحیه اول' };
    const token = jwt.sign(user, SECRET, { expiresIn: '30d' });
    return res.json({ token, user });
  }

  return res.status(401).json({ error: 'نام کاربری یا رمز اشتباه است' });
});

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
        result = await pool.query('SELECT * FROM records ORDER BY id DESC');
      }
    } else {
      if (search) {
        result = await pool.query(
          `SELECT * FROM records WHERE userid = $1 AND (schoolname ILIKE $2 OR district ILIKE $2 OR CAST(data AS TEXT) ILIKE $2) ORDER BY id DESC`, [req.user.id, `%${search}%`]
        );
      } else {
        result = await pool.query('SELECT * FROM records WHERE userid = \$1 ORDER BY id DESC', [req.user.id]);
      }
    }
    const rows = result.rows.map(r => ({ ...r, data: JSON.parse(r.data), status: r.status }));
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'خطا در دیتابیس' });
  }
});

app.post('/api/records', authRequired, async (req, res) => {
  const body = req.body || {};
  const schoolName = body.schoolName || req.user.schoolname || '';
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

app.put('/api/records/:id', authRequired, async (req, res) => {
  try {
    const body = req.body || {};
    const job = String(body.job || '').trim();
    const degree = String(body.degree || '').trim();
    const isServiceStaff = job.includes('خدماتی') || job.includes('معتمد') || job.includes('ملازم');
    
    if (!isServiceStaff && (!degree || degree.replace(/\s/g, '') === '')) {
      return res.status(400).json({ error: 'وارد کردن فیلد تحصیلات برای معلمان، مدیران و سایر اعضا الزامی است.' });
    }
    await pool.query('UPDATE records SET schoolname=\$1, district=\$2, data=\$3 WHERE id=\$4', [body.schoolName, body.district, JSON.stringify(body), req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'خطای ویرایش' });
  }
});

app.post('/api/records/:id/approve', authRequired, async (req, res) => {
  await pool.query("UPDATE records SET status = 'approved' WHERE id = \$1", [req.params.id]);
  res.json({ ok: true });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`🚀 System Live on port ${PORT}`));
