const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'maaref-secret-key-12345';

// اتصال به دیتابیس آنلاین پستگرس رندر
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ساخت جدول‌ها در صورت عدم وجود
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        schoolName TEXT,
        district TEXT,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS records (
        id SERIAL PRIMARY KEY,
        userId INTEGER NOT NULL,
        schoolName TEXT NOT NULL,
        district TEXT NOT NULL,
        data TEXT NOT NULL,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
      );
    `);

    // ادمین پیش‌فرض
    const res = await client.query('SELECT * FROM users WHERE username = \$1', ['admin']);
    if (res.rows.length === 0) {
      const hash = bcrypt.hashSync('admin123', 10);
      await client.query('INSERT INTO users (username, password, role) VALUES (\$1, \$2, \$3)', ['admin', hash, 'admin']);
      console.log('✅ ادمین ساخته شد: admin / admin123');
    }
  } catch (err) {
    console.error('Error initializing database:', err);
  } finally {
    client.release();
  }
}
initDB();

app.use(express.json({ limit: '10mb' }));
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
  return jwt.sign({ id: user.id, username: user.username, role: user.role, schoolName: user.schoolName, district: user.district }, SECRET, { expiresIn: '30d' });
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

function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین' });
  next();
}

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'نام و رمز الزامی' });
    const result = await pool.query('SELECT * FROM users WHERE username = \$1', [username]);
    const user = result.rows[0]; // اصلاح شد
    if (!user) return res.status(401).json({ error: 'نام کاربری یافت نشد' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'رمز عبور اشتباه' });
    const token = sign(user);
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, schoolName: user.schoolName, district: user.district } }); // حروف کوچک فیکس شد
  } catch (e) {
    res.status(500).json({ error: 'خطای سرور' });
  }
});

app.post('/api/auth/logout', (req, res) => res.json({ ok: true }));
app.get('/api/auth/me', authRequired, (req, res) => res.json(req.user));

app.get('/api/users', authRequired, adminOnly, async (req, res) => {
  const result = await pool.query("SELECT id, username, role, schoolName as \"schoolName\", district FROM users WHERE role = 'school' ORDER BY id DESC");
  res.json(result.rows);
});

app.post('/api/users', authRequired, adminOnly, async (req, res) => {
  const { username, password, schoolName, district } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'اطلاعات ناقص' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    await pool.query('INSERT INTO users (username, password, role, schoolName, district) VALUES (\$1, \$2, \$3, \$4, \$5)', [username, hash, 'school', schoolName, district]);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: 'نام کاربری تکراری است' });
  }
});

app.post('/api/users/bulk', authRequired, adminOnly, async (req, res) => {
  const list = req.body.list || [];
  let ok = 0, fail = 0;
  for (const u of list) {
    try {
      const hash = bcrypt.hashSync(String(u.password || '123456'), 10);
      await pool.query('INSERT INTO users (username, password, role, schoolName, district) VALUES (\$1, \$2, \$3, \$4, \$5)', [u.username, hash, 'school', u.schoolName, u.district]);
      ok++;
    } catch (e) { fail++; }
  }
  res.json({ ok, fail });
});

app.delete('/api/users/:id', authRequired, adminOnly, async (req, res) => {
  await pool.query('DELETE FROM users WHERE id = \$1 AND role = \$2', [req.params.id, 'school']);
  res.json({ ok: true });
});

app.put('/api/users/:id/password', authRequired, adminOnly, async (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'رمز جدید الزامی' });
  const hash = bcrypt.hashSync(password, 10);
  await pool.query('UPDATE users SET password = \$1 WHERE id = \$2', [hash, req.params.id]);
  res.json({ ok: true });
});

app.get('/api/records', authRequired, async (req, res) => {
  let result;
  if (req.user.role === 'admin') {
    result = await pool.query('SELECT r.*, u.schoolName as "userSchool", u.district as "userDistrict" FROM records r LEFT JOIN users u ON r.userId = u.id ORDER BY r.id DESC');
  } else {
    result = await pool.query('SELECT * FROM records WHERE userId = \$1 ORDER BY id DESC', [req.user.id]);
  }
  const rows = result.rows.map(r => ({ ...r, data: JSON.parse(r.data) }));
  res.json(rows);
});

app.post('/api/records', authRequired, async (req, res) => {
  const body = req.body || {};
  const schoolName = body.schoolName || req.user.schoolName || '';
  const district = body.district || req.user.district || '';
  await pool.query('INSERT INTO records (userId, schoolName, district, data) VALUES (\$1, \$2, \$3, \$4)', [req.user.id, schoolName, district, JSON.stringify(body)]);
  res.json({ ok: true });
});

app.put('/api/records/:id', authRequired, async (req, res) => {
  const result = await pool.query('SELECT * FROM records WHERE id = \$1', [req.params.id]);
  const rec = result.rows[0];
  if (!rec) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role !== 'admin' && rec.userid !== req.user.id) return res.status(403).json({ error: 'دسترسی ندارید' });
  const body = req.body || {};
  await pool.query('UPDATE records SET schoolName=\$1, district=\$2, data=\$3 WHERE id=\$4', [body.schoolName || rec.schoolname, body.district || rec.district, JSON.stringify(body), req.params.id]);
  res.json({ ok: true });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
