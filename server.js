const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'maaref-herat-secret-change-me';

// ══════════ دیتابیس ══════════
const DB_PATH = process.env.DB_PATH || './data.db';
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL,
  schoolName TEXT,
  district TEXT,
  createdAt TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userId INTEGER NOT NULL,
  schoolName TEXT NOT NULL,
  district TEXT NOT NULL,
  data TEXT NOT NULL,
  createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(userId) REFERENCES users(id)
);
`);

// ادمین پیش‌فرض
const admin = db.prepare('SELECT * FROM users WHERE role = ?').get('admin');
if (!admin) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO users (username, password, role) VALUES (?,?,?)')
    .run('admin', hash, 'admin');
  console.log('✅ ادمین ساخته شد: admin / admin123');
}

// ══════════ Middleware ══════════
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ══════════ Auth helpers ══════════
function sign(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role,
      schoolName: user.schoolName, district: user.district },
    SECRET, { expiresIn: '30d' }
  );
}

function authRequired(req, res, next) {
  const token = req.cookies?.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'وارد نشده‌اید' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'توکن نامعتبر' });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'فقط ادمین' });
  next();
}

// ══════════ Auth routes ══════════
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'نام کاربری یا رمز اشتباه' });

  const token = sign(user);
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', maxAge: 30*24*3600*1000 });
  res.json({ token, user: { id: user.id, username: user.username, role: user.role,
    schoolName: user.schoolName, district: user.district } });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/auth/me', authRequired, (req, res) => res.json(req.user));

// ══════════ Users routes ══════════
app.get('/api/users', authRequired, adminOnly, (req, res) => {
  const users = db.prepare(
    'SELECT id, username, role, schoolName, district, createdAt FROM users'
  ).all();
  res.json(users);
});

app.post('/api/users', authRequired, adminOnly, (req, res) => {
  const { username, password, schoolName, district } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'نام و رمز الزامی' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare(
      'INSERT INTO users (username, password, role, schoolName, district) VALUES (?,?,?,?,?)'
    ).run(username, hash, 'school', schoolName || username, district || '');
    res.json({ id: info.lastInsertRowid });
  } catch (e) {
    res.status(400).json({ error: 'نام کاربری تکراری است' });
  }
});

// ورود گروهی از آرایه
app.post('/api/users/bulk', authRequired, adminOnly, (req, res) => {
  const list = req.body.list || [];
  let ok = 0, fail = 0;
  const stmt = db.prepare(
    'INSERT INTO users (username, password, role, schoolName, district) VALUES (?,?,?,?,?)'
  );
  const tx = db.transaction((items) => {
    for (const u of items) {
      try {
        const hash = bcrypt.hashSync(String(u.password), 10);
        stmt.run(u.username, hash, 'school', u.schoolName || u.username, u.district || '');
        ok++;
      } catch { fail++; }
    }
  });
  tx(list);
  res.json({ ok, fail });
});

app.delete('/api/users/:id', authRequired, adminOnly, (req, res) => {
  db.prepare('DELETE FROM users WHERE id = ? AND role = ?').run(req.params.id, 'school');
  res.json({ ok: true });
});

app.put('/api/users/:id/password', authRequired, adminOnly, (req, res) => {
  const hash = bcrypt.hashSync(req.body.password, 10);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, req.params.id);
  res.json({ ok: true });
});

// ══════════ Records routes ══════════
app.get('/api/records', authRequired, (req, res) => {
  let rows;
  if (req.user.role === 'admin') {
    rows = db.prepare(`
      SELECT r.*, u.schoolName as userSchool, u.district as userDistrict
      FROM records r LEFT JOIN users u ON r.userId = u.id
      ORDER BY r.id DESC
    `).all();
  } else {
    rows = db.prepare('SELECT * FROM records WHERE userId = ? ORDER BY id DESC').all(req.user.id);
  }
  res.json(rows.map(r => ({
    id: r.id,
    ...JSON.parse(r.data),
    schoolName: r.schoolName,
    district: r.district,
    createdAt: r.createdAt,
    userId: r.userId
  })));
});

app.post('/api/records', authRequired, (req, res) => {
  const body = req.body || {};
  const schoolName = body.schoolName || req.user.schoolName || '';
  const district = body.district || req.user.district || '';

  if (req.user.role === 'school' && req.user.schoolName && schoolName !== req.user.schoolName)
    return res.status(403).json({ error: 'فقط برای مکتب خودتان' });

  const info = db.prepare(
    'INSERT INTO records (userId, schoolName, district, data) VALUES (?,?,?,?)'
  ).run(req.user.id, schoolName, district, JSON.stringify(body));
  res.json({ id: info.lastInsertRowid });
});

app.put('/api/records/:id', authRequired, (req, res) => {
  const rec = db.prepare('SELECT * FROM records WHERE id = ?').get(req.params.id);
  if (!rec) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role !== 'admin' && rec.userId !== req.user.id)
    return res.status(403).json({ error: 'دسترسی ندارید' });

  const body = req.body || {};
  db.prepare('UPDATE records SET schoolName=?, district=?, data=? WHERE id=?')
    .run(body.schoolName || rec.schoolName, body.district || rec.district,
         JSON.stringify(body), req.params.id);
  res.json({ ok: true });
});

app.delete('/api/records/:id', authRequired, (req, res) => {
  const rec = db.prepare('SELECT * FROM records WHERE id = ?').get(req.params.id);
  if (!rec) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role !== 'admin' && rec.userId !== req.user.id)
    return res.status(403).json({ error: 'دسترسی ندارید' });
  db.prepare('DELETE FROM records WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ══════════ Health ══════════
app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date() }));

// ══════════ SPA fallback ══════════
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`🚀 سرور روی پورت ${PORT} اجرا شد`));
