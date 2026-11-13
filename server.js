// ============================================================
// server.js
// سرور کامل — ریاست معارف ولایت هرات
// شامل: احراز هویت، مکاتب، کارمندان، ارزیابی، معاشات، تشکیل، تنظیمات
// ============================================================

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const XLSX = require('xlsx');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'hr-secret-key-change-me';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'database.db');

// ============================================================
// Middleware
// ============================================================
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
// Database
// ============================================================
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) console.error('❌ خطا در اتصال به دیتابیس:', err.message);
  else console.log('✅ دیتابیس متصل شد:', DB_PATH);
});
db.configure('busyTimeout', 10000);

// ============================================================
// ساخت جداول — با حفظ همه ستون‌های قبلی + ستون‌های جدید
// ============================================================
db.serialize(() => {
  // users
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    schoolname TEXT,
    district TEXT,
    role TEXT DEFAULT 'school',
    school_first_code TEXT,
    school_last_code TEXT,
    madaris_first_code TEXT,
    madaris_last_code TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  // اضافه کردن ستون‌های جدید اگر جدول موجود است (سازگاری با نسخه قبلی)
  ['school_first_code', 'school_last_code', 'madaris_first_code', 'madaris_last_code'].forEach(col => {
    db.run(`ALTER TABLE users ADD COLUMN ${col} TEXT`, () => {});
  });

  // records
  db.run(`CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userid INTEGER,
    schoolname TEXT,
    district TEXT,
    data TEXT,
    status TEXT DEFAULT 'pending',
    editAllowed INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  // evaluations
  db.run(`CREATE TABLE IF NOT EXISTS evaluations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userid INTEGER,
    record_id INTEGER,
    schoolname TEXT,
    first_name TEXT,
    last_name TEXT,
    father_name TEXT,
    grandfather_name TEXT,
    job_title TEXT,
    job_code TEXT,
    eval_date TEXT,
    eval_score REAL,
    eval_result TEXT,
    remarks TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  // salaries
  db.run(`CREATE TABLE IF NOT EXISTS salaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userid INTEGER,
    record_id INTEGER,
    schoolname TEXT,
    first_name TEXT,
    last_name TEXT,
    father_name TEXT,
    job_title TEXT,
    job_code TEXT,
    year INTEGER,
    month TEXT,
    base_salary REAL DEFAULT 0,
    other_base REAL DEFAULT 0,
    professional REAL DEFAULT 0,
    other_professional REAL DEFAULT 0,
    food REAL DEFAULT 0,
    other_food REAL DEFAULT 0,
    allowance REAL DEFAULT 0,
    other_allowance REAL DEFAULT 0,
    other_increase REAL DEFAULT 0,
    absence REAL DEFAULT 0,
    tax REAL DEFAULT 0,
    other_tax REAL DEFAULT 0,
    tax_10 REAL DEFAULT 0,
    deductions REAL DEFAULT 0,
    other_deductions REAL DEFAULT 0,
    total_entitlement REAL DEFAULT 0,
    total_deductions REAL DEFAULT 0,
    net_pay REAL DEFAULT 0,
    bank_number TEXT,
    appointment_letter TEXT,
    attendance TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  // school_settings
  db.run(`CREATE TABLE IF NOT EXISTS school_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userid INTEGER UNIQUE,
    schoolname TEXT,
    school_year INTEGER,
    settings_data TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  // evaluation_permission
  db.run(`CREATE TABLE IF NOT EXISTS evaluation_permission (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    allowed INTEGER DEFAULT 0,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  // ✅ tashkeel (تشکیل)
  db.run(`CREATE TABLE IF NOT EXISTS tashkeel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userid INTEGER,
    pub TEXT,
    priv TEXT,
    title TEXT NOT NULL,
    place TEXT NOT NULL,
    code TEXT NOT NULL,
    section TEXT DEFAULT 'amariat',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(code, section, place)
  )`);

  // ایندکس‌ها
  db.run(`CREATE INDEX IF NOT EXISTS idx_tashkeel_code ON tashkeel(code)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_tashkeel_section ON tashkeel(section)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_tashkeel_place ON tashkeel(place)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_tashkeel_userid ON tashkeel(userid)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_records_userid ON records(userid)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_evaluations_record ON evaluations(record_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_salaries_record ON salaries(record_id)`);

  console.log('✅ جداول آماده شدند');
});

// ============================================================
// Helpers — تاریخ شمسی، تبدیل کد، بازه‌ها
// ============================================================
function extractCodeNumber(codeOrNumeric) {
  if (codeOrNumeric === null || codeOrNumeric === undefined) return null;
  const str = String(codeOrNumeric).trim();
  if (!str) return null;
  const match = str.match(/^27-\d+-\d+-(\d+)$/);
  if (match) return parseInt(match[1], 10);
  const num = parseInt(str, 10);
  return isNaN(num) ? null : num;
}

function normalizeCode(codeOrNumeric) {
  const num = extractCodeNumber(codeOrNumeric);
  return num === null ? null : '27-32-02-' + num;
}

function isInRange(num, first, last) {
  if (num === null) return false;
  if (!first || !last) return false;
  const f = parseInt(first, 10), l = parseInt(last, 10);
  if (isNaN(f) || isNaN(l)) return false;
  return num >= f && num <= l;
}

function isCodeInSchoolRanges(code, user) {
  const num = extractCodeNumber(code);
  if (num === null) return { valid: false, reason: 'format', codeNum: null };
  const inSchools = isInRange(num, user.school_first_code, user.school_last_code);
  const inMadaris = isInRange(num, user.madaris_first_code, user.madaris_last_code);
  return {
    valid: inSchools || inMadaris,
    section: inSchools ? 'amariat' : (inMadaris ? 'madaris' : null),
    codeNum: num
  };
}

function findCodeOwnerSchool(code, currentId, callback) {
  const num = extractCodeNumber(code);
  if (num === null) return callback(null);
  db.all(
    'SELECT id, schoolname, school_first_code, school_last_code, madaris_first_code, madaris_last_code FROM users WHERE role = "school" AND id != ?',
    [currentId],
    (err, schools) => {
      if (err) return callback(null);
      for (const s of schools) {
        if (isInRange(num, s.school_first_code, s.school_last_code) ||
            isInRange(num, s.madaris_first_code, s.madaris_last_code)) {
          return callback(s.schoolname);
        }
      }
      callback(null);
    }
  );
}

function rangesOverlap(f1, l1, f2, l2) {
  if (!f1 || !l1 || !f2 || !l2) return false;
  const a = parseInt(f1, 10), b = parseInt(l1, 10);
  const c = parseInt(f2, 10), d = parseInt(l2, 10);
  if ([a, b, c, d].some(x => isNaN(x))) return false;
  return !(b < c || a > d);
}

function detectSchoolType(schoolName) {
  if (!schoolName) return 'نامشخص';
  const name = String(schoolName).trim().replace(/\s+/g, ' ');
  if (name.includes('لیسه')) return 'لیسه';
  if (name.includes('متوسطه')) return 'متوسطه';
  if (name.includes('ابتداییه') || name.includes('ابتدائیه')) return 'ابتداییه';
  if (name.includes('مدرسه') || name.includes('مکتب') || name.includes('دارالعلوم')) return 'مدرسه';
  return 'نامشخص';
}

// ============================================================
// Middleware احراز هویت
// ============================================================
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'توکن نامعتبر' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'توکن منقضی' });

    // ✅ خواندن اطلاعات کامل کاربر از دیتابیس (شامل بازه‌ها)
    db.get(
      `SELECT id, username, schoolname, district, role,
              school_first_code, school_last_code,
              madaris_first_code, madaris_last_code
       FROM users WHERE id = ?`,
      [decoded.id],
      (err2, user) => {
        if (err2 || !user) return res.status(403).json({ error: 'کاربر یافت نشد' });
        req.user = user;
        next();
      }
    );
  });
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'دسترسی فقط برای ادمین' });
  next();
}

// ============================================================
// Auth
// ============================================================
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'نام کاربری و رمز الزامی است' });

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(401).json({ error: 'نام کاربری یا رمز اشتباه است' });

    bcrypt.compare(password, user.password, (err2, match) => {
      if (err2) return res.status(500).json({ error: err2.message });
      if (!match) return res.status(401).json({ error: 'نام کاربری یا رمز اشتباه است' });

      const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
      res.json({
        token,
        user: {
          id: user.id,
          username: user.username,
          schoolname: user.schoolname,
          district: user.district,
          role: user.role,
          school_first_code: user.school_first_code,
          school_last_code: user.school_last_code,
          madaris_first_code: user.madaris_first_code,
          madaris_last_code: user.madaris_last_code
        }
      });
    });
  });
});

// ============================================================
// Users
// ============================================================
app.get('/api/users', authenticateToken, (req, res) => {
  const sql = req.user.role === 'admin'
    ? 'SELECT id, username, schoolname, district, role, school_first_code, school_last_code, madaris_first_code, madaris_last_code FROM users ORDER BY schoolname'
    : 'SELECT id, username, schoolname, district, role, school_first_code, school_last_code, madaris_first_code, madaris_last_code FROM users WHERE id = ?';

  db.all(sql, req.user.role === 'admin' ? [] : [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

// ============================================================
// POST /api/users — با بازه‌های مکاتب و مدارس
// ============================================================
app.post('/api/users', authenticateToken, requireAdmin, (req, res) => {
  const {
    username, password, schoolname, district, role,
    schoolFirstCode, schoolLastCode,
    madarisFirstCode, madarisLastCode
  } = req.body;

  if (!username || !password || !schoolname) {
    return res.status(400).json({ error: 'نام کاربری، رمز و نام مکتب الزامی است' });
  }

  // اعتبارسنجی بازه‌ها
  const ranges = [
    { name: 'مکاتب', f: schoolFirstCode, l: schoolLastCode },
    { name: 'مدارس', f: madarisFirstCode, l: madarisLastCode }
  ];
  for (const r of ranges) {
    if ((r.f && !r.l) || (!r.f && r.l)) {
      return res.status(400).json({ error: `هر دو کد بازه ${r.name} (اول و آخر) الزامی است` });
    }
    if (r.f && r.l) {
      const f = parseInt(r.f, 10), l = parseInt(r.l, 10);
      if (isNaN(f) || isNaN(l)) return res.status(400).json({ error: `کدهای بازه ${r.name} باید عدد باشند` });
      if (f > l) return res.status(400).json({ error: `کد اول بازه ${r.name} باید کمتر از کد آخر باشد` });
    }
  }

  // بررسی تداخل با مکاتب دیگر
  db.all('SELECT id, schoolname, school_first_code, school_last_code, madaris_first_code, madaris_last_code FROM users WHERE role = "school"', (err, schools) => {
    if (err) return res.status(500).json({ error: err.message });

    if (schoolFirstCode && schoolLastCode) {
      for (const s of schools) {
        if (rangesOverlap(schoolFirstCode, schoolLastCode, s.school_first_code, s.school_last_code)) {
          return res.status(409).json({
            error: `بازه مکاتب ${schoolFirstCode}–${schoolLastCode} با مکتب «${s.schoolname}» (${s.school_first_code}–${s.school_last_code}) تداخل دارد`
          });
        }
      }
    }
    if (madarisFirstCode && madarisLastCode) {
      for (const s of schools) {
        if (rangesOverlap(madarisFirstCode, madarisLastCode, s.madaris_first_code, s.madaris_last_code)) {
          return res.status(409).json({
            error: `بازه مدارس ${madarisFirstCode}–${madarisLastCode} با مکتب «${s.schoolname}» (${s.madaris_first_code}–${s.madaris_last_code}) تداخل دارد`
          });
        }
      }
    }

    bcrypt.hash(password, 10, (err2, hash) => {
      if (err2) return res.status(500).json({ error: err2.message });
      db.run(
        `INSERT INTO users
          (username, password, schoolname, district, role,
           school_first_code, school_last_code,
           madaris_first_code, madaris_last_code)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          username, hash, schoolname, district, role || 'school',
          schoolFirstCode || null, schoolLastCode || null,
          madarisFirstCode || null, madarisLastCode || null
        ],
        function(err3) {
          if (err3) {
            if (err3.message.includes('UNIQUE')) return res.status(409).json({ error: 'نام کاربری تکراری است' });
            return res.status(500).json({ error: err3.message });
          }
          res.json({ id: this.lastID, success: true });
        }
      );
    });
  });
});

// ============================================================
// PUT /api/users/:id — به‌روزرسانی مکتب + بازه‌ها
// ============================================================
app.put('/api/users/:id', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  const {
    username, password, schoolname, district,
    school_first_code, school_last_code,
    madaris_first_code, madaris_last_code
  } = req.body;

  if (!username || !schoolname) {
    return res.status(400).json({ error: 'نام کاربری و نام مکتب الزامی است' });
  }

  // اعتبارسنجی بازه‌ها
  const ranges = [
    { name: 'مکاتب', f: school_first_code, l: school_last_code },
    { name: 'مدارس', f: madaris_first_code, l: madaris_last_code }
  ];
  for (const r of ranges) {
    if (r.f && r.l) {
      const f = parseInt(r.f, 10), l = parseInt(r.l, 10);
      if (isNaN(f) || isNaN(l)) return res.status(400).json({ error: `کدهای بازه ${r.name} باید عدد باشند` });
      if (f > l) return res.status(400).json({ error: `کد اول بازه ${r.name} باید کمتر از کد آخر باشد` });
    }
  }

  // بررسی تداخل (به‌جز خود مکتب)
  db.all('SELECT id, schoolname, school_first_code, school_last_code, madaris_first_code, madaris_last_code FROM users WHERE role = "school" AND id != ?', [id], (err, schools) => {
    if (err) return res.status(500).json({ error: err.message });

    if (school_first_code && school_last_code) {
      for (const s of schools) {
        if (rangesOverlap(school_first_code, school_last_code, s.school_first_code, s.school_last_code)) {
          return res.status(409).json({
            error: `بازه مکاتب ${school_first_code}–${school_last_code} با مکتب «${s.schoolname}» تداخل دارد`
          });
        }
      }
    }
    if (madaris_first_code && madaris_last_code) {
      for (const s of schools) {
        if (rangesOverlap(madaris_first_code, madaris_last_code, s.madaris_first_code, s.madaris_last_code)) {
          return res.status(409).json({
            error: `بازه مدارس ${madaris_first_code}–${madaris_last_code} با مکتب «${s.schoolname}» تداخل دارد`
          });
        }
      }
    }

    function doUpdate(hash) {
      const updates = [
        'username = ?', 'schoolname = ?', 'district = ?',
        'school_first_code = ?', 'school_last_code = ?',
        'madaris_first_code = ?', 'madaris_last_code = ?'
      ];
      const values = [
        username, schoolname, district,
        school_first_code || null, school_last_code || null,
        madaris_first_code || null, madaris_last_code || null
      ];
      if (hash) { updates.push('password = ?'); values.push(hash); }
      values.push(id);

      db.run(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, values, function(err2) {
        if (err2) {
          if (err2.message.includes('UNIQUE')) return res.status(409).json({ error: 'نام کاربری تکراری است' });
          return res.status(500).json({ error: err2.message });
        }
        res.json({ success: true });
      });
    }

    if (password) {
      bcrypt.hash(password, 10, (err2, hash) => {
        if (err2) return res.status(500).json({ error: err2.message });
        doUpdate(hash);
      });
    } else {
      doUpdate(null);
    }
  });
});

// ============================================================
// DELETE /api/users/:id
// ============================================================
app.delete('/api/users/:id', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  db.run('DELETE FROM users WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ============================================================
// check-jobcode — با نرمال‌سازی کد و بازه‌ها
// ============================================================
app.get('/api/check-jobcode', authenticateToken, (req, res) => {
  const raw = req.query.code;
  const excludeId = req.query.excludeId;

  if (!raw) return res.json({ exists: false, valid: true });

  const normalizedCode = normalizeCode(raw);
  if (!normalizedCode) {
    return res.json({ exists: false, valid: false, error: 'فرمت کد نامعتبر (مثال: 27-32-02-12563)' });
  }

  // ۱. بررسی در records
  db.all(
    `SELECT id, userid, schoolname, data FROM records
     WHERE json_extract(data, '$.jobCode') = ?
        OR json_extract(data, '$.jobCode') = ?`,
    [normalizedCode, String(extractCodeNumber(normalizedCode))],
    (err, records) => {
      if (err) return res.status(500).json({ error: err.message });

      const filtered = excludeId ? records.filter(r => String(r.id) !== String(excludeId)) : records;

      if (filtered.length > 0) {
        const r = filtered[0];
        return res.json({
          exists: true,
          isSameSchool: r.userid === req.user.id,
          schoolname: r.schoolname,
          employeeName: (() => {
            try {
              const d = JSON.parse(r.data);
              return `${d.firstName || ''} ${d.lastName || ''}`.trim();
            } catch (e) { return ''; }
          })(),
          normalizedCode
        });
      }

      // ۲. بررسی در tashkeel
      db.get('SELECT id, userid, place, section FROM tashkeel WHERE code = ?', [normalizedCode], (err2, tRow) => {
        if (err2) return res.status(500).json({ error: err2.message });

        if (tRow) {
          return res.json({
            exists: true,
            isSameSchool: tRow.userid === req.user.id,
            schoolname: tRow.place,
            employeeName: '(در تشکیلات ثبت شده)',
            normalizedCode,
            section: tRow.section
          });
        }

        // ۳. بررسی بازه
        if (req.user.role === 'school') {
          const check = isCodeInSchoolRanges(normalizedCode, req.user);

          if (!check.valid) {
            return res.json({
              exists: false,
              outOfRange: true,
              normalizedCode,
              error: `کد «${normalizedCode}» متعلق به مکتب شما نیست.\nبازه مکاتب: ${req.user.school_first_code || '—'} تا ${req.user.school_last_code || '—'}\nبازه مدارس: ${req.user.madaris_first_code || '—'} تا ${req.user.madaris_last_code || '—'}`
            });
          }

          // ۴. بررسی تعلق به مکتب دیگر
          return findCodeOwnerSchool(normalizedCode, req.user.id, (other) => {
            if (other) {
              return res.json({
                exists: false,
                ownedByOther: true,
                normalizedCode,
                error: `این کد بست متعلق به مکتب «${other}» است`
              });
            }
            res.json({ exists: false, valid: true, section: check.section, normalizedCode });
          });
        }

        res.json({ exists: false, valid: true, normalizedCode });
      });
    }
  );
});

// ============================================================
// check-etazkira
// ============================================================
app.get('/api/check-etazkira', authenticateToken, (req, res) => {
  const code = req.query.code;
  const excludeId = req.query.excludeId;
  if (!code) return res.json({ exists: false });

  db.all(
    `SELECT id, userid, schoolname, data FROM records
     WHERE json_extract(data, '$.eTazkira') = ?`,
    [code],
    (err, records) => {
      if (err) return res.status(500).json({ error: err.message });

      const filtered = excludeId ? records.filter(r => String(r.id) !== String(excludeId)) : records;
      if (filtered.length === 0) return res.json({ exists: false });

      const r = filtered[0];
      res.json({
        exists: true,
        isSameSchool: r.userid === req.user.id,
        schoolname: r.schoolname,
        employeeName: (() => {
          try {
            const d = JSON.parse(r.data);
            return `${d.firstName || ''} ${d.lastName || ''}`.trim();
          } catch (e) { return ''; }
        })()
      });
    }
  );
});

console.log('✅ بخش اول server.js بارگذاری شد — ادامه در بخش دوم');
// ============================================================
// Records (کارمندان)
// ============================================================
app.get('/api/records', authenticateToken, (req, res) => {
  const { search } = req.query;
  let sql = 'SELECT * FROM records';
  const params = [];

  if (req.user.role === 'school') {
    sql += ' WHERE userid = ?';
    params.push(req.user.id);
  } else if (search) {
    sql += ' WHERE (data LIKE ? OR schoolname LIKE ?)';
    params.push('%' + search + '%', '%' + search + '%');
  }

  sql += ' ORDER BY id DESC';

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    // تجزیه data
    const result = (rows || []).map(r => {
      try { return { ...r, data: JSON.parse(r.data) }; }
      catch (e) { return { ...r, data: {} }; }
    });
    res.json(result);
  });
});

// ============================================================
// POST /api/records — با بررسی بازه کد بست
// ============================================================
app.post('/api/records', authenticateToken, (req, res) => {
  const body = req.body;

  // ✅ اگر مکتب است: کد بست باید در بازه خودش باشد
  if (req.user.role === 'school' && body.jobCode) {
    const normalized = normalizeCode(body.jobCode);
    if (!normalized) {
      return res.status(400).json({ error: 'فرمت کد بست نامعتبر', code: 'INVALID_CODE_FORMAT' });
    }
    body.jobCode = normalized;

    const check = isCodeInSchoolRanges(normalized, req.user);
    if (!check.valid) {
      return res.status(403).json({
        error: `کد بست «${normalized}» متعلق به مکتب شما نیست.\nبازه مکاتب: ${req.user.school_first_code || '—'} تا ${req.user.school_last_code || '—'}\nبازه مدارس: ${req.user.madaris_first_code || '—'} تا ${req.user.madaris_last_code || '—'}`,
        code: 'CODE_NOT_IN_SCHOOL_RANGE'
      });
    }

    return findCodeOwnerSchool(normalized, req.user.id, (other) => {
      if (other) {
        return res.status(409).json({
          error: `این کد بست متعلق به مکتب «${other}» است`,
          code: 'CODE_OWNED_BY_OTHER_SCHOOL'
        });
      }
      saveRecord();
    });
  }

  saveRecord();

  function saveRecord() {
    const data = JSON.stringify(body);
    db.run(
      'INSERT INTO records (userid, schoolname, district, data, status) VALUES (?, ?, ?, ?, "pending")',
      [req.user.id, req.user.schoolname, req.user.district, data],
      function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, success: true });
      }
    );
  }
});

// ============================================================
// PUT /api/records/:id
// ============================================================
app.put('/api/records/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const body = req.body;

  db.get('SELECT * FROM records WHERE id = ?', [id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'رکورد یافت نشد' });

    // مکتب فقط رکورد خودش
    if (req.user.role === 'school' && row.userid !== req.user.id) {
      return res.status(403).json({ error: 'دسترسی ندارید' });
    }

    // بررسی کد بست جدید اگر تغییر کرده
    if (req.user.role === 'school' && body.jobCode) {
      let oldData = {};
      try { oldData = JSON.parse(row.data); } catch (e) {}
      if (body.jobCode !== oldData.jobCode) {
        const normalized = normalizeCode(body.jobCode);
        if (!normalized) return res.status(400).json({ error: 'فرمت کد بست نامعتبر' });
        const check = isCodeInSchoolRanges(normalized, req.user);
        if (!check.valid) {
          return res.status(403).json({
            error: `کد بست جدید «${normalized}» متعلق به مکتب شما نیست`,
            code: 'CODE_NOT_IN_SCHOOL_RANGE'
          });
        }
        body.jobCode = normalized;
      }
    }

    // اگر فقط editAllowed تغییر کرده
    if (body.editAllowed !== undefined && Object.keys(body).length === 1) {
      return db.run('UPDATE records SET editAllowed = ? WHERE id = ?', [body.editAllowed ? 1 : 0, id], function(err2) {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json({ success: true });
      });
    }

    // آپدیت کامل
    let oldData = {};
    try { oldData = JSON.parse(row.data); } catch (e) {}
    const newData = { ...oldData, ...body, editAllowed: true };

    db.run(
      'UPDATE records SET data = ?, editAllowed = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [JSON.stringify(newData), 1, id],
      function(err2) {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json({ success: true });
      }
    );
  });
});

// ============================================================
// POST /api/records/:id/approve
// ============================================================
app.post('/api/records/:id/approve', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  db.run('UPDATE records SET status = "approved" WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ============================================================
// DELETE /api/records/:id
// ============================================================
app.delete('/api/records/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.get('SELECT * FROM records WHERE id = ?', [id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'یافت نشد' });
    if (req.user.role === 'school' && row.userid !== req.user.id) {
      return res.status(403).json({ error: 'دسترسی ندارید' });
    }
    db.run('DELETE FROM records WHERE id = ?', [id], function(err2) {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ success: true });
    });
  });
});

// ============================================================
// Evaluations
// ============================================================
app.get('/api/evaluations', authenticateToken, (req, res) => {
  let sql = 'SELECT * FROM evaluations';
  const params = [];
  if (req.user.role === 'school') {
    sql += ' WHERE userid = ?';
    params.push(req.user.id);
  }
  sql += ' ORDER BY id DESC';
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

app.post('/api/evaluations', authenticateToken, (req, res) => {
  const e = req.body;
  db.run(
    `INSERT INTO evaluations
      (userid, record_id, schoolname, first_name, last_name, father_name,
       grandfather_name, job_title, job_code, eval_date, eval_score, eval_result, remarks)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      req.user.id, e.record_id, req.user.schoolname,
      e.first_name, e.last_name, e.father_name, e.grandfather_name,
      e.job_title, e.job_code, e.eval_date, e.eval_score, e.eval_result, e.remarks
    ],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, success: true });
    }
  );
});

app.delete('/api/evaluations/:id', authenticateToken, requireAdmin, (req, res) => {
  db.run('DELETE FROM evaluations WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ============================================================
// Salaries
// ============================================================
app.get('/api/salaries', authenticateToken, (req, res) => {
  let sql = 'SELECT * FROM salaries';
  const params = [];
  if (req.user.role === 'school') {
    sql += ' WHERE userid = ?';
    params.push(req.user.id);
  }
  sql += ' ORDER BY id DESC';
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const result = (rows || []).map(r => {
      try { return { ...r, attendance: JSON.parse(r.attendance || '{}') }; }
      catch (e) { return { ...r, attendance: {} }; }
    });
    res.json(result);
  });
});

app.get('/api/salaries/:id', authenticateToken, (req, res) => {
  db.get('SELECT * FROM salaries WHERE id = ?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'یافت نشد' });
    if (req.user.role === 'school' && row.userid !== req.user.id) {
      return res.status(403).json({ error: 'دسترسی ندارید' });
    }
    try { row.attendance = JSON.parse(row.attendance || '{}'); }
    catch (e) { row.attendance = {}; }
    res.json(row);
  });
});

app.delete('/api/salaries/:id', authenticateToken, requireAdmin, (req, res) => {
  db.run('DELETE FROM salaries WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ============================================================
// School Settings
// ============================================================
app.get('/api/school-settings', authenticateToken, (req, res) => {
  db.get('SELECT * FROM school_settings WHERE userid = ?', [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.json({ exists: false });
    try { row.settings = JSON.parse(row.settings_data || '{}'); }
    catch (e) { row.settings = {}; }
    res.json({ exists: true, settings: row.settings });
  });
});

app.post('/api/school-settings', authenticateToken, (req, res) => {
  const settingsData = JSON.stringify(req.body);
  db.get('SELECT id FROM school_settings WHERE userid = ?', [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (row) {
      db.run(
        'UPDATE school_settings SET settings_data = ?, updated_at = CURRENT_TIMESTAMP WHERE userid = ?',
        [settingsData, req.user.id],
        function(err2) {
          if (err2) return res.status(500).json({ error: err2.message });
          res.json({ success: true });
        }
      );
    } else {
      db.run(
        'INSERT INTO school_settings (userid, schoolname, settings_data) VALUES (?, ?, ?)',
        [req.user.id, req.user.schoolname, settingsData],
        function(err2) {
          if (err2) return res.status(500).json({ error: err2.message });
          res.json({ id: this.lastID, success: true });
        }
      );
    }
  });
});

// ============================================================
// all-school-settings (ادمین)
// ============================================================
app.get('/api/all-school-settings', authenticateToken, requireAdmin, (req, res) => {
  db.all(
    `SELECT ss.*, u.schoolname, u.district
     FROM school_settings ss
     LEFT JOIN users u ON u.id = ss.userid
     ORDER BY ss.schoolname`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      const result = (rows || []).map(r => {
        try { return { ...r, ...JSON.parse(r.settings_data || '{}') }; }
        catch (e) { return r; }
      });
      res.json(result);
    }
  );
});

// ============================================================
// Evaluation Permission
// ============================================================
app.get('/api/evaluation-permission', authenticateToken, (req, res) => {
  db.get('SELECT allowed FROM evaluation_permission ORDER BY id DESC LIMIT 1', [], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ allowed: row ? !!row.allowed : false });
  });
});

app.post('/api/evaluation-permission', authenticateToken, requireAdmin, (req, res) => {
  const allowed = req.body.allowed ? 1 : 0;
  db.run('INSERT INTO evaluation_permission (allowed) VALUES (?)', [allowed], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ============================================================
// ✅ TASHKEEL (تشکیل)
// ============================================================

// GET /api/tashkeel
app.get('/api/tashkeel', authenticateToken, (req, res) => {
  const { school, section } = req.query;
  let sql = 'SELECT * FROM tashkeel WHERE 1=1';
  const params = [];

  if (req.user.role === 'admin') {
    if (school) { sql += ' AND place = ?'; params.push(school); }
    if (section) { sql += ' AND section = ?'; params.push(section); }
  } else {
    sql += ' AND (userid = ? OR place = ?)';
    params.push(req.user.id, req.user.schoolname);
    if (section) { sql += ' AND section = ?'; params.push(section); }
  }

  sql += ' ORDER BY place, id';

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

// POST /api/tashkeel
app.post('/api/tashkeel', authenticateToken, (req, res) => {
  const { pub, priv, title, place, code, section } = req.body;
  if (!title || !code) return res.status(400).json({ error: 'عنوان و کد الزامی است' });

  const normalizedCode = normalizeCode(code);
  if (!normalizedCode) {
    return res.status(400).json({ error: 'فرمت کد نامعتبر. مثال: 27-32-02-12563 یا 12563' });
  }

  const finalSection = section || 'amariat';
  const finalPlace = req.user.role === 'admin' ? (place || 'نامشخص') : req.user.schoolname;
  const userid = req.user.role === 'admin' ? null : req.user.id;

  if (req.user.role === 'school') {
    const check = isCodeInSchoolRanges(normalizedCode, req.user);
    if (!check.valid) {
      return res.status(403).json({
        error: `کد «${normalizedCode}» متعلق به مکتب شما نیست`,
        code: 'CODE_NOT_IN_SCHOOL_RANGE'
      });
    }
    if (check.section !== finalSection) {
      return res.status(400).json({
        error: `این کد مربوط به بخش «${check.section === 'amariat' ? 'مکاتب' : 'مدارس'}» است، نه «${finalSection === 'amariat' ? 'مکاتب' : 'مدارس'}»`,
        code: 'SECTION_MISMATCH'
      });
    }
    return findCodeOwnerSchool(normalizedCode, req.user.id, (other) => {
      if (other) {
        return res.status(409).json({ error: `متعلق به مکتب «${other}» است`, code: 'CODE_OWNED_BY_OTHER_SCHOOL' });
      }
      insertTashkeel();
    });
  }

  insertTashkeel();

  function insertTashkeel() {
    db.run(
      'INSERT INTO tashkeel (userid, pub, priv, title, place, code, section) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [userid, pub, priv, title, finalPlace, normalizedCode, finalSection],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            return res.status(409).json({
              error: `کد «${normalizedCode}» قبلاً در محل «${finalPlace}» ثبت شده`,
              code: 'DUPLICATE_CODE'
            });
          }
          return res.status(500).json({ error: err.message });
        }
        res.json({ id: this.lastID, code: normalizedCode, success: true });
      }
    );
  }
});

// PUT /api/tashkeel/:id
app.put('/api/tashkeel/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { title, place } = req.body;

  const sql = req.user.role === 'admin'
    ? 'SELECT * FROM tashkeel WHERE id = ?'
    : 'SELECT * FROM tashkeel WHERE id = ? AND (userid = ? OR place = ?)';
  const params = req.user.role === 'admin' ? [id] : [id, req.user.id, req.user.schoolname];

  db.get(sql, params, (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'یافت نشد یا دسترسی ندارید' });

    const updates = [], values = [];
    if (title !== undefined) { updates.push('title = ?'); values.push(title); }
    if (place !== undefined) { updates.push('place = ?'); values.push(place); }
    if (!updates.length) return res.status(400).json({ error: 'چیزی برای به‌روزرسانی نیست' });
    values.push(id);

    db.run(`UPDATE tashkeel SET ${updates.join(', ')} WHERE id = ?`, values, function(err2) {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ success: true });
    });
  });
});

// DELETE /api/tashkeel/:id
app.delete('/api/tashkeel/:id', authenticateToken, (req, res) => {
  const { id } = req.params;

  const sql = req.user.role === 'admin'
    ? 'SELECT * FROM tashkeel WHERE id = ?'
    : 'SELECT * FROM tashkeel WHERE id = ? AND (userid = ? OR place = ?)';
  const params = req.user.role === 'admin' ? [id] : [id, req.user.id, req.user.schoolname];

  db.get(sql, params, (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'یافت نشد یا دسترسی ندارید' });
    db.run('DELETE FROM tashkeel WHERE id = ?', [id], function(err2) {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ success: true });
    });
  });
});

// ============================================================
// SPA fallback
// ============================================================
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'اندپوینت یافت نشد' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'), (err) => {
    if (err) res.status(404).send('صفحه یافت نشد');
  });
});

// ============================================================
// Error handler
// ============================================================
app.use((err, req, res, next) => {
  console.error('❌ خطای سرور:', err);
  res.status(500).json({ error: 'خطای داخلی سرور', message: err.message });
});

// ============================================================
// Listen
// ============================================================
app.listen(PORT, () => {
  console.log('═══════════════════════════════════════════════════════════');
  console.log(`  🚀 سرور فعال شد روی پورت ${PORT}`);
  console.log(`  🌐 http://localhost:${PORT}`);
  console.log(`  📁 دیتابیس: ${DB_PATH}`);
  console.log('═══════════════════════════════════════════════════════════');
});


