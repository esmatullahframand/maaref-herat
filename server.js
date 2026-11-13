code = r'''// ============================================================
// server.js — ریاست معارف ولایت هرات
// PostgreSQL / Neon edition
// نسخه سازگار با ساختار موجود Neon؛ بدون حذف یا بازسازی اطلاعات
// ============================================================

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const XLSX = require('xlsx');
const fs = require('fs');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'hr-secret-key-change-me';
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('❌ متغیر DATABASE_URL در تنظیمات سرور تعریف نشده است.');
  process.exit(1);
}
if (!process.env.JWT_SECRET && process.env.NODE_ENV === 'production') {
  console.warn('⚠️ برای امنیت، JWT_SECRET را در تنظیمات Render تعریف کنید.');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : (process.env.PGSSLMODE === 'require' ? { rejectUnauthorized: false } : undefined),
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 15000
});

pool.on('error', (err) => console.error('❌ خطای اتصال PostgreSQL:', err));

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ------------------------------------------------------------
// ابزارهای عمومی
// ------------------------------------------------------------
const asyncRoute = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const q = (sql, params = []) => pool.query(sql, params);
const boolInt = (v) => (v === true || v === 1 || v === '1' || v === 'true') ? 1 : 0;
const parseJson = (value, fallback = {}) => {
  if (value && typeof value === 'object') return value;
  try { return JSON.parse(value || ''); } catch (_) { return fallback; }
};
const toIntOrNull = (v) => {
  if (v === undefined || v === null || v === '') return null;
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? n : null;
};
const toNumber = (v, fallback = 0) => {
  if (v === undefined || v === null || v === '') return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
};

// ------------------------------------------------------------
// ساخت/تکمیل ساختار به‌صورت افزایشی
// هیچ جدول یا رکورد موجودی حذف نمی‌شود.
// ستون‌های جدید فقط با ADD COLUMN IF NOT EXISTS افزوده می‌شوند.
// ------------------------------------------------------------
async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // ستون‌های موردنیاز نسخه فعلی در جدول users
    await client.query(`
      ALTER TABLE users
        ADD COLUMN IF NOT EXISTS school_first_code TEXT,
        ADD COLUMN IF NOT EXISTS school_last_code TEXT,
        ADD COLUMN IF NOT EXISTS madaris_first_code TEXT,
        ADD COLUMN IF NOT EXISTS madaris_last_code TEXT
    `);

    // فیلدهای سازگاری در records
    await client.query(`
      ALTER TABLE records
        ADD COLUMN IF NOT EXISTS editallowed INTEGER DEFAULT 0,
        ADD COLUMN IF NOT EXISTS updatedat TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
    `);

    // فیلدهای نسخه فعلی ارزیابی؛ ستون‌های اجباری اصلی Neon حفظ می‌شوند.
    await client.query(`
      ALTER TABLE evaluations
        ADD COLUMN IF NOT EXISTS remarks TEXT,
        ADD COLUMN IF NOT EXISTS employment_type TEXT,
        ADD COLUMN IF NOT EXISTS birth_year TEXT,
        ADD COLUMN IF NOT EXISTS service_duration TEXT,
        ADD COLUMN IF NOT EXISTS degree TEXT,
        ADD COLUMN IF NOT EXISTS gender TEXT,
        ADD COLUMN IF NOT EXISTS appointment_date TEXT,
        ADD COLUMN IF NOT EXISTS eval_date_prev TEXT,
        ADD COLUMN IF NOT EXISTS bust TEXT,
        ADD COLUMN IF NOT EXISTS grade TEXT
    `);

    // فیلدهای تکمیلی معاشات برای سازگاری با اطلاعات ارسالی برنامه
    await client.query(`
      ALTER TABLE salaries
        ADD COLUMN IF NOT EXISTS first_name TEXT,
        ADD COLUMN IF NOT EXISTS last_name TEXT,
        ADD COLUMN IF NOT EXISTS father_name TEXT,
        ADD COLUMN IF NOT EXISTS job_title TEXT,
        ADD COLUMN IF NOT EXISTS job_code TEXT,
        ADD COLUMN IF NOT EXISTS attendance TEXT
    `);

    // ساختار اصلی school_settings حفظ می‌شود؛ JSON فقط برای سازگاری API افزوده می‌شود.
    await client.query(`
      ALTER TABLE school_settings
        ADD COLUMN IF NOT EXISTS school_year TEXT,
        ADD COLUMN IF NOT EXISTS settings_data TEXT
    `);

    // این جدول در دیتابیس موجود نبود؛ فقط ایجاد می‌شود.
    await client.query(`
      CREATE TABLE IF NOT EXISTS evaluation_permission (
        id SERIAL PRIMARY KEY,
        allowed INTEGER NOT NULL DEFAULT 0,
        updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // جدول تشکیل در دیتابیس موجود نبود؛ فقط ایجاد می‌شود.
    await client.query(`
      CREATE TABLE IF NOT EXISTS tashkeel (
        id SERIAL PRIMARY KEY,
        userid INTEGER,
        pub TEXT,
        priv TEXT,
        title TEXT NOT NULL,
        place TEXT NOT NULL,
        code TEXT NOT NULL,
        section TEXT DEFAULT 'amariat',
        created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT tashkeel_code_section_place_unique UNIQUE (code, section, place)
      )
    `);

    await client.query(`CREATE INDEX IF NOT EXISTS idx_records_userid ON records(userid)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_evaluations_record ON evaluations(record_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_salaries_record ON salaries(record_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_tashkeel_code ON tashkeel(code)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_tashkeel_section ON tashkeel(section)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_tashkeel_place ON tashkeel(place)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_tashkeel_userid ON tashkeel(userid)`);

    await client.query('COMMIT');
    console.log('✅ ساختار Neon بررسی و تکمیل شد؛ هیچ جدول یا رکورد موجود حذف نشد.');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('❌ خطا در آماده‌سازی دیتابیس:', err);
    throw err;
  } finally {
    client.release();
  }
}

// ------------------------------------------------------------
// Helpers — کد بست و بازه‌ها
// ------------------------------------------------------------
function extractCodeNumber(codeOrNumeric) {
  if (codeOrNumeric === null || codeOrNumeric === undefined) return null;
  const str = String(codeOrNumeric).trim();
  if (!str) return null;
  const match = str.match(/^27-\d+-\d+-(\d+)$/);
  if (match) return Number.parseInt(match[1], 10);
  const num = Number.parseInt(str, 10);
  return Number.isNaN(num) ? null : num;
}
function normalizeCode(codeOrNumeric) {
  const num = extractCodeNumber(codeOrNumeric);
  return num === null ? null : `27-32-02-${num}`;
}
function isInRange(num, first, last) {
  if (num === null || first === null || first === undefined || first === '' ||
      last === null || last === undefined || last === '') return false;
  const f = Number.parseInt(first, 10);
  const l = Number.parseInt(last, 10);
  return Number.isFinite(f) && Number.isFinite(l) && num >= f && num <= l;
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
function rangesOverlap(f1, l1, f2, l2) {
  if (!f1 || !l1 || !f2 || !l2) return false;
  const a = Number.parseInt(f1, 10), b = Number.parseInt(l1, 10);
  const c = Number.parseInt(f2, 10), d = Number.parseInt(l2, 10);
  if ([a, b, c, d].some(Number.isNaN)) return false;
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

async function findCodeOwnerSchool(code, currentId) {
  const num = extractCodeNumber(code);
  if (num === null) return null;
  const result = await q(
    `SELECT id, schoolname, school_first_code, school_last_code,
            madaris_first_code, madaris_last_code
     FROM users WHERE role = $1 AND id <> $2`,
    ['school', currentId]
  );
  for (const s of result.rows) {
    if (isInRange(num, s.school_first_code, s.school_last_code) ||
        isInRange(num, s.madaris_first_code, s.madaris_last_code)) {
      return s.schoolname;
    }
  }
  return null;
}
async function recordsContaining(field, value) {
  const result = await q('SELECT id, userid, schoolname, data FROM records ORDER BY id DESC');
  return result.rows.filter((r) => {
    const d = parseJson(r.data, null);
    return d && String(d[field] ?? '') === String(value);
  });
}

// ------------------------------------------------------------
// Authentication
// ------------------------------------------------------------
const authenticateToken = asyncRoute(async (req, res, next) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'توکن نامعتبر' });

  let decoded;
  try { decoded = jwt.verify(token, JWT_SECRET); }
  catch (_) { return res.status(403).json({ error: 'توکن منقضی یا نامعتبر است' }); }

  const result = await q(
    `SELECT id, username, schoolname, district, role,
            school_first_code, school_last_code,
            madaris_first_code, madaris_last_code
     FROM users WHERE id = $1`,
    [decoded.id]
  );
  if (!result.rows[0]) return res.status(403).json({ error: 'کاربر یافت نشد' });
  req.user = result.rows[0];
  next();
});
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'دسترسی فقط برای ادمین' });
  next();
}

// ------------------------------------------------------------
// Login
// ------------------------------------------------------------
app.post('/api/login', asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'نام کاربری و رمز الزامی است' });
  }
  const result = await q('SELECT * FROM users WHERE username = $1', [String(username).trim()]);
  const user = result.rows[0];
  if (!user) return res.status(401).json({ error: 'نام کاربری یا رمز اشتباه است' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'نام کاربری یا رمز اشتباه است' });

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  res.json({
    token,
    user: {
      id: user.id, username: user.username, schoolname: user.schoolname,
      district: user.district, role: user.role,
      school_first_code: user.school_first_code,
      school_last_code: user.school_last_code,
      madaris_first_code: user.madaris_first_code,
      madaris_last_code: user.madaris_last_code
    }
  });
}));

// ------------------------------------------------------------
// Users
// ------------------------------------------------------------
app.get('/api/users', authenticateToken, asyncRoute(async (req, res) => {
  const fields = `id, username, schoolname, district, role,
    school_first_code, school_last_code, madaris_first_code, madaris_last_code`;
  const result = req.user.role === 'admin'
    ? await q(`SELECT ${fields} FROM users ORDER BY schoolname NULLS LAST, id`)
    : await q(`SELECT ${fields} FROM users WHERE id = $1`, [req.user.id]);
  res.json(result.rows);
}));

app.post('/api/users', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
  const {
    username, password, schoolname, district, role,
    schoolFirstCode, schoolLastCode, madarisFirstCode, madarisLastCode
  } = req.body || {};
  if (!username || !password || !schoolname) {
    return res.status(400).json({ error: 'نام کاربری، رمز و نام مکتب الزامی است' });
  }
  const ranges = [
    { name: 'مکاتب', f: schoolFirstCode, l: schoolLastCode },
    { name: 'مدارس', f: madarisFirstCode, l: madarisLastCode }
  ];
  for (const r of ranges) {
    if ((r.f && !r.l) || (!r.f && r.l)) {
      return res.status(400).json({ error: `هر دو کد بازه ${r.name} الزامی است` });
    }
    if (r.f && r.l) {
      const f = Number.parseInt(r.f, 10), l = Number.parseInt(r.l, 10);
      if (!Number.isFinite(f) || !Number.isFinite(l))
        return res.status(400).json({ error: `کدهای بازه ${r.name} باید عدد باشند` });
      if (f > l) return res.status(400).json({ error: `کد اول بازه ${r.name} باید کمتر از کد آخر باشد` });
    }
  }
  const schools = await q(
    `SELECT id, schoolname, school_first_code, school_last_code,
            madaris_first_code, madaris_last_code FROM users WHERE role = $1`,
    ['school']
  );
  for (const s of schools.rows) {
    if (schoolFirstCode && schoolLastCode &&
        rangesOverlap(schoolFirstCode, schoolLastCode, s.school_first_code, s.school_last_code)) {
      return res.status(409).json({ error: `بازه مکاتب با مکتب «${s.schoolname}» تداخل دارد` });
    }
    if (madarisFirstCode && madarisLastCode &&
        rangesOverlap(madarisFirstCode, madarisLastCode, s.madaris_first_code, s.madaris_last_code)) {
      return res.status(409).json({ error: `بازه مدارس با مکتب «${s.schoolname}» تداخل دارد` });
    }
  }
  const hash = await bcrypt.hash(password, 10);
  try {
    const inserted = await q(
      `INSERT INTO users
       (username, password, schoolname, district, role,
        school_first_code, school_last_code, madaris_first_code, madaris_last_code)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
      [String(username).trim(), hash, schoolname, district || null, role || 'school',
       schoolFirstCode || null, schoolLastCode || null, madarisFirstCode || null, madarisLastCode || null]
    );
    res.json({ id: inserted.rows[0].id, success: true });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'نام کاربری تکراری است' });
    throw err;
  }
}));

app.put('/api/users/:id', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
  const id = toIntOrNull(req.params.id);
  const {
    username, password, schoolname, district,
    school_first_code, school_last_code, madaris_first_code, madaris_last_code
  } = req.body || {};
  if (!id || !username || !schoolname)
    return res.status(400).json({ error: 'نام کاربری و نام مکتب الزامی است' });

  for (const r of [
    { name: 'مکاتب', f: school_first_code, l: school_last_code },
    { name: 'مدارس', f: madaris_first_code, l: madaris_last_code }
  ]) {
    if ((r.f && !r.l) || (!r.f && r.l))
      return res.status(400).json({ error: `هر دو کد بازه ${r.name} الزامی است` });
    if (r.f && r.l) {
      const f = Number.parseInt(r.f, 10), l = Number.parseInt(r.l, 10);
      if (!Number.isFinite(f) || !Number.isFinite(l) || f > l)
        return res.status(400).json({ error: `بازه ${r.name} معتبر نیست` });
    }
  }

  const schools = await q(
    `SELECT id, schoolname, school_first_code, school_last_code,
            madaris_first_code, madaris_last_code
     FROM users WHERE role = $1 AND id <> $2`,
    ['school', id]
  );
  for (const s of schools.rows) {
    if (school_first_code && school_last_code &&
        rangesOverlap(school_first_code, school_last_code, s.school_first_code, s.school_last_code))
      return res.status(409).json({ error: `بازه مکاتب با مکتب «${s.schoolname}» تداخل دارد` });
    if (madaris_first_code && madaris_last_code &&
        rangesOverlap(madaris_first_code, madaris_last_code, s.madaris_first_code, s.madaris_last_code))
      return res.status(409).json({ error: `بازه مدارس با مکتب «${s.schoolname}» تداخل دارد` });
  }

  const values = [
    String(username).trim(), schoolname, district || null,
    school_first_code || null, school_last_code || null,
    madaris_first_code || null, madaris_last_code || null
  ];
  let sql = `UPDATE users SET username=$1, schoolname=$2, district=$3,
    school_first_code=$4, school_last_code=$5,
    madaris_first_code=$6, madaris_last_code=$7`;
  if (password) {
    values.push(await bcrypt.hash(password, 10));
    sql += `, password=$${values.length}`;
  }
  values.push(id);
  sql += ` WHERE id=$${values.length}`;
  try {
    const updated = await q(sql, values);
    if (!updated.rowCount) return res.status(404).json({ error: 'کاربر یافت نشد' });
    res.json({ success: true });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'نام کاربری تکراری است' });
    throw err;
  }
}));

app.delete('/api/users/:id', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
  const id = toIntOrNull(req.params.id);
  if (!id) return res.status(400).json({ error: 'شناسه نامعتبر است' });
  // جلوگیری از حذف کاربر دارای سوابق؛ اطلاعات تاریخی حفظ می‌شود.
  const refs = await q(
    `SELECT
      (SELECT COUNT(*)::int FROM records WHERE userid=$1) AS records_count,
      (SELECT COUNT(*)::int FROM evaluations WHERE userid=$1) AS evaluations_count,
      (SELECT COUNT(*)::int FROM salaries WHERE userid=$1) AS salaries_count`,
    [id]
  );
  const c = refs.rows[0];
  if (c.records_count || c.evaluations_count || c.salaries_count) {
    return res.status(409).json({
      error: 'این کاربر سوابق دارد؛ برای حفظ اطلاعات، حذف مستقیم مجاز نیست. ابتدا حساب را غیرفعال یا منتقل کنید.',
      counts: c
    });
  }
  const result = await q('DELETE FROM users WHERE id=$1', [id]);
  res.json({ success: true, deleted: result.rowCount });
}));

// ------------------------------------------------------------
// Check job code / Tazkira
// ------------------------------------------------------------
app.get('/api/check-jobcode', authenticateToken, asyncRoute(async (req, res) => {
  const raw = req.query.code;
  const excludeId = req.query.excludeId;
  if (!raw) return res.json({ exists: false, valid: true });
  const normalizedCode = normalizeCode(raw);
  if (!normalizedCode)
    return res.json({ exists: false, valid: false, error: 'فرمت کد نامعتبر (مثال: 27-32-02-12563)' });

  const records = await q('SELECT id, userid, schoolname, data FROM records ORDER BY id DESC');
  const matches = records.rows.filter((r) => {
    if (excludeId && String(r.id) === String(excludeId)) return false;
    const d = parseJson(r.data, {});
    const n = normalizeCode(d.jobCode);
    return n === normalizedCode || String(d.jobCode ?? '') === String(extractCodeNumber(normalizedCode));
  });
  if (matches.length) {
    const r = matches[0], d = parseJson(r.data, {});
    return res.json({
      exists: true, isSameSchool: Number(r.userid) === Number(req.user.id),
      schoolname: r.schoolname,
      employeeName: `${d.firstName || ''} ${d.lastName || ''}`.trim(),
      normalizedCode
    });
  }

  const t = await q('SELECT id, userid, place, section FROM tashkeel WHERE code=$1 LIMIT 1', [normalizedCode]);
  if (t.rows[0]) {
    const row = t.rows[0];
    return res.json({
      exists: true, isSameSchool: Number(row.userid) === Number(req.user.id),
      schoolname: row.place, employeeName: '(در تشکیلات ثبت شده)',
      normalizedCode, section: row.section
    });
  }

  if (req.user.role === 'school') {
    const check = isCodeInSchoolRanges(normalizedCode, req.user);
    if (!check.valid) {
      return res.json({
        exists: false, outOfRange: true, normalizedCode,
        error: `کد «${normalizedCode}» متعلق به مکتب شما نیست.\nبازه مکاتب: ${req.user.school_first_code || '—'} تا ${req.user.school_last_code || '—'}\nبازه مدارس: ${req.user.madaris_first_code || '—'} تا ${req.user.madaris_last_code || '—'}`
      });
    }
    const other = await findCodeOwnerSchool(normalizedCode, req.user.id);
    if (other) return res.json({ exists: false, ownedByOther: true, normalizedCode, error: `این کد بست متعلق به مکتب «${other}» است` });
    return res.json({ exists: false, valid: true, section: check.section, normalizedCode });
  }
  res.json({ exists: false, valid: true, normalizedCode });
}));

app.get('/api/check-etazkira', authenticateToken, asyncRoute(async (req, res) => {
  const code = req.query.code;
  if (!code) return res.json({ exists: false });
  const excludeId = req.query.excludeId;
  const result = await q('SELECT id, userid, schoolname, data FROM records ORDER BY id DESC');
  const found = result.rows.find((r) => {
    if (excludeId && String(r.id) === String(excludeId)) return false;
    return String(parseJson(r.data, {}).eTazkira ?? '') === String(code);
  });
  if (!found) return res.json({ exists: false });
  const d = parseJson(found.data, {});
  res.json({
    exists: true, isSameSchool: Number(found.userid) === Number(req.user.id),
    schoolname: found.schoolname,
    employeeName: `${d.firstName || ''} ${d.lastName || ''}`.trim()
  });
}));

// ------------------------------------------------------------
// Records
// ------------------------------------------------------------
app.get('/api/records', authenticateToken, asyncRoute(async (req, res) => {
  const search = req.query.search;
  let result;
  if (req.user.role === 'school') {
    result = await q('SELECT * FROM records WHERE userid=$1 ORDER BY id DESC', [req.user.id]);
  } else if (search) {
    result = await q(
      'SELECT * FROM records WHERE data ILIKE $1 OR schoolname ILIKE $1 ORDER BY id DESC',
      [`%${search}%`]
    );
  } else {
    result = await q('SELECT * FROM records ORDER BY id DESC');
  }
  res.json(result.rows.map((r) => ({ ...r, data: parseJson(r.data, {}) })));
}));

app.post('/api/records', authenticateToken, asyncRoute(async (req, res) => {
  const body = { ...(req.body || {}) };
  if (req.user.role === 'school' && body.jobCode) {
    const normalized = normalizeCode(body.jobCode);
    if (!normalized) return res.status(400).json({ error: 'فرمت کد بست نامعتبر', code: 'INVALID_CODE_FORMAT' });
    body.jobCode = normalized;
    const check = isCodeInSchoolRanges(normalized, req.user);
    if (!check.valid) {
      return res.status(403).json({
        error: `کد بست «${normalized}» متعلق به مکتب شما نیست`,
        code: 'CODE_NOT_IN_SCHOOL_RANGE'
      });
    }
    const other = await findCodeOwnerSchool(normalized, req.user.id);
    if (other) return res.status(409).json({ error: `این کد بست متعلق به مکتب «${other}» است`, code: 'CODE_OWNED_BY_OTHER_SCHOOL' });
  }
  const result = await q(
    `INSERT INTO records (userid, schoolname, district, data, status)
     VALUES ($1,$2,$3,$4,$5) RETURNING id`,
    [req.user.id, req.user.schoolname, req.user.district, JSON.stringify(body), 'pending']
  );
  res.json({ id: result.rows[0].id, success: true });
}));

app.put('/api/records/:id', authenticateToken, asyncRoute(async (req, res) => {
  const id = toIntOrNull(req.params.id);
  if (!id) return res.status(400).json({ error: 'شناسه نامعتبر است' });
  const found = await q('SELECT * FROM records WHERE id=$1', [id]);
  const row = found.rows[0];
  if (!row) return res.status(404).json({ error: 'رکورد یافت نشد' });
  if (req.user.role === 'school' && Number(row.userid) !== Number(req.user.id))
    return res.status(403).json({ error: 'دسترسی ندارید' });

  const body = { ...(req.body || {}) };
  if (body.editAllowed !== undefined && Object.keys(body).length === 1) {
    await q('UPDATE records SET editallowed=$1, updatedat=CURRENT_TIMESTAMP WHERE id=$2',
      [boolInt(body.editAllowed), id]);
    return res.json({ success: true });
  }

  const oldData = parseJson(row.data, {});
  if (req.user.role === 'school' && body.jobCode && body.jobCode !== oldData.jobCode) {
    const normalized = normalizeCode(body.jobCode);
    if (!normalized) return res.status(400).json({ error: 'فرمت کد بست نامعتبر' });
    const check = isCodeInSchoolRanges(normalized, req.user);
    if (!check.valid) return res.status(403).json({ error: `کد بست جدید «${normalized}» متعلق به مکتب شما نیست`, code: 'CODE_NOT_IN_SCHOOL_RANGE' });
    const other = await findCodeOwnerSchool(normalized, req.user.id);
    if (other) return res.status(409).json({ error: `این کد بست متعلق به مکتب «${other}» است` });
    body.jobCode = normalized;
  }
  const newData = { ...oldData, ...body, editAllowed: true };
  await q('UPDATE records SET data=$1, editallowed=1, updatedat=CURRENT_TIMESTAMP WHERE id=$2',
    [JSON.stringify(newData), id]);
  res.json({ success: true });
}));

app.post('/api/records/:id/approve', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
  const result = await q('UPDATE records SET status=$1 WHERE id=$2', ['approved', req.params.id]);
  if (!result.rowCount) return res.status(404).json({ error: 'رکورد یافت نشد' });
  res.json({ success: true });
}));

app.delete('/api/records/:id', authenticateToken, asyncRoute(async (req, res) => {
  const id = toIntOrNull(req.params.id);
  const found = await q('SELECT * FROM records WHERE id=$1', [id]);
  const row = found.rows[0];
  if (!row) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role === 'school' && Number(row.userid) !== Number(req.user.id))
    return res.status(403).json({ error: 'دسترسی ندارید' });

  const related = await q(
    `SELECT
      (SELECT COUNT(*)::int FROM evaluations WHERE record_id=$1) AS evaluations_count,
      (SELECT COUNT(*)::int FROM salaries WHERE record_id=$1) AS salaries_count`,
    [id]
  );
  if (related.rows[0].evaluations_count || related.rows[0].salaries_count) {
    return res.status(409).json({
      error: 'برای حفظ سوابق ارزیابی و معاشات، این کارمند قابل حذف نیست.',
      counts: related.rows[0]
    });
  }
  await q('DELETE FROM records WHERE id=$1', [id]);
  res.json({ success: true });
}));

// ------------------------------------------------------------
// Evaluations
// ------------------------------------------------------------
app.get('/api/evaluations', authenticateToken, asyncRoute(async (req, res) => {
  const result = req.user.role === 'school'
    ? await q('SELECT * FROM evaluations WHERE userid=$1 ORDER BY id DESC', [req.user.id])
    : await q('SELECT * FROM evaluations ORDER BY id DESC');
  res.json(result.rows);
}));

app.post('/api/evaluations', authenticateToken, asyncRoute(async (req, res) => {
  const e = req.body || {};
  const recordId = toIntOrNull(e.record_id);
  let record = null;
  if (recordId) {
    const rr = await q('SELECT * FROM records WHERE id=$1', [recordId]);
    record = rr.rows[0] || null;
    if (!record) return res.status(400).json({ error: 'کارمند مرتبط یافت نشد' });
    if (req.user.role === 'school' && Number(record.userid) !== Number(req.user.id))
      return res.status(403).json({ error: 'دسترسی به کارمند انتخاب‌شده ندارید' });
  }
  const evalDate = e.eval_date || new Date().toISOString().slice(0, 10);
  const score = toNumber(e.eval_score, 0);
  if (!recordId) return res.status(400).json({ error: 'شناسه کارمند (record_id) الزامی است' });

  const result = await q(
    `INSERT INTO evaluations
     (record_id, userid, schoolname, district, first_name, last_name, father_name,
      grandfather_name, job_code, employment_type, birth_year, service_duration,
      degree, gender, job_title, appointment_date, eval_date_prev, bust, grade,
      eval_date, eval_score, eval_result, remarks)
     VALUES
     ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
     RETURNING id`,
    [
      recordId, req.user.id, record.schoolname || req.user.schoolname, record.district || req.user.district,
      e.first_name || null, e.last_name || null, e.father_name || null, e.grandfather_name || null,
      e.job_code || null, e.employment_type || null, e.birth_year || null, e.service_duration || null,
      e.degree || null, e.gender || null, e.job_title || null, e.appointment_date || null,
      e.eval_date_prev || null, e.bust || null, e.grade || null,
      evalDate, score, e.eval_result || '', e.remarks || null
    ]
  );
  res.json({ id: result.rows[0].id, success: true });
}));

app.delete('/api/evaluations/:id', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
  const result = await q('DELETE FROM evaluations WHERE id=$1', [req.params.id]);
  if (!result.rowCount) return res.status(404).json({ error: 'ارزیابی یافت نشد' });
  res.json({ success: true });
}));

// ------------------------------------------------------------
// Salaries
// ------------------------------------------------------------
app.get('/api/salaries', authenticateToken, asyncRoute(async (req, res) => {
  const result = req.user.role === 'school'
    ? await q('SELECT * FROM salaries WHERE userid=$1 ORDER BY id DESC', [req.user.id])
    : await q('SELECT * FROM salaries ORDER BY id DESC');
  res.json(result.rows.map((r) => ({ ...r, attendance: parseJson(r.attendance, {}) })));
}));

app.get('/api/salaries/:id', authenticateToken, asyncRoute(async (req, res) => {
  const result = await q('SELECT * FROM salaries WHERE id=$1', [req.params.id]);
  const row = result.rows[0];
  if (!row) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role === 'school' && Number(row.userid) !== Number(req.user.id))
    return res.status(403).json({ error: 'دسترسی ندارید' });
  row.attendance = parseJson(row.attendance, {});
  res.json(row);
}));

app.delete('/api/salaries/:id', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
  const result = await q('DELETE FROM salaries WHERE id=$1', [req.params.id]);
  if (!result.rowCount) return res.status(404).json({ error: 'معاش یافت نشد' });
  res.json({ success: true });
}));

// ------------------------------------------------------------
// School Settings — سازگار با ستون‌های واقعی Neon و API قدیمی
// ------------------------------------------------------------
app.get('/api/school-settings', authenticateToken, asyncRoute(async (req, res) => {
  const result = await q('SELECT * FROM school_settings WHERE userid=$1 ORDER BY id DESC LIMIT 1', [req.user.id]);
  const row = result.rows[0];
  if (!row) return res.json({ exists: false });
  const settings = parseJson(row.settings_data, null) || { ...row };
  delete settings.id;
  delete settings.settings_data;
  res.json({ exists: true, settings });
}));

app.post('/api/school-settings', authenticateToken, asyncRoute(async (req, res) => {
  const incoming = req.body || {};
  const settingsData = JSON.stringify(incoming);
  const columns = [
    'academic_member',
    'branches_f_1_3','branches_f_4_6','branches_f_7_9','branches_f_10_12',
    'branches_m_1_3','branches_m_4_6','branches_m_7_9','branches_m_10_12',
    'branches_x_1_3','branches_x_4_6','branches_x_7_9','branches_x_10_12',
    'branches_total','total_in_female','total_in_male','total_present_female','total_present_male',
    ...Array.from({length:12}, (_,i) => [`c${i+1}_in_f`,`c${i+1}_in_m`,`c${i+1}_pr_f`,`c${i+1}_pr_m`]).flat(),
    'budget_status','extra_bust_count','extra_bust_field','lack_bust_count','lack_bust_field','time_type'
  ];
  const values = columns.map((col) => {
    const camel = col.replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase());
    const v = incoming[col] !== undefined ? incoming[col] : incoming[camel];
    if (v === undefined) return null;
    if (/_count$|^branches_|^total_|^c\d+_/.test(col)) return toIntOrNull(v) ?? 0;
    return v;
  });
  const exists = await q('SELECT id FROM school_settings WHERE userid=$1 ORDER BY id DESC LIMIT 1', [req.user.id]);
  if (exists.rows[0]) {
    const sets = columns.map((c, i) => `${c}=$${i+1}`);
    const params = [...values, req.user.schoolname, req.user.district, incoming.school_year || incoming.schoolYear || null, settingsData, exists.rows[0].id];
    const offset = columns.length;
    await q(
      `UPDATE school_settings SET ${sets.join(', ')},
       schoolname=$${offset+1}, district=$${offset+2}, school_year=$${offset+3},
       settings_data=$${offset+4}, updatedat=CURRENT_TIMESTAMP WHERE id=$${offset+5}`,
      params
    );
    return res.json({ success: true });
  }

  const insertCols = ['userid','schoolname','district','school_year','settings_data', ...columns];
  const insertValues = [req.user.id, req.user.schoolname, req.user.district,
    incoming.school_year || incoming.schoolYear || null, settingsData, ...values];
  const placeholders = insertValues.map((_, i) => `$${i+1}`);
  const inserted = await q(
    `INSERT INTO school_settings (${insertCols.join(',')})
     VALUES (${placeholders.join(',')}) RETURNING id`,
    insertValues
  );
  res.json({ id: inserted.rows[0].id, success: true });
}));

app.get('/api/all-school-settings', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
  const result = await q(
    `SELECT ss.*, u.schoolname AS user_schoolname, u.district AS user_district
     FROM school_settings ss
     LEFT JOIN users u ON u.id=ss.userid
     ORDER BY ss.schoolname NULLS LAST`
  );
  const rows = result.rows.map((r) => {
    const settings = parseJson(r.settings_data, {});
    return { ...r, ...settings,
      schoolname: r.schoolname || r.user_schoolname,
      district: r.district || r.user_district };
  });
  res.json(rows);
}));

// ------------------------------------------------------------
// Evaluation Permission
// ------------------------------------------------------------
app.get('/api/evaluation-permission', authenticateToken, asyncRoute(async (req, res) => {
  const result = await q('SELECT allowed FROM evaluation_permission ORDER BY id DESC LIMIT 1');
  res.json({ allowed: result.rows[0] ? boolInt(result.rows[0].allowed) === 1 : false });
}));
app.post('/api/evaluation-permission', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
  const allowed = boolInt(req.body && req.body.allowed);
  await q('INSERT INTO evaluation_permission (allowed) VALUES ($1)', [allowed]);
  res.json({ success: true });
}));

// ------------------------------------------------------------
// Tashkeel
// ------------------------------------------------------------
app.get('/api/tashkeel', authenticateToken, asyncRoute(async (req, res) => {
  const { school, section } = req.query;
  let sql = 'SELECT * FROM tashkeel WHERE 1=1';
  const params = [];
  if (req.user.role === 'admin') {
    if (school) { params.push(school); sql += ` AND place=$${params.length}`; }
    if (section) { params.push(section); sql += ` AND section=$${params.length}`; }
  } else {
    params.push(req.user.id, req.user.schoolname);
    sql += ` AND (userid=$${params.length-1} OR place=$${params.length})`;
    if (section) { params.push(section); sql += ` AND section=$${params.length}`; }
  }
  sql += ' ORDER BY place, id';
  const result = await q(sql, params);
  res.json(result.rows);
}));

app.post('/api/tashkeel', authenticateToken, asyncRoute(async (req, res) => {
  const { pub, priv, title, place, code, section } = req.body || {};
  if (!title || !code) return res.status(400).json({ error: 'عنوان و کد الزامی است' });
  const normalizedCode = normalizeCode(code);
  if (!normalizedCode)
    return res.status(400).json({ error: 'فرمت کد نامعتبر. مثال: 27-32-02-12563 یا 12563' });
  const finalSection = section || 'amariat';
  const finalPlace = req.user.role === 'admin' ? (place || 'نامشخص') : req.user.schoolname;
  const userid = req.user.role === 'admin' ? null : req.user.id;

  if (req.user.role === 'school') {
    const check = isCodeInSchoolRanges(normalizedCode, req.user);
    if (!check.valid) return res.status(403).json({ error: `کد «${normalizedCode}» متعلق به مکتب شما نیست`, code: 'CODE_NOT_IN_SCHOOL_RANGE' });
    if (check.section !== finalSection)
      return res.status(400).json({ error: 'بخش انتخاب‌شده با بازه کد بست مطابقت ندارد', code: 'SECTION_MISMATCH' });
    const other = await findCodeOwnerSchool(normalizedCode, req.user.id);
    if (other) return res.status(409).json({ error: `متعلق به مکتب «${other}» است`, code: 'CODE_OWNED_BY_OTHER_SCHOOL' });
  }

  try {
    const result = await q(
      `INSERT INTO tashkeel (userid,pub,priv,title,place,code,section)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
      [userid, pub || null, priv || null, title, finalPlace, normalizedCode, finalSection]
    );
    res.json({ id: result.rows[0].id, code: normalizedCode, success: true });
  } catch (err) {
    if (err.code === '23505')
      return res.status(409).json({ error: `کد «${normalizedCode}» قبلاً در محل «${finalPlace}» ثبت شده`, code: 'DUPLICATE_CODE' });
    throw err;
  }
}));

app.put('/api/tashkeel/:id', authenticateToken, asyncRoute(async (req, res) => {
  const id = toIntOrNull(req.params.id);
  const { title, place } = req.body || {};
  const result = req.user.role === 'admin'
    ? await q('SELECT * FROM tashkeel WHERE id=$1', [id])
    : await q('SELECT * FROM tashkeel WHERE id=$1 AND (userid=$2 OR place=$3)', [id, req.user.id, req.user.schoolname]);
  if (!result.rows[0]) return res.status(404).json({ error: 'یافت نشد یا دسترسی ندارید' });
  const sets = [], values = [];
  if (title !== undefined) { values.push(title); sets.push(`title=$${values.length}`); }
  if (place !== undefined) {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'تغییر محل فقط برای ادمین مجاز است' });
    values.push(place); sets.push(`place=$${values.length}`);
  }
  if (!sets.length) return res.status(400).json({ error: 'چیزی برای به‌روزرسانی نیست' });
  values.push(id);
  await q(`UPDATE tashkeel SET ${sets.join(', ')} WHERE id=$${values.length}`, values);
  res.json({ success: true });
}));

app.delete('/api/tashkeel/:id', authenticateToken, asyncRoute(async (req, res) => {
  const id = toIntOrNull(req.params.id);
  const result = req.user.role === 'admin'
    ? await q('SELECT id FROM tashkeel WHERE id=$1', [id])
    : await q('SELECT id FROM tashkeel WHERE id=$1 AND (userid=$2 OR place=$3)', [id, req.user.id, req.user.schoolname]);
  if (!result.rows[0]) return res.status(404).json({ error: 'یافت نشد یا دسترسی ندارید' });
  await q('DELETE FROM tashkeel WHERE id=$1', [id]);
  res.json({ success: true });
}));

// ------------------------------------------------------------
// Health check
// ------------------------------------------------------------
app.get('/api/health', asyncRoute(async (req, res) => {
  const result = await q('SELECT NOW() AS server_time');
  res.json({ status: 'ok', database: 'connected', server_time: result.rows[0].server_time });
}));

// ------------------------------------------------------------
// SPA fallback و خطاها
// ------------------------------------------------------------
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'اندپوینت یافت نشد' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'), (err) => {
    if (err && !res.headersSent) res.status(404).send('صفحه یافت نشد');
  });
});

app.use((err, req, res, next) => {
  console.error('❌ خطای سرور:', err);
  if (res.headersSent) return next(err);
  res.status(500).json({
    error: 'خطای داخلی سرور',
    message: process.env.NODE_ENV === 'production' ? 'لطفاً گزارش سرور را بررسی کنید.' : err.message
  });
});

// ------------------------------------------------------------
// Start only after database initialization
// ------------------------------------------------------------
initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log('═══════════════════════════════════════════════════════════');
      console.log(`🚀 سرور فعال شد روی پورت ${PORT}`);
      console.log('🐘 دیتابیس: PostgreSQL / Neon');
      console.log('═══════════════════════════════════════════════════════════');
    });
  })
  .catch((err) => {
    console.error('❌ سرور به‌دلیل آماده‌نشدن دیتابیس اجرا نشد:', err);
    process.exit(1);
  });
'''
path = "/mnt/data/server-neon.js"
with open(path, "w", encoding="utf-8") as f:
    f.write(code)
print(path, len(code), "bytes")
