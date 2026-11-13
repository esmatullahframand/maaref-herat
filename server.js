
// ============================================================
// LOGIN — ورود مدیر و کاربران مکاتب
// ============================================================

app.post(['/api/login', '/api/auth/login'], asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({
      error: 'نام کاربری و رمز الزامی است'
    });
  }

  const result = await q(
    'SELECT * FROM users WHERE username = $1',
    [String(username).trim()]
  );

  const user = result.rows[0];

  if (!user) {
    return res.status(401).json({
      error: 'نام کاربری یا رمز اشتباه است'
    });
  }

  const match = await bcrypt.compare(
    String(password),
    user.password
  );

  if (!match) {
    return res.status(401).json({
      error: 'نام کاربری یا رمز اشتباه است'
    });
  }

  const token = jwt.sign(
    {
      id: user.id,
      username: user.username,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  return res.json({
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
}));


// ============================================================
// بازیابی موقت حساب مدیر
// این بخش پس از ایجاد حساب مدیر باید حذف شود
// ============================================================

app.post('/api/recover-admin-once', asyncRoute(async (req, res) => {
  const recoveryKey = req.get('x-admin-recovery-key');

  if (
    !process.env.ADMIN_RECOVERY_KEY ||
    recoveryKey !== process.env.ADMIN_RECOVERY_KEY
  ) {
    return res.status(403).json({
      error: 'دسترسی غیرمجاز'
    });
  }

  const { password } = req.body || {};

  if (
    typeof password !== 'string' ||
    password.length < 8 ||
    password.length > 128
  ) {
    return res.status(400).json({
      error: 'رمز باید حداقل ۸ و حداکثر ۱۲۸ حرف باشد'
    });
  }

  const existing = await q(
    'SELECT id FROM users WHERE username = $1',
    ['admin']
  );

  if (existing.rows.length > 0) {
    return res.status(409).json({
      error: 'حساب مدیر از قبل موجود است'
    });
  }

  const hashedPassword = await bcrypt.hash(password, 12);

  await q(
    `INSERT INTO users
      (username, password, role, schoolname, district)
     VALUES ($1, $2, $3, NULL, NULL)`,
    ['admin', hashedPassword, 'admin']
  );

  return res.json({
    success: true,
    message: 'حساب مدیر با موفقیت ایجاد شد'
  });
}));


// ============================================================
// USERS
// بخش مدیریت کاربران از کد قبلی خودت ادامه پیدا کند
// ============================================================
