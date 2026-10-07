// ============================================================
// ✏️ PUT /api/records/:id — ویرایش رکورد (فقط مکتب صاحب رکورد)
// ============================================================
app.put('/api/records/:id', authRequired, async (req, res) => {
  try {
    // فقط مکتب می‌تواند ویرایش کند (نه ادمین)
    if (req.user.role !== 'school') {
      return res.status(403).json({ error: 'فقط مکتب اجازه ویرایش دارد' });
    }

    const id = req.params.id;
    const body = req.body || {};

    // چک کن رکورد مال همین مکتب است
    const check = await pool.query(
      'SELECT * FROM records WHERE id = $1 AND userid = $2',
      [id, req.user.id]
    );
    if (check.rows.length === 0) {
      return res.status(404).json({ error: 'رکورد یافت نشد یا به شما تعلق ندارد' });
    }

    // اگر رکورد تایید شده، مکتب نمی‌تواند ویرایش کند
    if (check.rows[0].status === 'approved') {
      return res.status(403).json({ error: 'رکورد تایید شده قابل ویرایش نیست' });
    }

    const schoolName = body.schoolName || req.user.schoolname || '';
    const district = body.district || req.user.district || '';

    await pool.query(
      `UPDATE records 
       SET schoolname = $1, district = $2, data = $3
       WHERE id = $4 AND userid = $5`,
      [schoolName, district, JSON.stringify(body), id, req.user.id]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error('Records PUT Error:', err.message);
    res.status(500).json({ error: 'خطا در ویرایش رکورد: ' + err.message });
  }
});
