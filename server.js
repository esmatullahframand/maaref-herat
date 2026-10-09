// ============================================================
// ⭐ اعتبارسنجی کد بست
// فرمت: 27-32-02-XXXXX (شروع با 27-32-02- و بعد حداقل ۱ رقم)
// ============================================================
function isValidJobCode(jobCode) {
  if (!jobCode) return false;
  const cleaned = String(jobCode).trim();
  // الگو: 27-32-02- و بعد یک یا بیشتر رقم
  const pattern = /^27-32-02-\d+$/;
  return pattern.test(cleaned);
}

// ============================================================
// ⭐ اعتبارسنجی تذکره برقی
// فرمت: 1399-1200-63538 (سه بخش با خط تیره)
// ============================================================
function isValidETazkira(eTazkira) {
  if (!eTazkira) return false;
  const cleaned = String(eTazkira).trim();
  // الگو: 4 رقم - 4 رقم - 5 رقم
  const pattern = /^\d{4}-\d{4}-\d{5}$/;
  return pattern.test(cleaned);
}

// ============================================================
// ⭐ بررسی تکراری بودن کد بست در همه تشکیلات معارف
// ============================================================
async function isJobCodeDuplicate(jobCode, excludeRecordId = null) {
  if (!jobCode) return false;
  try {
    const searchPattern = `%"jobCode":"${jobCode}"%`;
    let result;
    if (excludeRecordId) {
      result = await pool.query(
        `SELECT id FROM records 
         WHERE CAST(data AS TEXT) LIKE $1 AND id != $2 
         LIMIT 1`,
        [searchPattern, excludeRecordId]
      );
    } else {
      result = await pool.query(
        `SELECT id FROM records 
         WHERE CAST(data AS TEXT) LIKE $1 
         LIMIT 1`,
        [searchPattern]
      );
    }
    return result.rows.length > 0;
  } catch (err) {
    console.error('Duplicate check error:', err.message);
    return false;
  }
}
