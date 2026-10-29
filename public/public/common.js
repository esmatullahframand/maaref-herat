const token = localStorage.getItem('hr_token');
const user = JSON.parse(localStorage.getItem('hr_user') || '{}');
if (!token || token === 'undefined' || token === 'null') { localStorage.clear(); window.location.href = '/'; throw new Error('No token'); }

function showToast(msg, isError = false) {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg; t.className = 'toast show' + (isError ? ' error' : '');
  clearTimeout(t._timer); t._timer = setTimeout(() => { t.classList.remove('show'); }, 4000);
}
function escapeHtml(s) { if (!s) return ''; return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
function normalizeDigits(str) { if (!str) return ''; const p = '۰۱۲۳۴۵۶۷۸۹', a = '٠١٢٣٤٥٦٧٨٩'; return String(str).split('').map(ch => { const pi = p.indexOf(ch); if (pi !== -1) return pi; const ai = a.indexOf(ch); if (ai !== -1) return ai; return ch; }).join(''); }
function numVal(id) { const el = document.getElementById(id); return el ? Number(normalizeDigits(el.value)) || 0 : 0; }
function setVal(id, val) { const el = document.getElementById(id); if (el) el.value = val || ''; }

function validateShamsiDate(dateStr) {
  if (!dateStr) return { valid: false, error: 'تاریخ الزامی است' };
  const cleaned = normalizeDigits(dateStr).trim().replace(/[.\-]/g, '/');
  const parts = cleaned.split('/').map(p => p.trim());
  if (parts.length !== 3) return { valid: false, error: 'فرمت: YYYY/MM/DD' };
  const p1 = parseInt(parts[0]), p2 = parseInt(parts[1]), p3 = parseInt(parts[2]);
  if (isNaN(p1) || isNaN(p2) || isNaN(p3)) return { valid: false, error: 'اعداد وارد کنید' };
  let year, month, day;
  if (parts[0].length === 4 || (p1 >= 1300 && p1 <= 1450)) { year = p1; month = p2; day = p3; }
  else if (parts[2].length === 4 || (p3 >= 1300 && p3 <= 1450)) { year = p3; month = p2; day = p1; }
  else return { valid: false, error: 'سال ۱۳۰۰ تا ۱۴۵۰' };
  if (year < 1300 || year > 1450) return { valid: false, error: 'سال نامعتبر' };
  if (month < 1 || month > 12) return { valid: false, error: 'ماه نامعتبر' };
  let maxDay = 31; if (month >= 7 && month <= 11) maxDay = 30; if (month === 12) maxDay = 29;
  if (day < 1 || day > maxDay) return { valid: false, error: `روز ۱ تا ${maxDay}` };
  return { valid: true, formatted: `${year}/${String(month).padStart(2, '0')}/${String(day).padStart(2, '0')}` };
}

function validateJobCode(codeStr) { if (!codeStr) return { valid: false, error: 'کد بست الزامی است' }; const cleaned = normalizeDigits(codeStr).trim().replace(/\s+/g, ''); if (!/^27-\d{1,3}-\d{1,3}-\d{3,6}$/.test(cleaned)) return { valid: false, error: 'فرمت: 27-XX-XX-XXXXX' }; return { valid: true, formatted: cleaned }; }
function validateETazkira(codeStr) { if (!codeStr) return { valid: false, error: 'تذکره الکترونیکی الزامی است' }; const cleaned = normalizeDigits(codeStr).trim().replace(/\s+/g, ''); if (!/^\d+-\d+-\d+$/.test(cleaned)) return { valid: false, error: 'فرمت: XXXXX-XXXXX-XXXX' }; return { valid: true, formatted: cleaned }; }
function validateTazkiraCode(codeStr) { if (!codeStr) return { valid: true, formatted: '' }; const cleaned = normalizeDigits(codeStr).trim().replace(/\s+/g, ''); if (!/^\d{1,20}$/.test(cleaned)) return { valid: false, error: 'فقط عدد' }; return { valid: true, formatted: cleaned }; }

async function checkJobCodeUnique(codeStr, excludeId) { if (!codeStr) return { unique: false }; try { let url = '/api/check-jobcode?code=' + encodeURIComponent(codeStr); if (excludeId) url += '&excludeId=' + encodeURIComponent(excludeId); const res = await fetch(url, { headers: { 'Authorization': 'Bearer ' + token } }); if (!res.ok) return { unique: true }; const data = await res.json(); if (!data.exists) return { unique: true }; return { unique: false, isSameSchool: !!data.isSameSchool, schoolname: data.schoolname, employeeName: data.employeeName }; } catch (e) { return { unique: true }; } }
async function checkETazkiraUnique(codeStr, excludeId) { if (!codeStr) return { unique: false }; try { let url = '/api/check-etazkira?code=' + encodeURIComponent(codeStr); if (excludeId) url += '&excludeId=' + encodeURIComponent(excludeId); const res = await fetch(url, { headers: { 'Authorization': 'Bearer ' + token } }); if (!res.ok) return { unique: true }; const data = await res.json(); if (!data.exists) return { unique: true }; return { unique: false, isSameSchool: !!data.isSameSchool, schoolname: data.schoolname, employeeName: data.employeeName }; } catch (e) { return { unique: true }; } }
function buildDuplicateMessage(kind, result) { const label = kind === 'jobcode' ? 'کد بست' : (kind === 'etazkira' ? 'تذکره الکترونیکی' : 'تذکره کاغذی'); if (result.isSameSchool) return `⚠️ این ${label} قبلاً برای «${result.employeeName || 'نامشخص'}» در مکتب خودتان ثبت شده است.`; return `❌ این ${label} قبلاً در مکتب «${result.schoolname || 'نامشخص'}» ثبت شده است.`; }

const MONTHS_SHAMSI = ['حمل', 'ثور', 'جوزا', 'سرطان', 'اسد', 'سنبله', 'میزان', 'عقرب', 'قوس', 'جدی', 'دلو', 'حوت'];
const MONTHS_ORDER = MONTHS_SHAMSI;
function parseShamsi(dateStr) { if (!dateStr) return null; const cleaned = normalizeDigits(dateStr).replace(/[.\-]/g, '/').trim(); const parts = cleaned.split('/').map(p => p.trim()); if (parts.length !== 3) return null; const p1 = parseInt(parts[0]), p2 = parseInt(parts[1]), p3 = parseInt(parts[2]); if (isNaN(p1) || isNaN(p2) || isNaN(p3)) return null; let year, month, day; if (parts[0].length === 4 || (p1 >= 1300 && p1 <= 1450)) { year = p1; month = p2; day = p3; } else if (parts[2].length === 4 || (p3 >= 1300 && p3 <= 1450)) { year = p3; month = p2; day = p1; } else return null; return { year, month, day, numeric: year * 10000 + month * 100 + day }; }
function closeModal(id) { document.getElementById(id).classList.remove('active'); }
function toggleYear(header) { header.classList.toggle('active'); header.nextElementSibling.classList.toggle('active'); }
function toggleEmployee(header) { header.classList.toggle('active'); header.nextElementSibling.classList.toggle('active'); }
function logout() { localStorage.clear(); window.location.href = '/'; }
