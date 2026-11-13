// ============================================================
// import-tashkeel.js
// اسکریپت وارد کردن داده‌های تشکیل به دیتابیس SQLite
// اجرا: node import-tashkeel.js
// ============================================================

const path = require('path');
const sqlite3 = require('sqlite3').verbose();

// ── وارد کردن داده‌ها از فایل tashkeel-data.js ──
let buildTashkeelRecords, AMARIAT_RAW, MADARIS_RAW, TASHKEEL_PREFIX;
try {
  const data = require('./tashkeel-data.js');
  buildTashkeelRecords = data.buildTashkeelRecords;
  AMARIAT_RAW = data.AMARIAT_RAW;
  MADARIS_RAW = data.MADARIS_RAW;
  TASHKEEL_PREFIX = data.TASHKEEL_PREFIX;
} catch (e) {
  console.error('❌ خطا در بارگذاری tashkeel-data.js:');
  console.error('   ', e.message);
  console.error('   مطمئن شوید فایل tashkeel-data.js در همان پوشه قرار دارد.');
  process.exit(1);
}

// ── مسیر دیتابیس ──
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'database.db');

// ── بررسی وجود دیتابیس ──
const fs = require('fs');
if (!fs.existsSync(DB_PATH)) {
  console.error(`❌ دیتابیس یافت نشد: ${DB_PATH}`);
  console.error('   ابتدا server.js را اجرا کنید تا دیتابیس ساخته شود،');
  console.error('   یا مسیر صحیح را با متغیر محیطی DB_PATH تنظیم کنید.');
  process.exit(1);
}

// ═══════════════════════════════════════════════════════════
// شروع
// ═══════════════════════════════════════════════════════════
console.log('');
console.log('═══════════════════════════════════════════════════════════');
console.log('  📊 وارد کردن داده‌های تشکیل آمریت معارف کشک رباط سنگی');
console.log('═══════════════════════════════════════════════════════════');
console.log(`  📁 دیتابیس: ${DB_PATH}`);
console.log(`  🔖 پیشوند کدها: ${TASHKEEL_PREFIX}`);
console.log('───────────────────────────────────────────────────────────');

const records = buildTashkeelRecords();

console.log(`  📋 مجموع رکورد: ${records.length}`);
console.log(`     ├─ 🏫 مکاتب: ${AMARIAT_RAW.length}`);
console.log(`     └─ 🏛️ مدارس: ${MADARIS_RAW.length}`);
console.log('');
console.log('  ✅ اصلاحات اعمال‌شده در داده:');
console.log('     ├─ 122896 → 12896  (مدیریت متوسطه خواجه نور)');
console.log('     ├─ 5513   → 513    (مدیریت متوسطه خلیفه رحمت)');
console.log('     └─ 133309 → 13309  (مدیریت ابتدائیه سنگر)');
console.log('═══════════════════════════════════════════════════════════');
console.log('');

// ── بررسی تداخل کدها پیش از وارد کردن ──
const codeMap = {};
records.forEach(r => {
  const key = r.section + '::' + r.code;
  if (!codeMap[key]) codeMap[key] = [];
  codeMap[key].push({ place: r.place, title: r.title, pub: r.pub });
});

const duplicates = Object.entries(codeMap).filter(([k, v]) => v.length > 1);

if (duplicates.length) {
  console.log('⚠️  هشدار: کدهای تکراری در همان بخش:');
  console.log('   (با UNIQUE سه‌گانه، هر کدام در محل خود جدا ذخیره می‌شوند)');
  console.log('');
  duplicates.forEach(([key, items]) => {
    const [section, code] = key.split('::');
    const sectionLabel = section === 'amariat' ? '🏫 مکاتب' : '🏛️ مدارس';
    console.log(`   • ${code} [${sectionLabel}] — ${items.length} بار:`);
    items.forEach(it => console.log(`       - ${it.place} (${it.title})`));
  });
  console.log('');
} else {
  console.log('✅ هیچ کد تکراری در همان بخش وجود ندارد.');
  console.log('');
}

// ═══════════════════════════════════════════════════════════
// اتصال به دیتابیس
// ═══════════════════════════════════════════════════════════
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('❌ خطا در اتصال به دیتابیس:', err.message);
    process.exit(1);
  }
});

db.configure('busyTimeout', 10000);

db.serialize(() => {
  // ── ساخت جدول tashkeel ──
  db.run(`
    CREATE TABLE IF NOT EXISTS tashkeel (
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
    )
  `, (err) => {
    if (err) {
      console.error('❌ خطا در ساخت جدول:', err.message);
      db.close();
      process.exit(1);
    }
  });

  // ── ایندکس‌های کمکی ──
  db.run(`CREATE INDEX IF NOT EXISTS idx_tashkeel_code ON tashkeel(code)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_tashkeel_section ON tashkeel(section)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_tashkeel_place ON tashkeel(place)`);

  // ── وضعیت فعلی ──
  db.get('SELECT COUNT(*) as total FROM tashkeel', (err, row) => {
    if (!err && row.total > 0) {
      console.log(`ℹ️  توجه: در حال حاضر ${row.total} رکورد در جدول tashkeel وجود دارد.`);
      console.log('   (رکوردهای تکراری با INSERT OR IGNORE رد می‌شوند و رکوردهای موجود تغییر نمی‌کنند)');
      console.log('');
    }
  });
});

// ═══════════════════════════════════════════════════════════
// وارد کردن دسته‌ای
// ═══════════════════════════════════════════════════════════
const BATCH_SIZE = 50;
let inserted = 0, skipped = 0, errors = [];

console.log('⏳ شروع وارد کردن...');
console.log('');

db.serialize(() => {
  const stmt = db.prepare(
    'INSERT OR IGNORE INTO tashkeel (pub, priv, title, place, code, section) VALUES (?, ?, ?, ?, ?, ?)'
  );

  records.forEach((r, index) => {
    stmt.run(
      [r.pub, r.priv, r.title, r.place, r.code, r.section],
      function (err) {
        if (err) {
          skipped++;
          if (errors.length < 20) {
            errors.push({ code: r.code, error: err.message });
          }
        } else if (this.changes > 0) {
          inserted++;
        } else {
          skipped++;
        }

        // چاپ پیشرفت
        if ((index + 1) % BATCH_SIZE === 0 || index + 1 === records.length) {
          const pct = Math.round(((index + 1) / records.length) * 100);
          process.stdout.write(
            `\r  ⏳ پیشرفت: ${index + 1}/${records.length} (${pct}%) — موفق: ${inserted}, رد: ${skipped}    `
          );
        }
      }
    );
  });

  stmt.finalize((err) => {
    if (err) {
      console.error('\n❌ خطا در finalize:', err.message);
    }
    console.log('\n');
    finish();
  });
});

// ═══════════════════════════════════════════════════════════
// پایان و گزارش
// ═══════════════════════════════════════════════════════════
function finish() {
  console.log('═══════════════════════════════════════════════════════════');
  console.log('  ✅ نتیجه وارد کردن');
  console.log('───────────────────────────────────────────────────────────');
  console.log(`     • موفق (جدید): ${inserted}`);
  console.log(`     • رد شده (تکراری): ${skipped}`);
  console.log(`     • خطا: ${errors.length}`);
  console.log('═══════════════════════════════════════════════════════════');

  if (errors.length) {
    console.log('');
    console.log('⚠️  نمونه خطاها (حداکثر ۲۰ مورد):');
    errors.slice(0, 20).forEach(e => {
      console.log(`     • ${e.code}: ${e.error}`);
    });
    console.log('');
  }

  // ── آمار نهایی از دیتابیس ──
  db.get('SELECT COUNT(*) as total FROM tashkeel', (err, row) => {
    if (err) {
      console.error('❌ خطا در خواندن آمار:', err.message);
      db.close();
      return;
    }
    console.log('');
    console.log(`  📊 مجموع رکوردهای موجود در دیتابیس: ${row.total}`);
    console.log('');

    db.all(
      `SELECT section, COUNT(*) as cnt FROM tashkeel GROUP BY section ORDER BY section`,
      (err2, rows) => {
        if (err2) {
          console.error('❌ خطا:', err2.message);
          db.close();
          return;
        }
        console.log('  📈 تفکیک بر اساس بخش:');
        rows.forEach(r => {
          const label = r.section === 'amariat' ? '🏫 مکاتب' : '🏛️ مدارس';
          console.log(`     • ${label}: ${r.cnt}`);
        });
        console.log('');

        // ── بررسی کدهای اصلاح‌شده ──
        const fixedCodes = ['27-32-02-12896', '27-32-02-513', '27-32-02-13309'];
        let checked = 0;

        console.log('  🔍 بررسی سه کد اصلاح‌شده:');

        fixedCodes.forEach(code => {
          db.get(
            'SELECT code, title, place, section FROM tashkeel WHERE code = ? LIMIT 1',
            [code],
            (err3, found) => {
              if (err3) {
                console.log(`     • ${code}: خطا در بررسی`);
              } else if (found) {
                console.log(`     ✅ ${code} → ${found.place} (${found.title})`);
              } else {
                console.log(`     ⚠️  ${code}: یافت نشد`);
              }

              checked++;
              if (checked === fixedCodes.length) {
                // ── نمونه کدهای اصلی ──
                db.get(
                  'SELECT code, title FROM tashkeel WHERE section = "amariat" ORDER BY id LIMIT 1',
                  (err4, firstRow) => {
                    if (!err4 && firstRow) {
                      console.log('');
                      console.log(`  🔖 نمونه اولین کد مکاتب: ${firstRow.code} (${firstRow.title})`);
                    }
                    db.get(
                      'SELECT code, title FROM tashkeel WHERE section = "madaris" ORDER BY id LIMIT 1',
                      (err5, madRow) => {
                        if (!err5 && madRow) {
                          console.log(`  🔖 نمونه اولین کد مدارس: ${madRow.code} (${madRow.title})`);
                        }
                        console.log('');
                        console.log('═══════════════════════════════════════════════════════════');
                        console.log('  🎉 عملیات با موفقیت به پایان رسید');
                        console.log('═══════════════════════════════════════════════════════════');
                        console.log('');
                        db.close();
                      }
                    );
                  }
                );
              }
            }
          );
        });
      }
    );
  });
}

// ── مدیریت خطای غیرمنتظره ──
process.on('uncaughtException', (err) => {
  console.error('\n❌ خطای غیرمنتظره:', err.message);
  console.error(err.stack);
  try { db.close(); } catch (e) {}
  process.exit(1);
});
