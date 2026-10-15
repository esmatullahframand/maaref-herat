// smsSender.js
const SMS_GATEWAY_URL = process.env.SMS_GATEWAY_URL || 'http://192.168.137.74:8080';
const SMS_USERNAME = process.env.SMS_USERNAME || 'sms';
const SMS_PASSWORD = process.env.SMS_PASSWORD || 'ZZEF6dep';
const DEFAULT_DELAY_MS = 15000;
const MAX_RETRIES = 2;

async function sendSingleSMS(phoneNumber, message, retries = 0) {
  const pair = `${SMS_USERNAME}:${SMS_PASSWORD}`;
  const encoded = Buffer.from(pair).toString('base64');

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);

    const res = await fetch(`${SMS_GATEWAY_URL}/message`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${encoded}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        textMessage: { text: message },
        phoneNumbers: [phoneNumber]
      }),
      signal: controller.signal
    });

    clearTimeout(timeout);

    let data;
    try { data = await res.json(); } catch (e) { data = {}; }

    if (res.ok) {
      return { success: true, id: data.id || null, state: data.state || 'Pending' };
    } else {
      if (retries < MAX_RETRIES && (res.status === 500 || res.status === 503)) {
        await new Promise(r => setTimeout(r, 5000));
        return sendSingleSMS(phoneNumber, message, retries + 1);
      }
      return { success: false, error: data.message || data.error || `HTTP ${res.status}` };
    }
  } catch (err) {
    if (retries < MAX_RETRIES) {
      await new Promise(r => setTimeout(r, 5000));
      return sendSingleSMS(phoneNumber, message, retries + 1);
    }
    return { success: false, error: err.name === 'AbortError' ? 'Timeout' : err.message };
  }
}

async function sendBulkSMS(phoneNumbers, message, options = {}) {
  const delayMs = options.delayMs || DEFAULT_DELAY_MS;
  const onProgress = options.onProgress || null;
  const onComplete = options.onComplete || null;

  const results = [];
  const total = phoneNumbers.length;
  const startTime = Date.now();

  console.log(`🚀 شروع ارسال پیامک گروهی — ${total} شماره`);

  for (let i = 0; i < phoneNumbers.length; i++) {
    const phone = phoneNumbers[i];
    console.log(`📤 [${i + 1}/${total}] ارسال به ${phone}...`);

    const result = await sendSingleSMS(phone, message);

    if (result.success) {
      console.log(`   ✅ موفق — ID: ${result.id || 'N/A'}`);
      results.push({ phone, success: true, id: result.id, state: result.state, timestamp: new Date().toISOString() });
    } else {
      console.log(`   ❌ خطا: ${result.error}`);
      results.push({ phone, success: false, error: result.error, timestamp: new Date().toISOString() });
    }

    if (onProgress && typeof onProgress === 'function') {
      try {
        await onProgress({
          current: i + 1, total: total, phone: phone,
          success: result.success, error: result.error || null, results: results
        });
      } catch (e) { console.error('onProgress error:', e.message); }
    }

    if (i < phoneNumbers.length - 1) {
      await new Promise(resolve => setTimeout(resolve, delayMs));
    }
  }

  const endTime = Date.now();
  const duration = Math.round((endTime - startTime) / 1000);
  const successCount = results.filter(r => r.success).length;
  const failCount = results.filter(r => !r.success).length;

  console.log(`✅ ارسال کامل شد — موفق: ${successCount} | ناموفق: ${failCount}`);

  const summary = {
    total, success: successCount, failed: failCount, duration, results,
    startTime: new Date(startTime).toISOString(),
    endTime: new Date(endTime).toISOString()
  };

  if (onComplete && typeof onComplete === 'function') {
    try { await onComplete(summary); } catch (e) { console.error('onComplete error:', e.message); }
  }

  return summary;
}

async function checkGatewayHealth() {
  const pair = `${SMS_USERNAME}:${SMS_PASSWORD}`;
  const encoded = Buffer.from(pair).toString('base64');

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const res = await fetch(`${SMS_GATEWAY_URL}/health`, {
      method: 'GET',
      headers: { 'Authorization': `Basic ${encoded}` },
      signal: controller.signal
    });

    clearTimeout(timeout);

    if (res.ok) {
      const data = await res.json().catch(() => ({}));
      return { ok: true, status: 'online', data: data };
    }

    return { ok: false, status: 'error', error: `HTTP ${res.status}` };
  } catch (err) {
    return { ok: false, status: 'offline', error: err.name === 'AbortError' ? 'Timeout' : err.message };
  }
}

function isValidPhoneNumber(phone) {
  if (!phone) return false;
  const cleaned = String(phone).replace(/[\s\-\(\)]/g, '');
  return /^0\d{9}$/.test(cleaned);
}

module.exports = {
  sendSingleSMS, sendBulkSMS, checkGatewayHealth, isValidPhoneNumber,
  SMS_GATEWAY_URL, SMS_USERNAME, SMS_PASSWORD, DEFAULT_DELAY_MS
};
