async function setRecordEditPermission(id, allowed) {
  const label = allowed ? 'اجازه ویرایش' : 'لغو اجازه ویرایش';
  if (!confirm(`آیا ${label} برای این کارمند فعال شود؟`)) return;
  try {
    const res = await fetch('/api/records/' + id + '/edit-permission', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: JSON.stringify({ editAllowed: !!allowed })
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      showToast(allowed ? '✅ اجازه ویرایش فعال شد' : '🔒 اجازه ویرایش لغو شد');
      const rec = loadedRecordsCache.find(r => r.id === id);
      if (rec) {
        rec.data = rec.data || {};
        rec.data.editAllowed = !!allowed;
      }
      await loadAllRecords();
    } else {
      showToast('❌ ' + (data.error || 'تغییر اجازه ویرایش ناکام شد'), true);
    }
  } catch (e) {
    showToast('❌ ارتباط برقرار نشد', true);
  }
}
