# SmartRisk Embed / Widget — Phase 2

## ما تم تنفيذه

تم توسيع Embed/Widget من MVP إلى طبقة Partner قابلة للإدارة من Admin Console، مع الحفاظ على نفس مسار التحليل الموجود في SmartRisk:

`Embed → ScanService → UnifiedRiskEngine → UnifiedRiskReport → EmbedReportFormatter`

### Partner Applications

كل تطبيق Partner يمتلك:

- `srw_pub_...` public integration key.
- قائمة exact Allowed Origins من نوع HTTP/HTTPS.
- Monthly quota، مع `-1` للدلالة على unlimited.
- Per-minute rate limit.
- حالة Active/Disabled.
- وقت إنشاء وتحديث.

المفتاح عام وليس Secret؛ الحماية تعتمد على Allowed Origins وCSP وتوكن قصير العمر موقّع ومربوط بالـorigin.

### Origin Security

عند تحميل:

`/embed/scanner?app=...`

يتم فحص parent origin من Origin/Referer، مع fallback إلى origin المرسل من loader. عند قبول التطبيق، يُنشأ token قصير العمر مرتبط بالتطبيق والـorigin.

ويستخدم iframe:

`Content-Security-Policy: frame-ancestors ...`

حسب origins المسموح بها للتطبيق.

### Quotas / Rate Limits

Partner requests لا تستخدم حد الـpublic IP القديم. لكل تطبيق:

- Monthly scan quota.
- Per-minute rate limit.
- Redis ليس مطلوبًا لهذه المرحلة؛ الحالة الحالية محفوظة في SQLite داخل نفس بنية SmartRisk.

### Analytics

تمت إضافة جداول:

- `embed_apps`
- `embed_scan_map`
- `embed_usage_monthly`
- `embed_events`

وتتوفر تحليلات للتطبيق:

- Submitted
- Completed
- Failed
- Daily usage
- Origins

التسجيل idempotent لكل job/event لمنع تكرار completion/failure في حالة polling المتكرر.

### Admin Console

تمت إضافة قسم **Embeds** مع:

- إنشاء Partner Application.
- تعديل الاسم/origins/quota/rate/status.
- تعطيل وتمكين التطبيق.
- تدوير public key.
- عرض analytics.
- توليد embed snippet جاهز للنسخ.

### API الإدارة

```text
GET  /v1/admin/embed/apps
POST /v1/admin/embed/apps
POST /v1/admin/embed/apps/{id}
POST /v1/admin/embed/apps/{id}/toggle
POST /v1/admin/embed/apps/{id}/rotate
GET  /v1/admin/embed/apps/{id}/analytics?days=30
GET  /v1/admin/embed/analytics?days=30
```

## إعداد الإنتاج

يوصى بتعيين:

```text
SMARTRISK_EMBED_TOKEN_SECRET=<high-entropy-stable-secret>
```

حتى تبقى tokens صالحة عبر إعادة تشغيل Railway.

يمكن الاستمرار باستخدام public widget بدون `data-app`، وسيظل خاضعًا لحد الـIP العام الموجود في Phase 1.

## الاختبارات

تم تشغيل الاختبارات على مجموعات مستقلة لتجنب مشكلة إنهاء process في بيئة التنفيذ الحالية:

- Core: 25 passed
- Heuristics: 17 passed
- Indexer: 12 passed
- Service: 39 passed
- Root tests: 21 passed
- State fork + Unified: 44 passed

الإجمالي: **158 passed — 0 failed**.

تم كذلك التحقق من:

- Python `compileall`.
- جميع ملفات `smartrisk/web/*.js` عبر `node --check`.
- JSON manifest عبر `python -m json.tool`.

ملاحظة: عند تشغيل suite الكامل في process واحد داخل بيئة التنفيذ الحالية، أبلغ pytest عن نجاح الاختبارات ولكنه لم ينهِ العملية ضمن مهلة التنفيذ. لذلك لم يُحسب ذلك كتجربة clean full-suite exit؛ نتائج المجموعات المستقلة أعلاه هي النتائج المعتمدة للتغييرات.
