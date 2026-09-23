# SmartRisk — تنفيذ خطة إصلاح البطء وفصل Free/Paid

تم تنفيذ الدفعة الأولى من الخطة المحفوظة:

- إنشاء `ScanProfile` منفصل لـFree وPaid.
- إجبار الفحص العام على `scan_profile=free` وحد نافذة 2000 بلوك.
- Paid API يعمل على `scan_profile=paid` بحد أعلى 10000 بلوك.
- تحسين `eth_getLogs` بتصفية Transfer topic، chunks أكبر، وتوازي bounded.
- تفعيل cache لنتائج logs بدل `fresh=True` في كل استدعاء.
- تمرير حدود pair/holder probe إلى Intelligence.
- تحليل LP pairs بالتوازي بشكل bounded.
- تحويل `/v1/scans/{job}` إلى public summary بدل التقرير الداخلي.
- public summary يستبعد evidence/evidence graph/raw engine payloads.
- إضافة entitlement `full_results` لخطط Developer API المدفوعة.
- رفض `include=full` عندما لا تسمح الخطة بذلك.
- تحديث صفحة النتائج المجانية لعرض الإشارات المهمة فقط.
- تمديد polling للواجهة إلى حد 180 ثانية مع احترام `poll_after_ms`.
- إضافة progress stage/percent محفوظة في JobStore وتُعرض في public polling.
- إضافة deadline تعاونية على مستوى مراحل الفحص: لا تبدأ مرحلة مكلفة جديدة بعد انتهاء ميزانية Free/Paid الزمنية.
- إضافة اختبارات جديدة للعزل بين Free/Paid ولـpublic sanitization وprofiles.

## الخطوة التالية

تشغيل المجموعة كاملة من الاختبارات، ثم مراجعة أي regressions في admin/billing/OpenAPI قبل النشر إلى Railway.
