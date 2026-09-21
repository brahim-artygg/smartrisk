# SmartRisk

منصة فحص مخاطر على شبكات EVM. يحتوي المستودع حالياً على الإصدار الأول من محرك التحليل الثابت AST/IR.

## Static engine

المحرك يستخدم:

- `solc`/`solc-select` لاختيار compiler مناسب.
- Slither كـworker خارجي للتحليل الثابت وSlithIR وdetectors الرسمية.
- كواشف SmartRisk دلالية فوق كائنات Slither لعناصر الصلاحيات والترقية والتوكن.
- عقد بيانات موحد يتضمن `StaticRun` و`Finding` و`Evidence`.

عدم توفر compiler أو Slither لا ينتج نتيجة `safe`; ينتج `unknown` مع سبب واضح.

## Compiler manager

يقرأ مدير compiler إصدارات `pragma solidity` من مجلد المشروع أو الملف المنفرد، ويدعم:

- اختيار نسخة صريحة عبر `--compiler-version`.
- اكتشاف الإصدارات المثبتة بواسطة `solc-select`.
- اكتشاف binaries محلية من نمط `solc-X.Y.Z`.
- تسجيل النسخة المختارة والـpragma والـexecutable داخل التقرير.
- رفض التشغيل عندما لا توجد نسخة مثبتة مناسبة بدلاً من تنزيل compiler بصمت.

مثال:

```bash
python -m smartrisk.static_engine tests/fixtures/VulnerableToken.sol \
  --compiler-version 0.8.20 \
  --output artifacts/vulnerable-static.json
```

## الكواشف المخصصة v0.2

الكواشف تعمل على كائنات Slither الدلالية، وليست regex للنص. النسخة الحالية تشمل:

- `access.unprotected-sensitive-function`
- `upgrade.unprotected`
- `token.unprotected-mint-burn`
- `token.unprotected-blacklist`
- `token.unprotected-pause`
- `token.unbounded-fee`

كل finding يتضمن rule ID وseverity وconfidence وsource location وevidence وremediation. الكاشف يستخدم أسماء الدوال والـmodifiers وinternal calls كمؤشرات دلالية أولية. ستتم إضافة تحليل data-flow وstorage وbounds في الإصدارات التالية قبل اعتماد النتائج كـhard block.

## اختبار على عقد ضعيف

يحتوي `tests/fixtures/VulnerableToken.sol` على ثغرات مقصودة في:

- `upgradeTo`
- `mint`
- `burn`
- `setBlacklist`
- `setPaused`
- `setFeeBps`
- `setOwner`

التشغيل:

```bash
PATH="$PWD/.venv/bin:$PATH" \
python -m smartrisk.static_engine tests/fixtures/VulnerableToken.sol \
  --compiler-version 0.8.20 \
  --run-id vulnerable-smoke \
  --output artifacts/vulnerable-static.json
```

في الاختبار الحالي تم العثور على 10 findings، منها 7 findings مخصصة تغطي الترقية وmint/burn وblacklist وpause وfees وتغيير المالك، مع مواقع الأسطر في العقد.

## الاختبارات

```bash
pytest -q
```

الاختبارات تغطي serialization، حالات `unknown`، حالة المشروع غير الموجود، وقراءة pragma. أما اختبار Slither الفعلي فيستخدم fixture الضعيف ويجب تشغيله مع compiler مثبت.

## حدود الإصدار الحالي

- الكواشف المخصصة لا تثبت الاستغلال وحدها؛ هي findings من نوع `likely`.
- اختيار compiler يرفض الإصدارات غير المثبتة ولا يقوم بتحميلها تلقائياً.
- تحليل المشروع يحتاج source/compilation artifacts؛ bytecode وحده لا ينتج AST/IR موثوقاً.
- ترخيص Slither AGPL-3.0 وترخيص compiler/أدواته يجب مراجعتهما قبل دمجهما في توزيع تجاري مغلق المصدر.
