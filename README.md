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
PATH="$PWD/.venv/bin:$PATH" \
python -m smartrisk.static_engine tests/fixtures/VulnerableToken.sol \
  --compiler-version 0.8.20 \
  --output artifacts/vulnerable-static.json
```

## الكواشف المخصصة v0.3

الكواشف تعمل على كائنات Slither الدلالية، وليست regex للنص ولا تعتمد على اسم الدالة وحده. كل قاعدة تتطلب:

1. دالة `public` أو `external` قابلة للوصول.
2. `state_variables_written` أو `variables_written` غير فارغة.
3. تصنيفاً مبنياً على أسماء **المتغيرات التي تمت كتابتها**.
4. فحص modifiers وinternal calls وعمليات IR لاكتشاف مسار authorization.

القواعد الحالية:

- `access.unprotected-sensitive-function`
- `upgrade.unprotected`
- `token.unprotected-mint-burn`
- `token.unprotected-blacklist`
- `token.unprotected-pause`
- `token.unprotected-fee`
- `token.unbounded-fee`

بالنسبة للـfees، تميز القواعد بين كتابة غير محمية لكنها bounded وبين كتابة غير محمية وغير bounded. كل finding يتضمن rule ID وseverity وconfidence وsource location وevidence وremediation وstorage variables وIR operations.

## اختبار العقد الضعيف والمحمي

العقد الضعيف `tests/fixtures/VulnerableToken.sol` يحتوي على:

- `upgradeTo`
- `mint`
- `burn`
- `setBlacklist`
- `setPaused`
- `setFeeBps`
- `setOwner`

العقد المحمي `tests/fixtures/ProtectedToken.sol` يستخدم `onlyOwner` و`onlyRole`، ويضع حداً أعلى للـfee. التشغيل الفعلي أعطى:

```text
VulnerableToken: 10 total findings, 7 custom data-flow findings
ProtectedToken: 4 total findings, 0 custom data-flow findings
```

الـ4 findings المتبقية في العقد المحمي صادرة من detectors العامة لـSlither، وليست من كواشف SmartRisk المخصصة. هذا يثبت أن الكواشف المخصصة لم تطلق findings على الوظائف الحساسة المحمية، ويقلل false positives في هذه المجموعة الاختبارية.

لتشغيل الاختبار:

```bash
PATH="$PWD/.venv/bin:$PATH" \
python -m smartrisk.static_engine tests/fixtures/VulnerableToken.sol \
  --compiler-version 0.8.20 \
  --run-id vulnerable-dataflow \
  --output artifacts/vulnerable-static.json

PATH="$PWD/.venv/bin:$PATH" \
python -m smartrisk.static_engine tests/fixtures/ProtectedToken.sol \
  --compiler-version 0.8.20 \
  --run-id protected-dataflow \
  --output artifacts/protected-static.json
```

## الاختبارات

```bash
pytest -q
```

تغطي الاختبارات serialization، حالات `unknown`، حالة المشروع غير الموجود، قراءة pragma، تصنيف storage writes، كشف authorization modifiers، والتمييز بين fee bounded وfee unbounded.

## حدود الإصدار الحالي

- الكواشف الحالية تثبت مسار كتابة وحالة authorization دلالياً، لكنها لا تثبت exploitability وحدها؛ findings من نوع `likely`.
- فحص inline authorization يعتمد حالياً على أدلة IR بسيطة؛ ستضاف reachability/data-dependency أعمق في الإصدار التالي.
- اختيار compiler يرفض الإصدارات غير المثبتة ولا يقوم بتحميلها تلقائياً.
- تحليل المشروع يحتاج source/compilation artifacts؛ bytecode وحده لا ينتج AST/IR موثوقاً.
- ترخيص Slither AGPL-3.0 وترخيص compiler/أدواته يجب مراجعتهما قبل دمجهما في توزيع تجاري مغلق المصدر.
