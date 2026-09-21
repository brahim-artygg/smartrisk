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


# المحرك الثاني: State-Fork Simulation v0.1

تمت إضافة محرك محاكاة معاملات على حالة مفروكة محلياً باستخدام Alchemy كمصدر RPC وAnvil كمحرك fork.

## مكونات المحرك

```text
AlchemyRpcClient
   ├── capability_probe
   ├── chainId / safe / finalized / latest
   ├── block anchor + block hash
   └── receipts / code / balance
          ↓
AnvilFork
   ├── fork-block-number
   ├── local impersonation فقط
   ├── snapshot / revert لكل scenario
   ├── receipt + logs
   └── debug_traceTransaction عند توفره
          ↓
SimulationResult / ForkRun
```

الطبقة لا تحتوي على private keys ولا ترسل المعاملة إلى الشبكة الحقيقية. `anvil_impersonateAccount` و`anvil_setBalance` يعملان داخل fork محلي فقط.

## التشغيل

المتطلبات:

- binary `anvil` متاح في `PATH`.
- `ALCHEMY_API_KEY` أو `ALCHEMY_RPC_URL`.
- بلوك `safe` أو `finalized` متاح على الشبكة.

مثال:

```bash
export ALCHEMY_API_KEY="..."
smartrisk-fork tests/fixtures/fork-scenario.json \
  --block-tag safe \
  --run-id fork-smoke \
  --output artifacts/fork.json
```

أو:

```bash
python -m smartrisk.state_fork tests/fixtures/fork-scenario.json \
  --block-number 21000000 \
  --output artifacts/fork.json
```

ملف السيناريو:

```json
{
  "scenario_id": "transfer",
  "from": "0x...",
  "to": "0x...",
  "data": "0xa9059cbb...",
  "value_wei": 0,
  "gas_limit": 250000,
  "description": "local fork transaction"
}
```

يمكن أن يحتوي الملف على object واحد أو array من السيناريوهات.

## ضمانات v0.1

- يثبت المحرك `chainId` وblock number وblock hash قبل التشغيل.
- يفضل `safe` ثم `finalized`، ولا يستخدم `latest` إلا عند طلبه صراحة.
- يقارن block hash داخل Anvil مع block hash الذي أعاده Alchemy ويرفض mismatch.
- ينشئ snapshot قبل كل scenario ويعمل revert بعده لمنع تسرب state بين السيناريوهات.
- يصنف التنفيذ إلى `success` أو `reverted` أو `unknown` أو `failed`.
- يحفظ receipt وlogs وtrace عند توفر `debug_traceTransaction`.
- عدم وجود Alchemy أو Anvil ينتج `unknown` وليس نجاحاً أو فشلاً أمنياً.
- لا تُرسل أي معاملة إلى Alchemy؛ Alchemy يستخدم upstream state فقط، والتنفيذ محلي.

## الاختبارات الحالية

```text
11 passed
```

وتغطي:

- ترميز calldata/value/gas إلى transaction RPC.
- تثبيت anchor وتشغيل السيناريوهات.
- التحقق من block hash.
- حالة غياب Alchemy.
- serialization للنتائج.
- smoke test CLI في بيئة بلا credentials ينتج `unknown` بأمان.

## حدود النسخة الأولى

- لا يوجد state diff كامل بعد؛ النسخة تحفظ receipt/logs/trace وتضع state diff كحقل قابل للتوسعة.
- لا يوجد scenario generator من ABI بعد؛ السيناريوهات تدخل حالياً كـJSON صريح.
- `debug_traceTransaction` اختياري لأن توفره يختلف حسب شبكة وخطة Alchemy.
- استخدام `eth_sendTransaction` يتطلب حساباً impersonated داخل Anvil؛ لا توجد مفاتيح خاصة في المحرك.
- لا ينبغي اعتبار نجاح scenario واحد دليلاً على قابلية البيع العامة؛ يجب بناء سيناريوهات buy/sell صحيحة وربطها لاحقاً بمحرك البيانات السوقية.
