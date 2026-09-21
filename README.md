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


## اختبارات متقدمة: Sell Simulation وHoneypot

أضيف إلى محرك State-Fork دعم sequence حقيقية داخل نفس حالة Anvil:

```text
buy → optional approve → sell
```

كل sequence تبدأ بـsnapshot واحد، وتنُفذ خطوات الشراء والموافقة والبيع بالترتيب، ثم تعود إلى snapshot الأصلي بعد انتهاء الاختبار. هذا يمنع أن تؤثر اختبارات honeypot على بعضها أو على fork process التالي.

### تشغيل honeypot عبر CLI

```bash
export ALCHEMY_API_KEY="..."

smartrisk-fork tests/fixtures/honeypot-sequence.json \
  --honeypot \
  --block-tag safe \
  --run-id honeypot-mainnet \
  --output artifacts/honeypot.json
```

### التصنيف

- `sell_succeeded`: نجح buy، وapprove عند وجوده، ثم نجح sell.
- `sell_blocked`: نجح buy وapprove، ثم reverted sell داخل نفس fork state.
- `buy_failed`: فشل الشراء؛ لا يتم تسميته honeypot لأن السيولة أو calldata أو السعر قد تكون غير صحيحة.
- `unknown`: نقص RPC أو receipt أو trace أو لم تصل sequence إلى نتيجة sell قابلة للحكم.

النتيجة لا تقول إن العقد احتيالي تلقائياً. `sell_blocked` هو finding قوي لقابلية البيع في السيناريو المحدد، ويجب حفظ calldata والـrouter والـpair والـanchor كأدلة.

### سيناريوهات الاختبار التي يجب استخدامها

1. **Basic buy/sell:** شراء بكمية صغيرة ثم بيع الرصيد المتوقع من نفس الحساب.
2. **Approve flow:** buy ثم `approve(router, amount)` ثم sell عبر router.
3. **Fee-on-transfer:** sell بنسبة من الرصيد، مع قياس token delta وnative delta.
4. **Blacklist trap:** تنفيذ buy من حساب عادي ثم sell من الحساب نفسه، مع تسجيل revert selector.
5. **Trading-open gate:** تكرار الاختبار مع block anchor قبل وبعد فتح التداول.
6. **Cooldown/anti-bot:** تنفيذ buy ثم تقدم block محلياً ضمن policy ثم sell، مع تسجيل الفشل كافتراض زمني لا كحكم عام.
7. **Low-liquidity control:** تمييز فشل السعر/السيولة عن revert في token transfer أو router.
8. **Alternate route:** تجربة أكثر من pair/router عندما تكون العناوين معروفة من طبقة السوق، مع إبقاء كل محاولة دليلاً مستقلاً.

### بيانات يجب تسجيلها لكل محاولة

- chainId وblock number وblock hash.
- buyer وtoken وrouter وpair.
- calldata وvalue وgas limit.
- receipt status وrevert data وlogs.
- call trace عند توفره.
- token/native balance deltas قبل وبعد كل خطوة.
- سبب `unknown` أو `not_tested`.
- نسخة السيناريو ونسخة المحرك.

الـfixture الحالي هو `tests/fixtures/honeypot-sequence.json`. في بيئة بلا Alchemy/Anvil يرجع CLI `unknown` بأمان؛ الاختبار الفعلي يحتاج `ALCHEMY_API_KEY` وbinary `anvil`.


# المحرك الثالث: On-chain Heuristics + Rule Scoring v0.1

تمت إضافة محرك التسجيل النقطي الذي يدمج:

- **Alchemy:** حقائق السلسلة، block anchor، runtime code، وlogs.
- **Dexscreener:** ملاحظات السوق: pairs، liquidity، volume، buys/sells، prices، pair age.
- **SmartRisk:** استخراج الميزات، evidence، coverage، confidence، وقواعد score versioned.

## المعمارية

```text
AlchemySource ───────┐
  chainId/block/code  │
  logs                ├── FeatureExtractor ── RuleEngine(score-v0.1)
DexscreenerClient ────┘                              │
  token-pairs                                        ▼
  liquidity/volume                              RiskScore + unknowns
```

### التشغيل

```bash
export ALCHEMY_API_KEY="..."

smartrisk-score ethereum 0x... \
  --block-tag safe \
  --window-blocks 10000 \
  --run-id score-mainnet \
  --output artifacts/score.json
```

أو:

```bash
python -m smartrisk.heuristics ethereum 0x... \
  --block-number 21000000 \
  --output artifacts/score.json
```

يستخدم Dexscreener واجهة `token-pairs/v1/{chainId}/{tokenAddress}` مع cache TTL وretries. ويستطيع client أيضاً استدعاء pair lookup وsearch.

## الميزات الحالية

- `market.pair_count`
- `market.best_liquidity_usd`
- `market.volume_h24_usd`
- `market.buys_h24`
- `market.sells_h24`
- `market.price_min_usd`
- `market.price_max_usd`
- `market.pair_age_hours`
- `chain.token_has_code`
- `chain.log_count_window`

كل feature تحتوي على source وconfidence وcoverage وevidence references وunknown reasons.

## القواعد الحالية

- `market.no_pair` — لا يوجد pair معروف في استجابة Dexscreener.
- `market.low_liquidity` — أفضل سيولة مرصودة أقل من 10,000 USD.
- `market.sell_activity_absent` — توجد buys في نافذة h24 ولا توجد sells.
- `market.price_divergence` — تباعد سعري بين الأزواج أكبر من 25%.
- `market.stale_pair` — pair أقدم من سنة، كإشارة سياقية منخفضة الوزن.
- `chain.no_contract_code` — Alchemy يعيد runtime code فارغاً.

الدرجة تستخدم أوزاناً capped داخل `RuleEngine.VERSION = score-v0.1`، وتنتج band من `low` إلى `critical`. إذا كانت coverage أقل من 75% تصبح band `unknown` بدلاً من عرض درجة مطمئنة.

## فصل مصادر الحقيقة

- Alchemy هو المصدر المرجعي للـchain facts.
- Dexscreener هو مصدر market observation فقط.
- لا تُستخدم `priceUsd` أو `liquidity.usd` وحدها كإثبات شرعية أو قابلية بيع.
- فشل Dexscreener لا يتحول إلى `market.no_pair`؛ ينتج feature ناقصة و`unknown`.
- لا ينتج المحرك `pass` عند غياب Alchemy أو نقص البيانات الجوهرية.

## الاختبارات

```text
17 passed
```

تغطي:

- تجميع ميزات السوق والسلسلة.
- low liquidity وغياب sell activity.
- unknown عند timeout أو نقص Dexscreener.
- عدم خلط فشل المزود مع غياب الزوج.
- serializing evidence وrisk decisions.
- CLI في بيئة بلا credentials.

في البيئة الحالية لا توجد credentials لـAlchemy، لذلك يعطي التشغيل المحلي:

```json
{
  "status": "unknown",
  "risk": {
    "band": "unknown",
    "coverage": 0.0
  }
}
```

## الحدود الحالية

- event ledger والحائزون وproxy/roles ستضاف في الإصدارات التالية.
- لا يُعاد بناء liquidity أو volume محلياً بالكامل بعد؛ Dexscreener observation يجب cross-check مع Alchemy قبل hard evidence.
- لا تستخدم القواعد الحالية بيانات reputational أو labels خارجية.
- يجب مراجعة شروط Dexscreener الحالية قبل الاستخدام التجاري المباشر، خصوصاً قيد المنافسة وإعادة إتاحة البيانات.
