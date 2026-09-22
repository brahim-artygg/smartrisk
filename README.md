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


# Unified Risk Engine v0.1

تم دمج المحركات الثلاثة في Orchestrator موحد:

```text
Unified Risk Engine
   ├── Static AST/IR
   ├── State-Fork Simulation
   └── On-chain Heuristics + Rule Scoring
              ↓
      Unified JSON Risk Report
```

## الواجهة الموحدة

```bash
smartrisk scan \
  --project tests/fixtures/VulnerableToken.sol \
  --chain-id ethereum \
  --token-address 0x... \
  --scenarios tests/fixtures/fork-scenario.json \
  --honeypot tests/fixtures/honeypot-sequence.json \
  --compiler-version 0.8.20 \
  --block-tag safe \
  --output artifacts/unified-risk.json
```

يمكن أيضاً استخدام config JSON:

```json
{
  "project": "tests/fixtures/VulnerableToken.sol",
  "chain_id": "ethereum",
  "token_address": "0x...",
  "scenarios": "tests/fixtures/fork-scenario.json",
  "honeypot": "tests/fixtures/honeypot-sequence.json",
  "block_tag": "safe",
  "compiler_version": "0.8.20",
  "window_blocks": 10000
}
```

ثم:

```bash
smartrisk scan --config scan.json --output artifacts/unified-risk.json
```

## مخرج JSON النهائي

يحتوي التقرير الموحد على:

- `risk.score`
- `risk.band`
- `risk.confidence`
- `risk.coverage`
- نتائج كل محرك في `engines`
- static findings في `findings`
- fork وheuristics decisions في `decisions`
- الأدلة الخام في `evidence`
- `unknowns`
- assumptions
- إصدارات جميع المحركات والقواعد

كل محرك يظل قابلاً للفحص بشكل مستقل داخل `engines[].report`، لذلك لا تضيع الأدلة أو أسباب القرار عند دمج الدرجة.

### طريقة الدمج

- Static findings تتحول إلى score حسب severity.
- `sell_blocked` في Honeypot sequence يعطي contribution مرتفعاً.
- Heuristics تستخدم score الخاص بـ`score-v0.1`.
- أوزان الدمج الحالية:
  - Static AST: 30%
  - State-Fork: 40%
  - Heuristics: 30%
- إذا لم يتوفر أي محرك ينتج التقرير `unknown`.
- إذا نقصت التغطية عن الحد المطلوب، لا ينتج المحرك band مطمئناً.
- غياب مدخلات محرك لا يُعامل كـsafe.

## الاختبارات

```text
20 passed
```

وتغطي:

- تشغيل المحركات الثلاثة عبر orchestrator.
- دمج static findings وfork decisions وheuristics features.
- Unified score وband وcoverage.
- دعم honeypot داخل Unified Engine.
- CLI وconfig JSON.
- مخرج unknown آمن عند غياب credentials أو مدخلات المحرك.

## Engine expansion v0.2 — Contract Intelligence foundation

تم تنفيذ الدفعة الأولى من خطة SmartRisk Engine دون إزالة المحركات الثلاثة:

- إضافة `ContractIntelligence` وتحليل bytecode مستقل عن مزودات الأمن الخارجية.
- استخراج runtime code hash، حجم bytecode، opcode profile، selectors من PUSH4، وsignals لـ `CALL` و`DELEGATECALL` و`SSTORE` و`SELFDESTRUCT` و`TIMESTAMP` و`NUMBER`.
- قراءة EIP-1967 implementation/admin/beacon slots على anchor محدد، وقراءة `owner()` عند توفرها عبر Alchemy.
- إضافة `proxy_detected` وprivilege observations إلى طبقة Heuristics.
- جعل `eth_getLogs` adaptive chunked بدل الاعتماد على مدى ثابت؛ يبدأ بنطاق صغير ويقسّم النطاق عند أخطاء RPC/حجم النتائج.
- إزالة `market.stale_pair` كإشارة خطر منفردة، لأن عمر الزوج ليس دليل احتيال بحد ذاته.
- إضافة قواعد محافظة لـ `selfdestruct` و`delegatecall` وtime/block logic وproxy detection مع Evidence refs.
- رفع إصدار Unified إلى `unified-v0.2` وإدخال triggered heuristic decisions كـfindings داخل التقرير الموحد.

هذه الدفعة لا تدّعي بعد أن proxy/delegatecall/selfdestruct = malicious؛ هذه signals تحتاج correlation مع الصلاحيات ومسار التحكم في المراحل التالية.

### State-Fork runtime accounting expansion

`SimulationScenario` يدعم الآن:
- `observed_allowances`: أزواج `(token, spender)` لقياس تغير allowance قبل/بعد التنفيذ.
- `observed_pairs`: عناوين UniswapV2-like pairs لقراءة `getReserves()` قبل/بعد التنفيذ.
- `category` و`risk_tags` لتوجيه السيناريوهات حسب سطح الخطر.

ويحفظ `AnvilFork` الآن:
- ERC-20 `Transfer` و`Approval` event decoding.
- allowance deltas.
- pair reserve deltas.
- balance deltas.
- event analysis داخل `state_diff`.

هذه البيانات هي أساس Dynamic Tax/Honeypot/Liquidity accounting في المراحل التالية، ولا تُحوّل أي delta وحده إلى verdict بدون correlation.

## State-Fork v0.3 — Automatic DEX/Trading Analysis

أضيفت طبقة تداول تلقائية لا تعتمد على مزود أمني خارجي:

```text
DexScreener token-pairs
        ↓
DexPair normalization
        ↓
Local DexRouteRegistry
        ↓
Native V2 buy plan
        ↓
Approve
        ↓
Observed buy token delta
        ↓
Partial / baseline / full sell
        ↓
Transfer + reserve + native state diff
        ↓
Dynamic tax correlation
```

### تشغيل التخطيط فقط

يمكن تشغيل الاكتشاف وبناء الخطة دون بدء Anvil:

```bash
smartrisk-fork --auto-trade \
  --chain-id 1 \
  --token-address 0x... \
  --trader 0x... \
  --plan-only \
  --output artifacts/auto-trade-plan.json
```

### تشغيل الاختبار على fork

```bash
export ALCHEMY_API_KEY="..."
smartrisk-fork --auto-trade \
  --chain-id 1 \
  --token-address 0x... \
  --trader 0x... \
  --buy-amount-wei 1000000000000000 \
  --output artifacts/auto-trade.json
```

مسار الـrouter لا يؤخذ من GoPlus/TokenSniffer/De.Fi أو أي مزود أمني. توجد معرفة محلية لمسارات Uniswap v2 المعروفة، ويمكن إضافة مسارات أخرى عبر `SMARTRISK_DEX_ROUTES` بصيغة `policies/dex-routes.example.json`.

### مبدأ مهم

عدم وجود router محلي معروف أو عدم كفاية البيانات لا يتحول إلى نجاح أو فشل أمني؛ يسجل المحرك `unknown` أو `partial`.

# Intelligence Engine v0.4

أضيفت طبقة Intelligence محلية فوق محرك Heuristics دون استبدال Static أو State-Fork.

## Holder intelligence
- إعادة بناء ERC-20 holders من `Transfer` logs.
- Top 10/20/50/100 concentration.
- holder churn وactive wallet counts.
- probe محدود لأعلى الحائزين عبر `eth_getCode` لتصنيف contract/EOA-or-unknown.

## LP / liquidity intelligence
- تحليل كل pair مكتشف من DexScreener.
- قراءة `token0` و`token1` و`getReserves` و`totalSupply` مباشرة من العقد.
- إعادة بناء حاملي LP من أحداث ERC-20.
- LP top-holder concentration.
- creator/distribution-candidate LP control عندما توجد الأدلة.
- burn-share كسياق معلوماتي، وليس penalty تلقائي.

## Deployer / distribution intelligence
- دعم `--deployer-address` في Unified CLI عند توفر عنوان موثوق.
- first mint recipient يوسم كـ`distribution candidate` فقط؛ لا يتم اعتباره deployer مؤكدًا تلقائيًا.
- حساب candidate supply share وfirst mint block/amount.

## Wallet clusters + history
- connected components من transfer graph.
- largest cluster supply share.
- narrow-window fan-out bursts.
- unique buy-like/sell-like wallets عند توفر pair addresses.
- round-trip wallets.
- early/late wallet overlap وhistorical transfer volume.

## Unified correlation
المحرك الموحد يخرج الآن `correlations` بالإضافة إلى findings وdecisions وevidence، ويربط الأدلة عندما تتفق إشارات مستقلة بين:

```text
Static
  + Intelligence
  + State-Fork
  + Market context
        ↓
Correlation
        ↓
confirmed / corroborated finding
```

كما أضيفت أبعاد مخاطر مستقلة:
- `holder_distribution`
- `deployer_risk`
- `cluster_behavior`
- `historical_behavior`
- `liquidity_market`
- `ownership_security`
- `trading_security`
- `contract_security`

## السياسة

القاعدة الافتراضية الحالية هي `score-v0.3`. ملف `policies/score-v0.2.json` بقي كما هو للتوافق الرجعي، بينما `policies/score-v0.3.json` يحتوي القواعد الجديدة. ويمكن تمرير سياسة صريحة عبر `--policy` في `smartrisk-score`.

## قيد التكلفة والاعتماد

لا يستخدم Intelligence Engine أي GoPlus أو TokenSniffer أو De.Fi أو security API. البيانات الخارجية تبقى محصورة في Alchemy/RPC لحقائق السلسلة وDexScreener لملاحظات السوق.

## تصحيح مهم

تم تصحيح `TRANSFER_TOPIC` في `TransferLedger` إلى القيمة الناتجة من Keccak-256 القياسية لـ`Transfer(address,address,uint256)`. هذا التصحيح ضروري لإعادة بناء holders والتاريخ من سجلات ERC-20 بشكل صحيح.

## v0.5 implementation delta

The current working tree extends v0.4 with recursive EIP-1967 implementation inspection, executable `transfer_only` trade-matrix coverage, normalized prestate storage/account diffs, deterministic scam-fingerprint indicators, and unified anchor-consistency evidence. Fingerprints are review indicators rather than maliciousness verdicts; missing tracer data remains unknown.

## v0.6 implementation delta

The current working tree extends v0.5 with deterministic revert decoding, normalized runtime accounting summaries, bounded standard scenario generation, deeper Alchemy capability/pagination support, and a first-class Unified evidence graph. Anchor mismatches now explicitly downgrade correlation trust and coverage rather than being merged as if they shared one canonical block.

# التشغيل الحالي — Engine v0.7

الإصدار الحالي لم يعد Static-only. الحزمة تتضمن Static Engine وState-Fork وHeuristics/Intelligence وUnified Engine، إضافة إلى طبقة تشغيل مشتركة.

## Gateway وEvidence

`AlchemyGateway` هو حد مشترك قابل لإعادة الاستخدام لقراءات RPC، مع bounded cache، raw evidence capture، latency/error metrics، capability matrix، pagination، وقراءات block/storage/tx/receipt/call/trace.

يمكن تمرير `SQLiteEvidenceStore` إلى gateway لحفظ evidence الخام بشكل durable مع retention محدود. التخزين اختياري حتى لا يفرض كتابة محلية على كل استخدام.

## Reorg-aware indexing

`PollingChainIndexer` ينفذ backfill/sync على JSON-RPC، ويبني `CanonicalChain` فوق `TransferLedger`. يتم تجنب الاعتماد على cache في قراءات block/log الحساسة للـreorg، وتوجد إعادة بناء canonical ledger عند اكتشاف branch replacement.

الطبقة الحالية polling وليست WebSocket. كما أنها in-memory canonical index + اختياري durable evidence، وليست distributed indexer.

## Durable scan jobs

`JobStore` يستخدم SQLite لتخزين jobs ويدعم atomic claim، attempts، started_at، stale-running recovery، واستئناف pending jobs. `ScanService` يقدم metrics محلية عبر `/v1/metrics` بالإضافة إلى `/v1/scans` وrerun/status.

مثال:

```bash
python -m smartrisk.unified.cli serve --host 127.0.0.1 --port 8787
```

ثم:

```text
GET /v1/metrics
```

يعيد counters ومدد التنفيذ وحالة العمل الحالية.

## التحقق الأخير

```text
75 passed
compileall: PASS
```

## الحدود الحالية

- WebSocket subscription وdistributed queue وcontainer sandbox غير منفذة بعد.
- provider failover متعدد المزودين ليس implementation مكتملًا داخل gateway.
- Phase 6 لم تصل بعد إلى symbolic/control-flow deep analysis.
- Phase 7 fuzzing/symbolic scan غير منفذة.
- Phase 9 ما زالت تحتاج corpus واسع ومعايرة FP/FN إحصائية.

## v0.8 — Deep verification and production execution controls

The engine now provides production-oriented building blocks for the roadmap gaps:

- `smartrisk-realtime`: reconnectable WebSocket `newHeads` watcher with canonical RPC backfill/reconciliation.
- `smartrisk-worker`: Redis Streams distributed workers using consumer groups and stale-message recovery.
- `smartrisk-deep symbolic`: bounded symbolic branch guidance with optional Z3.
- `smartrisk-deep fuzz`: deterministic calldata mutation execution on an Anvil fork.
- `smartrisk-calibrate`: holdout-based FP/FN threshold calibration from a labeled corpus.

Recommended installation for the full runtime:

```bash
pip install .[production]
```

### Runtime gates

WebSocket, Redis and Z3 are optional dependencies. Their absence is reported as unavailable rather than silently treated as success. On Linux, the static-analysis sandbox uses bubblewrap for network isolation when present; otherwise CPU/RAM/file/process/output limits remain enforced and the report records the weaker host capability.

### Calibration policy

The calibration command never changes a production score policy by itself. It reports a candidate threshold, train/holdout confusion metrics, Wilson confidence intervals, Brier score and ECE. Production thresholds should only be changed after reviewing a sufficiently large, independently labeled corpus.


## v0.8.1 hardening

- Redis worker reclaim window defaults to 15 minutes and is configurable.
- WebSocket failover is covered by a provider-failure integration test.
- Bubblewrap maps the actual project into `/work`, mounts writable subdirectories explicitly, and only enables host networking when requested.
- `smartrisk-deep foundry` can run existing Foundry fuzz suites or Halmos symbolic suites inside the sandbox when those host tools are installed.
- Calibration supports optional `group_id` holdout separation and rejects duplicate sample IDs.

Verification: **100 passed**, `compileall: PASS`.

## v0.9.0 — Accuracy Foundation

تم تحسين المحرك الحالي دون إضافة محركات جديدة:
- semantic authorization/internal-call analysis
- reflection-style token control detection
- multi-size honeypot probes وtransfer-only
- token-level failure-cause classification
- dynamic tax/threshold detection
- holder/market false-positive controls
- selector-aware fuzzing وbounded symbolic guard hints
- decisive State-Fork/Unified verdicts

Verification: **115 tests passed** + `compileall` PASS.

## Account authentication (v0.9)

SmartRisk account authentication is optional for scanning. The public `POST /v1/scans` endpoint remains available to anonymous visitors.

For production email delivery, configure:

```text
RESEND_API_KEY=...
RESEND_FROM_EMAIL=SmartRisk <security@your-domain.example>
APP_BASE_URL=https://your-domain.example
SMARTRISK_SECURE_COOKIE=true
```

The authentication system provides email/password registration, email verification, login/logout, server-side sessions, password reset, and rate limiting for authentication endpoints. Passwords are stored only as PBKDF2-SHA256 hashes and session/reset/verification tokens are stored only as SHA-256 hashes.
