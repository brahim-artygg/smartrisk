# SmartRisk

منصة فحص مخاطر على شبكات EVM. هذا المستودع يبدأ بمحرك التحليل الثابت AST/IR.

## Static engine MVP

المحرك يشغل Slither كـworker خارجي ويحوّل مخرجاته إلى عقد بيانات موحد يتضمن:

- `StaticRun`
- `Finding`
- `Evidence`
- source locations
- severity وconfidence وstatus
- unknown reasons وcompiler manifest

عدم توفر `solc` أو Slither لا ينتج نتيجة `safe`؛ ينتج `unknown` مع سبب واضح.

### التشغيل

```bash
# من جذر المستودع
python -m smartrisk.static_engine tests/fixtures --output artifacts/static.json
```

لتشغيل التحليل الفعلي ثبّت solc وSlither، ثم شغّل المحرك على جذر مشروع Solidity قابل للترجمة، ويفضل مشروعاً مبنياً عبر Foundry أو Hardhat:

```bash
python -m smartrisk.static_engine /path/to/solidity-project -o artifacts/static.json
```

### الاختبارات

```bash
pytest -q
```

## التصميم

`smartrisk/static_engine/slither_adapter.py` يعزل تشغيل Slither كعملية منفصلة. هذا يجعل حدود الترخيص واضحة ويتيح لاحقاً إضافة Aderyn أو كواشف TypeScript خلف نفس عقد البيانات. `engine.py` مسؤول عن hash المدخلات، compiler manifest، وحالات `complete` و`unknown` و`failed`.

هذه أول طبقة فقط. لا يمثل التقرير الحالي فحصاً كاملاً ولا يستنتج سلامة العقد عند غياب المحلل أو المصدر.
