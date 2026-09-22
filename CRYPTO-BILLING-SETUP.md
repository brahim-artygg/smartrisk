# SmartRisk Crypto Billing

This release adds USDT billing on Ethereum Mainnet while keeping the existing Developer API plans, subscriptions, keys, and quota enforcement.

## Production configuration

Set these environment variables before enabling paid access:

```text
SMARTRISK_BILLING_ENABLED=true
SMARTRISK_BILLING_REQUIRED=true
SMARTRISK_PAYMENT_RECEIVER=0x5a9fe13fbcc6055144e594391adf30ecb287e5cf
SMARTRISK_PAYMENT_RPC_URL=https://YOUR_ETHEREUM_RPC_ENDPOINT
```

`SMARTRISK_PAYMENT_RPC_URL` is optional when the existing SmartRisk Ethereum provider configuration is available (`ALCHEMY_RPC_URL`, `ALCHEMY_API_KEY`, or the existing multi-provider settings). For resilience, use at least two configured RPC providers through the existing multi-provider layer. The production receiving address is fixed to `0x5a9fe13fbcc6055144e594391adf30ecb287e5cf`. RPC credentials are intentionally not bundled with the source archive.

Optional tuning:

```text
SMARTRISK_PAYMENT_INVOICE_TTL_MINUTES=30
SMARTRISK_PAYMENT_POLL_SECONDS=15
SMARTRISK_PAYMENT_SCAN_LOOKBACK_BLOCKS=50
SMARTRISK_PAYMENT_SCAN_CHUNK=1000
```

The accepted token is hard-coded to the Ethereum USDT contract used by the billing verifier. The receiver address is supplied by configuration and is the single receiving address.

## Payment rules

Each invoice stores the plan price in integer USDT base units and receives a unique payment amount so invoices can be matched even though the platform uses one receiving address.

When a wallet is available, the frontend records the expected payer address. Automatic settlement requires a known payer. Manual payments without a pre-registered payer remain non-settled until the authenticated account owner supplies the transaction hash for verification.

A transaction is accepted only when the Ethereum chain, configured USDT contract, receiving address, exact invoice amount, Transfer event, receipt status, and invoice validity all match. Settlement waits for Ethereum `finalized` state.

A transaction/event can only produce one settlement. Database uniqueness and an atomic `BEGIN IMMEDIATE` settlement prevent duplicate subscription extensions under concurrent verification requests.

Underpayments, wrong tokens, wrong recipients, payer mismatches, expired invoices, failed transactions, and ambiguous transfers do not activate subscriptions.

## Main API

```text
GET  /v1/billing/plans
POST /v1/billing/invoices
GET  /v1/billing/invoices/latest
GET  /v1/billing/invoices/{invoice_id}
POST /v1/billing/invoices/{invoice_id}/verify
GET  /v1/billing/subscription
```

The existing `/v1/developer/api-keys` and `/v1/api/*` entitlement path remains authoritative for API access and plan quotas.
