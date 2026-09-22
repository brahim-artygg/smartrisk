# Crypto Billing Production Deployment

Use `production.billing.env` for the non-secret billing configuration.

Receiving address:
`0x5a9fe13fbcc6055144e594391adf30ecb287e5cf`

Network: Ethereum Mainnet (chain ID 1)
Token: USDT (`0xdac17f958d2ee523a2206206994597C13D831ec7`)

Before enabling the service, configure at least one authenticated Ethereum RPC provider in the deployment secret store. For production resilience, configure two providers using the existing SmartRisk multi-provider variables.

The repository intentionally does not contain an RPC credential or endpoint secret.
