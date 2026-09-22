# SmartRisk Admin Console

Open `/admin` with an administrator account.

## Initial administrator
Set these environment variables before first production start:

```text
SMARTRISK_ADMIN_EMAIL=admin@example.com
SMARTRISK_ADMIN_PASSWORD=<strong-random-password>
SMARTRISK_ADMIN_CSRF_SECRET=<long-random-secret>
```

If the email does not exist, SmartRisk creates a verified admin account. If it already exists, its stored password must match `SMARTRISK_ADMIN_PASSWORD` before the role is elevated.

The console includes:

- Users and roles
- API key disable/enable/revoke
- Developer/Pro pricing and limits
- Subscriptions
- USDT payment records and confirmation
- Coupons
- Grants
- Ads and promotions
- Platform settings
- Audit log

All state-changing admin requests require the session-bound `X-CSRF-Token` returned by `/v1/admin/csrf`. Administrative changes are audited.

USDT checkout itself is intentionally not part of this release; the payment ledger and subscription controls are ready for a later on-chain checkout integration.
