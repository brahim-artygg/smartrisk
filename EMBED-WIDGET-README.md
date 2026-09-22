# SmartRisk Embed / Widget — v0.9

SmartRisk Embed lets third-party websites embed the consumer scanner without exposing SmartRisk engine internals or Developer API keys in the browser.

## Quick start

Add this to a third-party page:

```html
<div data-smartrisk-widget data-theme="dark" data-height="430px"></div>
<script src="https://YOUR-SMARTRISK-DOMAIN/assets/embed.js" defer></script>
```

The loader creates an isolated iframe pointing to `/embed/scanner`. The user enters one EVM contract address; the widget calls the SmartRisk Embed API and renders a public-safe report.

## Current MVP routes

- `GET /embed/scanner` — iframe UI.
- `POST /v1/embed/scans` — create an asynchronous scan.
- `GET /v1/embed/scans/{job_id}` — poll job state and receive the public-safe result after completion.
- `GET /v1/embed/reports/{job_id}` — public-safe completed result only.

The Embed result is deliberately smaller than `UnifiedRiskReport`. It excludes raw evidence, engine reports, request payloads, assumptions, internal graphs, and other implementation details.

## Network behavior

The widget does not display a network selector. When `chain_id` is omitted, the server uses the existing SmartRisk network resolver to auto-detect the supported network from deployed bytecode.

## Rate limiting

Default: 5 new Embed scans per client IP per 3600 seconds.

Configure with:

```text
SMARTRISK_EMBED_RATE_LIMIT=5
SMARTRISK_EMBED_RATE_WINDOW=3600
```

## Feature flag

Admin platform settings include:

```text
embed_enabled=true
```

Embed also respects `maintenance_mode` and `public_scans_enabled`.

## Phase 2 — Partner Applications

Partner sites can receive a server-managed Embed Application. Each application has:

- a public integration key (`srw_pub_...`);
- one or more exact HTTP/HTTPS allowed origins;
- a monthly scan quota (`-1` for unlimited);
- a per-minute rate limit;
- an active/disabled state;
- usage and origin analytics in Admin Console.

Example partner integration:

```html
<div data-smartrisk-widget data-app="srw_pub_..." data-theme="dark"></div>
<script src="https://YOUR-SMARTRISK-DOMAIN/assets/embed.js" defer></script>
```

The iframe bootstrap validates the parent origin against the application allowlist and returns a short-lived, origin-bound signed token. The browser never receives a secret API key. The iframe response uses a per-application `Content-Security-Policy: frame-ancestors ...` policy, while scan requests are additionally protected by application quota and rate limits.

Public widgets without an application key keep the Phase 1 IP-based rate limit.

## Admin routes

- `GET /v1/admin/embed/apps` — list partner applications.
- `POST /v1/admin/embed/apps` — create an application.
- `POST /v1/admin/embed/apps/{id}` — update application.
- `POST /v1/admin/embed/apps/{id}/toggle` — enable/disable.
- `POST /v1/admin/embed/apps/{id}/rotate` — rotate public integration key.
- `GET /v1/admin/embed/apps/{id}/analytics?days=30` — application analytics.
- `GET /v1/admin/embed/analytics?days=30` — global Embed analytics.

Analytics are backed by durable SQLite tables (`embed_usage_monthly`, `embed_events`, and `embed_scan_map`). Completion/failure events are recorded idempotently per job.

## Partner token secret

For production, set `SMARTRISK_EMBED_TOKEN_SECRET` to a stable high-entropy secret and keep it private. If omitted, SmartRisk falls back to the existing admin CSRF secret and then a process-local random secret, which is suitable for development but can invalidate partner iframe tokens after a restart.
