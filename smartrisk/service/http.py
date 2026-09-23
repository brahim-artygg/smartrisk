from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..core.networks import supported_networks
from ..state_fork.cli import _load_honeypot, _load_scenarios
from ..unified.models import UnifiedRequest
from .auth import AuthError, AuthService, AuthStore, EmailDeliveryError, clear_session_cookie, parse_cookie, session_cookie
from .developer_api import DeveloperAPIService
from .billing import BillingService
from .embed import format_public_result, validate_address
from .embed_partner import csp_for_origins, create_token, normalize_origin, origin_from_headers, verify_token
from .admin import AdminService
from .network_resolver import NetworkResolutionError, resolve_network
from .service import ScanService


class RateLimiter:
    def __init__(self, limit: int = 8, window_seconds: int = 900):
        self.limit = max(1, limit)
        self.window_seconds = max(1, window_seconds)
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            values = [item for item in self._hits.get(key, []) if item > cutoff]
            if len(values) >= self.limit:
                self._hits[key] = values
                return False
            values.append(now)
            self._hits[key] = values
            if len(self._hits) > 5000:
                self._hits = {k: v for k, v in self._hits.items() if v and v[-1] > cutoff}
            return True


class KeyRateLimiter:
    def __init__(self, window_seconds: float = 1.0):
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str, limit: int) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            values = [stamp for stamp in self._hits.get(key, []) if stamp > cutoff]
            if len(values) >= max(1, int(limit)):
                self._hits[key] = values
                return False
            values.append(now)
            self._hits[key] = values
            if len(self._hits) > 10000:
                self._hits = {k: v for k, v in self._hits.items() if v and v[-1] > cutoff}
            return True


class ScanHandler(BaseHTTPRequestHandler):
    service: ScanService
    auth_service: AuthService
    developer_api: DeveloperAPIService
    admin_service: AdminService
    billing: BillingService
    web_root = Path(__file__).resolve().parent.parent / "web"
    admin_csrf_secret = os.getenv("SMARTRISK_ADMIN_CSRF_SECRET") or secrets.token_hex(32)
    auth_limiter = RateLimiter(int(os.getenv("SMARTRISK_AUTH_RATE_LIMIT", "8")), 900)
    embed_limiter = RateLimiter(int(os.getenv("SMARTRISK_EMBED_RATE_LIMIT", "5")), int(os.getenv("SMARTRISK_EMBED_RATE_WINDOW", "3600")))
    embed_partner_limiter = KeyRateLimiter(60.0)
    embed_token_secret = os.getenv("SMARTRISK_EMBED_TOKEN_SECRET") or os.getenv("SMARTRISK_ADMIN_CSRF_SECRET") or secrets.token_hex(32)
    secure_cookie = os.getenv("SMARTRISK_SECURE_COOKIE", "").lower() in {"1", "true", "yes", "on"} or os.getenv("APP_BASE_URL", "").startswith("https://")

    def _bytes(self, status: int, content_type: str, data: bytes, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _asset(self, relative: str, headers: dict[str, str] | None = None) -> None:
        allowed = {
            "index.html": ("text/html; charset=utf-8", "index.html"),
            "results.html": ("text/html; charset=utf-8", "results.html"),
            "auth.html": ("text/html; charset=utf-8", "auth.html"),
            "contact.html": ("text/html; charset=utf-8", "contact.html"),
            "privacy.html": ("text/html; charset=utf-8", "privacy.html"),
            "fulfillment-policy.html": ("text/html; charset=utf-8", "fulfillment-policy.html"),
            "cookies-policy.html": ("text/html; charset=utf-8", "cookies-policy.html"),
            "about.html": ("text/html; charset=utf-8", "about.html"),
            "security.html": ("text/html; charset=utf-8", "security.html"),
            "terms.html": ("text/html; charset=utf-8", "terms.html"),
            "how-it-works.html": ("text/html; charset=utf-8", "how-it-works.html"),
            "methodology.html": ("text/html; charset=utf-8", "methodology.html"),
            "supported-networks.html": ("text/html; charset=utf-8", "supported-networks.html"),
            "risk-library.html": ("text/html; charset=utf-8", "risk-library.html"),
            "faq.html": ("text/html; charset=utf-8", "faq.html"),
            "disclaimer.html": ("text/html; charset=utf-8", "disclaimer.html"),
            "assets/app.css": ("text/css; charset=utf-8", "app.css"),
            "assets/app.js": ("application/javascript; charset=utf-8", "app.js"),
            "assets/results.css": ("text/css; charset=utf-8", "results.css"),
            "assets/results.js": ("application/javascript; charset=utf-8", "results.js"),
            "assets/auth.css": ("text/css; charset=utf-8", "auth.css"),
            "assets/auth.js": ("application/javascript; charset=utf-8", "auth.js"),
            "assets/info.css": ("text/css; charset=utf-8", "info.css"),
            "assets/site-footer.css": ("text/css; charset=utf-8", "site-footer.css"),
            "developer.html": ("text/html; charset=utf-8", "developer.html"),
            "assets/developer.css": ("text/css; charset=utf-8", "developer.css"),
            "assets/developer.js": ("application/javascript; charset=utf-8", "developer.js"),
            "assets/embed.css": ("text/css; charset=utf-8", "embed.css"),
            "assets/embed.js": ("application/javascript; charset=utf-8", "embed.js"),
            "assets/embed-frame.js": ("application/javascript; charset=utf-8", "embed-frame.js"),
            "embed.html": ("text/html; charset=utf-8", "embed.html"),
            "developer-api.yaml": ("application/yaml; charset=utf-8", "developer-api.yaml"),
            "admin.html": ("text/html; charset=utf-8", "admin.html"),
            "assets/admin.css": ("text/css; charset=utf-8", "admin.css"),
            "assets/admin.js": ("application/javascript; charset=utf-8", "admin.js"),
            "assets/logo.png": ("image/png", "logo.png"),
            "favicon.ico": ("image/x-icon", "favicon.ico"),
            "favicon-96x96.png": ("image/png", "favicon-96x96.png"),
            "apple-touch-icon.png": ("image/png", "apple-touch-icon.png"),
            "site.webmanifest": ("application/manifest+json; charset=utf-8", "site.webmanifest"),
            "robots.txt": ("text/plain; charset=utf-8", "robots.txt"),
            "sitemap.xml": ("application/xml; charset=utf-8", "sitemap.xml"),
            "assets/og-image.png": ("image/png", "og-image.png"),
        }
        item = allowed.get(relative)
        if item is None:
            self._json(404, {"error": "not found"})
            return
        content_type, filename = item
        path = self.web_root / filename
        if not path.is_file():
            self._json(404, {"error": "not found"})
            return
        self._bytes(200, content_type, path.read_bytes(), headers)

    def _json(self, status: int, payload: dict[str, Any], headers: dict[str, str] | None = None) -> None:
        data = json.dumps(payload, sort_keys=True, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _body(self, max_bytes: int = 64 * 1024) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > max_bytes:
            raise AuthError("Request is too large.", "REQUEST_TOO_LARGE", 413)
        raw = self.rfile.read(length) or b"{}"
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise AuthError("Invalid JSON body.", "INVALID_JSON", 400)
        return payload

    def _client_key(self, action: str) -> str:
        return f"{action}:{self.client_address[0]}"

    def _session_user(self):
        return self.auth_service.session_user(parse_cookie(self.headers.get("Cookie"), "smartrisk_session"))

    def _auth_page(self, mode: str | None = None, token: str | None = None) -> None:
        query = []
        if mode:
            query.append(f"mode={mode}")
        if token:
            query.append(f"token={token}")
        location = "/auth" + ("?" + "&".join(query) if query else "")
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _session_required(self):
        user = self._session_user()
        if not user:
            raise AuthError("Authentication required.", "AUTH_REQUIRED", 401)
        return user

    def _api_key_context(self):
        raw_key = self.headers.get("X-API-Key", "")
        return self.developer_api.authenticate(raw_key)

    def _api_rate_allowed(self, key_id: str, limit: int) -> bool:
        return self.developer_api.rate_allowed(key_id, limit)

    def _admin_required(self):
        user = self._session_required()
        return self.admin_service.require_admin(user)

    def _admin_csrf_token(self, raw_session: str) -> str:
        return hmac.new(self.admin_csrf_secret.encode("utf-8"), raw_session.encode("utf-8"), hashlib.sha256).hexdigest()

    def _platform_setting(self, key: str, default: Any = False) -> Any:
        try:
            return self.admin_service.store.setting_value(key, default)
        except Exception:
            return default

    def _admin_mutation_allowed(self) -> bool:
        raw_session = parse_cookie(self.headers.get("Cookie"), "smartrisk_session")
        if not raw_session:
            self._json(401, {"error": "Authentication required.", "code": "AUTH_REQUIRED"})
            return False
        try:
            self._admin_required()
        except AuthError as exc:
            self._json(exc.status, {"error": str(exc), "code": exc.code})
            return False
        supplied = self.headers.get("X-CSRF-Token", "")
        expected = self._admin_csrf_token(raw_session)
        if not supplied or not hmac.compare_digest(supplied, expected):
            self._json(403, {"error": "Invalid CSRF token.", "code": "CSRF_INVALID"})
            return False
        return True

    def _admin_json_error(self, exc: Exception) -> None:
        if isinstance(exc, AuthError):
            self._json(exc.status, {"error": str(exc), "code": exc.code})
        else:
            self._json(500, {"error": "Internal admin error.", "code": "ADMIN_INTERNAL_ERROR"})

    def _embed_origin(self, query: dict[str, list[str]] | None = None) -> str | None:
        origin = origin_from_headers(self.headers)
        if origin:
            return origin
        if query:
            return normalize_origin((query.get('origin') or [''])[0])
        return None

    def _embed_context(self, payload: dict[str, Any] | None = None, query: dict[str, list[str]] | None = None, *, require_partner: bool = False) -> dict[str, Any]:
        payload = payload or {}
        public_key = self.headers.get('X-SmartRisk-Embed-Key') or payload.get('app_key') or ((query or {}).get('app') or [''])[0]
        token = self.headers.get('X-SmartRisk-Embed-Token') or payload.get('embed_token')
        if not public_key:
            if require_partner:
                raise AuthError('Embed application credentials are required.', 'EMBED_APP_REQUIRED', 401)
            return {'app': None, 'app_id': None, 'origin': None, 'token': None}
        app = self.admin_service.store.get_embed_app_by_public_key(str(public_key))
        if not app:
            raise AuthError('Unknown Embed application.', 'EMBED_APP_NOT_FOUND', 403)
        if not app['active']:
            raise AuthError('Embed application is disabled.', 'EMBED_APP_DISABLED', 403)
        if not token:
            raise AuthError('Embed token is required.', 'EMBED_TOKEN_REQUIRED', 401)
        try:
            claims = verify_token(self.embed_token_secret, str(token), app['id'])
        except ValueError as exc:
            raise AuthError(str(exc), 'EMBED_TOKEN_INVALID', 401) from exc
        claims_origin = claims['origin']
        if claims_origin not in app['allowed_origins']:
            raise AuthError('Embed origin is not allowed for this application.', 'EMBED_ORIGIN_NOT_ALLOWED', 403)
        request_origin = self._embed_origin(query)
        # A fetch from the SmartRisk iframe normally carries SmartRisk's own Origin.
        # The signed token is the authoritative parent-origin binding for partner calls.
        if request_origin and request_origin not in {claims_origin, normalize_origin(os.getenv('APP_BASE_URL', ''))} and query:
            raise AuthError('Embed origin mismatch.', 'EMBED_ORIGIN_MISMATCH', 403)
        return {'app': app, 'app_id': app['id'], 'origin': claims_origin, 'token': token}

    def _render_embed_frame(self, query: dict[str, list[str]]) -> None:
        public_key = (query.get('app') or [''])[0].strip()
        parent_origin = self._embed_origin(query)
        config = {'app_key': None, 'token': None, 'origin': None, 'partner': False}
        headers = {'Referrer-Policy': 'strict-origin-when-cross-origin'}
        if public_key:
            app = self.admin_service.store.get_embed_app_by_public_key(public_key)
            if not app:
                self._json(404, {'error': 'Unknown Embed application.', 'code': 'EMBED_APP_NOT_FOUND'})
                return
            if not app['active']:
                self._json(403, {'error': 'Embed application is disabled.', 'code': 'EMBED_APP_DISABLED'})
                return
            if not parent_origin or parent_origin not in app['allowed_origins']:
                self._json(403, {'error': 'This website is not authorized to embed this SmartRisk application.', 'code': 'EMBED_ORIGIN_NOT_ALLOWED'})
                return
            config = {'app_key': app['public_key'], 'token': create_token(self.embed_token_secret, app['id'], parent_origin), 'origin': parent_origin, 'partner': True}
            headers['Content-Security-Policy'] = csp_for_origins(app['allowed_origins'])
        else:
            headers['Content-Security-Policy'] = 'frame-ancestors *'
        path = self.web_root / 'embed.html'
        if not path.is_file():
            self._json(404, {'error': 'not found'})
            return
        html = path.read_text(encoding='utf-8').replace('__SMART_RISK_EMBED_CONFIG__', __import__('json').dumps(config, separators=(',', ':')))
        self._bytes(200, 'text/html; charset=utf-8', html.encode(), headers)

    def do_POST(self):
        # Admin routes are authenticated separately from the public scanner and developer API.
        if self.path.startswith("/v1/admin/"):
            if not self._admin_mutation_allowed():
                return
            admin=self._admin_required(); ip=self.client_address[0]; payload=self._body(max_bytes=256*1024)
            try:
                if self.path.startswith("/v1/admin/users/"):
                    parts=self.path.split("/")
                    user_id=parts[4] if len(parts)>4 else ""
                    action=parts[5] if len(parts)>5 else ""
                    if action=="status": self._json(200,{"user":self.admin_service.store.set_user_status(user_id,str(payload.get("status")),admin.id,ip)}); return
                    if action=="role": self._json(200,{"user":self.admin_service.store.set_user_role(user_id,str(payload.get("role")),admin.id,ip)}); return
                    if action=="subscription": self._json(200,{"subscription":self.admin_service.store.upsert_subscription(user_id,str(payload.get("plan_id")),str(payload.get("status","active")),payload.get("ends_at"),admin.id,ip)}); return
                if self.path.startswith("/v1/admin/api-keys/"):
                    parts=self.path.split("/"); key_id=parts[4] if len(parts)>4 else ""
                    state=str(payload.get("state","disabled")); self.admin_service.store.key_state(key_id,state,admin.id,ip); self._json(200,{"ok":True,"key_id":key_id,"state":state}); return
                if self.path.startswith("/v1/admin/plans/"):
                    plan_id=self.path.split("/")[4]; self._json(200,{"plan":self.admin_service.store.update_plan(plan_id,payload,admin.id,ip)}); return
                if self.path == "/v1/admin/coupons":
                    self._json(201,{"coupon":self.admin_service.store.create_coupon(payload,admin.id,ip)}); return
                if self.path.startswith("/v1/admin/coupons/"):
                    cid=self.path.split("/")[4]; self.admin_service.store.toggle_coupon(cid,bool(payload.get("active")),admin.id,ip); self._json(200,{"ok":True}); return
                if self.path == "/v1/admin/grants":
                    self._json(201,{"grant":self.admin_service.store.create_grant(payload,admin.id,ip)}); return
                if self.path.startswith("/v1/admin/grants/"):
                    gid=self.path.split("/")[4]; self.admin_service.store.revoke_grant(gid,admin.id,ip); self._json(200,{"ok":True}); return
                if self.path == "/v1/admin/billing/reconcile":
                    result = self.admin_service.store.billing.mark_expired()
                    if self.billing._monitor is not None and self.billing.configured:
                        try:
                            self.billing._monitor.reconcile_confirming()
                        except Exception:
                            pass
                    data = self.admin_service.store.billing_overview()
                    data["expired_invoices"] = int(result)
                    self.admin_service.store.audit(admin.id,"billing.reconciled","billing",None,{"expired_invoices":int(result),"confirming":data["confirming"],"unmatched_events":data["unmatched_events"]},ip)
                    self._json(200,{"billing":data}); return
                if self.path == "/v1/admin/payments":
                    self._json(201,{"payment":self.admin_service.store.create_payment(payload,admin.id,ip)}); return
                if self.path.startswith("/v1/admin/payments/"):
                    pid=self.path.split("/")[4]; self._json(200,{"payment":self.admin_service.store.set_payment_status(pid,str(payload.get("status")),admin.id,ip)}); return
                if self.path == "/v1/admin/embed/apps":
                    self._json(201,{"app":self.admin_service.store.create_embed_app(payload,admin.id,ip)}); return
                if self.path.startswith("/v1/admin/embed/apps/"):
                    suffix=self.path[len("/v1/admin/embed/apps/"):].strip("/")
                    if suffix.endswith("/rotate"):
                        app_id=suffix[:-len("/rotate")].strip("/")
                        self._json(200,{"app":self.admin_service.store.rotate_embed_app_key(app_id,admin.id,ip)}); return
                    if suffix.endswith("/toggle"):
                        app_id=suffix[:-len("/toggle")].strip("/")
                        self.admin_service.store.toggle_embed_app(app_id,bool(payload.get("active")),admin.id,ip); self._json(200,{"ok":True}); return
                    app_id=suffix
                    self._json(200,{"app":self.admin_service.store.update_embed_app(app_id,payload,admin.id,ip)}); return
                if self.path == "/v1/admin/ads":
                    self._json(201,{"ad":self.admin_service.store.create_ad(payload,admin.id,ip)}); return
                if self.path.startswith("/v1/admin/ads/"):
                    aid=self.path.split("/")[4]; self.admin_service.store.toggle_ad(aid,bool(payload.get("active")),admin.id,ip); self._json(200,{"ok":True}); return
                if self.path.startswith("/v1/admin/settings/"):
                    key=self.path.split("/",4)[4]; self._json(200,{"setting":self.admin_service.store.update_setting(key,payload.get("value"),admin.id,ip)}); return
                self._json(404,{"error":"Admin route not found.","code":"ADMIN_ROUTE_NOT_FOUND"})
            except Exception as exc:
                self._admin_json_error(exc)
            return

        if self.path == "/v1/embed/scans":
            if not self._platform_setting("embed_enabled", True) or self._platform_setting("maintenance_mode", False) or not self._platform_setting("public_scans_enabled", True):
                self._json(503, {"error": "Embedded scanning is temporarily unavailable.", "code": "EMBED_DISABLED"})
                return
            context = {'app': None, 'app_id': None, 'origin': None, 'token': None}
            quota_reserved = False
            try:
                payload = self._body(max_bytes=16 * 1024)
                context = self._embed_context(payload, require_partner=bool(self.headers.get('X-SmartRisk-Embed-Key') or payload.get('app_key')))
                if context['app'] is None:
                    if not self.embed_limiter.allow(self._client_key("embed_scan")):
                        self._json(429, {"error": "Embed scan limit reached. Please try again later.", "code": "EMBED_RATE_LIMITED"}, {"Retry-After": os.getenv("SMARTRISK_EMBED_RATE_WINDOW", "3600")})
                        return
                else:
                    limit = context['app']['rate_limit_per_minute']
                    if not self.embed_partner_limiter.allow(f"app:{context['app_id']}:{self.client_address[0]}", limit):
                        self._json(429, {"error": "Embed application rate limit reached.", "code": "EMBED_RATE_LIMITED", "retry_after": 60}, {"Retry-After": "60"})
                        return
                    self.admin_service.store.reserve_embed_scan(context['app_id'])
                    quota_reserved = True
                token_address = validate_address(payload.get("address") or payload.get("token_address"))
                chain_id = payload.get("chain_id")
                if not chain_id:
                    chain_id = resolve_network(token_address).chain_id
                request = UnifiedRequest(
                    project="embed", chain_id=chain_id, token_address=token_address,
                    scenarios=_load_scenarios(payload["scenarios"]) if payload.get("scenarios") else [],
                    honeypot=_load_honeypot(payload["honeypot"]) if payload.get("honeypot") else None,
                    block_tag=payload.get("block_tag", "safe"), block_number=payload.get("block_number"),
                    compiler_version=payload.get("compiler_version"), window_blocks=payload.get("window_blocks", 10000),
                )
                try:
                    job = self.service.submit(request, run_id=f"embed_{secrets.token_hex(16)}")
                except Exception:
                    if quota_reserved:
                        self.admin_service.store.release_reserved_embed_scan(context['app_id'])
                    raise
                self.admin_service.store.bind_embed_job(job['job_id'], context['app_id'], context['origin'])
                self.admin_service.store.record_embed_event(job['job_id'], 'scan_submitted', context['app_id'], context['origin'], self.client_address[0], self.headers.get('User-Agent'))
                self._json(202, {
                    "job_id": job["job_id"], "status": job["status"], "poll_after_ms": 1000,
                    "report_url": f"/v1/embed/reports/{job['job_id']}", "full_report_url": f"/scan/{job['job_id']}",
                })
            except NetworkResolutionError as exc:
                if quota_reserved:
                    self.admin_service.store.release_reserved_embed_scan(context['app_id'])
                self._json(422, {"error": str(exc), "code": "NETWORK_RESOLUTION_FAILED"})
            except AuthError as exc:
                if quota_reserved:
                    self.admin_service.store.release_reserved_embed_scan(context['app_id'])
                self._json(exc.status, {"error": str(exc), "code": exc.code})
            except ValueError as exc:
                if quota_reserved:
                    self.admin_service.store.release_reserved_embed_scan(context['app_id'])
                self._json(422, {"error": str(exc), "code": "INVALID_ADDRESS"})
            except Exception as exc:
                if quota_reserved:
                    self.admin_service.store.release_reserved_embed_scan(context['app_id'])
                self._json(400, {"error": str(exc), "code": "INVALID_REQUEST"})
            return

        if self.path == "/v1/scans":
            if not self._platform_setting("public_scans_enabled", True) or self._platform_setting("maintenance_mode", False):
                self._json(503, {"error": "Public scanning is temporarily unavailable.", "code": "PUBLIC_SCANS_DISABLED"})
                return
            try:
                payload = self._body()
                token_address = payload.get("token_address")
                chain_id = payload.get("chain_id")
                if not chain_id:
                    chain_id = resolve_network(token_address).chain_id
                request = UnifiedRequest(
                    project=payload.get("project"), chain_id=chain_id, token_address=token_address,
                    scenarios=_load_scenarios(payload["scenarios"]) if payload.get("scenarios") else [],
                    honeypot=_load_honeypot(payload["honeypot"]) if payload.get("honeypot") else None,
                    block_tag=payload.get("block_tag", "safe"), block_number=payload.get("block_number"),
                    compiler_version=payload.get("compiler_version"), window_blocks=payload.get("window_blocks", 10000),
                )
                # Deliberately public: a scan never requires authentication.
                self._json(202, self.service.submit(request))
            except NetworkResolutionError as exc:
                self._json(422, {"error": str(exc), "code": "NETWORK_RESOLUTION_FAILED"})
            except AuthError as exc:
                self._json(exc.status, {"error": str(exc), "code": exc.code})
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return

        if self.path == "/v1/auth/register":
            if not self._platform_setting("registration_enabled", True) or self._platform_setting("maintenance_mode", False):
                self._json(503, {"error": "Registration is temporarily unavailable.", "code": "REGISTRATION_DISABLED"})
                return
            def register_action():
                payload = self._body()
                return self.auth_service.register(payload.get("email", ""), payload.get("password", ""))
            self._handle_auth_action("register", register_action)
            return
        if self.path == "/v1/auth/login":
            self._handle_login()
            return
        if self.path == "/v1/auth/logout":
            self.auth_service.logout(parse_cookie(self.headers.get("Cookie"), "smartrisk_session"))
            self._json(200, {"ok": True}, {"Set-Cookie": clear_session_cookie(self.secure_cookie)})
            return
        if self.path == "/v1/auth/resend-verification":
            self._handle_auth_action("resend", lambda: self.auth_service.resend_verification(self._body().get("email", "")), generic=True)
            return
        if self.path == "/v1/auth/forgot-password":
            self._handle_auth_action("forgot", lambda: self.auth_service.request_password_reset(self._body().get("email", "")), generic=True)
            return
        if self.path == "/v1/auth/reset-password":
            def reset_action():
                payload = self._body()
                self.auth_service.reset_password(payload.get("token", ""), payload.get("password", ""))
                return {"ok": True}
            self._handle_auth_action("reset", reset_action)
            return
        if self.path == "/v1/billing/invoices":
            try:
                user = self._session_required()
                payload = self._body()
                invoice = self.billing.create_invoice(user, str(payload.get("plan_id", "")).strip(), payload.get("payer_address"), self.developer_api.store)
                self._json(201, {"invoice": invoice})
            except AuthError as exc:
                self._json(exc.status, {"error": str(exc), "code": exc.code})
            except Exception as exc:
                self._json(400, {"error": str(exc), "code": "BILLING_REQUEST_FAILED"})
            return

        if self.path.startswith("/v1/billing/invoices/") and self.path.endswith("/verify"):
            invoice_id = self.path[len("/v1/billing/invoices/"):-len("/verify")].strip("/")
            try:
                user = self._session_required()
                payload = self._body()
                result = self.billing.verify_transaction(user, invoice_id, str(payload.get("tx_hash", "")))
                self._json(200, result)
            except AuthError as exc:
                self._json(exc.status, {"error": str(exc), "code": exc.code})
            except Exception as exc:
                self._json(400, {"error": str(exc), "code": "BILLING_VERIFY_FAILED"})
            return

        if self.path == "/v1/developer/api-keys":
            if not self._platform_setting("developer_api_enabled", True) or self._platform_setting("maintenance_mode", False):
                self._json(503, {"error": "Developer API is temporarily unavailable.", "code": "DEVELOPER_API_DISABLED"})
                return
            try:
                user = self._session_required()
                payload = self._body()
                self._json(201, self.developer_api.create_api_key(user, payload.get("name", "Default key")))
            except AuthError as exc:
                self._json(exc.status, {"error": str(exc), "code": exc.code})
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return

        if self.path.startswith("/v1/developer/api-keys/"):
            if not self._platform_setting("developer_api_enabled", True) or self._platform_setting("maintenance_mode", False):
                self._json(503, {"error": "Developer API is temporarily unavailable.", "code": "DEVELOPER_API_DISABLED"})
                return
            suffix = self.path[len("/v1/developer/api-keys/"):].strip("/")
            if suffix.endswith("/rotate"):
                key_id = suffix[:-len("/rotate")].strip("/")
                try:
                    user = self._session_required()
                    self._json(201, self.developer_api.rotate_api_key(user, key_id))
                except AuthError as exc:
                    self._json(exc.status, {"error": str(exc), "code": exc.code})
                except Exception as exc:
                    self._json(400, {"error": str(exc)})
                return
            key_id = suffix
            if key_id:
                try:
                    user = self._session_required()
                    self.developer_api.revoke_api_key(user, key_id)
                    self._json(200, {"ok": True, "key_id": key_id, "status": "revoked"})
                except AuthError as exc:
                    self._json(exc.status, {"error": str(exc), "code": exc.code})
                except Exception as exc:
                    self._json(400, {"error": str(exc)})
                return

        if self.path == "/v1/api/batches":
            if not self._platform_setting("developer_api_enabled", True) or self._platform_setting("maintenance_mode", False):
                self._json(503, {"error": "Developer API is temporarily unavailable.", "code": "DEVELOPER_API_DISABLED"})
                return
            try:
                key_meta, plan = self._api_key_context()
                if not self._api_rate_allowed(key_meta["id"], plan["requests_per_second"]):
                    self._json(429, {"error": "Rate limit exceeded.", "code": "RATE_LIMITED", "retry_after": 1}, {"Retry-After": "1"})
                    return
                payload = self._body(max_bytes=1024 * 1024)
                items = payload.get("items")
                user_id = key_meta["user_id"]
                batch = self.developer_api.create_batch(user_id, key_meta["id"], plan, items, self.headers.get("Idempotency-Key"))
                self._json(202, batch)
            except AuthError as exc:
                self._json(exc.status, {"error": str(exc), "code": exc.code})
            except Exception as exc:
                self._json(400, {"error": str(exc), "code": "INVALID_REQUEST"})
            return

        if self.path.startswith("/v1/scans/") and self.path.endswith("/rerun"):
            job_id = self.path[len("/v1/scans/"):-len("/rerun")]
            try:
                self._json(202, self.service.rerun(job_id))
            except KeyError:
                self._json(404, {"error": "job not found"})
            return
        self._json(404, {"error": "not found"})

    def _handle_auth_action(self, action: str, callback, generic: bool = False) -> None:
        if not self.auth_limiter.allow(self._client_key(action)):
            self._json(429, {"error": "Too many requests. Please try again later.", "code": "RATE_LIMITED"}, {"Retry-After": "900"})
            return
        try:
            result = callback()
            self._json(200 if action not in {"register"} else 201, result if isinstance(result, dict) else {"ok": True, "message": "If the account exists, an email has been sent."} if generic else {"ok": True})
        except EmailDeliveryError:
            if action in {"forgot", "resend"}:
                self._json(200, {"ok": True, "message": "If the request is eligible, an email has been sent."})
            else:
                self._json(503, {"error": "Email delivery is temporarily unavailable.", "code": "EMAIL_DELIVERY_FAILED"})
        except AuthError as exc:
            self._json(exc.status, {"error": str(exc), "code": exc.code})
        except Exception as exc:
            self._json(400, {"error": str(exc)})

    def _handle_login(self) -> None:
        if not self.auth_limiter.allow(self._client_key("login")):
            self._json(429, {"error": "Too many login attempts. Please try again later.", "code": "RATE_LIMITED"}, {"Retry-After": "900"})
            return
        try:
            payload = self._body()
            user, token, expires_at = self.auth_service.login(payload.get("email", ""), payload.get("password", ""))
            self._json(200, {"user": user.to_dict()}, {"Set-Cookie": session_cookie(token, expires_at, self.secure_cookie)})
        except AuthError as exc:
            self._json(exc.status, {"error": str(exc), "code": exc.code})
        except Exception as exc:
            self._json(400, {"error": str(exc)})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/":
            self._asset("index.html")
            return
        if path == "/favicon.ico":
            self._asset("favicon.ico", {"Cache-Control": "public, max-age=604800"})
            return
        if path == "/favicon-96x96.png":
            self._asset("favicon-96x96.png", {"Cache-Control": "public, max-age=604800"})
            return
        if path == "/apple-touch-icon.png":
            self._asset("apple-touch-icon.png", {"Cache-Control": "public, max-age=604800"})
            return
        if path == "/site.webmanifest":
            self._asset("site.webmanifest", {"Cache-Control": "public, max-age=604800"})
            return
        if path == "/robots.txt":
            self._asset("robots.txt", {"Cache-Control": "public, max-age=3600"})
            return
        if path == "/sitemap.xml":
            self._asset("sitemap.xml", {"Cache-Control": "public, max-age=3600"})
            return
        if path == "/assets/og-image.png":
            self._asset("assets/og-image.png", {"Cache-Control": "public, max-age=604800"})
            return
        if path == "/auth":
            self._asset("auth.html", {"X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet"})
            return
        if path == "/developer":
            self._asset("developer.html", {"X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet"})
            return
        if path == "/embed/scanner":
            self._render_embed_frame(query)
            return
        if path == "/admin":
            try:
                self._admin_required()
                self._asset("admin.html", {"X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet"})
            except AuthError as exc:
                if exc.code == "AUTH_REQUIRED": self._auth_page("login")
                else: self._json(exc.status,{"error":str(exc),"code":exc.code})
            return
        if path == "/assets/developer.css":
            self._asset("assets/developer.css")
            return
        if path == "/assets/developer.js":
            self._asset("assets/developer.js")
            return
        if path == "/assets/embed.css":
            self._asset("assets/embed.css")
            return
        if path == "/assets/embed.js":
            self._asset("assets/embed.js")
            return
        if path == "/assets/embed-frame.js":
            self._asset("assets/embed-frame.js")
            return
        if path == "/assets/admin.css":
            self._asset("assets/admin.css")
            return
        if path == "/assets/admin.js":
            self._asset("assets/admin.js")
            return
        if path == "/assets/logo.png":
            self._asset("assets/logo.png", {"Cache-Control": "public, max-age=86400"})
            return
        if path == "/developer-api.yaml":
            self._asset("developer-api.yaml")
            return
        if path == "/contact":
            self._asset("contact.html")
            return
        if path == "/privacy":
            self._asset("privacy.html")
            return
        if path == "/fulfillment-policy":
            self._asset("fulfillment-policy.html")
            return
        if path == "/cookies-policy":
            self._asset("cookies-policy.html")
            return
        if path == "/about":
            self._asset("about.html")
            return
        if path == "/security":
            self._asset("security.html")
            return
        if path == "/terms":
            self._asset("terms.html")
            return
        if path == "/how-it-works":
            self._asset("how-it-works.html")
            return
        if path == "/methodology":
            self._asset("methodology.html")
            return
        if path == "/supported-networks":
            self._asset("supported-networks.html")
            return
        if path == "/risk-library":
            self._asset("risk-library.html")
            return
        if path == "/faq":
            self._asset("faq.html")
            return
        if path == "/disclaimer":
            self._asset("disclaimer.html")
            return
        if path == "/assets/app.css":
            self._asset("assets/app.css")
            return
        if path == "/assets/app.js":
            self._asset("assets/app.js")
            return
        if path.startswith("/scan/") and len(path) > len("/scan/"):
            self._asset("results.html", {"X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet"})
            return
        if path == "/assets/results.css":
            self._asset("assets/results.css")
            return
        if path == "/assets/results.js":
            self._asset("assets/results.js")
            return
        if path == "/assets/auth.css":
            self._asset("assets/auth.css")
            return
        if path == "/assets/auth.js":
            self._asset("assets/auth.js")
            return
        if path == "/assets/info.css":
            self._asset("assets/info.css")
            return
        if path == "/assets/site-footer.css":
            self._asset("assets/site-footer.css")
            return
        if path == "/v1/networks":
            self._json(200, {"networks": [network.to_dict() for network in supported_networks()]})
            return
        if path == "/v1/auth/me":
            user = self._session_user()
            self._json(200, {"authenticated": bool(user), "user": user.to_dict() if user else None})
            return
        if path == "/v1/billing/plans":
            try:
                self._json(200, {"plans": self.billing.plans(self.developer_api.store), "network": "Ethereum", "currency": "USDT", "receiver_address": self.billing.receiver_address if self.billing.configured else None, "billing_enabled": self.billing.configured})
            except AuthError as exc:
                self._json(exc.status, {"error": str(exc), "code": exc.code})
            return
        if path == "/v1/billing/invoices/latest":
            try:
                user = self._session_required()
                self._json(200, {"invoice": self.billing.store.latest_invoice(user.id)})
            except AuthError as exc:
                self._json(exc.status, {"error": str(exc), "code": exc.code})
            return
        if path.startswith("/v1/billing/invoices/"):
            invoice_id = path[len("/v1/billing/invoices/"):].strip("/")
            try:
                user = self._session_required()
                self._json(200, {"invoice": self.billing.get_invoice(user, invoice_id)})
            except AuthError as exc:
                self._json(exc.status, {"error": str(exc), "code": exc.code})
            return
        if path == "/v1/billing/subscription":
            try:
                user = self._session_required()
                self._json(200, {"subscription": self.developer_api.store.subscription(user.id)})
            except AuthError as exc:
                self._json(exc.status, {"error": str(exc), "code": exc.code})
            return

        if path == "/v1/developer/plans":
            if not self._platform_setting("developer_api_enabled", True):
                self._json(503, {"error": "Developer API is temporarily unavailable.", "code": "DEVELOPER_API_DISABLED"})
                return
            self._json(200, {"plans": self.developer_api.store.plans()})
            return
        if path == "/v1/developer":
            if not self._platform_setting("developer_api_enabled", True):
                self._json(503, {"error": "Developer API is temporarily unavailable.", "code": "DEVELOPER_API_DISABLED"})
                return
            try:
                user = self._session_required()
                self._json(200, self.developer_api.dashboard(user))
            except AuthError as exc:
                self._json(exc.status, {"error": str(exc), "code": exc.code})
            return
        if path == "/v1/developer/api-keys":
            if not self._platform_setting("developer_api_enabled", True):
                self._json(503, {"error": "Developer API is temporarily unavailable.", "code": "DEVELOPER_API_DISABLED"})
                return
            try:
                user = self._session_required()
                self._json(200, {"api_keys": self.developer_api.list_api_keys(user)})
            except AuthError as exc:
                self._json(exc.status, {"error": str(exc), "code": exc.code})
            return
        if path == "/v1/developer/usage":
            if not self._platform_setting("developer_api_enabled", True):
                self._json(503, {"error": "Developer API is temporarily unavailable.", "code": "DEVELOPER_API_DISABLED"})
                return
            try:
                user = self._session_required()
                _, plan = self.developer_api.subscription_for_user(user.id)
                self._json(200, self.developer_api.store.usage(user.id, plan))
            except AuthError as exc:
                self._json(exc.status, {"error": str(exc), "code": exc.code})
            return

        if path == "/v1/auth/verify":
            token = query.get("token", [""])[0]
            try:
                self.auth_service.verify_email(token)
                self._auth_page("verified")
            except AuthError as exc:
                self._auth_page("error", exc.code)
            return
        if path == "/v1/admin/csrf":
            try:
                self._admin_required()
                raw_session = parse_cookie(self.headers.get("Cookie"), "smartrisk_session")
                self._json(200, {"csrf_token": self._admin_csrf_token(raw_session or "")})
            except AuthError as exc:
                self._json(exc.status, {"error": str(exc), "code": exc.code})
            return
        if path == "/v1/admin/overview":
            try:
                self._admin_required(); self._json(200, self.admin_service.store.overview())
            except AuthError as exc: self._json(exc.status, {"error": str(exc), "code": exc.code})
            return
        if path == "/v1/admin/users":
            try:
                self._admin_required(); self._json(200, self.admin_service.store.list_users(query.get("search",[""])[0], query.get("status",[None])[0], int(query.get("limit",[50])[0]), int(query.get("offset",[0])[0])))
            except (AuthError,ValueError) as exc: self._admin_json_error(exc)
            return
        if path.startswith("/v1/admin/users/") and path.endswith("/detail"):
            user_id=path[len("/v1/admin/users/"):-len("/detail")].strip("/")
            try: self._admin_required(); self._json(200,self.admin_service.store.user_detail(user_id))
            except AuthError as exc: self._json(exc.status,{"error":str(exc),"code":exc.code})
            return
        if path == "/v1/admin/api-keys":
            try:
                self._admin_required(); self._json(200,self.admin_service.store.list_api_keys(query.get("search",[""])[0],query.get("status",[None])[0],int(query.get("limit",[100])[0]),int(query.get("offset",[0])[0])))
            except (AuthError,ValueError) as exc: self._admin_json_error(exc)
            return
        if path == "/v1/admin/plans":
            try: self._admin_required(); self._json(200,{"plans":self.admin_service.store.plans()})
            except AuthError as exc: self._json(exc.status,{"error":str(exc),"code":exc.code})
            return
        if path == "/v1/admin/coupons":
            try: self._admin_required(); self._json(200,{"coupons":self.admin_service.store.list_coupons()})
            except AuthError as exc: self._json(exc.status,{"error":str(exc),"code":exc.code})
            return
        if path == "/v1/admin/grants":
            try: self._admin_required(); self._json(200,{"grants":self.admin_service.store.list_grants()})
            except AuthError as exc: self._json(exc.status,{"error":str(exc),"code":exc.code})
            return
        if path == "/v1/admin/billing/overview":
            try:
                self._admin_required()
                data = self.admin_service.store.billing_overview()
                data["runtime"] = {"configured": bool(self.billing.configured), "monitor_running": bool(self.billing._monitor and self.billing._monitor._thread and self.billing._monitor._thread.is_alive())}
                self._json(200, data)
            except (AuthError,ValueError) as exc: self._admin_json_error(exc)
            return
        if path == "/v1/admin/billing/invoices":
            try:
                self._admin_required(); self._json(200,self.admin_service.store.list_billing_invoices(query.get("status",[None])[0],query.get("search",[""])[0],int(query.get("limit",[100])[0]),int(query.get("offset",[0])[0])))
            except (AuthError,ValueError) as exc: self._admin_json_error(exc)
            return
        if path.startswith("/v1/admin/billing/invoices/"):
            invoice_id=path[len("/v1/admin/billing/invoices/"):].strip("/")
            try: self._admin_required(); self._json(200,self.admin_service.store.billing_invoice_detail(invoice_id))
            except (AuthError,ValueError) as exc: self._admin_json_error(exc)
            return
        if path == "/v1/admin/billing/events":
            try:
                self._admin_required(); self._json(200,self.admin_service.store.list_billing_events(query.get("status",[None])[0],query.get("search",[""])[0],int(query.get("limit",[100])[0]),int(query.get("offset",[0])[0]),False))
            except (AuthError,ValueError) as exc: self._admin_json_error(exc)
            return
        if path == "/v1/admin/billing/unmatched":
            try:
                self._admin_required(); self._json(200,self.admin_service.store.list_billing_events(query.get("status",[None])[0],query.get("search",[""])[0],int(query.get("limit",[100])[0]),int(query.get("offset",[0])[0]),True))
            except (AuthError,ValueError) as exc: self._admin_json_error(exc)
            return
        if path == "/v1/admin/payments":
            try: self._admin_required(); self._json(200,self.admin_service.store.list_payments(query.get("status",[None])[0],int(query.get("limit",[100])[0]),int(query.get("offset",[0])[0])))
            except (AuthError,ValueError) as exc: self._admin_json_error(exc)
            return
        if path == "/v1/admin/ads":
            try: self._admin_required(); self._json(200,{"ads":self.admin_service.store.list_ads()})
            except AuthError as exc: self._json(exc.status,{"error":str(exc),"code":exc.code})
            return
        if path == "/v1/admin/embed/apps":
            try: self._admin_required(); self._json(200,{"apps":self.admin_service.store.list_embed_apps()})
            except AuthError as exc: self._json(exc.status,{"error":str(exc),"code":exc.code})
            return
        if path.startswith("/v1/admin/embed/apps/") and path.endswith("/analytics"):
            app_id=path[len("/v1/admin/embed/apps/"):-len("/analytics")].strip("/")
            try: self._admin_required(); self._json(200,self.admin_service.store.embed_analytics(app_id or None,int(query.get("days",[30])[0])))
            except (AuthError,ValueError) as exc: self._admin_json_error(exc)
            return
        if path == "/v1/admin/embed/analytics":
            try: self._admin_required(); self._json(200,self.admin_service.store.embed_analytics(None,int(query.get("days",[30])[0])))
            except (AuthError,ValueError) as exc: self._admin_json_error(exc)
            return
        if path == "/v1/admin/settings":
            try: self._admin_required(); self._json(200,{"settings":self.admin_service.store.settings()})
            except AuthError as exc: self._json(exc.status,{"error":str(exc),"code":exc.code})
            return
        if path == "/v1/admin/audit":
            try: self._admin_required(); self._json(200,self.admin_service.store.audit_log(int(query.get("limit",[100])[0]),int(query.get("offset",[0])[0])))
            except (AuthError,ValueError) as exc: self._admin_json_error(exc)
            return
        if path == "/v1/ads":
            if not self._platform_setting("ads_enabled", True):
                self._json(200, {"ads": []})
                return
            placement = query.get("placement", ["banner"])[0]
            audience = query.get("audience", ["all"])[0]
            now = datetime.now(timezone.utc).isoformat()
            ads = [a for a in self.admin_service.store.list_ads()
                   if a["active"] and a["placement"] == placement
                   and a["audience"] in {"all", audience}
                   and (not a.get("starts_at") or a["starts_at"] <= now)
                   and (not a.get("ends_at") or a["ends_at"] > now)]
            self._json(200, {"ads": ads})
            return
        if path == "/v1/metrics":
            self._json(200, self.service.metrics())
            return
        if path.startswith("/v1/api/batches/"):
            suffix = path[len("/v1/api/batches/"):].strip("/")
            if suffix.endswith("/results"):
                batch_id = suffix[:-len("/results")].strip("/")
                try:
                    key_meta, plan = self._api_key_context()
                    if not self._api_rate_allowed(key_meta["id"], plan["requests_per_second"]):
                        self._json(429, {"error": "Rate limit exceeded.", "code": "RATE_LIMITED", "retry_after": 1}, {"Retry-After": "1"})
                        return
                    offset = max(0, int(query.get("offset", ["0"])[0]))
                    limit = min(int(plan["batch_limit"]), max(1, int(query.get("limit", ["100"])[0])))
                    include_full = query.get("include", ["summary"])[0].lower() == "full"
                    rows, total, batch = self.developer_api.result_rows(key_meta["user_id"], batch_id, offset, limit, include_full=include_full)
                    self._json(200, {"batch": {k: batch[k] for k in ("batch_id","status","total","queued","running","completed","failed","created_at","updated_at")}, "data": rows, "pagination": {"offset": offset, "limit": limit, "total": total, "next_offset": offset + limit if offset + limit < total else None}})
                except (AuthError, ValueError) as exc:
                    if isinstance(exc, AuthError):
                        self._json(exc.status, {"error": str(exc), "code": exc.code})
                    else:
                        self._json(400, {"error": "Invalid pagination.", "code": "INVALID_PAGINATION"})
                except KeyError:
                    self._json(404, {"error": "Batch not found.", "code": "BATCH_NOT_FOUND"})
                return
            if suffix.endswith("/export"):
                batch_id = suffix[:-len("/export")].strip("/")
                try:
                    key_meta, plan = self._api_key_context()
                    if not self._api_rate_allowed(key_meta["id"], plan["requests_per_second"]):
                        self._json(429, {"error": "Rate limit exceeded.", "code": "RATE_LIMITED", "retry_after": 1}, {"Retry-After": "1"})
                        return
                    fmt = query.get("format", ["jsonl"])[0].lower()
                    include_full = query.get("include", ["summary"])[0].lower() == "full"
                    content_type, text = self.developer_api.export(key_meta["user_id"], batch_id, fmt, include_full=include_full)
                    self._bytes(200, content_type, text.encode(), {"Content-Disposition": f'attachment; filename="{batch_id}.{fmt}"'})
                except AuthError as exc:
                    self._json(exc.status, {"error": str(exc), "code": exc.code})
                except KeyError:
                    self._json(404, {"error": "Batch not found.", "code": "BATCH_NOT_FOUND"})
                return
            batch_id = suffix
            try:
                key_meta, plan = self._api_key_context()
                if not self._api_rate_allowed(key_meta["id"], plan["requests_per_second"]):
                    self._json(429, {"error": "Rate limit exceeded.", "code": "RATE_LIMITED", "retry_after": 1}, {"Retry-After": "1"})
                    return
                self._json(200, self.developer_api.batch(key_meta["user_id"], batch_id))
            except AuthError as exc:
                self._json(exc.status, {"error": str(exc), "code": exc.code})
            except KeyError:
                self._json(404, {"error": "Batch not found.", "code": "BATCH_NOT_FOUND"})
            return
        if path.startswith("/v1/api/scans/"):
            scan_job_id = path[len("/v1/api/scans/"):].strip("/")
            try:
                key_meta, plan = self._api_key_context()
                if not self._api_rate_allowed(key_meta["id"], plan["requests_per_second"]):
                    self._json(429, {"error": "Rate limit exceeded.", "code": "RATE_LIMITED", "retry_after": 1}, {"Retry-After": "1"})
                    return
                include_full = query.get("include", ["summary"])[0].lower() == "full"
                self._json(200, self.developer_api.single_scan(key_meta["user_id"], scan_job_id, include_full=include_full))
            except AuthError as exc:
                self._json(exc.status, {"error": str(exc), "code": exc.code})
            return

        if path.startswith("/v1/embed/reports/"):
            if not self._platform_setting("embed_enabled", True):
                self._json(503, {"error": "Embedded scanning is temporarily unavailable.", "code": "EMBED_DISABLED"})
                return
            job_id = path[len("/v1/embed/reports/"):].strip("/")
            if not job_id.startswith("embed_"):
                self._json(404, {"error": "Embed scan not found.", "code": "EMBED_SCAN_NOT_FOUND"})
                return
            mapping = self.admin_service.store.embed_job_context(job_id)
            if not mapping:
                self._json(404, {"error": "Embed scan not found.", "code": "EMBED_SCAN_NOT_FOUND"})
                return
            try:
                if mapping.get('app_id'):
                    context = self._embed_context({}, require_partner=True)
                    if context['app_id'] != mapping['app_id']:
                        raise AuthError('Embed application mismatch.', 'EMBED_APP_MISMATCH', 403)
                job = self.service.get(job_id)
                if job.get("status") not in {"complete", "partial", "unknown"}:
                    self._json(409, {"error": "Scan is not complete yet.", "code": "SCAN_NOT_COMPLETE", "status": job.get("status"), "job_id": job_id})
                    return
                self.admin_service.store.record_embed_event(job_id, 'scan_completed', mapping.get('app_id'), mapping.get('origin'), self.client_address[0], self.headers.get('User-Agent'))
                self._json(200, format_public_result(job))
            except KeyError:
                self._json(404, {"error": "Embed scan not found.", "code": "EMBED_SCAN_NOT_FOUND"})
            except AuthError as exc:
                self._json(exc.status, {"error": str(exc), "code": exc.code})
            return

        if path.startswith("/v1/embed/scans/"):
            if not self._platform_setting("embed_enabled", True):
                self._json(503, {"error": "Embedded scanning is temporarily unavailable.", "code": "EMBED_DISABLED"})
                return
            job_id = path[len("/v1/embed/scans/"):].strip("/")
            if not job_id.startswith("embed_"):
                self._json(404, {"error": "Embed scan not found.", "code": "EMBED_SCAN_NOT_FOUND"})
                return
            mapping = self.admin_service.store.embed_job_context(job_id)
            if not mapping:
                self._json(404, {"error": "Embed scan not found.", "code": "EMBED_SCAN_NOT_FOUND"})
                return
            try:
                if mapping.get('app_id'):
                    context = self._embed_context({}, require_partner=True)
                    if context['app_id'] != mapping['app_id']:
                        raise AuthError('Embed application mismatch.', 'EMBED_APP_MISMATCH', 403)
                job = self.service.get(job_id)
                payload = {"job_id": job["job_id"], "status": job["status"], "poll_after_ms": 1000}
                if job.get("status") in {"complete", "partial", "unknown"}:
                    self.admin_service.store.record_embed_event(job_id, 'scan_completed', mapping.get('app_id'), mapping.get('origin'), self.client_address[0], self.headers.get('User-Agent'))
                    payload.update(format_public_result(job))
                elif job.get("status") == "failed":
                    self.admin_service.store.record_embed_event(job_id, 'scan_failed', mapping.get('app_id'), mapping.get('origin'), self.client_address[0], self.headers.get('User-Agent'))
                    payload.update({"error": job.get("error") or "The scan failed."})
                self._json(200, payload)
            except KeyError:
                self._json(404, {"error": "Embed scan not found.", "code": "EMBED_SCAN_NOT_FOUND"})
            except AuthError as exc:
                self._json(exc.status, {"error": str(exc), "code": exc.code})
            return

        if path.startswith("/v1/scans/"):
            job_id = path[len("/v1/scans/"):]
            try:
                self._json(200, self.service.get(job_id))
            except KeyError:
                self._json(404, {"error": "job not found"})
            return
        self._json(404, {"error": "not found"})

    def log_message(self, format, *args):
        return


def serve(host: str = "127.0.0.1", port: int = 8787, service: ScanService | None = None, auth_service: AuthService | None = None) -> ThreadingHTTPServer:
    service = service or ScanService(max_workers=max(1, int(os.getenv("SMARTRISK_SCAN_WORKERS", "8"))))
    auth_store_path = os.getenv("SMARTRISK_AUTH_DB", service.store.path)
    ScanHandler.service = service
    ScanHandler.auth_service = auth_service or AuthService(store=AuthStore(auth_store_path))
    ScanHandler.auth_service.store.bootstrap_admin_from_env()
    ScanHandler.developer_api = DeveloperAPIService(service)
    ScanHandler.admin_service = AdminService(auth_store_path)
    ScanHandler.billing = BillingService(service.store.path)
    if ScanHandler.developer_api.billing_required and not ScanHandler.billing.configured:
        raise RuntimeError("SMARTRISK_BILLING_REQUIRED is enabled but crypto billing is not fully configured; set SMARTRISK_BILLING_ENABLED=true, SMARTRISK_PAYMENT_RECEIVER, and at least one Ethereum RPC provider (preferably two for redundancy).")
    server = ThreadingHTTPServer((host, port), ScanHandler)
    server.smartrisk_developer_api = ScanHandler.developer_api
    server.smartrisk_admin_service = ScanHandler.admin_service
    server.smartrisk_billing = ScanHandler.billing
    ScanHandler.billing.start_monitor()
    return server
