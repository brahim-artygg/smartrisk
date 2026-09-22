from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any
from urllib.parse import urlparse


def normalize_origin(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return None
    candidate = value if '://' in value else f'https://{value}'
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
        return None
    if parsed.username or parsed.password or parsed.path not in {'', '/'} or parsed.query or parsed.fragment:
        return None
    host = (parsed.hostname or '').lower().rstrip('.')
    if not host:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is None:
        return f'{parsed.scheme}://{host}'
    default = 443 if parsed.scheme == 'https' else 80
    return f'{parsed.scheme}://{host}:{port}' if port != default else f'{parsed.scheme}://{host}'


def origin_from_headers(headers) -> str | None:
    origin = normalize_origin(headers.get('Origin'))
    if origin:
        return origin
    referer = headers.get('Referer') or headers.get('Referrer')
    if not referer:
        return None
    try:
        parsed = urlparse(referer)
        if not parsed.scheme or not parsed.netloc:
            return None
        return normalize_origin(f'{parsed.scheme}://{parsed.netloc}')
    except ValueError:
        return None


def validate_origins(values: Any) -> list[str]:
    if isinstance(values, str):
        values = [line.strip() for line in values.replace(',', '\n').splitlines() if line.strip()]
    if not isinstance(values, list):
        raise ValueError('allowed_origins must be an array of HTTP/HTTPS origins.')
    result: list[str] = []
    for value in values:
        origin = normalize_origin(value)
        if not origin:
            raise ValueError(f'Invalid allowed origin: {value!r}')
        if origin not in result:
            result.append(origin)
    if not result:
        raise ValueError('At least one allowed origin is required.')
    if len(result) > 50:
        raise ValueError('A maximum of 50 allowed origins is supported.')
    return result


def create_token(secret: str, app_id: str, origin: str, ttl_seconds: int = 600) -> str:
    payload = {
        'v': 1,
        'app_id': app_id,
        'origin': origin,
        'exp': int(time.time()) + max(60, int(ttl_seconds)),
        'nonce': secrets.token_urlsafe(12),
    }
    raw = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
    body = base64.urlsafe_b64encode(raw).decode().rstrip('=')
    sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f'{body}.{sig}'


def verify_token(secret: str, token: str, app_id: str, expected_origin: str | None = None) -> dict[str, Any]:
    if not isinstance(token, str) or '.' not in token:
        raise ValueError('Invalid embed token.')
    body, supplied_sig = token.rsplit('.', 1)
    expected_sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied_sig, expected_sig):
        raise ValueError('Invalid embed token.')
    try:
        padded = body + '=' * (-len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
    except Exception as exc:
        raise ValueError('Invalid embed token.') from exc
    if payload.get('v') != 1 or payload.get('app_id') != app_id:
        raise ValueError('Invalid embed token.')
    if int(payload.get('exp', 0)) < int(time.time()):
        raise ValueError('Embed token expired.')
    token_origin = normalize_origin(payload.get('origin'))
    if not token_origin:
        raise ValueError('Invalid embed token origin.')
    if expected_origin and token_origin != expected_origin:
        raise ValueError('Embed origin mismatch.')
    return payload


def csp_for_origins(origins: list[str]) -> str:
    sources = ' '.join(["'self'", *origins]) if origins else '*'
    return f'frame-ancestors {sources}'
