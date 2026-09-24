from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from .models import RawObservation


class DexscreenerError(RuntimeError):
    pass


class DexscreenerClient:
    BASE_URL = "https://api.dexscreener.com"

    def __init__(self, base_url: str | None = None, timeout_seconds: float = 15.0, retries: int = 2, cache_ttl: int = 30):
        self.base_url = (base_url or os.getenv("DEXSCREENER_API_URL") or self.BASE_URL).rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.retries = retries
        self.cache_ttl = cache_ttl
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}

    def get_token_pairs(self, chain_id: str, token_address: str) -> RawObservation:
        path = f"/token-pairs/v1/{urllib.parse.quote(chain_id)}/{urllib.parse.quote(token_address)}"
        return self._get(path, f"{chain_id}:{token_address}")

    def get_pairs(self, chain_id: str, pair_id: str) -> RawObservation:
        path = f"/latest/dex/pairs/{urllib.parse.quote(chain_id)}/{urllib.parse.quote(pair_id)}"
        return self._get(path, f"{chain_id}:{pair_id}")

    def search(self, query: str) -> RawObservation:
        path = "/latest/dex/search?" + urllib.parse.urlencode({"q": query})
        return self._get(path, query)

    def capability_probe(self) -> dict[str, Any]:
        return {"provider": "dexscreener", "status": "ready", "base_url": self.base_url, "cache_ttl": self.cache_ttl}

    def _get(self, path: str, subject: str) -> RawObservation:
        cached = self._cache.get(path)
        now = time.time()
        if cached and now - cached[0] < self.cache_ttl:
            payload = cached[1]
            return self._observation(path, subject, payload, stale=False)
        url = self.base_url + path
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "smartrisk-heuristics/0.1"})
                with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                if isinstance(payload, list):
                    # Some Dexscreener edge/cache responses return the pair
                    # collection directly rather than {"pairs": [...] }.
                    payload = {"pairs": payload}
                if not isinstance(payload, dict):
                    raise DexscreenerError("Dexscreener response is not an object")
                self._cache[path] = (now, payload)
                return self._observation(path, subject, payload, stale=False)
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, DexscreenerError) as exc:
                last_error = exc
                if attempt < self.retries:
                    time.sleep(min(0.25 * (2**attempt), 2.0))
        return self._observation(path, subject, {}, stale=True, error=str(last_error))

    @staticmethod
    def _observation(path: str, subject: str, payload: dict[str, Any], stale: bool, error: str | None = None) -> RawObservation:
        return RawObservation(
            observation_id=f"dexscreener:{path}:{subject}",
            provider="dexscreener",
            endpoint=path,
            subject=subject,
            observed_at=datetime.now(timezone.utc).isoformat(),
            payload=payload,
            stale=stale,
            error=error,
        )
