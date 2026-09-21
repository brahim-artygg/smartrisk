from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from ..state_fork.cli import _load_honeypot, _load_scenarios
from ..unified.models import UnifiedRequest
from .service import ScanService


class ScanHandler(BaseHTTPRequestHandler):
    service: ScanService

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, sort_keys=True, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path == "/v1/scans":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length) or b"{}")
                request = UnifiedRequest(
                    project=payload.get("project"), chain_id=payload.get("chain_id"), token_address=payload.get("token_address"),
                    scenarios=_load_scenarios(payload["scenarios"]) if payload.get("scenarios") else [],
                    honeypot=_load_honeypot(payload["honeypot"]) if payload.get("honeypot") else None,
                    block_tag=payload.get("block_tag", "safe"), block_number=payload.get("block_number"),
                    compiler_version=payload.get("compiler_version"), window_blocks=payload.get("window_blocks", 10000),
                )
                self._json(202, self.service.submit(request))
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return
        if self.path.startswith("/v1/scans/") and self.path.endswith("/rerun"):
            job_id = self.path[len("/v1/scans/"):-len("/rerun")]
            try:
                self._json(202, self.service.rerun(job_id))
            except KeyError:
                self._json(404, {"error": "job not found"})
            return
        self._json(404, {"error": "not found"})

    def do_GET(self):
        if self.path.startswith("/v1/scans/"):
            job_id = self.path[len("/v1/scans/"):]
            try:
                self._json(200, self.service.get(job_id))
            except KeyError:
                self._json(404, {"error": "job not found"})
            return
        self._json(404, {"error": "not found"})

    def log_message(self, format, *args):
        return


def serve(host: str = "127.0.0.1", port: int = 8787, service: ScanService | None = None) -> ThreadingHTTPServer:
    ScanHandler.service = service or ScanService()
    server = ThreadingHTTPServer((host, port), ScanHandler)
    return server
