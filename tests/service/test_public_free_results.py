import json

from smartrisk.service.embed import format_public_result


def test_public_result_excludes_internal_payloads():
    job = {
        "job_id": "job_1", "status": "complete",
        "request": {"chain_id": "1", "token_address": "0x" + "1" * 40},
        "result": {
            "risk": {"score": 72, "band": "high", "confidence": 0.8, "coverage": 0.9},
            "verdict": {"code": "HIGH_RISK", "label": "High risk", "primary_detection": {"title": "Owner control", "explanation": "Centralized control signal"}},
            "findings": [{"title": "Owner control", "severity": "high", "status": "likely", "description": "Owner can change controls", "evidence_refs": ["secret-ref"]}],
            "risk_dimensions": {"ownership_security": {"signals": 2, "severity": "high"}},
            "unknowns": ["x"], "evidence": [{"raw": "secret"}], "evidence_graph": {"nodes": {"x": {}}},
            "engines": [{"name": "heuristics", "report": {"secret": True}}],
        },
    }
    out = format_public_result(job)
    dumped = json.dumps(out)
    assert "secret-ref" not in dumped
    assert "evidence_graph" not in out
    assert "engines" not in out
    assert out["signals"][0]["title"] == "Owner control"
    assert out["upgrade_available"] is True


def test_public_http_scan_exposes_summary_not_internal_result(tmp_path):
    import http.client, json, threading
    from smartrisk.service.http import serve
    from smartrisk.service.service import ScanService
    from smartrisk.service.store import JobStore

    class Report:
        status = "complete"
        def to_dict(self):
            return {
                "run_id": "run", "status": "complete",
                "verdict": {"code": "HIGH_RISK", "label": "HIGH RISK", "primary_detection": {"title": "signal", "explanation": "reason"}},
                "risk": {"score": 80, "band": "high", "confidence": 0.9, "coverage": 0.8},
                "risk_dimensions": {"ownership_security": {"signals": 1, "severity": "high"}},
                "findings": [{"title": "signal", "severity": "high", "status": "observed", "description": "reason", "evidence_refs": ["secret"]}],
                "evidence": [{"secret": True}], "evidence_graph": {"nodes": {"x": {}}},
                "engines": [{"name": "heuristics", "report": {"secret": True}}],
                "unknowns": [], "versions": {"release": "0.9.0"},
            }
    class Engine:
        def analyze(self, request, run_id=None): return Report()
    scan=ScanService(JobStore(tmp_path/'db.sqlite3'), Engine(), max_workers=1)
    server=serve('127.0.0.1',0,service=scan)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    try:
        host,port=server.server_address
        conn=http.client.HTTPConnection(host,port,timeout=5)
        body=json.dumps({"token_address":"0x"+"2"*40,"chain_id":"1"})
        conn.request('POST','/v1/scans',body,{"Content-Type":"application/json"})
        created=json.loads(conn.getresponse().read())
        job_id=created['job_id']
        import time
        deadline=time.time()+2
        while time.time()<deadline:
            conn.request('GET',f'/v1/scans/{job_id}')
            response=conn.getresponse(); payload=json.loads(response.read())
            if payload['status']=='complete': break
            time.sleep(0.02)
        assert payload['status']=='complete'
        assert 'result' not in payload
        assert 'evidence' not in json.dumps(payload)
        assert payload['address']=='0x'+"2"*40
        assert payload['signals'][0]['title']=='signal'
    finally:
        server.shutdown(); server.server_close(); scan.executor.shutdown(wait=True)
