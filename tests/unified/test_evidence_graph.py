from smartrisk.unified.engine import UnifiedRiskEngine
from smartrisk.unified.models import EngineSummary


def test_evidence_graph_builds_nodes_and_edges():
    graph = UnifiedRiskEngine._build_evidence_graph(
        [EngineSummary("static_ast", "complete", 10, .8, .9)],
        [{"finding_id": "f1", "engine": "static", "rule_id": "r1", "severity": "high", "status": "likely", "evidence_refs": ["e1"]}],
        [{"evidence_id": "e1", "provider": "slither", "endpoint": "custom"}],
        [{"rule_id": "r1", "outcome": "triggered", "contribution": 2, "evidence_refs": ["e1"]}],
        [{"correlation_id": "c1", "strength": "high", "finding_ids": ["f1"], "evidence_refs": ["e1"]}],
    )
    assert graph["node_count"] >= 4
    assert graph["edge_count"] >= 3
