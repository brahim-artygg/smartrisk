from smartrisk.state_fork.state_diff import normalize_prestate_diff


def test_normalize_geth_prestate_diff():
    trace = {
        "pre": {
            "0xabc": {
                "balance": "0x64",
                "nonce": "0x1",
                "storage": {"0x01": "0x10"},
            }
        },
        "post": {
            "0xabc": {
                "balance": "0x46",
                "nonce": "0x2",
                "storage": {"0x01": "0x20", "0x02": "0x01"},
            }
        },
    }
    result = normalize_prestate_diff(trace)
    account = result["accounts"]["0xabc"]
    assert account["balance"]["delta"] == -30
    assert account["nonce"]["delta"] == 1
    assert account["storage"]["0x01"]["before"] == "0x10"
    assert account["storage"]["0x02"]["after"] == "0x01"


def test_unknown_tracer_shape_is_preserved_not_zeroed():
    result = normalize_prestate_diff({"unexpected": True})
    assert result["status"] == "unknown"
    assert result["unknown_reasons"]
    assert result["raw"] == {"unexpected": True}
