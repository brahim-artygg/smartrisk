from smartrisk.state_fork.revert import decode_revert_data


def test_decode_error_string():
    text = "SELL_DISABLED"
    encoded = text.encode().hex()
    payload = "0x08c379a0" + (32).to_bytes(32, "big").hex() + len(text).to_bytes(32, "big").hex() + encoded.ljust(64, "0")
    decoded = decode_revert_data(payload)
    assert decoded["status"] == "decoded"
    assert decoded["reason"] == text


def test_decode_panic():
    payload = "0x4e487b71" + (0x11).to_bytes(32, "big").hex()
    decoded = decode_revert_data(payload)
    assert decoded["type"] == "Panic(uint256)"
    assert decoded["panic_code"] == 0x11


def test_unknown_revert_shape_is_preserved():
    decoded = decode_revert_data("0xdeadbeef0011")
    assert decoded["status"] == "unknown"
    assert decoded["selector"] == "0xdeadbeef"
