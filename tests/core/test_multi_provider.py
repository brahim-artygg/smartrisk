from smartrisk.core.multi_provider import MultiProviderRpc, ProviderError, ProviderSpec


class FakeProvider:
    def __init__(self, name, values=None, errors=None):
        self.provider_name = name
        self.rpc_url = f"https://{name}.test"
        self.spec = ProviderSpec(name, self.rpc_url, f"wss://{name}.test")
        self.values = list(values or [])
        self.errors = list(errors or [])
        self.calls = 0

    def request(self, method, params=None):
        self.calls += 1
        if self.errors:
            value = self.errors.pop(0)
            if isinstance(value, Exception):
                raise value
            raise RuntimeError(str(value))
        return self.values.pop(0) if self.values else {"provider": self.provider_name}


def test_router_fails_over_on_transient_error_and_records_provider():
    primary = FakeProvider("primary", errors=[RuntimeError("429 rate limit")])
    secondary = FakeProvider("secondary", values=[{"ok": True}])
    router = MultiProviderRpc([primary, secondary], failure_threshold=1, cool_down_seconds=60)
    assert router.request("eth_chainId") == {"ok": True}
    assert router.last_provider == "secondary"
    health = router.health()
    assert health["failover_count"] == 1
    assert primary.calls == 1 and secondary.calls == 1


def test_router_keeps_non_transient_rpc_error_visible():
    primary = FakeProvider("primary", errors=[ProviderError("invalid params")])
    secondary = FakeProvider("secondary", values=[{"ok": True}])
    router = MultiProviderRpc([primary, secondary])
    try:
        router.request("eth_call")
    except ProviderError as exc:
        assert "invalid params" in str(exc)
    else:
        raise AssertionError("non-transient error should not silently fail over")
    assert secondary.calls == 0


def test_router_exposes_websocket_urls():
    router = MultiProviderRpc([FakeProvider("a"), FakeProvider("b")])
    assert router.websocket_urls() == [("a", "wss://a.test"), ("b", "wss://b.test")]


def test_gateway_evidence_records_actual_failover_provider():
    from smartrisk.core.alchemy_gateway import AlchemyGateway
    primary = FakeProvider("primary", errors=[RuntimeError("503 gateway unavailable")])
    secondary = FakeProvider("secondary", values=[{"ok": True}])
    router = MultiProviderRpc([primary, secondary], failure_threshold=1)
    gateway = AlchemyGateway(router)
    result, evidence = gateway.call("eth_chainId", [])
    assert result == {"ok": True}
    assert evidence.provider == "secondary"


def test_environment_router_orders_bsc_chainstack_before_quicknode(monkeypatch):
    monkeypatch.delenv("ALCHEMY_RPC_URL", raising=False)
    monkeypatch.delenv("ALCHEMY_API_KEY", raising=False)
    monkeypatch.delenv("CHAINSTACK_RPC_URL", raising=False)
    monkeypatch.delenv("QUICKNODE_RPC_URL", raising=False)
    monkeypatch.setenv("SMARTRISK_BSC_CHAINSTACK_RPC_URL", "https://chainstack.test")
    monkeypatch.setenv("SMARTRISK_BSC_QUICKNODE_RPC_URL", "https://quicknode.test")
    router = MultiProviderRpc.from_environment("bsc-mainnet")
    assert [item.provider_name for item in router.providers] == ["chainstack", "quicknode"]
    assert router.expected_chain_id == "56"


def test_environment_router_builds_network_specific_alchemy_endpoint(monkeypatch):
    monkeypatch.delenv("ALCHEMY_RPC_URL", raising=False)
    monkeypatch.delenv("ALCHEMY_WS_URL", raising=False)
    monkeypatch.setenv("ALCHEMY_API_KEY", "test-key")
    monkeypatch.delenv("CHAINSTACK_RPC_URL", raising=False)
    monkeypatch.delenv("QUICKNODE_RPC_URL", raising=False)
    router = MultiProviderRpc.from_environment("8453")
    assert router.providers[0].rpc_url == "https://base-mainnet.g.alchemy.com/v2/test-key"
    assert router.providers[0].spec.ws_url == "wss://base-mainnet.g.alchemy.com/v2/test-key"


def test_environment_router_ignores_ethereum_only_generic_rpc_for_non_ethereum(monkeypatch):
    monkeypatch.setenv("ALCHEMY_RPC_URL", "https://ethereum-only.test")
    monkeypatch.delenv("ALCHEMY_API_KEY", raising=False)
    monkeypatch.delenv("SMARTRISK_BASE_RPC_URL", raising=False)
    monkeypatch.delenv("SMARTRISK_BASE_QUICKNODE_RPC_URL", raising=False)
    monkeypatch.delenv("SMARTRISK_BASE_CHAINSTACK_RPC_URL", raising=False)
    try:
        MultiProviderRpc.from_environment("base")
    except Exception as exc:
        assert "no RPC providers configured for Base" in str(exc)
    else:
        raise AssertionError("generic Ethereum RPC must not be reused for Base")


def test_environment_router_accepts_per_network_rpc_override(monkeypatch):
    monkeypatch.delenv("ALCHEMY_RPC_URL", raising=False)
    monkeypatch.delenv("ALCHEMY_API_KEY", raising=False)
    monkeypatch.delenv("CHAINSTACK_RPC_URL", raising=False)
    monkeypatch.delenv("QUICKNODE_RPC_URL", raising=False)
    monkeypatch.setenv("SMARTRISK_CELO_RPC_URL", "https://celo-rpc.test")
    monkeypatch.setenv("SMARTRISK_CELO_WS_URL", "wss://celo-rpc.test")
    router = MultiProviderRpc.from_environment("celo")
    assert router.providers[0].provider_name == "alchemy"
    assert router.providers[0].rpc_url == "https://celo-rpc.test"
    assert router.providers[0].spec.ws_url == "wss://celo-rpc.test"


def test_capability_probe_rejects_provider_on_wrong_chain():
    wrong = FakeProvider("wrong", values=["0x38", {"number": "0x123"}])
    right = FakeProvider("right", values=["0x2105", {"number": "0x124"}])
    router = MultiProviderRpc([wrong, right], expected_chain_id=8453)
    probe = router.capability_probe()
    assert probe["status"] == "ready"
    assert probe["providers"][0]["status"] == "chain_mismatch"
    assert probe["providers"][1]["status"] == "ready"
