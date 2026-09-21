from types import SimpleNamespace

from smartrisk.static_engine.custom_detectors import CustomDetectorRunner


def function(*, writes, modifiers=(), internal=(), irs=(), visibility="external"):
    node = SimpleNamespace(irs=[SimpleNamespace(__str__=lambda self: "")])
    # Use a concrete object whose string representation is controlled by the test.
    class IR:
        def __str__(self):
            return " ".join(irs)

    node = SimpleNamespace(irs=[IR()])
    return SimpleNamespace(
        visibility=visibility,
        state_variables_written=[SimpleNamespace(name=name) for name in writes],
        variables_written=[],
        modifiers=[SimpleNamespace(name=name) for name in modifiers],
        internal_calls=[SimpleNamespace(name=name) for name in internal],
        nodes=[node],
    )


def test_storage_writes_drive_classification_not_function_name():
    runner = CustomDetectorRunner()
    target = function(writes=["totalSupply", "balanceOf"])
    ordinary = function(writes=["value"])
    assert runner._group_for_writes(runner._storage_writes(target)) == "mint_burn"
    assert runner._group_for_writes(runner._storage_writes(ordinary)) is None


def test_authorization_modifier_suppresses_sensitive_write():
    runner = CustomDetectorRunner()
    protected = function(writes=["feeBps"], modifiers=["onlyOwner"], irs=["feeBps := nextFeeBps"])
    evidence = runner._authorization_evidence(protected)
    assert evidence["detected"] is True


def test_bounded_fee_is_distinguished_from_unbounded_fee():
    runner = CustomDetectorRunner()
    bounded = function(
        writes=["feeBps"],
        irs=["require(nextFeeBps <= MAX_FEE_BPS)", "feeBps := nextFeeBps"],
    )
    unbounded = function(writes=["feeBps"], irs=["feeBps := nextFeeBps"])
    assert runner._has_fee_bound(bounded) is True
    assert runner._has_fee_bound(unbounded) is False
