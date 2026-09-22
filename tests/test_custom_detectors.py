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


def test_internal_authorization_path_is_respected_for_public_wrapper():
    runner = CustomDetectorRunner()
    class Internal:
        name = "_setTrading"
        modifiers = []
        internal_calls = []
        nodes = []
        state_variables_written = [SimpleNamespace(name="tradingEnabled")]
        variables_written = []
    class Public:
        name = "setTrading"
        visibility = "external"
        state_variables_written = []
        variables_written = []
        modifiers = []
        internal_calls = [Internal()]
        nodes = []
    assert runner._storage_writes(Public()) == ["tradingEnabled"]
    # The internal setter itself is named as a control path and therefore the
    # wrapper has a reachable sensitive write; absent auth it must be classified.
    assert runner._group_for_function(Public(), ["tradingEnabled"]) == "trading"


def test_authorized_internal_modifier_suppresses_public_wrapper():
    runner = CustomDetectorRunner()
    class Internal:
        name = "_setFee"
        modifiers = [SimpleNamespace(name="onlyOwner")]
        internal_calls = []
        nodes = []
        state_variables_written = [SimpleNamespace(name="feeBps")]
        variables_written = []
    class Public:
        name = "setFee"
        visibility = "external"
        state_variables_written = []
        variables_written = []
        modifiers = []
        internal_calls = [Internal()]
        nodes = []
    evidence = runner._authorization_evidence(Public())
    assert evidence["detected"] is True
    assert "_setFee" in evidence["recursive_authorized_path"]


def test_reflection_supply_names_are_semantically_classified():
    runner = CustomDetectorRunner()
    target = function(writes=["_rOwned", "_tOwned", "_tTotal"], visibility="external")
    target.name = "mint"
    assert runner._group_for_function(target, runner._storage_writes(target)) == "mint_burn"


def test_public_set_balance_is_classified_as_supply_control():
    runner = CustomDetectorRunner()
    target = function(writes=["_rOwned"], visibility="external")
    target.name = "setBalance"
    assert runner._group_for_function(target, runner._storage_writes(target)) == "mint_burn"


def test_generic_public_setter_without_sensitive_state_is_not_classified():
    runner = CustomDetectorRunner()
    target = function(writes=["metadataVersion"], visibility="external")
    target.name = "setValue"
    assert runner._group_for_function(target, runner._storage_writes(target)) is None
