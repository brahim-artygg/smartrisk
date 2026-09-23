from smartrisk.unified.models import UnifiedRequest
from smartrisk.unified.profiles import FREE_PROFILE, PAID_PROFILE, clamp_window, get_scan_profile


def test_profiles_have_expected_limits():
    assert FREE_PROFILE.window_blocks == 2000
    assert FREE_PROFILE.max_pairs == 2
    assert FREE_PROFILE.max_holder_contract_probes == 4
    assert PAID_PROFILE.window_blocks == 10000
    assert PAID_PROFILE.max_pairs == 5

def test_free_window_is_capped():
    assert clamp_window(10000, FREE_PROFILE) == 2000
    assert clamp_window(None, FREE_PROFILE) == 2000
    assert get_scan_profile("free") is FREE_PROFILE
    assert get_scan_profile("paid") is PAID_PROFILE
    assert UnifiedRequest(scan_profile="free").scan_profile == "free"
