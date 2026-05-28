import pytest


pytestmark = pytest.mark.real_network


def test_real_network_tests_are_opt_in():
    assert False, "real network tests should be skipped unless explicitly selected"
