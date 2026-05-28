from tokenverify.models import Rating


def test_rating_values_are_stable_for_report_output():
    assert Rating.HIGH_TRUST.value == "高可信"
    assert Rating.MEDIUM_TRUST.value == "中可信"
    assert Rating.LOW_TRUST.value == "低可信"
    assert Rating.INCONCLUSIVE.value == "无法判定"
