from tokenverify.relay_fake import build_fake_relay_result
from tokenverify.relay_models import RelayAuditProfile, RelayPackSummary, RelayVerdict
from tokenverify.relay_report import render_relay_markdown


def test_relay_report_renders_required_sections_and_sanitized_endpoint():
    result = build_fake_relay_result(
        profile=RelayAuditProfile.GENERAL,
        scenario=RelayVerdict.SUSPICIOUS,
        endpoint="https://api.relay.com/v1/chat/completions?user=heiyan_studio#frag",
        model="example-model",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
    )

    markdown = render_relay_markdown(result)

    assert "# TokenVerify Relay Audit Report" in markdown
    assert "Plain-Language Summary" in markdown
    assert "Target Summary" in markdown
    assert "Relay Verdict" in markdown
    assert "Risk Categories" in markdown
    assert "Sanitized Evidence" in markdown
    assert "Retest Guidance" in markdown
    assert "Fake-run mode was deterministic and no live network request was made." in markdown
    assert "api.relay.com" in markdown
    assert result.endpoint_hash in markdown
    assert "https://" not in markdown
    assert "/v1" not in markdown
    assert "heiyan_studio" not in markdown
    assert "#frag" not in markdown


def test_relay_report_includes_safe_pack_summary_without_private_content():
    result = build_fake_relay_result(
        profile=RelayAuditProfile.GENERAL,
        scenario=RelayVerdict.PASS,
        endpoint="https://relay.example/v1",
        model="example-model",
        pack_summary=RelayPackSummary(
            label="Local Private Pack",
            pack_hash="a1b2c3d4e5f60708",
            pack_id="private-media-pack",
            version="2026.06",
            basename="my_private_pack.yaml",
        ),
    )

    markdown = render_relay_markdown(result)

    assert "Local Private Pack" in markdown
    assert "private-media-pack" in markdown
    assert "2026.06" in markdown
    assert "a1b2c3d4e5f60708" in markdown
    assert "my_private_pack.yaml" in markdown
    assert "raw prompt" not in markdown
    assert "expected answer" not in markdown
    assert "verifier expression" not in markdown
    assert "/Users" not in markdown


def test_relay_report_inconclusive_section_is_explicit():
    result = build_fake_relay_result(
        profile=RelayAuditProfile.GENERAL,
        scenario=RelayVerdict.INCONCLUSIVE,
        endpoint="https://relay.example/v1",
        model="example-model",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
    )

    markdown = render_relay_markdown(result)

    assert "Inconclusive Explanation" in markdown
    assert "not a relay misconduct finding" in markdown
