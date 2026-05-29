from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def test_real_network_tests_are_default_skipped_and_opt_in_documented():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    pytest_options = pyproject["tool"]["pytest"]["ini_options"]
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "not real_network" in pytest_options["addopts"]
    assert any(marker.startswith("real_network:") for marker in pytest_options["markers"])
    assert "Real-network tests are opt-in" in readme
    assert "PYTHONPATH=src python3 -m pytest -v -m real_network" in readme


def test_provider_and_probe_regression_policy_is_documented():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "Every new provider or probe module must add regression tests" in readme
    assert "Provider HTTP behavior must use httpx.MockTransport" in readme
    assert "Probe behavior should use direct probe inputs or mock observations" in readme


def test_current_provider_and_probe_modules_have_regression_tests():
    expected_tests = {
        "src/tokenverify/providers/anthropic.py": "tests/providers/test_anthropic.py",
        "src/tokenverify/providers/openai_compatible.py": "tests/providers/test_openai_compatible.py",
        "src/tokenverify/providers/openai.py": "tests/providers/test_adapter_interface.py",
        "src/tokenverify/probes/messages.py": "tests/probes/test_messages.py",
        "src/tokenverify/probes/openai_compatible.py": "tests/probes/test_openai_compatible.py",
        "src/tokenverify/probes/openai.py": "tests/probes/test_openai.py",
        "src/tokenverify/probes/deepseek.py": "tests/probes/test_deepseek.py",
        "src/tokenverify/probes/thinking.py": "tests/probes/test_thinking.py",
        "src/tokenverify/probes/streaming.py": "tests/probes/test_streaming.py",
        "src/tokenverify/probes/categories.py": "tests/probes/test_categories.py",
    }

    for source_path, test_path in expected_tests.items():
        assert (ROOT / source_path).exists(), source_path
        assert (ROOT / test_path).exists(), test_path
