from pathlib import Path
import re
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def test_project_metadata_is_ready_for_local_package_builds():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]

    assert project["name"] == "tokenverify"
    assert re.fullmatch(r"\d+\.\d+\.\d+", project["version"])
    assert "audit" in project["description"].lower()
    assert project["scripts"]["tokenverify"] == "tokenverify.cli:app"
    assert {"httpx>=0.28", "PyYAML>=6.0", "typer>=0.12"}.issubset(set(project["dependencies"]))


def test_release_readiness_doc_covers_versioning_and_packaging_checks():
    release_doc = (ROOT / "docs" / "release-readiness.md").read_text(encoding="utf-8")

    assert "## Versioning Policy" in release_doc
    assert "## Packaging Check" in release_doc
    assert "python3 -m pip wheel . --no-deps" in release_doc
    assert "tokenverify audit --help" in release_doc
    assert "Do not include API keys, raw event logs, or local scratch files" in release_doc


def test_user_guide_covers_supported_audit_paths_and_interpretation():
    user_guide = (ROOT / "docs" / "user-guide.md").read_text(encoding="utf-8")

    for required in [
        "Claude Native",
        "OpenAI-Compatible Claude Relay",
        "OpenAI-Compatible OpenAI",
        "DeepSeek R1",
        "No-Key / Offline Behavior",
        "Plain-Language Summary",
        "Channel Risk Profile",
        "Suspected Upstream Signals",
        "Authenticity Assertions",
        "Heuristic Risk Profile",
    ]:
        assert required in user_guide
    assert "--detail-audit yes" in user_guide
    assert "--language zh" in user_guide
    assert "--repeat" not in user_guide
    assert "--output" not in user_guide


def test_readme_documents_auto_report_names_and_detail_audit():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "reports/audit-[model-name]-[date].md" in readme
    assert "--detail-audit yes" in readme
    assert "--language zh" in readme
    assert "8 samples" in readme
    assert "--repeat" not in readme


def test_user_facing_docs_and_example_reports_use_english_rating_labels():
    forbidden = ("高可信", "中可信", "低可信", "无法判定")
    paths = [
        ROOT / "README.md",
        ROOT / "docs" / "user-guide.md",
        ROOT / "examples" / "reports" / "claude-native-high-trust.md",
        ROOT / "examples" / "reports" / "deepseek-r1-reasoning-missing.md",
    ]

    for path in paths:
        text = path.read_text(encoding="utf-8")
        for rating in forbidden:
            assert rating not in text, f"{rating} found in {path}"


def test_offline_example_reports_exist_and_are_safe_to_publish():
    report_dir = ROOT / "examples" / "reports"
    expected_reports = [
        report_dir / "claude-native-high-trust.md",
        report_dir / "deepseek-r1-reasoning-missing.md",
    ]
    required_sections = [
        "# TokenVerify Audit Report",
        "## Plain-Language Summary",
        "## Channel Risk Profile",
        "## Suspected Upstream Signals",
        "## Overall Verdict",
        "## Authenticity Assertions",
        "## Heuristic Risk Profile",
        "## Configuration Summary",
    ]

    for path in expected_reports:
        text = path.read_text(encoding="utf-8")
        for section in required_sections:
            assert section in text
        assert "TOKEN_" not in text
        assert "sk-" not in text
        assert "api_key" not in text.lower()


def test_release_artifacts_are_not_gitignored():
    paths = [
        "docs/release-readiness.md",
        "docs/user-guide.md",
        "examples/reports/claude-native-high-trust.md",
        "examples/reports/deepseek-r1-reasoning-missing.md",
    ]

    result = subprocess.run(
        ["git", "check-ignore", *paths],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1, result.stdout
