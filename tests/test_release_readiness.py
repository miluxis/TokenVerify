from pathlib import Path
import re
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def test_project_metadata_is_ready_for_local_package_builds():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]
    package_init = (ROOT / "src" / "tokenverify" / "__init__.py").read_text(encoding="utf-8")

    assert project["name"] == "tokenverify"
    assert re.fullmatch(r"\d+\.\d+\.\d+", project["version"])
    assert f'__version__ = "{project["version"]}"' in package_init
    assert "audit" in project["description"].lower()
    assert project["license"]["text"] == "AGPL-3.0-only"
    assert project["scripts"]["tokenverify"] == "tokenverify.cli:app"
    assert {"httpx>=0.28", "PyYAML>=6.0", "typer>=0.12"}.issubset(set(project["dependencies"]))


def test_repository_license_documents_agpl_and_cla_terms():
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    cla_text = (ROOT / "CLA.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    for required in [
        "GNU AFFERO GENERAL PUBLIC LICENSE",
        "Version 3, 19 November 2007",
        "13. Remote Network Interaction",
        "END OF TERMS AND CONDITIONS",
    ]:
        assert required in license_text

    for required in [
        "Contributor License Agreement",
        "You retain copyright",
        "perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable license",
        "sublicensable",
        "TokenVerify and its derivatives can be distributed under AGPL-3.0-only",
        "separate commercial license terms or proprietary arrangements",
        "To the best of your knowledge",
        "original creation",
        "does not infringe any third-party intellectual property rights",
        "AGPL-3.0-only",
        "commercial license",
    ]:
        assert required in cla_text

    assert "## License" in readme
    assert "AGPL-3.0-only" in readme
    assert "## Contributor License Agreement" in readme
    assert "Contributors retain copyright" in readme
    assert "white-box trust for individual developers, researchers, and community users" in readme
    assert "alternative commercial licensing paths may be explored in the future" in readme
    assert "Commercial licensing may be offered in the future" not in readme
    assert "BUSL" not in readme


def test_release_readiness_doc_covers_versioning_and_packaging_checks():
    release_doc = (ROOT / "docs" / "release-readiness.md").read_text(encoding="utf-8")

    assert "## Versioning Policy" in release_doc
    assert "## Packaging Check" in release_doc
    assert "python3 -m pip wheel . --no-deps" in release_doc
    assert "tokenverify audit --help" in release_doc
    assert "Do not include API keys, raw event logs, or local scratch files" in release_doc
    assert "## GitHub Release Checklist" in release_doc
    assert "v0.2.0-preview" in release_doc
    assert "GitHub About" in release_doc


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
        "Dynamic Challenge Suite",
        "Dynamic Challenge Results",
    ]:
        assert required in user_guide
    assert "--detail-audit yes" in user_guide
    assert "--challenge-pack" in user_guide
    assert "--challenge-level standard" in user_guide
    assert "--language zh" in user_guide
    assert "--repeat" not in user_guide
    assert "--output" not in user_guide


def test_docs_describe_security_profile_for_ordinary_users():
    docs = "\n".join(
        (ROOT / path).read_text(encoding="utf-8")
        for path in (
            "README.md",
            "README.zh-CN.md",
            "docs/user-guide.md",
            "docs/relay-audit-user-guide.zh-CN.md",
        )
    )

    assert "--profile security" in docs
    assert "prompt boundaries" in docs.lower() or "提示词边界" in docs
    assert "jailbreak-proof" not in docs.lower()
    assert "越狱免疫" not in docs


def test_docs_describe_context_profile_for_ordinary_users():
    docs = "\n".join(
        (ROOT / path).read_text(encoding="utf-8")
        for path in (
            "README.md",
            "README.zh-CN.md",
            "docs/user-guide.md",
            "docs/relay-audit-user-guide.zh-CN.md",
        )
    )

    assert "--profile context" in docs
    assert "early, middle, and late public context anchors" in docs or "早段、中段和末段公开上下文锚点" in docs
    assert "proof of malicious truncation" not in docs.lower()
    assert "恶意截断证明" not in docs


def test_docs_describe_fraud_scenario_summary_and_boundaries():
    docs = "\n".join(
        (ROOT / path).read_text(encoding="utf-8")
        for path in (
            "README.md",
            "README.zh-CN.md",
            "docs/user-guide.md",
            "docs/relay-audit-user-guide.zh-CN.md",
        )
    )

    assert "Fraud Scenario Summary" in docs
    assert "欺诈场景总结" in docs
    assert "detected" in docs
    assert "suspicious" in docs
    assert "not_detected" in docs
    assert "not_evaluated" in docs
    assert "exact upstream model" in docs
    assert "精确上游模型" in docs
    assert "billing reconciliation" in docs
    assert "账单对账" in docs


def test_readme_documents_auto_report_names_and_detail_audit():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "reports/audit-provider-[model-name]-[date].md" in readme
    assert "--detail-audit yes" in readme
    assert "--challenge-pack" in readme
    assert "--challenge-level standard" in readme
    assert "Dynamic Challenge Results" in readme
    assert "--language zh" in readme
    assert "8 samples" in readme
    assert "--repeat" not in readme


def test_readme_community_entrypoint_documents_supported_paths_and_boundaries():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    for required in [
        "## Quick Start",
        "## Supported Audit Paths",
        "Claude native",
        "OpenAI-compatible Claude relay",
        "OpenAI-compatible OpenAI",
        "DeepSeek R1",
        "## Example Reports",
        "examples/reports/claude-native-high-trust.md",
        "examples/reports/deepseek-r1-reasoning-missing.md",
        "examples/dynamic-challenge-pack.yaml",
        "## Safety and Privacy",
        "black-box audit",
        "does not prove the true upstream provider with certainty",
        "No live network requests are made by the default test suite",
        "## License",
    ]:
        assert required in readme

    assert "Claude relay authenticity audit tool" not in readme
    assert "other non-Claude provider auditing" not in readme


def test_readme_has_chinese_companion_without_mixing_long_chinese_into_english_readme():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    zh_readme = (ROOT / "README.zh-CN.md").read_text(encoding="utf-8")

    assert "[简体中文](README.zh-CN.md)" in readme
    assert "[English](README.md)" in zh_readme
    assert len(re.findall(r"[\u4e00-\u9fff]", readme)) < 20

    for required in [
        "# TokenVerify",
        "## 快速开始",
        "## 支持的检测路径",
        "Claude 原生",
        "OpenAI 兼容 Claude 中转",
        "OpenAI 兼容 OpenAI",
        "DeepSeek R1",
        "Dynamic Challenge Results",
        "## 报告解读",
        "## 安全与隐私",
        "## 贡献者许可协议",
        "## 许可证",
        "AGPL-3.0-only",
        "CLA.md",
        "--language zh",
        "--challenge-pack",
        "--challenge-level standard",
        "reports/audit-provider-[model-name]-[date].md",
    ]:
        assert required in zh_readme

    assert "BUSL" not in zh_readme
    assert "COMMERCIAL_LICENSE" not in zh_readme


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
        "examples/dynamic-challenge-pack.yaml",
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


def test_release_and_community_materials_are_ready_to_publish():
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    launch_post = (ROOT / "docs" / "launch-post.md").read_text(encoding="utf-8")
    pr_template = (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
    issue_templates = {
        "bug": ROOT / ".github" / "ISSUE_TEMPLATE" / "bug-report.yml",
        "provider": ROOT / ".github" / "ISSUE_TEMPLATE" / "provider-request.yml",
        "endpoint": ROOT / ".github" / "ISSUE_TEMPLATE" / "suspicious-endpoint-report.yml",
        "config": ROOT / ".github" / "ISSUE_TEMPLATE" / "config-help.yml",
    }

    for required in [
        "# Changelog",
        "## v0.2.0-preview",
        "Dynamic Challenge Suite",
        "--challenge-pack",
        "Claude native",
        "OpenAI-compatible Claude relay",
        "OpenAI-compatible OpenAI",
        "DeepSeek R1",
        "AGPL-3.0-only",
        "Known limitations",
    ]:
        assert required in changelog

    for required in [
        "# TokenVerify Launch Post",
        "English launch post",
        "Chinese short version",
        "examples/reports/claude-native-high-trust.md",
        "examples/reports/deepseek-r1-reasoning-missing.md",
        "does not prove the true upstream provider with certainty",
    ]:
        assert required in launch_post

    for required in [
        "I have read and agree to the CLA",
        "PYTHONPATH=src python3 -m pytest -v",
        "git diff --check",
        "No live network requests",
        "No API keys, raw event logs, or customer secrets",
    ]:
        assert required in pr_template

    for path in issue_templates.values():
        text = path.read_text(encoding="utf-8")
        assert "name:" in text
        assert "description:" in text
        assert "Do not include API keys" in text

    provider_text = issue_templates["provider"].read_text(encoding="utf-8")
    assert "Provider request" in provider_text
    assert "No implementation without spec and implementation plan" in provider_text

    endpoint_text = issue_templates["endpoint"].read_text(encoding="utf-8")
    assert "Suspicious endpoint report" in endpoint_text
    assert "redacted" in endpoint_text

    assert "sk-" not in changelog + launch_post + pr_template
    assert "TOKEN_" not in changelog + launch_post + pr_template
