from stelarstrike.core.report import Finding, ReportBuilder
from stelarstrike.core.target import ScopeError, Target, enforce_scope
from stelarstrike.plugins import PLUGIN_REGISTRY
from stelarstrike.utils.http_client import build_url_with_params, get_query_params


def test_all_expected_plugins_registered():
    expected = {"sqli", "nosqli", "xss", "ssrf", "csrf", "file_upload", "idor", "jwt"}
    assert expected.issubset(PLUGIN_REGISTRY.keys())


def test_plugin_ids_are_unique_and_match_keys():
    for plugin_id, plugin_cls in PLUGIN_REGISTRY.items():
        assert plugin_cls.id == plugin_id


def test_scope_enforcement_blocks_out_of_scope_target():
    target = Target(url="https://evil.example.com/page")
    try:
        enforce_scope(target, scope=["https://target.example.com/*"], out_of_scope=[])
        assert False, "expected ScopeError"
    except ScopeError:
        pass


def test_scope_enforcement_allows_in_scope_target():
    target = Target(url="https://target.example.com/page?id=1")
    enforce_scope(target, scope=["https://target.example.com/*"], out_of_scope=[])


def test_get_query_params():
    params = get_query_params("https://target.example.com/page?id=1&name=test")
    assert params == {"id": "1", "name": "test"}


def test_build_url_with_params_roundtrip():
    url = build_url_with_params("https://target.example.com/page", {"id": "5"})
    assert url == "https://target.example.com/page?id=5"


def test_report_builder_adds_and_serializes_findings(tmp_path):
    report = ReportBuilder(engagement_name="unit-test", report_dir=str(tmp_path))
    report.add(Finding(plugin="sqli", title="Test finding", severity="high", url="https://target.example.com"))
    assert len(report.findings) == 1

    json_path = report.write_json()
    md_path = report.write_markdown()
    assert json_path.exists()
    assert md_path.exists()
