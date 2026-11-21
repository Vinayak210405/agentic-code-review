import pytest

from benchmarks.owasp_cases import CASES
from scripts.evaluate_owasp import evaluate
from src.analysis.findings import OWASP_TOP_10, SEVERITY_ORDER
from src.analysis.security_engine import analyze_file, analyze_source
from tests.conftest import SQLI_PATCH, make_patch

VULNERABLE = [c for c in CASES if c["vulnerable"]]
SAFE = [c for c in CASES if not c["vulnerable"]]


@pytest.mark.parametrize("case", VULNERABLE, ids=[c["id"] for c in VULNERABLE])
def test_detects_vulnerable_case_in_expected_owasp_category(case):
    findings = analyze_source(case["filename"], case["code"].lstrip("\n"))
    assert case["owasp"] in {f["owasp_id"] for f in findings}, findings


@pytest.mark.parametrize("case", SAFE, ids=[c["id"] for c in SAFE])
def test_secure_counterpart_has_no_medium_or_higher_findings(case):
    findings = analyze_source(case["filename"], case["code"].lstrip("\n"))
    serious = [f for f in findings if SEVERITY_ORDER[f["severity"]] >= SEVERITY_ORDER["MEDIUM"]]
    assert serious == []


def test_corpus_covers_all_ten_owasp_categories():
    assert {c["owasp"] for c in VULNERABLE} == set(OWASP_TOP_10)
    result = evaluate("full")
    assert result["categories_covered"] == 10
    assert result["recall"] >= 0.95 and result["precision"] >= 0.95


def test_holdout_recall_regression_guard():
    from benchmarks.owasp_holdout import CASES as HOLDOUT

    result = evaluate("full", HOLDOUT)
    assert result["recall"] >= 0.70
    assert result["false_positive_rate"] <= 0.15


def test_full_engine_beats_bandit_only_baseline():
    assert evaluate("full")["recall"] > evaluate("bandit")["recall"] + 0.3


def test_real_line_numbers_not_hardcoded():
    findings = analyze_file("controllers/pay.py", SQLI_PATCH)
    sqli = [f for f in findings if f["rule_id"] == "SQLI-001"]
    assert sqli and sqli[0]["line_number"] == 16
    assert sqli[0]["severity"] == "CRITICAL"
    assert sqli[0]["owasp_category"] == "A03:2021-Injection"
    assert sqli[0]["cwe"] == "CWE-89"


def test_bandit_confirms_native_finding():
    findings = analyze_file("controllers/pay.py", SQLI_PATCH)
    assert any("bandit:" in c for f in findings for c in f["confirmed_by"])


def test_context_lines_are_not_reported():
    patch = ("@@ -1,2 +1,3 @@\n"
             " import pickle\n"
             " data = pickle.loads(blob)\n"
             "+x = 1\n")
    assert [f for f in analyze_file("old.py", patch) if f["rule_id"] == "DESER-001"] == []


def test_nosec_suppression():
    patch = make_patch("import pickle\nobj = pickle.loads(trusted_blob)  # nosec - signed upstream\n")
    assert not [f for f in analyze_file("s.py", patch) if f["owasp_id"] == "A08" and f["line_number"] == 2]


def test_taint_flows_through_assignment_to_ssrf():
    code = "import requests\nfrom flask import request\n\ndef f():\n    u = request.args['u']\n    v = u\n    return requests.get(v, timeout=1)\n"
    assert any(f["rule_id"] == "SSRF-001" for f in analyze_source("t.py", code))


def test_non_python_secret_detection():
    findings = analyze_source("config/settings.yaml", "aws_key: AKIAABCDEFGHIJKLMNOP\n")
    assert any(f["rule_id"] == "SECRET-001" and f["severity"] == "CRITICAL" for f in findings)


def test_vulnerable_dependency_detection():
    findings = analyze_source("requirements.txt", "PyYAML==5.3.1\nrequests>=2.0\n")
    rules = {(f["rule_id"], f["line_number"]) for f in findings}
    assert ("DEP-001", 1) in rules and ("DEP-002", 2) in rules


def test_template_and_docs_files_do_not_raise_false_positives():
    assert analyze_source(".env.example", "REVIEW_API_KEY=change-me\nOPENAI_API_KEY=\n") == []
    assert analyze_source("docs/guide.md", "Never run `curl https://x.sh | bash` in CI.\n") == []
    assert analyze_source("docs/leak.md", "key: AKIAABCDEFGHIJKLMNOP\n")  # real secrets still caught in docs


def test_unpinned_dependency_with_safe_floor_is_not_flagged():
    assert analyze_source("requirements.txt", "fastapi>=0.110.0\n") == []
    assert analyze_source("requirements.txt", "fastapi>=0.100.0\n")[0]["rule_id"] == "DEP-002"
