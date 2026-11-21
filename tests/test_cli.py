from src.cli import main
from tests.conftest import CLEAN_PATCH, SQLI_PATCH


def _diff(name, patch):
    return f"diff --git a/{name} b/{name}\n--- a/{name}\n+++ b/{name}\n{patch}"


def test_cli_review_blocks_on_critical(tmp_path, capsys):
    d = tmp_path / "c.diff"
    d.write_text(_diff("pay.py", SQLI_PATCH))
    report = tmp_path / "r.md"
    assert main(["review", "--diff", str(d), "--report", str(report)]) == 1
    assert "SQLI-001" in capsys.readouterr().out and report.read_text().startswith("## ")


def test_cli_review_passes_clean_change_and_writes_tests(tmp_path):
    d = tmp_path / "c.diff"
    d.write_text(_diff("utils/m.py", CLEAN_PATCH))
    assert main(["review", "--diff", str(d), "--write-tests", str(tmp_path / "gen")]) == 0
    assert (tmp_path / "gen" / "test_m.py").exists()


def test_cli_scan_fail_on(tmp_path):
    f = tmp_path / "bad.py"
    f.write_text("import pickle\nx = pickle.loads(b)\n")
    assert main(["scan", str(f), "--fail-on", "HIGH"]) == 1
    assert main(["scan", str(f), "--fail-on", "CRITICAL"]) == 0
