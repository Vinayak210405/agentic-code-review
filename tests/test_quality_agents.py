import subprocess
import sys
from pathlib import Path

from src.agents.documentation_agent import documentation_node
from src.agents.linter_agent import linter_node
from src.agents.test_generator_agent import test_generator_node
from src.analysis.diff_parser import build_analysis_unit
from src.analysis.doc_synth import document_unit
from src.analysis.lint_rules import analyze_quality
from src.analysis.test_synth import synthesize_tests
from tests.conftest import make_patch

SAMPLE_MODULE = '''
from typing import List


class InsufficientFunds(Exception):
    pass


def apply_discount(price: float, percent: int) -> float:
    if price < 0:
        raise ValueError("negative price")
    if percent > 100:
        raise ValueError("percent too large")
    return round(price * (100 - percent) / 100, 2)


def normalize_username(name: str) -> str:
    if not name:
        raise ValueError("empty")
    if len(name) > 32:
        raise ValueError("too long")
    return name.strip().lower()


def bulk_total(prices: List[float]) -> float:
    return sum(prices)


class Wallet:
    def __init__(self, owner: str, balance: float = 0.0):
        self.owner = owner
        self.balance = balance

    def withdraw(self, amount: float) -> float:
        if amount <= 0:
            raise ValueError("amount must be positive")
        if amount > self.balance:
            raise InsufficientFunds("insufficient")
        self.balance -= amount
        return self.balance
'''


def test_lint_rules_detect_institutional_standard_violations():
    patch = make_patch('''
def addItem(x, items=[]):
    for o in items:
        db.execute("SELECT 1 WHERE id = ?", (o,))
    try:
        if x == None:
            print(x)
    except:
        pass
''')
    rules = {f["rule_id"] for f in analyze_quality(build_analysis_unit("svc/items.py", patch))}
    assert {"LINT-B006", "LINT-PERF001", "LINT-E722", "LINT-E711", "LINT-N802", "LINT-T201"} <= rules


def test_linter_node_returns_metrics():
    out = linter_node({"files_changed": [{"filename": "a.py", "patch": make_patch("def f(x=[]):\n    return x\n")}]})
    assert out["lint_findings"] and out["metrics"]["linter"]["files"] == 1


def test_generated_tests_compile_and_pass_against_real_code(tmp_path: Path):
    pkg = tmp_path / "pricing"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "calc.py").write_text(SAMPLE_MODULE, encoding="utf-8")
    result = synthesize_tests(build_analysis_unit("pricing/calc.py", content=SAMPLE_MODULE))
    assert result["compiles"]
    assert set(result["functions_covered"]) >= {"apply_discount", "normalize_username", "Wallet.withdraw"}
    # error-path tests derived from guard clauses
    assert "pytest.raises(ValueError)" in result["test_code"]
    assert "percent=101" in result["test_code"] and "amount=0" in result["test_code"]
    (tmp_path / "test_generated.py").write_text(result["test_code"], encoding="utf-8")
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "test_generated.py"],
                          cwd=tmp_path, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"{result['test_count']} passed" in proc.stdout


def test_test_generator_skips_test_files_and_non_python():
    out = test_generator_node({"files_changed": [
        {"filename": "tests/test_x.py", "patch": make_patch("def test_a():\n    assert True\n")},
        {"filename": "web/app.js", "patch": make_patch("function a() {}\n")},
    ]})
    assert out["generated_tests"] == []


def test_docstrings_include_raises_from_guard_clauses():
    doc = document_unit(build_analysis_unit("pricing/calc.py", content=SAMPLE_MODULE))
    by_symbol = {d["symbol"]: d["docstring"] for d in doc["docstrings"]}
    ds = by_symbol["apply_discount"]
    assert "Args:" in ds and "price (float)" in ds and "Returns:" in ds
    assert "ValueError: If `price < 0`." in ds
    assert "Wallet" in by_symbol


def test_documentation_node_builds_endpoint_reference_and_summary():
    code = '''
from fastapi import FastAPI
app = FastAPI()

@app.post("/orders")
def create_order(sku: str, qty: int):
    return {"sku": sku}
'''
    out = documentation_node({"files_changed": [{"filename": "api/orders.py", "patch": make_patch(code), "status": "added"}]})
    docs = out["documentation"]
    assert docs["endpoints"][0]["method"] == "POST" and docs["endpoints"][0]["auth"] == "**not enforced**"
    assert "Endpoint reference" in docs["summary_markdown"]
    assert docs["docstrings_generated"] >= 1
