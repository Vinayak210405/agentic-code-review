"""Evaluate OWASP Top 10 detection on the labelled corpus.

Usage:  python -m scripts.evaluate_owasp [--json benchmarks/results/owasp_eval.json]

Metrics per category:
  recall    = vulnerable cases whose expected category was detected / vulnerable cases
  precision = TP / (TP + FP), where FP = a safe case that produced any MEDIUM+ finding
Compares the full engine against a Bandit-only baseline on the same corpus.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks.owasp_cases import CASES as DEV_CASES  # noqa: E402
from benchmarks.owasp_holdout import CASES as HOLDOUT_CASES  # noqa: E402
from src.analysis.bandit_runner import run_bandit  # noqa: E402
from src.analysis.diff_parser import build_analysis_unit  # noqa: E402
from src.analysis.findings import OWASP_TOP_10, SEVERITY_ORDER  # noqa: E402
from src.analysis.security_engine import analyze_unit  # noqa: E402


def _predict(case: Dict[str, Any], engine: str) -> List[Dict[str, Any]]:
    unit = build_analysis_unit(case["filename"], content=case["code"].lstrip("\n"))
    if engine == "bandit":
        return run_bandit(unit) if unit.language == "python" else []
    return analyze_unit(unit, enable_bandit=True)


def evaluate(engine: str = "full", cases: List[Dict[str, Any]] = DEV_CASES) -> Dict[str, Any]:
    per_cat: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
    misses, false_alarms = [], []
    for case in cases:
        findings = _predict(case, engine)
        cats = {f["owasp_id"] for f in findings}
        serious = [f for f in findings if SEVERITY_ORDER[f["severity"]] >= SEVERITY_ORDER["MEDIUM"]]
        c = per_cat[case["owasp"]]
        if case["vulnerable"]:
            if case["owasp"] in cats:
                c["tp"] += 1
            else:
                c["fn"] += 1
                misses.append(case["id"])
        else:
            if serious:
                c["fp"] += 1
                false_alarms.append({"case": case["id"], "rules": sorted({f["rule_id"] for f in serious})})
            else:
                c["tn"] += 1

    def ratio(a: int, b: int) -> float:
        return round(a / b, 3) if b else 1.0

    rows = {}
    for cat in sorted(OWASP_TOP_10):
        c = per_cat[cat]
        rows[cat] = {**c, "category": OWASP_TOP_10[cat],
                     "recall": ratio(c["tp"], c["tp"] + c["fn"]), "precision": ratio(c["tp"], c["tp"] + c["fp"])}
    tp = sum(c["tp"] for c in per_cat.values())
    fn = sum(c["fn"] for c in per_cat.values())
    fp = sum(c["fp"] for c in per_cat.values())
    tn = sum(c["tn"] for c in per_cat.values())
    return {
        "engine": engine,
        "cases": len(cases),
        "vulnerable_cases": tp + fn,
        "safe_cases": fp + tn,
        "recall": ratio(tp, tp + fn),
        "precision": ratio(tp, tp + fp),
        "false_positive_rate": ratio(fp, fp + tn) if (fp + tn) else 0.0,
        "categories_covered": sum(1 for r in rows.values() if r["tp"] > 0),
        "per_category": rows,
        "missed": misses,
        "false_alarms": false_alarms,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", default="benchmarks/results/owasp_eval.json")
    args = parser.parse_args()
    os.environ.setdefault("LLM_PROVIDER", "none")

    full, bandit = evaluate("full"), evaluate("bandit")
    print("== Development corpus (rules developed against these cases) ==")
    print(f"{'Category':<52} {'Recall':>7} {'Prec.':>7} {'Bandit-only recall':>19}")
    for cat, row in full["per_category"].items():
        print(f"{row['category']:<52} {row['recall']:>7.0%} {row['precision']:>7.0%} "
              f"{bandit['per_category'][cat]['recall']:>19.0%}")
    print("-" * 88)
    print(f"{'Overall (' + str(full['vulnerable_cases']) + ' vulnerable / ' + str(full['safe_cases']) + ' safe cases)':<52} "
          f"{full['recall']:>7.0%} {full['precision']:>7.0%} {bandit['recall']:>19.0%}")
    print(f"OWASP categories detected: {full['categories_covered']}/10   "
          f"false-positive rate on safe code: {full['false_positive_rate']:.0%}")
    if full["missed"]:
        print("Missed:", ", ".join(full["missed"]))
    if full["false_alarms"]:
        print("False alarms:", full["false_alarms"])

    held, held_bandit = evaluate("full", HOLDOUT_CASES), evaluate("bandit", HOLDOUT_CASES)
    print("\n== Held-out corpus (written after the rules; NOT tuned on) ==")
    print(f"Recall {held['recall']:.0%}  precision {held['precision']:.0%}  "
          f"FP rate {held['false_positive_rate']:.0%}  ({held['vulnerable_cases']} vulnerable / "
          f"{held['safe_cases']} safe)   Bandit-only recall {held_bandit['recall']:.0%}")
    if held["missed"]:
        print("Missed:", ", ".join(held["missed"]))
    if held["false_alarms"]:
        print("False alarms:", held["false_alarms"])

    out = Path(args.json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"development": {"full": full, "bandit_only": bandit},
                               "holdout": {"full": held, "bandit_only": held_bandit}}, indent=2), encoding="utf-8")
    print(f"\nWrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
