"""Command-line interface — run the full multi-agent review locally or as a CI gate.

Examples (PowerShell or bash):
    python -m src.cli review --git origin/main...HEAD --fail-on CRITICAL,HIGH
    python -m src.cli review --diff changes.diff --report review.md --interactive
    python -m src.cli review --files examples/vulnerable_app.py --write-tests generated_tests
    python -m src.cli scan src/
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any, Dict, List

os.environ.setdefault("CHECKPOINT_BACKEND", "memory")

from src.analysis.findings import SEVERITY_ORDER  # noqa: E402
from src.analysis.git_diff import split_git_diff  # noqa: E402
from src.analysis.security_engine import analyze_source  # noqa: E402

COLORS = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[33m", "LOW": "\033[94m"}
RESET = "\033[0m"


def _color(sev: str, text: str) -> str:
    return f"{COLORS.get(sev, '')}{text}{RESET}" if sys.stdout.isatty() else text


def _files_from_args(args: argparse.Namespace) -> List[Dict[str, Any]]:
    if args.diff:
        return split_git_diff(Path(args.diff).read_text(encoding="utf-8"))
    if args.git:
        out = subprocess.run(["git", "diff", "--unified=3", args.git], capture_output=True, text=True, check=True)  # nosec B603 B607
        return split_git_diff(out.stdout)
    files = []
    for path in args.files or []:
        p = Path(path)
        content = p.read_text(encoding="utf-8")
        files.append({"filename": p.as_posix(), "status": "added", "patch": "", "content": content})
    return files


def cmd_review(args: argparse.Namespace) -> int:
    from src.graph.runner import resume_review, run_review
    from src.graph.state import initial_state

    if args.mode:
        os.environ["EXECUTION_MODE"] = args.mode
    if args.fail_on is not None:
        os.environ["HITL_BLOCK_SEVERITIES"] = args.fail_on
    files = [f for f in _files_from_args(args)
             if not any(fnmatch.fnmatch(f["filename"], pat) for pat in (args.exclude or []))]
    if not files:
        print("No changed files to review.")
        return 0
    state = initial_state(repo_name=args.repo, pr_id=args.pr, files=files, commit_sha="local", author="cli")
    review = run_review(state)

    if review["awaiting_human"]:
        pending = review["pending_interrupt"] or {}
        print(f"\n⏸  Security gate: {len(pending.get('blocking_findings', []))} blocking finding(s)")
        for f in pending.get("blocking_findings", []):
            print("   " + _color(f["severity"], f"[{f['severity']}] {f['rule_id']}") +
                  f" {f['file_path']}:{f['line_number']} — {f['title']}")
        if args.interactive and sys.stdin.isatty():
            answer = input("\nApprove and accept the risk? [y/N] ").strip().lower()
            feedback = input("Feedback: ").strip()
            review = resume_review(review["thread_id"], answer in {"y", "yes"}, feedback, os.getenv("USER", "cli"))
        else:
            review = resume_review(review["thread_id"], False, "Blocked by CI gate", "ci")

    values = review["values"]
    risk = values.get("risk", {})
    print(f"\nDecision: {values.get('decision')}  |  Risk: {risk.get('level')}  |  "
          f"Security: {len(values.get('security_findings', []))}  Lint: {len(values.get('lint_findings', []))}  "
          f"Tests: {risk.get('tests_generated', 0)}  Docstrings: {values.get('documentation', {}).get('docstrings_generated', 0)}")
    for f in values.get("security_findings", [])[: args.limit]:
        print("  " + _color(f["severity"], f"{f['severity']:<8}") + f" {f['owasp_id']} {f['rule_id']:<14} "
              f"{f['file_path']}:{f['line_number']}  {f['title']}")

    if args.report:
        Path(args.report).write_text(values.get("report_markdown", ""), encoding="utf-8")
        print(f"\nReport written to {args.report}")
    if args.json:
        Path(args.json).write_text(json.dumps(values, indent=2, default=str), encoding="utf-8")
    if args.write_tests:
        out = Path(args.write_tests)
        out.mkdir(parents=True, exist_ok=True)
        for t in values.get("generated_tests", []):
            target = out / Path(t["test_file_path"]).name
            target.write_text(t["test_code"], encoding="utf-8")
            print(f"Generated tests: {target}")
    return 1 if values.get("decision") == "REJECTED_BY_HUMAN" else 0


def cmd_scan(args: argparse.Namespace) -> int:
    worst = 0
    paths: List[Path] = []
    for p in map(Path, args.paths):
        paths += sorted(p.rglob("*.py")) if p.is_dir() else [p]
    total = 0
    for p in paths:
        for f in analyze_source(p.as_posix(), p.read_text(encoding="utf-8")):
            total += 1
            worst = max(worst, SEVERITY_ORDER[f["severity"]])
            print(_color(f["severity"], f"{f['severity']:<8}") + f" {f['owasp_id']} {f['rule_id']:<14} "
                  f"{f['file_path']}:{f['line_number']}  {f['title']}")
    print(f"\n{total} finding(s) in {len(paths)} file(s)")
    threshold = SEVERITY_ORDER.get(args.fail_on.upper(), 99) if args.fail_on else 99
    return 1 if worst >= threshold else 0


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentic-review")
    sub = parser.add_subparsers(dest="command", required=True)

    r = sub.add_parser("review", help="Run the full multi-agent review")
    src = r.add_mutually_exclusive_group(required=True)
    src.add_argument("--diff", help="Path to a unified/git diff file")
    src.add_argument("--git", help="git diff range, e.g. origin/main...HEAD")
    src.add_argument("--files", nargs="+", help="Review whole files as newly added")
    r.add_argument("--repo", default="local/repo")
    r.add_argument("--pr", type=int, default=0)
    r.add_argument("--mode", choices=["parallel", "sequential"])
    r.add_argument("--fail-on", help="Severities that block (default CRITICAL,HIGH)")
    r.add_argument("--interactive", action="store_true", help="Prompt for human approval at the gate")
    r.add_argument("--report", help="Write markdown report to this path")
    r.add_argument("--json", help="Write full JSON state to this path")
    r.add_argument("--write-tests", help="Directory to write generated test files to")
    r.add_argument("--limit", type=int, default=25)
    r.add_argument("--exclude", nargs="*", help="Glob patterns of files to skip, e.g. 'examples/*'")
    r.set_defaults(func=cmd_review)

    s = sub.add_parser("scan", help="SAST-only scan of files/directories")
    s.add_argument("paths", nargs="+")
    s.add_argument("--fail-on", help="Exit 1 if a finding at/above this severity exists")
    s.set_defaults(func=cmd_scan)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
