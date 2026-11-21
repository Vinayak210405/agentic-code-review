"""Pipeline latency benchmark: sequential baseline vs. optimised execution.

The review workload is dominated by LLM round-trips (one per agent per file
plus a PR summary). To measure the effect of the *orchestration* changes
reproducibly and without spending tokens, the default provider is
``simulated`` — every LLM call sleeps a fixed latency. Pass
``--provider openai`` (with OPENAI_API_KEY) to benchmark against the real API.

Scenarios on the same synthetic PR:
  1. baseline           sequential agents, one file at a time, no cache
  2. parallel_agents    LangGraph fan-out of the 4 agents, one file at a time
  3. optimized          fan-out + per-file concurrency (FILE_WORKERS)
  4. optimized_rereview a follow-up push changing 2 files, served from the
                        content-hash cache for the unchanged ones

Usage:  python -m scripts.benchmark_latency [--files 8] [--latency 1.0] [--runs 3]
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

TEMPLATE = '''\
import logging

logger = logging.getLogger(__name__)


def calculate_{n}_total(prices: list, tax_rate: float) -> float:
    if tax_rate < 0:
        raise ValueError("tax_rate must be >= 0")
    subtotal = sum(prices)
    return round(subtotal * (1 + tax_rate), 2)


def lookup_{n}_orders(db, customer_id: int) -> list:
    rows = db.execute("SELECT id FROM orders WHERE customer_id = ?", (customer_id,)).fetchall()
    return [r[0] for r in rows]


class Service{n}:
    def __init__(self, client):
        self.client = client

    def sync(self, batch_size: int) -> int:
        if batch_size <= 0:
            raise ValueError("batch_size must be positive")
        return self.client.push(batch_size)
'''


def make_pr(n_files: int, revision: int = 0, changed: int = 0) -> List[Dict[str, Any]]:
    files = []
    for i in range(n_files):
        body = TEMPLATE.format(n=i)
        if i < changed:
            body += f"\n\ndef added_in_revision_{revision}_{i}(x: int) -> int:\n    return x * {revision + 2}\n"
        patch = "@@ -0,0 +1,{} @@\n".format(len(body.splitlines())) + "\n".join("+" + ln for ln in body.splitlines()) + "\n"
        files.append({"filename": f"services/module_{i}.py", "status": "modified", "patch": patch, "content": body})
    return files


def _configure(env: Dict[str, str]) -> None:
    for k, v in env.items():
        os.environ[k] = v


def run_once(files: List[Dict[str, Any]], mode: str, thread: str) -> float:
    from src.graph.runner import run_review
    from src.graph.state import initial_state

    state = initial_state(repo_name="bench/repo", pr_id=1, files=files, commit_sha=thread)
    start = time.perf_counter()
    review = run_review(state, thread_id=thread, mode=mode)
    elapsed = time.perf_counter() - start
    assert review["status"] == "COMPLETED", review["status"]
    return elapsed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--files", type=int, default=8)
    parser.add_argument("--latency", type=float, default=1.0, help="Simulated seconds per LLM call")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--llm-concurrency", type=int, default=8)
    parser.add_argument("--provider", default="simulated", choices=["simulated", "openai"])
    parser.add_argument("--json", default="benchmarks/results/latency.json")
    args = parser.parse_args()

    _configure({
        "LLM_PROVIDER": args.provider, "SIMULATED_LLM_LATENCY_S": str(args.latency),
        "CHECKPOINT_BACKEND": "memory", "HITL_BLOCK_SEVERITIES": "NONE", "GITHUB_TOKEN": "",
        "SLACK_WEBHOOK_URL": "", "ENABLE_BANDIT": "true", "EMBEDDING_PROVIDER": "local",
    })
    from src.agents.base import clear_cache
    from src.agents.llm import LLM_STATS
    from src.rag.vector_store import initialize_vector_store

    initialize_vector_store()
    pr = make_pr(args.files)
    scenarios = [
        ("baseline", "sequential", {"FILE_WORKERS": "1", "ENABLE_RESULT_CACHE": "false", "LLM_MAX_CONCURRENCY": "1"}),
        ("parallel_agents", "parallel", {"FILE_WORKERS": "1", "ENABLE_RESULT_CACHE": "false",
                                         "LLM_MAX_CONCURRENCY": str(args.llm_concurrency)}),
        ("optimized", "parallel", {"FILE_WORKERS": str(args.workers), "ENABLE_RESULT_CACHE": "false",
                                   "LLM_MAX_CONCURRENCY": str(args.llm_concurrency)}),
    ]
    results: Dict[str, Any] = {}
    for name, mode, env in scenarios:
        _configure(env)
        times = []
        for r in range(args.runs):
            clear_cache()
            before = LLM_STATS["calls"]
            times.append(run_once(pr, mode, f"{name}-{r}"))
            calls = LLM_STATS["calls"] - before
        results[name] = {"mode": mode, **env, "runs_s": [round(t, 3) for t in times],
                         "median_s": round(statistics.median(times), 3), "llm_calls": calls}
        print(f"{name:<20} median {results[name]['median_s']:>7.2f}s  (llm calls/run: {calls})")

    # Re-review after a synchronize push touching 2 files: baseline re-reviews everything, optimized uses cache.
    revised = make_pr(args.files, revision=1, changed=2)
    for name, mode, env in [
        ("baseline_rereview", "sequential", scenarios[0][2]),
        ("optimized_rereview", "parallel", {**scenarios[2][2], "ENABLE_RESULT_CACHE": "true"}),
    ]:
        _configure(env)
        times = []
        for r in range(args.runs):
            clear_cache()
            run_once(pr, mode, f"{name}-warm-{r}")  # first push populates the cache
            before = LLM_STATS["calls"]
            times.append(run_once(revised, mode, f"{name}-{r}"))
            calls = LLM_STATS["calls"] - before
        results[name] = {"mode": mode, **env, "runs_s": [round(t, 3) for t in times],
                         "median_s": round(statistics.median(times), 3), "llm_calls": calls}
        print(f"{name:<20} median {results[name]['median_s']:>7.2f}s  (llm calls/run: {calls})")

    base = results["baseline"]["median_s"]
    base_re = results["baseline_rereview"]["median_s"]
    reductions = {
        "parallel_agents_vs_baseline": round(1 - results["parallel_agents"]["median_s"] / base, 3),
        "optimized_vs_baseline": round(1 - results["optimized"]["median_s"] / base, 3),
        "optimized_rereview_vs_baseline_rereview": round(1 - results["optimized_rereview"]["median_s"] / base_re, 3),
    }
    print("\nLatency reduction vs sequential baseline:")
    for k, v in reductions.items():
        print(f"  {k:<42} {v:.1%}")

    # Static analysis only (no LLM) for reference.
    _configure({"LLM_PROVIDER": "none", **scenarios[2][2]})
    clear_cache()
    static = statistics.median(run_once(pr, "parallel", f"static-{r}") for r in range(args.runs))
    print(f"\nStatic-only pipeline (no LLM): {static * 1000:.0f} ms for {args.files} files")

    report = {
        "config": {"files": args.files, "simulated_llm_latency_s": args.latency, "runs": args.runs,
                   "provider": args.provider, "file_workers": args.workers, "llm_max_concurrency": args.llm_concurrency},
        "scenarios": results, "reductions": reductions, "static_only_median_s": round(static, 3),
    }
    out = Path(args.json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
