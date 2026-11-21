"""Unit Test Generator agent: deterministic signature/guard-driven PyTest
synthesis, optionally replaced by an LLM-written suite that must compile."""
from __future__ import annotations

import ast
from typing import Any, Dict, List, Optional

from src.agents.base import run_per_file
from src.agents.llm import LLMTestSuite, llm_enabled, structured_call
from src.analysis.diff_parser import build_analysis_unit
from src.analysis.test_synth import synthesize_tests
from src.rag.vector_store import retrieve_standards

SYSTEM_PROMPT = (
    "You are a test engineer. Write a complete, runnable PyTest module for the changed functions. Follow the "
    "testing standards provided. Mock external dependencies. Return only Python code."
)


def _compiles(code: str) -> bool:
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False


def generate_for_file(file: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not file["filename"].endswith(".py") or "/tests/" in f"/{file['filename']}" or \
            file["filename"].rsplit("/", 1)[-1].startswith("test_"):
        return None
    unit = build_analysis_unit(file["filename"], file.get("patch", ""), file.get("content"))
    synthesized = synthesize_tests(unit)
    if synthesized is None:
        return None
    if llm_enabled():
        standards = "\n".join(h["text"] for h in retrieve_standards("unit testing standards pytest mock", 4))
        suite = structured_call(
            LLMTestSuite, SYSTEM_PROMPT,
            f"Testing standards:\n{standards}\n\nBaseline generated tests (improve on them):\n"
            f"```python\n{synthesized['test_code']}\n```\n\nSource under test ({file['filename']}):\n"
            f"```python\n{file.get('content') or unit.source}\n```",
            temperature=0.2,
        )
        if suite is not None and suite.test_code.strip() and _compiles(suite.test_code):
            synthesized = {**synthesized, "test_code": suite.test_code, "source": "llm",
                           "test_count": suite.test_code.count("def test_")}
    return synthesized


def test_generator_node(state: Dict[str, Any]) -> Dict[str, Any]:
    results, metrics = run_per_file("test_generator", state.get("files_changed", []), generate_for_file)
    tests: List[Dict[str, Any]] = [r for r in results if r]
    return {"generated_tests": tests, "metrics": metrics}


test_generator_node.__test__ = False  # type: ignore[attr-defined]  # not a pytest test
