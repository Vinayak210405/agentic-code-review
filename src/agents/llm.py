"""LLM access shared by all agents.

* ``LLM_PROVIDER=none``      – deterministic static analysis only (default without a key)
* ``LLM_PROVIDER=openai``    – GPT via LangChain with structured (Pydantic) output
* ``LLM_PROVIDER=simulated`` – sleeps ``SIMULATED_LLM_LATENCY_S`` per call and returns
  an empty structured result; used by the latency benchmark to model network
  LLM latency reproducibly without spending tokens.

A process-wide semaphore caps concurrent LLM calls (``LLM_MAX_CONCURRENCY``)
so parallel agents never exceed provider rate limits.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import List, Optional, Type, TypeVar

from pydantic import BaseModel, Field

from config.settings import get_settings

logger = logging.getLogger(__name__)
T = TypeVar("T", bound=BaseModel)

_semaphore_lock = threading.Lock()
_semaphore: Optional[threading.BoundedSemaphore] = None
_semaphore_size = 0
_stats_lock = threading.Lock()
LLM_STATS = {"calls": 0, "failures": 0}


def _get_semaphore() -> threading.BoundedSemaphore:
    global _semaphore, _semaphore_size
    size = get_settings().llm_max_concurrency
    with _semaphore_lock:
        if _semaphore is None or _semaphore_size != size:
            _semaphore = threading.BoundedSemaphore(size)
            _semaphore_size = size
        return _semaphore


def llm_enabled() -> bool:
    return get_settings().llm_provider in {"openai", "simulated"}


# ---------------------------------------------------------------- schemas
class LLMSecurityFinding(BaseModel):
    owasp_id: str = Field(description="OWASP Top 10 2021 id, e.g. 'A03'")
    cwe: str = Field(description="CWE id, e.g. 'CWE-89'")
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM or LOW")
    line_number: int = Field(description="Line number in the NEW file where the issue is")
    title: str
    description: str
    mitigation: str


class LLMSecurityReview(BaseModel):
    findings: List[LLMSecurityFinding] = Field(default_factory=list)


class LLMLintFinding(BaseModel):
    line_number: int
    issue: str
    suggestion: str
    severity: str = Field(default="warning", description="error, warning or info")


class LLMLintReview(BaseModel):
    findings: List[LLMLintFinding] = Field(default_factory=list)


class LLMTestSuite(BaseModel):
    test_code: str = Field(default="", description="A complete, runnable PyTest module")


class LLMDocSummary(BaseModel):
    summary: str = Field(default="", description="Two-to-four sentence description of the change")


# ---------------------------------------------------------------- calls
def structured_call(schema: Type[T], system: str, user: str, temperature: float = 0.0) -> Optional[T]:
    """Call the configured LLM and parse the result into ``schema``.

    Returns ``None`` when no LLM is configured or the call fails, so callers
    always fall back to deterministic analysis.
    """
    settings = get_settings()
    provider = settings.llm_provider
    if provider not in {"openai", "simulated"}:
        return None

    with _get_semaphore():
        with _stats_lock:
            LLM_STATS["calls"] += 1
        if provider == "simulated":
            time.sleep(settings.simulated_llm_latency_s)
            return schema()
        try:
            from langchain_core.messages import HumanMessage, SystemMessage
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI(model=settings.openai_model, temperature=temperature, timeout=60, max_retries=2)
            return llm.with_structured_output(schema).invoke(
                [SystemMessage(content=system), HumanMessage(content=user)]
            )
        except Exception as exc:  # network/quota/parse errors must not break the pipeline
            with _stats_lock:
                LLM_STATS["failures"] += 1
            logger.warning("LLM call failed (%s); falling back to static analysis.", exc)
            return None


def numbered_diff(patch: str, max_chars: int = 12000) -> str:
    """Render added/context lines with their new-file line numbers for the LLM."""
    from src.analysis.diff_parser import parse_patch

    parsed = parse_patch(patch)
    out: List[str] = []
    for hunk in parsed.hunks:
        for n, text, kind in hunk.lines:
            out.append(f"{n:>5} {kind} {text}")
        out.append("  ...")
    return "\n".join(out)[:max_chars]
