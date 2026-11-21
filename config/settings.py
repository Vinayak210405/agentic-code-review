"""Central runtime configuration, read from environment variables.

Settings are re-read on every call to :func:`get_settings` so tests (and
operators) can change behaviour through the environment without restarting.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class Settings:
    app_env: str = "development"

    # --- LLM ---------------------------------------------------------------
    # "none" = deterministic static analysis only, "openai" = GPT via LangChain,
    # "simulated" = sleeps for a fixed latency (used by the latency benchmark).
    llm_provider: str = "none"
    openai_model: str = "gpt-4o-mini"
    llm_max_concurrency: int = 4
    simulated_llm_latency_s: float = 1.2

    # --- Execution / performance --------------------------------------------
    execution_mode: str = "parallel"  # "parallel" | "sequential"
    file_workers: int = 4  # per-agent concurrency across changed files
    enable_result_cache: bool = True
    enable_bandit: bool = True

    # --- RAG -----------------------------------------------------------------
    embedding_provider: str = "local"  # "local" | "openai"
    rag_top_k: int = 3
    qdrant_url: str = ""

    # --- Human-in-the-loop gate ---------------------------------------------
    hitl_block_severities: List[str] = field(default_factory=lambda: ["CRITICAL", "HIGH"])

    # --- Persistence ---------------------------------------------------------
    checkpoint_backend: str = "sqlite"  # "sqlite" | "memory"
    checkpoint_db_path: str = "checkpoints.sqlite"

    # --- Integrations --------------------------------------------------------
    github_token: str = ""
    github_webhook_secret: str = ""
    review_api_key: str = ""
    slack_webhook_url: str = ""

    @property
    def is_development(self) -> bool:
        return self.app_env.lower() in {"development", "dev", "local", "test"}


def get_settings() -> Settings:
    provider = os.getenv("LLM_PROVIDER")
    if provider is None:
        provider = "openai" if os.getenv("OPENAI_API_KEY") else "none"
    severities = os.getenv("HITL_BLOCK_SEVERITIES", "CRITICAL,HIGH")
    return Settings(
        app_env=os.getenv("APP_ENV", "development"),
        llm_provider=provider.lower(),
        openai_model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        llm_max_concurrency=max(1, _int("LLM_MAX_CONCURRENCY", 4)),
        simulated_llm_latency_s=_float("SIMULATED_LLM_LATENCY_S", 1.2),
        execution_mode=os.getenv("EXECUTION_MODE", "parallel").lower(),
        file_workers=max(1, _int("FILE_WORKERS", 4)),
        enable_result_cache=_bool("ENABLE_RESULT_CACHE", True),
        enable_bandit=_bool("ENABLE_BANDIT", True),
        embedding_provider=os.getenv(
            "EMBEDDING_PROVIDER", "openai" if os.getenv("OPENAI_API_KEY") else "local"
        ).lower(),
        rag_top_k=max(1, _int("RAG_TOP_K", 3)),
        qdrant_url=os.getenv("QDRANT_URL", ""),
        hitl_block_severities=[s.strip().upper() for s in severities.split(",") if s.strip()],
        checkpoint_backend=os.getenv("CHECKPOINT_BACKEND", "sqlite").lower(),
        checkpoint_db_path=os.getenv("CHECKPOINT_DB_PATH", "checkpoints.sqlite"),
        github_token=os.getenv("GITHUB_TOKEN", ""),
        github_webhook_secret=os.getenv("GITHUB_WEBHOOK_SECRET", ""),
        review_api_key=os.getenv("REVIEW_API_KEY", ""),
        slack_webhook_url=os.getenv("SLACK_WEBHOOK_URL", ""),
    )
