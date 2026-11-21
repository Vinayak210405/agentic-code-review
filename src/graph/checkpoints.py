"""Checkpointer factory: SQLite (durable, survives restarts so a review can be
approved hours later) or in-memory (tests/benchmarks)."""
from __future__ import annotations

import sqlite3
import threading
from typing import Optional

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import MemorySaver

from config.settings import get_settings

_lock = threading.Lock()
_instance: Optional[BaseCheckpointSaver] = None


def get_checkpointer() -> BaseCheckpointSaver:
    global _instance
    with _lock:
        if _instance is None:
            settings = get_settings()
            if settings.checkpoint_backend == "memory":
                _instance = MemorySaver()
            else:
                from langgraph.checkpoint.sqlite import SqliteSaver

                conn = sqlite3.connect(settings.checkpoint_db_path, check_same_thread=False)
                _instance = SqliteSaver(conn)
        return _instance


def reset_checkpointer() -> None:
    global _instance
    with _lock:
        _instance = None
