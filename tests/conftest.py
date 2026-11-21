import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Deterministic, offline, side-effect-free defaults for every test.
os.environ.update({
    "APP_ENV": "test",
    "LLM_PROVIDER": "none",
    "EMBEDDING_PROVIDER": "local",
    "CHECKPOINT_BACKEND": "memory",
    "GITHUB_TOKEN": "",
    "GITHUB_WEBHOOK_SECRET": "",
    "REVIEW_API_KEY": "",
    "SLACK_WEBHOOK_URL": "",
    "QDRANT_URL": "",
    "EXECUTION_MODE": "parallel",
    "HITL_BLOCK_SEVERITIES": "CRITICAL,HIGH",
})


@pytest.fixture(autouse=True)
def _fresh_pipeline(monkeypatch):
    from src.agents.base import clear_cache
    from src.graph.checkpoints import reset_checkpointer
    from src.graph.runner import reset_graphs

    clear_cache()
    reset_checkpointer()
    reset_graphs()
    yield
    clear_cache()
    reset_checkpointer()
    reset_graphs()


def make_patch(code: str, start: int = 1) -> str:
    lines = code.strip("\n").splitlines()
    return f"@@ -0,0 +{start},{len(lines)} @@\n" + "\n".join("+" + ln for ln in lines) + "\n"


SQLI_PATCH = (
    "@@ -15,3 +15,5 @@\n"
    " def charge(db, card_num):\n"
    "+    query = f\"SELECT * FROM cards WHERE number='{card_num}'\"\n"
    "+    db.execute(query)\n"
)

CLEAN_PATCH = make_patch('''
def add(a: int, b: int) -> int:
    """Add two numbers."""
    if a < 0:
        raise ValueError("a must be >= 0")
    return a + b
''')
