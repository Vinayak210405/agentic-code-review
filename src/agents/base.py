"""Shared execution helpers for agent nodes: per-file concurrency, a
content-addressed result cache (unchanged files are not re-reviewed on
``synchronize`` pushes) and timing metrics."""
from __future__ import annotations

import copy
import hashlib
import logging
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Tuple

from config.settings import get_settings

logger = logging.getLogger(__name__)

_CACHE: "OrderedDict[Tuple[str, str], Any]" = OrderedDict()
_CACHE_LOCK = threading.Lock()
_CACHE_MAX = 5000
CACHE_STATS = {"hits": 0, "misses": 0}

SKIP_SUFFIXES = (".lock", ".min.js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".zip")
SKIP_PARTS = ("node_modules/", "vendor/", "dist/", "build/", ".venv/", "site-packages/")


def reviewable(file: Dict[str, Any]) -> bool:
    name = file.get("filename", "")
    if file.get("status") == "removed":
        return False
    if not (file.get("patch") or file.get("content")):
        return False
    if name.endswith(SKIP_SUFFIXES) or any(p in name for p in SKIP_PARTS):
        return False
    return True


def file_fingerprint(file: Dict[str, Any]) -> str:
    h = hashlib.sha256()
    for key in ("filename", "patch", "content"):
        h.update(str(file.get(key) or "").encode("utf-8", "replace"))
        h.update(b"\0")
    return h.hexdigest()


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()
        CACHE_STATS["hits"] = CACHE_STATS["misses"] = 0


def run_per_file(
    agent: str,
    files: List[Dict[str, Any]],
    fn: Callable[[Dict[str, Any]], Any],
) -> Tuple[List[Any], Dict[str, Any]]:
    """Run ``fn`` for every reviewable file, concurrently, with caching."""
    settings = get_settings()
    targets = [f for f in files if reviewable(f)]
    start = time.perf_counter()
    hits = 0

    def work(f: Dict[str, Any]) -> Any:
        nonlocal hits
        key = (agent, file_fingerprint(f))
        if settings.enable_result_cache:
            with _CACHE_LOCK:
                if key in _CACHE:
                    _CACHE.move_to_end(key)
                    CACHE_STATS["hits"] += 1
                    hits += 1
                    return copy.deepcopy(_CACHE[key])
                CACHE_STATS["misses"] += 1
        result = fn(f)
        if settings.enable_result_cache:
            with _CACHE_LOCK:
                _CACHE[key] = copy.deepcopy(result)
                while len(_CACHE) > _CACHE_MAX:
                    _CACHE.popitem(last=False)
        return result

    if settings.file_workers > 1 and len(targets) > 1:
        with ThreadPoolExecutor(max_workers=settings.file_workers, thread_name_prefix=agent) as pool:
            results = list(pool.map(work, targets))
    else:
        results = [work(f) for f in targets]

    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    metrics = {agent: {"duration_ms": elapsed_ms, "files": len(targets), "cache_hits": hits}}
    logger.info("[%s] %d file(s) in %.1f ms (cache hits: %d)", agent, len(targets), elapsed_ms, hits)
    return results, metrics
