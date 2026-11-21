"""Vector RAG over institutional coding & security standards (LlamaIndex).

``docs_rag/*.md`` is chunked into one node per rule (e.g. ``SEC-09``) with its
section heading as context, embedded, and stored in a LlamaIndex
``VectorStoreIndex`` (in-memory by default, Qdrant when ``QDRANT_URL`` is set).
Agents retrieve the most relevant rules for each finding / diff and cite the
rule ids in their review output.
"""
from __future__ import annotations

import logging
import re
import threading
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

from llama_index.core import StorageContext, VectorStoreIndex
from llama_index.core.schema import TextNode

from config.settings import get_settings
from src.rag.embeddings import HashingEmbedding

logger = logging.getLogger(__name__)

DOCS_DIR = Path(__file__).resolve().parent.parent.parent / "docs_rag"
_RULE_LINE = re.compile(r"^\s*-\s*\**([A-Z]{2,4}-\d{2})\**:\s*(.+)$")
_lock = threading.Lock()
_INDEX: Optional[VectorStoreIndex] = None


def load_standard_nodes(docs_dir: Path = DOCS_DIR) -> List[TextNode]:
    """Split every markdown standard into one node per rule bullet."""
    nodes: List[TextNode] = []
    for md in sorted(docs_dir.glob("*.md")):
        title, section = md.stem, ""
        for line in md.read_text(encoding="utf-8").splitlines():
            if line.startswith("# "):
                title = line[2:].strip()
                continue
            if line.startswith("## "):
                section = line[3:].strip()
                continue
            m = _RULE_LINE.match(line)
            if not m:
                continue
            rule_id, text = m.group(1), m.group(2).strip()
            nodes.append(TextNode(
                id_=rule_id,
                text=f"{section or title}\n{rule_id}: {text}",
                metadata={"rule_id": rule_id, "section": section or title, "source": md.name, "standard": title},
                excluded_embed_metadata_keys=["source", "standard", "rule_id", "section"],
                excluded_llm_metadata_keys=["source"],
            ))
    return nodes


def _embed_model(nodes: List[TextNode]):
    settings = get_settings()
    if settings.embedding_provider == "openai":
        try:
            from llama_index.embeddings.openai import OpenAIEmbedding

            return OpenAIEmbedding(model="text-embedding-3-small")
        except ImportError:
            logger.warning("llama-index-embeddings-openai not installed; using local embeddings.")
    return HashingEmbedding().fit(n.get_content() for n in nodes)


def _storage_context() -> Optional[StorageContext]:
    url = get_settings().qdrant_url
    if not url:
        return None
    try:
        import qdrant_client
        from llama_index.vector_stores.qdrant import QdrantVectorStore

        client = qdrant_client.QdrantClient(url=url)
        store = QdrantVectorStore(client=client, collection_name="code_review_standards")
        return StorageContext.from_defaults(vector_store=store)
    except Exception as exc:  # pragma: no cover - optional integration
        logger.warning("Qdrant unavailable (%s); falling back to in-memory vector store.", exc)
        return None


def initialize_vector_store(force: bool = False) -> VectorStoreIndex:
    global _INDEX
    with _lock:
        if _INDEX is not None and not force:
            return _INDEX
        nodes = load_standard_nodes()
        kwargs: Dict[str, Any] = {"embed_model": _embed_model(nodes), "show_progress": False}
        storage = _storage_context()
        if storage is not None:
            kwargs["storage_context"] = storage
        _INDEX = VectorStoreIndex(nodes, **kwargs)
        retrieve_standards.cache_clear()
        logger.info("Indexed %d institutional standard rules.", len(nodes))
        return _INDEX


@lru_cache(maxsize=2048)
def _retrieve_cached(query: str, top_k: int) -> tuple:
    index = initialize_vector_store()
    retriever = index.as_retriever(similarity_top_k=top_k)
    results = []
    for hit in retriever.retrieve(query):
        meta = hit.node.metadata
        results.append((
            meta.get("rule_id", hit.node.node_id),
            meta.get("section", ""),
            meta.get("source", ""),
            hit.node.get_content(),
            round(float(hit.score or 0.0), 4),
        ))
    return tuple(results)


def retrieve_standards(query: str, top_k: Optional[int] = None) -> List[Dict[str, Any]]:
    """Return the top-k institutional rules most similar to ``query``."""
    k = top_k or get_settings().rag_top_k
    return [
        {"rule_id": r, "section": s, "source": src, "text": t, "score": score}
        for r, s, src, t, score in _retrieve_cached(query.strip()[:2000], k)
    ]


retrieve_standards.cache_clear = _retrieve_cached.cache_clear  # type: ignore[attr-defined]
retrieve_standards.cache_info = _retrieve_cached.cache_info  # type: ignore[attr-defined]


def query_security_standards(query_str: str, top_k: int = 3) -> str:
    """Backwards-compatible helper returning retrieved rules as a context string."""
    return "\n---\n".join(h["text"] for h in retrieve_standards(query_str, top_k))
