import os
from pathlib import Path
from typing import List, Optional

from llama_index.core import Document, SimpleDirectoryReader, VectorStoreIndex
from llama_index.core.retrievers import VectorIndexRetriever

DOCS_DIR = Path(__file__).resolve().parent.parent.parent / "docs_rag"
_INDEX_INSTANCE: Optional[VectorStoreIndex] = None

def initialize_vector_store() -> VectorStoreIndex:
    """Reads docs_rag/ markdown documents and initializes the LlamaIndex VectorStore."""
    global _INDEX_INSTANCE
    if _INDEX_INSTANCE is not None:
        return _INDEX_INSTANCE

    documents: List[Document] = []
    if DOCS_DIR.exists():
        reader = SimpleDirectoryReader(input_dir=str(DOCS_DIR), required_exts=[".md"])
        documents = reader.load_data()
    else:
        documents = [
            Document(text="A01:2021-Broken Access Control: Ensure authorization checks on API routes."),
            Document(text="A03:2021-Injection: Never use raw string interpolation in SQL queries. Always parameterize queries."),
        ]

    _INDEX_INSTANCE = VectorStoreIndex.from_documents(documents)
    return _INDEX_INSTANCE

def query_security_standards(query_str: str, top_k: int = 3) -> str:
    """Retrieves relevant security guidelines and coding standards matching a code diff or query string."""
    openai_key = os.getenv("OPENAI_API_KEY")
    if not openai_key:
        fallback_rules = []
        lowered = query_str.lower()
        if any(kw in lowered for kw in ["select", "sql", "execute", "db"]):
            fallback_rules.append("[OWASP A03:2021 - Injection] Do not use string interpolation (f-strings) in SQL queries. Always use parameterized queries or ORM models.")
        if any(kw in lowered for kw in ["auth", "login", "user"]):
            fallback_rules.append("[OWASP A01:2021 - Broken Access Control] Ensure proper access control checks and auth decorators on API routes.")
        if not fallback_rules:
            fallback_rules.append("[Coding Standard] Follow PEP8 conventions and perform null/boundary checks.")
        return "\n".join(fallback_rules)

    index = initialize_vector_store()
    retriever = VectorIndexRetriever(index=index, similarity_top_k=top_k)
    nodes = retriever.retrieve(query_str)
    return "\n---\n".join([node.node.get_content() for node in nodes])