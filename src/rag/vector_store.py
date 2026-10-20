import os
from pathlib import Path
from typing import List, Optional

from llama_index.core import Document, Settings, SimpleDirectoryReader, VectorStoreIndex
from llama_index.core.retrievers import VectorIndexRetriever
from llama_index.embeddings.huggingface import HuggingFaceEmbedding

# Set local BGE model for embeddings (runs 100% locally on CPU without OpenAI credits)
Settings.embed_model = HuggingFaceEmbedding(model_name="BAAI/bge-small-en-v1.5")

DOCS_DIR = Path(__file__).resolve().parent.parent.parent / "docs_rag"
_INDEX_INSTANCE: Optional[VectorStoreIndex] = None


def initialize_vector_store() -> VectorStoreIndex:
    global _INDEX_INSTANCE
    if _INDEX_INSTANCE is not None:
        return _INDEX_INSTANCE

    if not DOCS_DIR.exists():
        DOCS_DIR.mkdir(parents=True, exist_ok=True)

    # Load security/linting guideline files from docs_rag/
    try:
        reader = SimpleDirectoryReader(str(DOCS_DIR))
        documents = reader.load_data()
    except Exception:
        documents = []

    # Fallback default document if docs_rag directory is empty
    if not documents:
        documents = [
            Document(
                text=(
                    "Default Security Standards:\n"
                    "1. Never hardcode secrets, API keys, or tokens in source code.\n"
                    "2. Avoid unsafe execution functions like eval(), exec(), or os.system().\n"
                    "3. Parameterize all SQL queries to prevent SQL injection.\n"
                    "4. Always validate and sanitize user-supplied input."
                )
            )
        ]

    _INDEX_INSTANCE = VectorStoreIndex.from_documents(documents)
    return _INDEX_INSTANCE


def query_security_standards(query_str: str, top_k: int = 2) -> str:
    """Retrieves relevant security guidelines matching the PR diff query."""
    index = initialize_vector_store()
    retriever = VectorIndexRetriever(index=index, similarity_top_k=top_k)
    nodes = retriever.retrieve(query_str)
    
    if not nodes:
        return "No specific security standards retrieved."
        
    return "\n\n".join([node.node.get_content() for node in nodes])