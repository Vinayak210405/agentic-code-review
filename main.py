"""FastAPI entry point for the Agentic Code Review & Security Pipeline."""
import logging
import os
from contextlib import asynccontextmanager

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI

load_dotenv()

from config.settings import get_settings  # noqa: E402
from src.api.webhooks import router as api_router  # noqa: E402
from src.rag.vector_store import initialize_vector_store  # noqa: E402

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")

if os.getenv("LANGCHAIN_API_KEY"):
    os.environ.setdefault("LANGCHAIN_TRACING_V2", "true")
    os.environ.setdefault("LANGCHAIN_PROJECT", "agentic-code-review")


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_vector_store()  # warm the RAG index so the first review isn't slower
    yield


app = FastAPI(
    title="Agentic Code Review & Security Pipeline",
    description="Multi-agent PR review (LangGraph) with OWASP Top 10 SAST, LlamaIndex RAG over institutional "
                "standards, unit-test & documentation generation, and a human-in-the-loop security gate.",
    version="2.0.0",
    lifespan=lifespan,
)
app.include_router(api_router)


@app.get("/health")
def health_check():
    s = get_settings()
    return {
        "status": "HEALTHY",
        "service": "agentic-code-review-pipeline",
        "engine": "LangGraph + LlamaIndex + FastAPI",
        "llm_provider": s.llm_provider,
        "embedding_provider": s.embedding_provider,
        "execution_mode": s.execution_mode,
        "observability": "ENABLED" if os.getenv("LANGCHAIN_API_KEY") else "DISABLED",
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8000")))
