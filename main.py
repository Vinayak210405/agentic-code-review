import os
import uvicorn
from fastapi import FastAPI
from src.api.webhooks import router as api_router

# Configure LangSmith Observability Tracing
if os.getenv("LANGCHAIN_API_KEY"):
    os.environ["LANGCHAIN_TRACING_V2"] = "true"
    os.environ["LANGCHAIN_PROJECT"] = os.getenv("LANGCHAIN_PROJECT", "agentic-code-review")
    print("[Observability] LangSmith Tracing Active.")

app = FastAPI(
    title="Autonomous Agentic Code Review & Security Pipeline",
    description="Enterprise Multi-Agent Orchestration with LangGraph, SAST, LlamaIndex, and FastAPI.",
    version="1.0.0"
)

app.include_router(api_router)


@app.get("/health")
def health_check():
    return {
        "status": "HEALTHY",
        "service": "agentic-code-review-pipeline",
        "observability": "ENABLED" if os.getenv("LANGCHAIN_API_KEY") else "DISABLED",
        "engine": "LangGraph + FastAPI"
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
