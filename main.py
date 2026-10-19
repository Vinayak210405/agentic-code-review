import os
import uvicorn
from fastapi import FastAPI
from src.api.webhooks import router as webhooks_router

if os.getenv("LANGCHAIN_API_KEY"):
    os.environ["LANGCHAIN_TRACING_V2"] = "true"
    os.environ["LANGCHAIN_PROJECT"] = os.getenv("LANGCHAIN_PROJECT", "agentic-code-review")

app = FastAPI(
    title="Autonomous Agentic Code Review Pipeline",
    version="1.0.0"
)

app.include_router(webhooks_router)

@app.get("/health")
def health_check():
    return {"status": "HEALTHY", "engine": "LangGraph + FastAPI"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
