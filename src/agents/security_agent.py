from typing import Dict, Any
from langchain_groq import ChatGroq
from src.rag.vector_store import query_security_standards

# Active Groq LLM with automatic rate limit backoff
llm = ChatGroq(
    model_name="openai/gpt-oss-120b",
    temperature=0,
    max_retries=5,
)


def security_auditor_node(state: Dict[str, Any]) -> Dict[str, Any]:
    files = state.get("files_changed", [])
    findings = list(state.get("security_findings", []))

    if not files:
        findings.append("No file diffs provided for security audit.")
        return {"security_findings": findings}

    for file in files:
        filename = file.get("filename", "unknown")
        patch = file.get("patch", "")

        if not patch:
            continue

        rag_context = query_security_standards(patch)

        prompt = f"""
You are an expert Security Auditor evaluating code diffs for potential vulnerabilities.

File: {filename}

Diff Patch:
{patch}

Relevant Security Standards & Guidelines:
{rag_context}

Analyze the code diff against these guidelines. Identify any vulnerabilities (e.g., hardcoded secrets, injection flaws, unsafe functions).
Categorize finding severity as CRITICAL, HIGH, MEDIUM, LOW, or CLEAN.
Provide concise, actionable recommendations.
"""
        response = llm.invoke(prompt)
        findings.append(f"### Security Audit for `{filename}`\n{response.content}")

    return {"security_findings": findings}