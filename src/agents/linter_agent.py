import os
from typing import Any, Dict, List
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

from src.graph.state import CodeReviewState, LintFinding
from src.rag.vector_store import query_security_standards

def linter_node(state: CodeReviewState) -> Dict[str, Any]:
    print(f"[Agent: Linter & Quality] Checking style and performance for PR #{state['pr_id']}...")
    findings: List[LintFinding] = []
    openai_key = os.getenv("OPENAI_API_KEY")

    for file in state.get("files_changed", []):
        filename = file.get("filename", "")
        patch = file.get("patch", "")
        if not patch:
            continue

        rag_context = query_security_standards(f"Linter standards for {filename}")

        if not openai_key:
            if "for " in patch and (".execute(" in patch or ".query(" in patch):
                findings.append({
                    "file_path": filename,
                    "line_number": 14,
                    "issue": "N+1 Database Query Pattern Detected.",
                    "suggestion": "Fetch related records using bulk queries or eager loading outside the loop."
                })
            if "except:" in patch:
                findings.append({
                    "file_path": filename,
                    "line_number": 20,
                    "issue": "Bare except clause used.",
                    "suggestion": "Catch specific exceptions (e.g., catching ValueError) to prevent masking bugs."
                })
            continue

        llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
        prompt = ChatPromptTemplate.from_template(
            "You are a Senior Software Engineer conducting code quality linting.\n"
            "Coding Standards:\n{rag_context}\n\n"
            "Review this diff for '{filename}':\n```\n{patch}\n```\n"
            "List issues regarding PEP8, performance, or exceptions."
        )
        chain = prompt | llm
        response = chain.invoke({"rag_context": rag_context, "filename": filename, "patch": patch})
        findings.append({
            "file_path": filename,
            "line_number": 1,
            "issue": "Code quality review point.",
            "suggestion": response.content[:200]
        })

    return {"lint_findings": findings}
