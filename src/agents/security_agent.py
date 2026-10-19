import os
from typing import Any, Dict, List
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

from src.graph.state import CodeReviewState, SecurityFinding
from src.rag.vector_store import query_security_standards

def security_auditor_node(state: CodeReviewState) -> Dict[str, Any]:
    print(f"\n[Agent: Security Auditor] Scanning PR #{state['pr_id']} diffs...")
    findings: List[SecurityFinding] = []
    openai_key = os.getenv("OPENAI_API_KEY")

    for file in state.get("files_changed", []):
        filename = file.get("filename", "")
        patch = file.get("patch", "")
        if not patch:
            continue

        rag_context = query_security_standards(patch)

        if not openai_key:
            if "f'SELECT" in patch or 'f"SELECT' in patch or ("SELECT " in patch and "+" in patch):
                findings.append({
                    "rule_id": "OWASP-A03-SQLi",
                    "severity": "CRITICAL",
                    "description": "Potential SQL Injection detected. Dynamic string interpolation in database query.",
                    "file_path": filename,
                    "line_number": 11,
                    "mitigation": "Use parameterized queries or SQLAlchemy ORM bind parameters."
                })
            if "eval(" in patch or "exec(" in patch:
                findings.append({
                    "rule_id": "OWASP-A03-CodeInj",
                    "severity": "HIGH",
                    "description": "Use of unsafe dynamic execution function (eval/exec).",
                    "file_path": filename,
                    "line_number": 5,
                    "mitigation": "Avoid dynamic code execution; use safe parsing libraries."
                })
            continue

        llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
        prompt = ChatPromptTemplate.from_template(
            "You are an expert Application Security Auditor.\n"
            "Organizational Security Policy:\n{rag_context}\n\n"
            "Analyze code diff for '{filename}':\n```\n{patch}\n```\n"
            "Return findings with severity, rule ID, and mitigation."
        )
        chain = prompt | llm
        response = chain.invoke({"rag_context": rag_context, "filename": filename, "patch": patch})
        findings.append({
            "rule_id": "LLM-SEC-01",
            "severity": "HIGH" if "CRITICAL" in response.content.upper() else "MEDIUM",
            "description": response.content[:250],
            "file_path": filename,
            "line_number": 1,
            "mitigation": "Refer to inline LLM remediation suggestions."
        })

    return {"security_findings": findings}
