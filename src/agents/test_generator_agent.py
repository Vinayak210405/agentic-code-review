from typing import Dict, Any
from langchain_groq import ChatGroq

llm = ChatGroq(
    model_name="openai/gpt-oss-120b",
    temperature=0,
    max_retries=5,
)


def test_generator_node(state: Dict[str, Any]) -> Dict[str, Any]:
    files = state.get("files_changed", [])
    generated_tests = list(state.get("generated_tests", []))

    if not files:
        generated_tests.append("No file diffs provided for test generation.")
        return {"generated_tests": generated_tests}

    for file in files:
        filename = file.get("filename", "unknown")
        patch = file.get("patch", "")

        if not patch:
            continue

        prompt = f"""
You are an automated Test Engineering Agent.
Construct modular unit tests using `pytest` to validate newly added or modified logic in this code diff.

File: {filename}

Diff Patch:
{patch}

Provide runnable Python unit tests covering edge cases and core function behavior.
Format response with executable python code blocks (` ```python ... ``` `).
"""
        response = llm.invoke(prompt)
        generated_tests.append(f"### Unit Tests for `{filename}`\n{response.content}")

    return {"generated_tests": generated_tests}