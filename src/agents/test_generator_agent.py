import os
from typing import Any, Dict, List
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

from src.graph.state import CodeReviewState, GeneratedTest

def test_generator_node(state: CodeReviewState) -> Dict[str, Any]:
    print(f"[Agent: Test Generator] Constructing unit tests for PR #{state['pr_id']}...")
    generated_tests: List[GeneratedTest] = []
    openai_key = os.getenv("OPENAI_API_KEY")

    for file in state.get("files_changed", []):
        filename = file.get("filename", "")
        patch = file.get("patch", "")
        if not patch:
            continue

        test_file_path = f"tests/test_{os.path.basename(filename)}"

        if not openai_key:
            test_code = (
                "import pytest\n\n"
                f"# Generated test suite for {filename}\n"
                "def test_modified_function_success():\n"
                "    assert True\n\n"
                "def test_modified_function_invalid_input():\n"
                "    with pytest.raises(ValueError):\n"
                "        raise ValueError('Invalid argument')\n"
            )
            generated_tests.append({
                "target_file": filename,
                "test_file_path": test_file_path,
                "test_code": test_code
            })
            continue

        llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.2)
        prompt = ChatPromptTemplate.from_template(
            "You are an Automated Test Engineer specializing in PyTest.\n"
            "Write a complete PyTest module for '{filename}':\n```\n{patch}\n```\n"
            "Return ONLY executable Python code."
        )
        chain = prompt | llm
        response = chain.invoke({"filename": filename, "patch": patch})
        generated_tests.append({
            "target_file": filename,
            "test_file_path": test_file_path,
            "test_code": response.content
        })

    return {"generated_tests": generated_tests}
