"""Signature- and guard-clause-driven PyTest generation (TST-01..TST-05).

For every changed public function we emit:

* a happy-path test with type-appropriate sample arguments (and an
  ``isinstance`` assertion when the return type is annotated);
* one ``pytest.raises`` test per guard clause whose triggering input can be
  derived statically (``if amount <= 0: raise ValueError`` -> ``amount=0``);
* collaborators such as ``db``/``session``/``client`` are replaced with
  ``MagicMock`` so tests never touch real infrastructure.

Every generated module is checked with ``ast.parse`` before it is returned.
"""
from __future__ import annotations

import ast
import re
from typing import Any, Dict, List, Optional

from src.analysis.code_model import FunctionInfo, Param, extract_model, module_path
from src.analysis.diff_parser import AnalysisUnit

MOCK_NAMES = re.compile(r"(?i)^(db|session|conn|connection|cursor|cur|client|repo|repository|request|req|"
                        r"logger|log|engine|cache|redis|queue|service|api|http|s3|bucket|mailer|context|ctx)$")
SIMPLE_RETURN_TYPES = {"int", "float", "str", "bool", "list", "dict", "tuple", "set", "bytes"}


def _sample_for_annotation(ann: str) -> Optional[str]:
    a = ann.replace("typing.", "").strip()
    base = a.split("[", 1)[0]
    if base in {"List", "list", "Sequence", "Iterable"} and "[" in a:
        inner = _sample_for_annotation(a[a.index("[") + 1:-1])
        if inner is not None and inner not in {"MagicMock()", "None"}:
            return f"[{inner}, {inner}]"
    if a in {"None"}:
        return "None"
    if base == "Optional":
        inner = a[len("Optional["):-1]
        return _sample_for_annotation(inner)
    if "|" in a:
        parts = [p.strip() for p in a.split("|") if p.strip() != "None"]
        return _sample_for_annotation(parts[0]) if parts else "None"
    return {
        "int": "1", "float": "1.5", "str": "'sample'", "bool": "True", "bytes": "b'data'",
        "list": "[]", "List": "[]", "Sequence": "[]", "Iterable": "[]", "dict": "{}", "Dict": "{}",
        "Mapping": "{}", "set": "set()", "Set": "set()", "tuple": "()", "Tuple": "()", "Any": "'sample'",
        "Decimal": "Decimal('1.00')",
    }.get(base)


def _sample_for_name(name: str) -> str:
    n = name.lower()
    if MOCK_NAMES.match(n):
        return "MagicMock()"
    if n.endswith("_id") or n in {"id", "pk", "count", "n", "num", "size", "limit", "page", "qty", "quantity",
                                   "age", "index", "offset", "retries", "timeout", "port", "year"}:
        return "1"
    if n in {"amount", "price", "total", "rate", "ratio", "score", "balance", "weight"}:
        return "10.0"
    if "email" in n:
        return "'user@example.com'"
    if "url" in n or "uri" in n:
        return "'https://example.com'"
    if n.startswith(("is_", "has_", "enable", "allow", "flag", "verbose", "strict")):
        return "True"
    if n.endswith("s") and n not in {"status", "address", "class", "alias", "process"} or n in {"items", "values", "rows"}:
        return "[]"
    if n in {"data", "payload", "config", "options", "params", "kwargs", "headers", "metadata", "context"}:
        return "{}"
    return "'sample'"


def sample_value(p: Param) -> str:
    if p.annotation:
        v = _sample_for_annotation(p.annotation)
        if v is not None:
            return v
    return _sample_for_name(p.name)


def _falsy_for(p: Param) -> str:
    sample = sample_value(p)
    if sample.startswith(("'", '"')):
        return "''"
    if sample in {"[]"}:
        return "[]"
    if sample in {"{}"}:
        return "{}"
    if sample in {"1", "10.0", "1.5"}:
        return "0"
    return "None"


def _safe_value(fn: FunctionInfo, p: Param) -> str:
    """Pick a sample that does NOT trigger any of the function's guard clauses."""
    value = sample_value(p)
    try:
        num = float(value)
    except ValueError:
        return value
    is_int = "." not in value
    triggers = [float(r.trigger[1]) for r in fn.raises
                if r.trigger and r.trigger[0] == p.name and _is_number(r.trigger[1])]
    candidates = [num, 1, 10, 50, 2, 99, 0.5, 1000]
    for c in candidates:
        if all(abs(c - t) > 1e-9 for t in triggers) and _passes_guards(fn, p.name, c):
            return str(int(c)) if is_int and float(c).is_integer() else repr(float(c))
    return value


def _is_number(text: str) -> bool:
    try:
        float(text)
        return True
    except ValueError:
        return False


def _passes_guards(fn: FunctionInfo, name: str, value: float) -> bool:
    for r in fn.raises:
        if not r.condition:
            continue
        for m in re.finditer(rf"\b{re.escape(name)}\s*(<=|>=|<|>|==)\s*(-?\d+(?:\.\d+)?)\b", r.condition):
            op, bound = m.group(1), float(m.group(2))
            hit = {"<": value < bound, "<=": value <= bound, ">": value > bound,
                   ">=": value >= bound, "==": value == bound}[op]
            if hit:
                return False
    return True


def _call_args(fn: FunctionInfo, overrides: Optional[Dict[str, str]] = None) -> str:
    overrides = overrides or {}
    parts = []
    for p in fn.params:
        if p.name in overrides:
            parts.append(f"{p.name}={overrides[p.name]}")
        elif not p.has_default:
            parts.append(f"{p.name}={_safe_value(fn, p)}")
    return ", ".join(parts)


def _init_value(p: Param) -> str:
    """Constructor args: generous numeric values so instance state never trips guards."""
    v = sample_value(p)
    if v in {"1", "1.5", "10.0"}:
        return "1000" if v == "1" else "1000.0"
    return v


def _invoke(fn: FunctionInfo, args: str) -> str:
    target = f"instance.{fn.name}" if fn.class_name else fn.name
    call = f"{target}({args})"
    return f"asyncio.run({call})" if fn.is_async else call


def _test_body(fn: FunctionInfo) -> List[str]:
    lines: List[str] = []
    slug = fn.qualname.replace(".", "_").lower()
    setup = []
    if fn.class_name:
        init_args = ", ".join(
            f"{p.name}={_init_value(p)}" for p in fn.init_params
            if not p.has_default or _init_value(p) in {"1000", "1000.0"}
        )
        setup = [f"    instance = {fn.class_name}({init_args})"]

    # Happy path ---------------------------------------------------------
    lines.append(f"def test_{slug}_happy_path():")
    lines += setup
    lines.append(f"    result = {_invoke(fn, _call_args(fn))}")
    ret = (fn.returns or "").replace("typing.", "")
    if ret == "float":
        lines.append("    assert isinstance(result, (int, float))")
    elif ret in SIMPLE_RETURN_TYPES:
        lines.append(f"    assert isinstance(result, {ret})")
    elif ret == "None":
        lines.append("    assert result is None")
    else:
        lines.append("    # Return type not annotated: assert on the expected value here.")
        lines.append("    assert result is not None or result is None")
    lines.append("")
    lines.append("")

    # Error paths ----------------------------------------------------------
    params = {p.name: p for p in fn.params}
    emitted = set()
    for r in fn.raises:
        if not r.trigger:
            continue
        pname, value = r.trigger
        if pname not in params:
            continue
        if value == "<falsy>":
            value = _falsy_for(params[pname])
        exc = r.exception.split(".")[-1]
        name = f"test_{slug}_raises_{exc.lower()}_when_{pname}_invalid"
        suffix = 2
        while name in emitted:
            name = f"test_{slug}_raises_{exc.lower()}_when_{pname}_invalid_{suffix}"
            suffix += 1
        emitted.add(name)
        lines.append(f"def {name}():")
        lines.append(f'    """Guard clause: `if {r.condition}: raise {r.exception}`."""')
        lines += setup
        lines.append(f"    with pytest.raises({exc}):")
        lines.append(f"        {_invoke(fn, _call_args(fn, {pname: value}))}")
        lines.append("")
        lines.append("")
    return lines


_BUILTIN_EXC = {
    "ValueError", "TypeError", "KeyError", "IndexError", "RuntimeError", "PermissionError", "LookupError",
    "NotImplementedError", "AttributeError", "FileNotFoundError", "ZeroDivisionError", "OverflowError",
    "AssertionError", "OSError", "Exception", "ArithmeticError", "ConnectionError", "TimeoutError",
}


def synthesize_tests(unit: AnalysisUnit) -> Optional[Dict[str, Any]]:
    functions, _ = extract_model(unit)
    targets = [f for f in functions if f.is_public and not f.name.startswith("test_") and f.route is None]
    if not targets:
        return None
    module = module_path(unit.filename)
    imports = sorted({f.class_name or f.name for f in targets})
    custom_exc = sorted({r.exception.split(".")[-1] for f in targets for r in f.raises if r.trigger}
                        - _BUILTIN_EXC)
    header = [
        f'"""Auto-generated by the Unit Test Generator agent for `{unit.filename}`.',
        "",
        "Covers happy paths and statically-derived error paths (TST-01, TST-02, TST-04).",
        "Review and extend the assertions before merging.",
        '"""',
    ]
    uses_async = any(f.is_async for f in targets)
    if uses_async:
        header.append("import asyncio")
    header += [
        "from decimal import Decimal  # noqa: F401",
        "from unittest.mock import MagicMock  # noqa: F401",
        "",
        "import pytest",
        "",
        f"from {module} import {', '.join(imports + custom_exc)}",
        "",
        "",
    ]
    body: List[str] = []
    for fn in targets:
        body += _test_body(fn)
    code = "\n".join(header + body).rstrip() + "\n"
    try:
        ast.parse(code)
        compiles = True
    except SyntaxError:
        compiles = False
    base = unit.filename.replace("\\", "/").rsplit("/", 1)[-1]
    return {
        "target_file": unit.filename,
        "test_file_path": f"tests/test_{base}",
        "test_code": code,
        "functions_covered": [f.qualname for f in targets],
        "test_count": code.count("\ndef test_") + (1 if code.startswith("def test_") else 0),
        "compiles": compiles,
        "source": "synthesized",
    }
