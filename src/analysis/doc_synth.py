"""Documentation generation (DOC-01..DOC-04).

* Google-style docstrings for changed public functions/classes that lack one,
  with ``Raises:`` entries derived from the actual guard clauses.
* An endpoint reference for new HTTP routes (method, path, auth requirement).
* A PR-level change summary used in the review report / changelog.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from src.analysis.code_model import ClassInfo, FunctionInfo, extract_model, words
from src.analysis.diff_parser import AnalysisUnit, diff_stats

VERB_HINTS = {
    "get": "Return", "fetch": "Fetch", "load": "Load", "list": "List", "create": "Create", "add": "Add",
    "update": "Update", "delete": "Delete", "remove": "Remove", "set": "Set", "compute": "Compute",
    "calculate": "Calculate", "validate": "Validate", "parse": "Parse", "build": "Build", "send": "Send",
    "apply": "Apply", "normalize": "Normalize", "generate": "Generate", "process": "Process",
    "handle": "Handle", "check": "Check", "save": "Save", "find": "Find", "search": "Search",
    "convert": "Convert", "render": "Render", "run": "Run", "withdraw": "Withdraw", "deposit": "Deposit",
}


def _summary(fn: FunctionInfo) -> str:
    w = words(fn.name).split()
    if not w:
        return "Perform the operation."
    if w[0] in {"is", "has", "can", "should"}:
        return f"Return whether {' '.join(w[1:]) or 'the condition holds'}."
    verb = VERB_HINTS.get(w[0], w[0].capitalize())
    rest = " ".join(w[1:])
    if fn.class_name and not rest:
        rest = f"on the {words(fn.class_name)}"
    return f"{verb} {rest}".strip() + "."


def _param_desc(name: str) -> str:
    return f"The {words(name)}."


def build_docstring(fn: FunctionInfo, indent: str = "    ") -> str:
    lines = [_summary(fn), ""]
    if fn.params:
        lines.append("Args:")
        for p in fn.params:
            typ = f" ({p.annotation})" if p.annotation else ""
            default = f" Defaults to {p.default_src}." if p.has_default and p.default_src else ""
            lines.append(f"    {p.name}{typ}: {_param_desc(p.name)}{default}")
        lines.append("")
    if fn.returns and fn.returns != "None":
        lines.append("Returns:")
        lines.append(f"    {fn.returns}: The resulting {words(fn.name.split('_', 1)[-1]) or 'value'}.")
        lines.append("")
    if fn.raises:
        lines.append("Raises:")
        for r in fn.raises:
            cond = f"If `{r.condition}`." if r.condition else "On invalid input or state."
            lines.append(f"    {r.exception}: {cond}")
        lines.append("")
    while lines and lines[-1] == "":
        lines.pop()
    body = "\n".join((indent + ln) if ln else "" for ln in lines)
    return f'{indent}"""{body.lstrip()}\n{indent}"""'


def build_class_docstring(cls: ClassInfo, indent: str = "    ") -> str:
    base = f" Extends {', '.join(cls.bases)}." if cls.bases else ""
    return f'{indent}"""{words(cls.name).capitalize()}.{base}"""'


def _auth_status(fn: FunctionInfo) -> str:
    deco = " ".join(fn.decorators).lower()
    if any(k in deco for k in ("auth", "login_required", "jwt", "permission")):
        return "required"
    return "**not enforced**"


def document_unit(unit: AnalysisUnit) -> Dict[str, Any]:
    functions, classes = extract_model(unit)
    docstrings: List[Dict[str, Any]] = []
    endpoints: List[Dict[str, Any]] = []
    for fn in functions:
        if fn.route:
            method, path = fn.route
            endpoints.append({
                "file_path": unit.filename, "line_number": fn.lineno, "method": method, "path": path,
                "handler": fn.qualname, "auth": _auth_status(fn),
                "params": [p.name for p in fn.params],
            })
        if fn.is_public and not fn.docstring:
            indent = "        " if fn.class_name else "    "
            docstrings.append({
                "file_path": unit.filename, "symbol": fn.qualname, "line_number": fn.lineno,
                "kind": "function", "docstring": build_docstring(fn, indent),
            })
    for cls in classes:
        if not cls.name.startswith("_") and not cls.docstring:
            docstrings.append({
                "file_path": unit.filename, "symbol": cls.name, "line_number": cls.lineno,
                "kind": "class", "docstring": build_class_docstring(cls),
            })
    return {
        "file_path": unit.filename,
        "symbols_changed": [f.qualname for f in functions] + [c.name for c in classes],
        "docstrings": docstrings,
        "endpoints": endpoints,
    }


def pr_summary_markdown(files: List[Dict[str, Any]], per_file_docs: List[Dict[str, Any]],
                        llm_summary: Optional[str] = None) -> str:
    adds = dels = 0
    rows = []
    for f in files:
        st = diff_stats(f.get("patch", ""))
        adds += st["additions"]
        dels += st["deletions"]
        rows.append(f"| `{f['filename']}` | {f.get('status', 'modified')} | +{st['additions']} / -{st['deletions']} |")
    symbols = [s for d in per_file_docs for s in d.get("symbols_changed", [])]
    endpoints = [e for d in per_file_docs for e in d.get("endpoints", [])]
    md = ["#### Change summary (DOC-03)", ""]
    if llm_summary:
        md += [llm_summary, ""]
    md += [f"{len(files)} file(s) changed, +{adds} / -{dels} lines.", "",
           "| File | Status | Lines |", "|---|---|---|", *rows, ""]
    if symbols:
        md += ["**Changed symbols:** " + ", ".join(f"`{s}`" for s in symbols[:30]), ""]
    if endpoints:
        md += ["#### Endpoint reference (DOC-04)", "", "| Method | Path | Handler | Auth |", "|---|---|---|---|"]
        md += [f"| {e['method']} | `{e['path']}` | `{e['handler']}` | {e['auth']} |" for e in endpoints]
        md.append("")
    return "\n".join(md)
