"""AST-based code-quality rules aligned with the institutional standards (STD-xx)."""
from __future__ import annotations

import ast
import builtins
import re
from typing import Any, Dict, List, Optional, Set

from src.analysis.diff_parser import AnalysisUnit

DB_CALLS = {
    "execute", "executemany", "query", "filter", "filter_by", "get", "first", "one", "all", "fetchone",
    "fetchall", "find", "find_one", "raw", "select", "scalar", "scalars",
}
DB_RECEIVERS = re.compile(r"(?i)(db|cursor|cur|conn|connection|session|objects|collection|engine|repo|query)")
SNAKE = re.compile(r"^_{0,2}[a-z][a-z0-9_]*_{0,2}$")
CAPWORDS = re.compile(r"^_?[A-Z][A-Za-z0-9]*$")
SHADOWABLE = {"list", "dict", "set", "id", "type", "input", "file", "str", "int", "len", "max", "min", "sum",
              "filter", "map", "object", "format", "hash", "iter", "next", "range", "open", "bytes"}
BUILTINS = set(dir(builtins))


def _lint(unit: AnalysisUnit, node: Optional[ast.AST], line: Optional[int], rule: str, severity: str,
          issue: str, suggestion: str, standard: str) -> Optional[Dict[str, Any]]:
    real = unit.real_line(line if line is not None else getattr(node, "lineno", None))
    if not unit.is_changed(real):
        return None
    return {
        "rule_id": rule,
        "file_path": unit.filename,
        "line_number": real,
        "severity": severity,
        "issue": issue,
        "suggestion": suggestion,
        "standard_refs": [standard],
        "source": "ast",
    }


def _complexity(fn: ast.AST) -> int:
    score = 1
    for n in ast.walk(fn):
        if isinstance(n, (ast.If, ast.For, ast.While, ast.AsyncFor, ast.IfExp, ast.ExceptHandler,
                          ast.With, ast.AsyncWith, ast.Assert, ast.comprehension)):
            score += 1
        elif isinstance(n, ast.BoolOp):
            score += len(n.values) - 1
        elif isinstance(n, ast.Match):
            score += len(n.cases)
    return score


class _LintVisitor(ast.NodeVisitor):
    def __init__(self, unit: AnalysisUnit) -> None:
        self.unit = unit
        self.out: List[Dict[str, Any]] = []
        self.loop_depth = 0
        self.lines = unit.source.splitlines()

    def add(self, *args: Any, **kwargs: Any) -> None:
        f = _lint(self.unit, *args, **kwargs)
        if f is not None:
            self.out.append(f)

    # --------------------------------------------------------------- defs
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        public = not node.name.startswith("_")
        if not SNAKE.match(node.name) and not node.name.startswith("visit_"):
            self.add(node, None, "LINT-N802", "warning", f"Function `{node.name}` is not snake_case.",
                     "Rename using snake_case.", "STD-01")
        for default in node.args.defaults + [d for d in node.args.kw_defaults if d is not None]:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)) or (
                isinstance(default, ast.Call) and isinstance(default.func, ast.Name)
                and default.func.id in {"list", "dict", "set"}
            ):
                self.add(default, None, "LINT-B006", "error",
                         f"Mutable default argument in `{node.name}`.",
                         "Use `None` as the default and create the object inside the function.", "STD-05")
        if public and ast.get_docstring(node) is None:
            self.add(node, None, "LINT-D103", "info", f"Public function `{node.name}` has no docstring.",
                     "Add a Google-style docstring (see the Documentation agent's suggestion).", "DOC-01")
        if public:
            params = [a for a in node.args.args if a.arg not in {"self", "cls"}]
            if any(a.annotation is None for a in params) or node.returns is None:
                self.add(node, None, "LINT-ANN001", "info", f"`{node.name}` is missing type hints.",
                         "Annotate every parameter and the return type.", "STD-03")
        end = getattr(node, "end_lineno", node.lineno)
        if end - node.lineno + 1 > 50:
            self.add(node, None, "LINT-R0915", "warning",
                     f"`{node.name}` is {end - node.lineno + 1} lines long (limit 50).",
                     "Extract helper functions.", "STD-08")
        cc = _complexity(node)
        if cc > 10:
            self.add(node, None, "LINT-C901", "warning",
                     f"`{node.name}` has cyclomatic complexity {cc} (limit 10).",
                     "Reduce branching or split the function.", "STD-08")
        for arg in node.args.args + node.args.kwonlyargs:
            if arg.arg in SHADOWABLE:
                self.add(node, None, "LINT-A002", "warning", f"Argument `{arg.arg}` shadows a built-in.",
                         "Rename the argument.", "STD-10")
        saved = self.loop_depth
        self.loop_depth = 0
        self.generic_visit(node)
        self.loop_depth = saved

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        if not CAPWORDS.match(node.name):
            self.add(node, None, "LINT-N801", "warning", f"Class `{node.name}` is not CapWords.",
                     "Rename using CapWords.", "STD-01")
        if not node.name.startswith("_") and ast.get_docstring(node) is None:
            self.add(node, None, "LINT-D101", "info", f"Public class `{node.name}` has no docstring.",
                     "Add a class docstring.", "DOC-01")
        self.generic_visit(node)

    # -------------------------------------------------------------- loops
    def _visit_loop(self, node: ast.AST) -> None:
        self.loop_depth += 1
        self.generic_visit(node)
        self.loop_depth -= 1

    visit_For = _visit_loop  # type: ignore[assignment]
    visit_AsyncFor = _visit_loop  # type: ignore[assignment]
    visit_While = _visit_loop  # type: ignore[assignment]

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        func = node.func
        if self.loop_depth and isinstance(func, ast.Attribute) and func.attr in DB_CALLS:
            receiver = ast.unparse(func.value)
            if DB_RECEIVERS.search(receiver):
                self.add(node, None, "LINT-PERF001", "error",
                         f"N+1 query: `{receiver}.{func.attr}()` is called inside a loop.",
                         "Fetch related records in one bulk query (IN clause / join / prefetch) before the loop.",
                         "STD-07")
        if isinstance(func, ast.Name) and func.id == "print":
            if not self.unit.filename.split("/")[-1].startswith(("test_", "cli", "manage", "__main__")):
                self.add(node, None, "LINT-T201", "info", "`print()` used in application code.",
                         "Use the `logging` module.", "STD-09")
        self.generic_visit(node)

    # ----------------------------------------------------------- misc
    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:  # noqa: N802
        if node.type is None:
            self.add(node, None, "LINT-E722", "error", "Bare `except:` clause.",
                     "Catch specific exceptions (e.g. `except ValueError:`).", "STD-04")
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:  # noqa: N802
        for op, comp in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(comp, ast.Constant) and comp.value is None:
                self.add(node, None, "LINT-E711", "warning", "Comparison to None with `==`/`!=`.",
                         "Use `is None` / `is not None`.", "STD-06")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id in SHADOWABLE:
                self.add(node, None, "LINT-A001", "warning", f"Variable `{t.id}` shadows a built-in.",
                         "Choose a descriptive name.", "STD-10")
        self.generic_visit(node)


def _unused_imports(unit: AnalysisUnit) -> List[Dict[str, Any]]:
    if not unit.full_file or unit.tree is None:
        return []
    imported: Dict[str, ast.AST] = {}
    for node in ast.walk(unit.tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                name = (alias.asname or alias.name).split(".")[0]
                if name != "*":
                    imported[name] = node
    used: Set[str] = {n.id for n in ast.walk(unit.tree) if isinstance(n, ast.Name)}
    used |= {n.value.id for n in ast.walk(unit.tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)}
    exported: Set[str] = set()
    for node in ast.walk(unit.tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
            exported |= {c.value for c in ast.walk(node.value) if isinstance(c, ast.Constant)}
    out = []
    if unit.filename.endswith("__init__.py"):
        return out
    for name, node in imported.items():
        if name not in used and name not in exported:
            f = _lint(unit, node, None, "LINT-F401", "warning", f"`{name}` imported but unused.",
                      "Remove the unused import.", "STD-12")
            if f:
                out.append(f)
    return out


def analyze_quality(unit: AnalysisUnit) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if unit.language == "python" and unit.tree is not None:
        visitor = _LintVisitor(unit)
        visitor.visit(unit.tree)
        findings += visitor.out
        findings += _unused_imports(unit)
    for lineno, text in sorted(unit.changed_text().items()):
        if len(text) > 120:
            findings.append({
                "rule_id": "LINT-E501", "file_path": unit.filename, "line_number": lineno, "severity": "info",
                "issue": f"Line too long ({len(text)} > 120).", "suggestion": "Wrap the line.",
                "standard_refs": ["STD-02"], "source": "ast",
            })
        m = re.search(r"#\s*(TODO|FIXME|XXX)\b(?!\s*\([A-Z]+-\d+\))", text)
        if m:
            findings.append({
                "rule_id": "LINT-FIX001", "file_path": unit.filename, "line_number": lineno, "severity": "info",
                "issue": f"{m.group(1)} without a ticket reference.",
                "suggestion": "Reference a ticket, e.g. `# TODO(PROJ-123): ...`.",
                "standard_refs": ["STD-11"], "source": "ast",
            })
    seen = set()
    unique = []
    for f in findings:
        key = (f["rule_id"], f["line_number"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return sorted(unique, key=lambda f: (f["line_number"] or 0, f["rule_id"]))
