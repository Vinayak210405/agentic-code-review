"""Extract a structural model (functions, signatures, raise-conditions, routes)
from changed Python code. Shared by the Test Generator and Documentation agents.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from src.analysis.diff_parser import AnalysisUnit


@dataclass
class Param:
    name: str
    annotation: Optional[str]
    has_default: bool
    default_src: Optional[str] = None


@dataclass
class RaiseInfo:
    exception: str
    condition: Optional[str]  # source of the guarding `if` test
    trigger: Optional[Tuple[str, str]] = None  # (param, python literal that triggers it)


@dataclass
class FunctionInfo:
    name: str
    qualname: str
    class_name: Optional[str]
    lineno: int  # real line number in the PR
    params: List[Param]
    returns: Optional[str]
    is_async: bool
    docstring: Optional[str]
    raises: List[RaiseInfo] = field(default_factory=list)
    decorators: List[str] = field(default_factory=list)
    route: Optional[Tuple[str, str]] = None  # (METHOD, path)
    init_params: List[Param] = field(default_factory=list)  # for methods: the class __init__ params

    @property
    def is_public(self) -> bool:
        return not self.name.startswith("_")


@dataclass
class ClassInfo:
    name: str
    lineno: int
    docstring: Optional[str]
    bases: List[str]


def _params(fn: ast.FunctionDef) -> List[Param]:
    args = fn.args
    positional = args.posonlyargs + args.args
    defaults: List[Optional[ast.AST]] = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
    out: List[Param] = []
    for a, d in zip(positional, defaults):
        if a.arg in {"self", "cls"}:
            continue
        out.append(Param(a.arg, ast.unparse(a.annotation) if a.annotation else None, d is not None,
                         ast.unparse(d) if d is not None else None))
    for a, d in zip(args.kwonlyargs, args.kw_defaults):
        out.append(Param(a.arg, ast.unparse(a.annotation) if a.annotation else None, d is not None,
                         ast.unparse(d) if d is not None else None))
    return out


_NUM_OPS = {ast.Lt: "lt", ast.LtE: "le", ast.Gt: "gt", ast.GtE: "ge", ast.Eq: "eq"}


def _trigger_for(test: ast.AST, params: List[str]) -> Optional[Tuple[str, str]]:
    """Find an argument value that makes ``test`` true (so the guarded raise fires)."""
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
        for v in test.values:
            t = _trigger_for(v, params)
            if t:
                return t
        return None
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        inner = test.operand
        if isinstance(inner, ast.Name) and inner.id in params:
            return (inner.id, "<falsy>")
        if (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name) and inner.func.id == "isinstance"
                and inner.args and isinstance(inner.args[0], ast.Name) and inner.args[0].id in params):
            expected = ast.unparse(inner.args[1]) if len(inner.args) > 1 else ""
            return (inner.args[0].id, "123" if "str" in expected else "'not-a-valid-value'")
        if (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute)
                and isinstance(inner.func.value, ast.Name) and inner.func.value.id in params):
            return (inner.func.value.id, "'!!invalid!!'")
        return None
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        left, op, right = test.left, test.ops[0], test.comparators[0]
        if isinstance(left, ast.Call) and isinstance(left.func, ast.Name) and left.func.id == "len" and left.args:
            if isinstance(left.args[0], ast.Name) and left.args[0].id in params and isinstance(right, ast.Constant):
                n = right.value
                if isinstance(n, int):
                    size = {ast.Lt: n - 1, ast.LtE: n, ast.Eq: n, ast.Gt: n + 1, ast.GtE: n}.get(type(op))
                    if size is not None and size >= 0:
                        return (left.args[0].id, repr("x" * min(size, 500)))
            return None
        if isinstance(left, ast.Name) and left.id in params:
            if isinstance(op, (ast.Is, ast.Eq)) and isinstance(right, ast.Constant) and right.value is None:
                return (left.id, "None")
            if isinstance(right, ast.Constant) and isinstance(right.value, (int, float)) and not isinstance(right.value, bool):
                v = right.value
                step = 1 if isinstance(v, int) else 0.5
                val = {ast.Lt: v - step, ast.LtE: v, ast.Gt: v + step, ast.GtE: v, ast.Eq: v}.get(type(op))
                if val is not None:
                    return (left.id, repr(val))
            if isinstance(op, ast.NotIn) and isinstance(right, (ast.Tuple, ast.List, ast.Set)):
                return (left.id, "'__not_allowed__'")
            if isinstance(op, ast.In) and isinstance(right, (ast.Tuple, ast.List, ast.Set)) and right.elts:
                first = right.elts[0]
                if isinstance(first, ast.Constant):
                    return (left.id, repr(first.value))
    return None


def _raises(fn: ast.FunctionDef, params: List[str]) -> List[RaiseInfo]:
    out: List[RaiseInfo] = []
    seen = set()

    def exc_name(node: Optional[ast.AST]) -> Optional[str]:
        if node is None:
            return None
        target = node.func if isinstance(node, ast.Call) else node
        if isinstance(target, (ast.Name, ast.Attribute)):
            return ast.unparse(target)
        return None

    # Only look at the function's own top-level guard clauses for triggers.
    for stmt in fn.body:
        if isinstance(stmt, ast.If):
            for inner in stmt.body:
                if isinstance(inner, ast.Raise):
                    name = exc_name(inner.exc)
                    if name and (name, ast.unparse(stmt.test)) not in seen:
                        seen.add((name, ast.unparse(stmt.test)))
                        out.append(RaiseInfo(name, ast.unparse(stmt.test), _trigger_for(stmt.test, params)))
    for node in ast.walk(fn):
        if isinstance(node, ast.Raise):
            name = exc_name(node.exc)
            if name and not any(r.exception == name for r in out):
                out.append(RaiseInfo(name, None, None))
    return out


def _route(fn: ast.FunctionDef) -> Optional[Tuple[str, str]]:
    for dec in fn.decorator_list:
        if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
            attr = dec.func.attr
            if attr in {"get", "post", "put", "delete", "patch", "route", "api_route"}:
                path = dec.args[0].value if dec.args and isinstance(dec.args[0], ast.Constant) else "?"
                method = attr.upper() if attr not in {"route", "api_route"} else "GET"
                for kw in dec.keywords:
                    if kw.arg == "methods":
                        consts = [c.value for c in ast.walk(kw.value) if isinstance(c, ast.Constant)]
                        if consts:
                            method = "/".join(str(c).upper() for c in consts)
                return method, str(path)
    return None


def _touches_changes(unit: AnalysisUnit, node: ast.AST) -> bool:
    start = getattr(node, "lineno", 0)
    end = getattr(node, "end_lineno", start)
    for ln in range(start, end + 1):
        if unit.is_changed(unit.real_line(ln)):
            return True
    return False


def extract_model(unit: AnalysisUnit, only_changed: bool = True) -> Tuple[List[FunctionInfo], List[ClassInfo]]:
    if unit.tree is None:
        return [], []
    functions: List[FunctionInfo] = []
    classes: List[ClassInfo] = []

    def handle_fn(fn: ast.FunctionDef, cls: Optional[ast.ClassDef], init_params: List[Param]) -> None:
        if only_changed and not _touches_changes(unit, fn):
            return
        params = _params(fn)
        functions.append(FunctionInfo(
            name=fn.name,
            qualname=f"{cls.name}.{fn.name}" if cls else fn.name,
            class_name=cls.name if cls else None,
            lineno=unit.real_line(fn.lineno) or fn.lineno,
            params=params,
            returns=ast.unparse(fn.returns) if fn.returns else None,
            is_async=isinstance(fn, ast.AsyncFunctionDef),
            docstring=ast.get_docstring(fn),
            raises=_raises(fn, [p.name for p in params]),
            decorators=[ast.unparse(d) for d in fn.decorator_list],
            route=_route(fn),
            init_params=init_params,
        ))

    for node in unit.tree.body:  # type: ignore[attr-defined]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            handle_fn(node, None, [])
        elif isinstance(node, ast.ClassDef):
            init = next((n for n in node.body if isinstance(n, ast.FunctionDef) and n.name == "__init__"), None)
            init_params = _params(init) if init else []
            if not only_changed or _touches_changes(unit, node):
                classes.append(ClassInfo(node.name, unit.real_line(node.lineno) or node.lineno,
                                         ast.get_docstring(node), [ast.unparse(b) for b in node.bases]))
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name != "__init__":
                    handle_fn(item, node, init_params)
    return functions, classes


def module_path(filename: str) -> str:
    path = re.sub(r"\.py$", "", filename.replace("\\", "/")).strip("/")
    if path.endswith("/__init__"):
        path = path[: -len("/__init__")]
    return path.replace("/", ".")


def words(identifier: str) -> str:
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", identifier)
    return " ".join(w for w in spaced.strip("_").split("_") if w).lower()
