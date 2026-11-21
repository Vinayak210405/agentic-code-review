"""Unified-diff parsing and construction of analysable source units.

GitHub's pull-request API returns a ``patch`` per file (unified diff hunks).
To run AST-based analysis with *real* line numbers we:

1. walk the hunks and record, for every added line, its line number in the
   new version of the file;
2. rebuild parseable Python from those hunks (dedenting fragments and
   repairing dangling block headers when needed);
3. keep a ``line_map`` so any finding in the rebuilt source can be reported
   at its true position in the PR.

When the full post-change file content is available (fetched from GitHub at
the head SHA) the whole file is parsed instead, and findings are filtered to
the lines the PR actually touched.
"""
from __future__ import annotations

import ast
import re
import textwrap
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

LANGUAGE_BY_EXT = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".cfg": "ini",
    ".ini": "ini",
    ".env": "dotenv",
    ".sql": "sql",
    ".md": "markdown",
}


def detect_language(filename: str) -> str:
    lower = filename.lower()
    base = lower.rsplit("/", 1)[-1]
    if base.startswith("requirements") and base.endswith(".txt"):
        return "requirements"
    if base in {"pyproject.toml", "pipfile"}:
        return "requirements"
    if base == "dockerfile" or base.endswith(".dockerfile"):
        return "dockerfile"
    if base == ".env" or (base.startswith(".env.") and not base.endswith((".example", ".sample", ".template"))):
        return "dotenv"
    for ext, lang in LANGUAGE_BY_EXT.items():
        if lower.endswith(ext):
            return lang
    return "text"


@dataclass
class Hunk:
    new_start: int
    # (new_line_number, text, kind) where kind is "+" (added) or " " (context)
    lines: List[Tuple[int, str, str]] = field(default_factory=list)


@dataclass
class ParsedPatch:
    hunks: List[Hunk]
    added: Dict[int, str]  # new line number -> added text
    removed_count: int

    @property
    def added_line_numbers(self) -> Set[int]:
        return set(self.added)


def parse_patch(patch: str) -> ParsedPatch:
    """Parse a unified diff ``patch`` string (one file) into hunks."""
    hunks: List[Hunk] = []
    added: Dict[int, str] = {}
    removed = 0
    current: Optional[Hunk] = None
    new_line = 0

    for raw in (patch or "").splitlines():
        header = HUNK_HEADER.match(raw)
        if header:
            new_line = int(header.group(3))
            current = Hunk(new_start=new_line)
            hunks.append(current)
            continue
        if current is None:
            # Patches without headers (hand-written / tests): treat as a hunk at line 1.
            if raw.startswith(("+", "-", " ")) and not raw.startswith(("+++", "---")):
                new_line = 1
                current = Hunk(new_start=1)
                hunks.append(current)
            else:
                continue
        if raw.startswith("+++") or raw.startswith("---"):
            continue
        if raw.startswith("\\"):  # "\ No newline at end of file"
            continue
        if raw.startswith("+"):
            text = raw[1:]
            current.lines.append((new_line, text, "+"))
            added[new_line] = text
            new_line += 1
        elif raw.startswith("-"):
            removed += 1
        else:
            text = raw[1:] if raw.startswith(" ") else raw
            current.lines.append((new_line, text, " "))
            new_line += 1

    return ParsedPatch(hunks=hunks, added=added, removed_count=removed)


@dataclass
class AnalysisUnit:
    """Source code ready for analysis plus a map back to PR line numbers."""

    filename: str
    language: str
    source: str
    line_map: List[int]  # index (0-based line in ``source``) -> real line number
    tree: Optional[ast.AST]
    changed_lines: Set[int]
    unparsed_lines: Dict[int, str]  # added lines we could not fit into an AST
    full_file: bool = False

    def real_line(self, source_lineno: Optional[int]) -> Optional[int]:
        if source_lineno is None:
            return None
        idx = source_lineno - 1
        if 0 <= idx < len(self.line_map):
            return self.line_map[idx]
        return None

    def is_changed(self, real_lineno: Optional[int]) -> bool:
        return real_lineno is not None and real_lineno in self.changed_lines

    def changed_text(self) -> Dict[int, str]:
        """Added line text keyed by real line number (for regex rules)."""
        lines = self.source.splitlines()
        out: Dict[int, str] = {}
        for idx, real in enumerate(self.line_map):
            if real in self.changed_lines and idx < len(lines):
                out[real] = lines[idx]
        out.update(self.unparsed_lines)
        return out


_BLOCK_HEADER = re.compile(
    r"^\s*(def |async def |class |if |elif |else|for |async for |while |try|except|finally|with |async with )"
    r".*:\s*(#.*)?$"
)


def _try_parse(src: str) -> Optional[ast.AST]:
    try:
        return ast.parse(src)
    except (SyntaxError, ValueError):
        return None


def _repair_block_headers(lines: List[str]) -> List[str]:
    """Append ``pass`` after block headers that have no indented body."""
    repaired: List[str] = []
    for i, line in enumerate(lines):
        repaired.append(line)
        if _BLOCK_HEADER.match(line):
            indent = len(line) - len(line.lstrip())
            nxt = next((n for n in lines[i + 1:] if n.strip()), None)
            if nxt is None or (len(nxt) - len(nxt.lstrip())) <= indent:
                repaired.append(" " * (indent + 4) + "pass")
    return repaired


def _fit_block(numbered: List[Tuple[int, str]]) -> Optional[Tuple[str, List[int]]]:
    """Dedent + repair a block of (line_no, text); return parseable src and map."""
    if not numbered:
        return None
    texts = [t for _, t in numbered]
    dedented = textwrap.dedent("\n".join(texts)).split("\n")
    for candidate in (dedented, _repair_block_headers(dedented)):
        src = "\n".join(candidate) + "\n"
        if _try_parse(src) is not None:
            # Build the map: repaired "pass" lines map to the preceding header.
            mapping: List[int] = []
            last = numbered[0][0]
            j = 0
            for line in candidate:
                if j < len(dedented) and line == dedented[j]:
                    last = numbered[j][0]
                    j += 1
                mapping.append(last)
            return src, mapping
    return None


def build_analysis_unit(filename: str, patch: str = "", content: Optional[str] = None) -> AnalysisUnit:
    """Create an :class:`AnalysisUnit` for one changed file."""
    language = detect_language(filename)
    parsed = parse_patch(patch) if patch else ParsedPatch([], {}, 0)
    changed = parsed.added_line_numbers

    # Full post-change file available: analyse it all, report only changed lines.
    if content is not None:
        lines = content.splitlines()
        if not changed:
            changed = set(range(1, len(lines) + 1))
        tree = _try_parse(content) if language == "python" else None
        return AnalysisUnit(
            filename=filename,
            language=language,
            source=content if content.endswith("\n") else content + "\n",
            line_map=list(range(1, len(lines) + 1)),
            tree=tree,
            changed_lines=changed,
            unparsed_lines={},
            full_file=True,
        )

    if language != "python":
        added_lines = [parsed.added[n] for n in sorted(parsed.added)]
        return AnalysisUnit(
            filename=filename,
            language=language,
            source="\n".join(added_lines) + "\n",
            line_map=sorted(parsed.added),
            tree=None,
            changed_lines=changed,
            unparsed_lines={},
        )

    # Python fragments: fit each hunk into parseable source.
    chunks: List[Tuple[str, List[int]]] = []
    unparsed: Dict[int, str] = {}
    for hunk in parsed.hunks:
        whole = [(n, t) for n, t, _ in hunk.lines]
        fitted = _fit_block(whole)
        if fitted is None:
            fitted = _fit_block([(n, t) for n, t, k in hunk.lines if k == "+"])
        if fitted is not None:
            chunks.append(fitted)
            continue
        # Last resort: statement-by-statement.
        for n, t, k in hunk.lines:
            if k != "+" or not t.strip():
                continue
            single = _fit_block([(n, t)])
            if single is not None:
                chunks.append(single)
            else:
                unparsed[n] = t

    source = "".join(src for src, _ in chunks)
    line_map: List[int] = [n for _, mapping in chunks for n in mapping]
    tree = _try_parse(source) if source.strip() else None
    return AnalysisUnit(
        filename=filename,
        language=language,
        source=source,
        line_map=line_map,
        tree=tree,
        changed_lines=changed,
        unparsed_lines=unparsed,
    )


def diff_stats(patch: str) -> Dict[str, int]:
    parsed = parse_patch(patch)
    return {"additions": len(parsed.added), "deletions": parsed.removed_count, "hunks": len(parsed.hunks)}
