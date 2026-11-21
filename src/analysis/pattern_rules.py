"""Language-agnostic pattern rules (JS/TS, config, Dockerfile, .env, secrets)
plus the A06 dependency audit for requirements files.

Python files are primarily handled by the AST engine; these patterns are
applied to Python only for lines that could not be parsed and for secret
formats (cloud keys, private keys) that are dangerous regardless of context.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.analysis.diff_parser import AnalysisUnit
from src.analysis.findings import make_finding


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    owasp: str
    cwe: str
    severity: str
    title: str
    pattern: re.Pattern
    mitigation: str
    languages: Tuple[str, ...]  # "*" = every language


ALL = ("*",)
JS = ("javascript", "typescript")
CONFIG = ("yaml", "json", "toml", "ini", "dotenv", "text")
PY_FALLBACK = ("python",)

SECRET_RULES: List[PatternRule] = [
    PatternRule("SECRET-001", "A07", "CWE-798", "CRITICAL", "AWS access key committed",
                re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
                "Revoke the key in IAM immediately and load credentials from the environment/role.", ALL),
    PatternRule("SECRET-002", "A07", "CWE-798", "CRITICAL", "Private key committed",
                re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
                "Remove the key from history, rotate it and store it in a secret manager.", ALL),
    PatternRule("SECRET-003", "A07", "CWE-798", "CRITICAL", "GitHub token committed",
                re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
                "Revoke the token in GitHub settings and use repository/Actions secrets.", ALL),
    PatternRule("SECRET-004", "A07", "CWE-798", "CRITICAL", "API secret key committed",
                re.compile(r"\b(sk-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]{10,})\b"),
                "Rotate the key and inject it at runtime from a secret store.", ALL),
]

GENERIC_RULES: List[PatternRule] = [
    PatternRule("SECRET-005", "A07", "CWE-798", "HIGH", "Hard-coded credential",
                re.compile(r"""(?i)\b[\w.-]*(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b["']?\s*[:=]\s*["']?(?!\$\{|<|your|changeme_placeholder|\s*$)[^\s"',;]{6,}"""),
                "Load credentials from environment variables or a secret manager.", JS + CONFIG + ("dockerfile",)),
    PatternRule("SQLI-002", "A03", "CWE-89", "CRITICAL", "SQL injection via string-built query",
                re.compile(r"""(?i)(["'`]\s*(select\b.+\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)[^"'`]*(\$\{|["'`]\s*\+))|(f["'](select|insert|update|delete)\b[^"']*\{)"""),
                "Use parameterised queries / prepared statements.", JS + PY_FALLBACK + ("java", "php", "go", "ruby")),
    PatternRule("CODEI-002", "A03", "CWE-95", "HIGH", "Dynamic code evaluation",
                re.compile(r"\b(eval|exec)\s*\(\s*(?![\"'`][^\"'`]*[\"'`]\s*\))|new\s+Function\s*\("),
                "Avoid evaluating dynamic code; parse data with JSON.parse / ast.literal_eval.", JS + PY_FALLBACK),
    PatternRule("CMDI-003", "A03", "CWE-78", "CRITICAL", "OS command injection",
                re.compile(r"""(child_process\.)?\bexec(Sync)?\s*\(\s*(`[^`]*\$\{|["'][^"']*["']\s*\+)|os\.system\s*\((?!\s*["'][^"']*["']\s*\))"""),
                "Use execFile/spawn with an argument array (JS) or subprocess with a list (Python).", JS + PY_FALLBACK),
    PatternRule("XSS-003", "A03", "CWE-79", "HIGH", "DOM XSS via innerHTML/document.write",
                re.compile(r"\.(innerHTML|outerHTML)\s*=\s*(?![\"'`][^\"'`$]*[\"'`]\s*;?\s*$)|document\.write\s*\(|dangerouslySetInnerHTML"),
                "Use textContent or a sanitiser such as DOMPurify.", JS),
    PatternRule("DESER-004", "A08", "CWE-502", "HIGH", "Insecure deserialization",
                re.compile(r"\bpickle\.loads?\s*\(|\byaml\.load\s*\((?!.*SafeLoader)"),
                "Use JSON or yaml.safe_load.", PY_FALLBACK),
    PatternRule("TLS-003", "A07", "CWE-295", "HIGH", "TLS verification disabled",
                re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
                "Keep certificate verification enabled.", ALL),
    PatternRule("CONF-004", "A05", "CWE-489", "MEDIUM", "Debug mode enabled in configuration",
                re.compile(r"(?i)^\s*[\"']?(debug|flask_debug|app_debug)[\"']?\s*[:=]\s*[\"']?(true|1|on)\b"),
                "Disable debug in committed/production configuration.", CONFIG + PY_FALLBACK),
    PatternRule("CONF-005", "A05", "CWE-942", "MEDIUM", "Wildcard CORS origin",
                re.compile(r"(?i)(access-control-allow-origin[\"']?\s*[:,]\s*[\"']\*|origin\s*:\s*[\"']\*[\"']|allow_origins\s*=\s*\[\s*[\"']\*)"),
                "Restrict CORS to known origins.", JS + CONFIG + PY_FALLBACK),
    PatternRule("CONF-006", "A05", "CWE-732", "MEDIUM", "World-writable permissions",
                re.compile(r"chmod\s+(-R\s+)?0?777|os\.chmod\([^)]*0o?777"),
                "Grant the minimum permissions required.", ALL),
    PatternRule("INTEG-001", "A08", "CWE-494", "HIGH", "Remote script piped to shell",
                re.compile(r"(curl|wget)\s+[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b"),
                "Download, verify a checksum/signature, then execute.", ALL),
    PatternRule("SSRF-002", "A10", "CWE-918", "HIGH", "Server-side request to user-supplied URL",
                re.compile(r"(fetch|axios\.(get|post)|http\.get|got)\s*\(\s*req\.(query|body|params)"),
                "Validate destinations against an allow-list and block internal IP ranges.", JS),
    PatternRule("CRYPTO-005", "A02", "CWE-328", "MEDIUM", "Weak hash algorithm",
                re.compile(r"createHash\(\s*[\"'](md5|sha1)[\"']\s*\)|MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\""),
                "Use SHA-256+ (or bcrypt/argon2 for passwords).", JS + ("java",)),
    PatternRule("CRYPTO-006", "A02", "CWE-338", "HIGH", "Math.random used for security token",
                re.compile(r"(?i)(token|secret|password|otp|nonce|session)\w*\s*=.*Math\.random\(\)"),
                "Use crypto.randomBytes / crypto.randomUUID.", JS),
    PatternRule("CONF-007", "A05", "CWE-250", "MEDIUM", "Container runs as root",
                re.compile(r"(?i)^\s*USER\s+(root|0)\s*$"),
                "Create and switch to an unprivileged user.", ("dockerfile",)),
]

_PLACEHOLDER = re.compile(r"(?i)(your[_-]|example|change[_-]?me|placeholder|<[^>]+>|\$\{|xxxx|dummy|\*{3,})")
TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")


def _applies(rule: PatternRule, language: str) -> bool:
    return "*" in rule.languages or language in rule.languages


def _is_comment(line: str, language: str) -> bool:
    s = line.strip()
    if language in JS + ("java", "go", "php"):
        return s.startswith("//") or s.startswith("*") or s.startswith("/*")
    if language in ("python", "yaml", "toml", "ini", "dotenv", "dockerfile", "requirements"):
        return s.startswith("#")
    return False


def analyze_patterns(unit: AnalysisUnit, python_ast_ok: bool) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = unit.changed_text()
    for lineno, text in sorted(lines.items()):
        if "nosec" in text or "acr: ignore" in text or _is_comment(text, unit.language):
            continue
        rules: List[PatternRule] = list(SECRET_RULES)
        is_unparsed_py = unit.language == "python" and (lineno in unit.unparsed_lines or not python_ast_ok)
        is_docs = unit.language == "markdown"  # prose: only real secret formats matter
        is_template = unit.filename.endswith(TEMPLATE_SUFFIXES)
        if (unit.language != "python" or is_unparsed_py) and not is_docs:
            rules += [r for r in GENERIC_RULES if not (is_template and r.rule_id == "SECRET-005")]
        for rule in rules:
            if not _applies(rule, unit.language):
                continue
            m = rule.pattern.search(text)
            if not m:
                continue
            if rule.rule_id == "SECRET-005" and _PLACEHOLDER.search(m.group(0)):
                continue
            findings.append(make_finding(
                rule_id=rule.rule_id, owasp=rule.owasp, cwe=rule.cwe, severity=rule.severity,
                title=rule.title, description=f"{rule.title} detected in changed line.",
                mitigation=rule.mitigation, file_path=unit.filename, line_number=lineno,
                snippet=text, source="pattern", confidence="MEDIUM",
            ))
    if unit.language == "dotenv":
        findings += _dotenv_committed(unit)
    return findings


def _dotenv_committed(unit: AnalysisUnit) -> List[Dict[str, Any]]:
    if not unit.changed_lines:
        return []
    first = min(unit.changed_lines)
    return [make_finding(
        rule_id="CONF-008", owasp="A05", cwe="CWE-538", severity="HIGH",
        title="Environment file committed to repository",
        description=f"`{unit.filename}` is tracked in version control and may contain live secrets.",
        mitigation="Remove it from git, add it to .gitignore and commit a .env.example with placeholders.",
        file_path=unit.filename, line_number=first, snippet="", source="pattern",
    )] if not unit.filename.endswith((".example", ".sample", ".template")) else []


# ----------------------------------------------------------------- A06 audit
ADVISORY_DB = Path(__file__).resolve().parent / "advisories.json"
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*(==|>=|<=|~=|>|<|!=)?\s*([0-9][\w.\-]*)?")


def _version_tuple(v: str) -> Tuple[int, ...]:
    parts: List[int] = []
    for p in re.split(r"[.\-]", v):
        m = re.match(r"\d+", p)
        if not m:
            break
        parts.append(int(m.group()))
    return tuple(parts)


def load_advisories() -> Dict[str, List[Dict[str, str]]]:
    with open(ADVISORY_DB, encoding="utf-8") as fh:
        return json.load(fh)


def analyze_requirements(unit: AnalysisUnit, advisories: Optional[Dict[str, List[Dict[str, str]]]] = None) -> List[Dict[str, Any]]:
    advisories = advisories if advisories is not None else load_advisories()
    findings: List[Dict[str, Any]] = []
    for lineno, text in sorted(unit.changed_text().items()):
        line = text.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = _REQ_LINE.match(line)
        if not m:
            continue
        pkg = re.sub(r"\[.*\]", "", m.group(1)).lower().replace("_", "-")
        op, version = m.group(2), m.group(3)
        if op != "==" or not version:
            floor_is_safe = bool(version) and all(
                _version_tuple(version) >= _version_tuple(a["fixed_in"]) for a in advisories.get(pkg, []))
            if pkg in advisories and op in (None, ">=", ">") and not floor_is_safe:
                findings.append(make_finding(
                    rule_id="DEP-002", owasp="A06", cwe="CWE-1104", severity="LOW",
                    title="Unpinned dependency with known vulnerable releases",
                    description=f"`{pkg}` is not pinned; builds may resolve to a vulnerable version.",
                    mitigation="Pin exact versions (==) and update via a lock file / Dependabot.",
                    file_path=unit.filename, line_number=lineno, snippet=text, source="sca",
                ))
            continue
        for adv in advisories.get(pkg, []):
            if _version_tuple(version) < _version_tuple(adv["fixed_in"]):
                findings.append(make_finding(
                    rule_id="DEP-001", owasp="A06", cwe="CWE-1104", severity=adv.get("severity", "HIGH"),
                    title=f"Vulnerable dependency: {pkg}=={version}",
                    description=f"{adv['id']}: {adv['summary']} (fixed in {adv['fixed_in']}).",
                    mitigation=f"Upgrade {pkg} to >= {adv['fixed_in']}.",
                    file_path=unit.filename, line_number=lineno, snippet=text, source="sca",
                ))
    return findings
