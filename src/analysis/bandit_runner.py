"""Run Bandit on the analysable source and map its results to OWASP Top 10.

Bandit acts as a second, independent SAST engine. When it agrees with a
native rule, the finding is marked ``confirmed_by: bandit:<test_id>``; when
it finds something the native rules missed, its finding is added.
"""
from __future__ import annotations

import logging
import os
import tempfile
from typing import Any, Dict, List, Tuple

from src.analysis.diff_parser import AnalysisUnit
from src.analysis.findings import make_finding

logger = logging.getLogger(__name__)
for _noisy in ("bandit", "stevedore"):
    logging.getLogger(_noisy).setLevel(logging.ERROR)

# Bandit test id -> (OWASP id, default CWE)
BANDIT_TO_OWASP: Dict[str, Tuple[str, str]] = {
    "B101": ("A04", "CWE-617"),
    "B102": ("A03", "CWE-78"),
    "B103": ("A05", "CWE-732"),
    "B104": ("A05", "CWE-605"),
    "B105": ("A07", "CWE-798"),
    "B106": ("A07", "CWE-798"),
    "B107": ("A07", "CWE-798"),
    "B108": ("A01", "CWE-377"),
    "B110": ("A09", "CWE-778"),
    "B112": ("A09", "CWE-778"),
    "B113": ("A04", "CWE-400"),
    "B201": ("A05", "CWE-489"),
    "B202": ("A01", "CWE-22"),
    "B301": ("A08", "CWE-502"),
    "B302": ("A08", "CWE-502"),
    "B303": ("A02", "CWE-328"),
    "B304": ("A02", "CWE-327"),
    "B305": ("A02", "CWE-327"),
    "B306": ("A01", "CWE-377"),
    "B307": ("A03", "CWE-95"),
    "B310": ("A10", "CWE-918"),
    "B311": ("A02", "CWE-338"),
    "B313": ("A05", "CWE-611"),
    "B314": ("A05", "CWE-611"),
    "B318": ("A05", "CWE-611"),
    "B319": ("A05", "CWE-611"),
    "B320": ("A05", "CWE-611"),
    "B321": ("A02", "CWE-319"),
    "B323": ("A07", "CWE-295"),
    "B324": ("A02", "CWE-328"),
    "B403": ("A08", "CWE-502"),
    "B405": ("A05", "CWE-611"),
    "B408": ("A05", "CWE-611"),
    "B410": ("A05", "CWE-611"),
    "B501": ("A07", "CWE-295"),
    "B502": ("A02", "CWE-326"),
    "B503": ("A02", "CWE-326"),
    "B504": ("A02", "CWE-326"),
    "B505": ("A02", "CWE-326"),
    "B506": ("A08", "CWE-502"),
    "B507": ("A07", "CWE-295"),
    "B601": ("A03", "CWE-78"),
    "B602": ("A03", "CWE-78"),
    "B603": ("A03", "CWE-78"),
    "B604": ("A03", "CWE-78"),
    "B605": ("A03", "CWE-78"),
    "B606": ("A03", "CWE-78"),
    "B607": ("A03", "CWE-78"),
    "B608": ("A03", "CWE-89"),
    "B609": ("A03", "CWE-78"),
    "B610": ("A03", "CWE-89"),
    "B611": ("A03", "CWE-89"),
    "B612": ("A03", "CWE-94"),
    "B701": ("A03", "CWE-79"),
    "B702": ("A03", "CWE-79"),
    "B703": ("A03", "CWE-79"),
    "B704": ("A03", "CWE-79"),
}

# Noisy tests that only matter with additional context; skip unless MEDIUM+.
LOW_SIGNAL = {"B101", "B404", "B603", "B607", "B105", "B311"}


def bandit_available() -> bool:
    try:
        import bandit  # noqa: F401
        return True
    except ImportError:
        return False


def run_bandit(unit: AnalysisUnit) -> List[Dict[str, Any]]:
    if unit.tree is None or not unit.source.strip():
        return []
    try:
        from bandit.core import config as b_config
        from bandit.core import manager as b_manager
    except ImportError:  # pragma: no cover - bandit is in requirements
        return []

    fd, path = tempfile.mkstemp(suffix=".py", prefix="acr_bandit_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(unit.source)
        conf = b_config.BanditConfig()
        mgr = b_manager.BanditManager(conf, "file", debug=False, verbose=False, quiet=True)
        mgr.discover_files([path], recursive=False)
        mgr.run_tests()
        issues = mgr.get_issue_list()
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Bandit failed on %s: %s", unit.filename, exc)
        return []
    finally:
        try:
            os.unlink(path)
        except OSError as exc:
            logger.debug("Could not remove temp file %s: %s", path, exc)

    lines = unit.source.splitlines()
    findings: List[Dict[str, Any]] = []
    for issue in issues:
        test_id = issue.test_id
        if test_id not in BANDIT_TO_OWASP:
            continue
        severity = str(issue.severity).upper()
        if test_id in LOW_SIGNAL and severity == "LOW":
            continue
        real = unit.real_line(issue.lineno)
        if not unit.is_changed(real):
            continue
        owasp, cwe = BANDIT_TO_OWASP[test_id]
        cwe_obj = getattr(issue, "cwe", None)
        if cwe_obj is not None and getattr(cwe_obj, "id", None):
            cwe = f"CWE-{cwe_obj.id}"
        snippet = lines[issue.lineno - 1] if 0 < issue.lineno <= len(lines) else ""
        findings.append(make_finding(
            rule_id=f"BANDIT-{test_id}", owasp=owasp, cwe=cwe, severity=severity,
            title=f"Bandit {test_id}: {issue.test}", description=issue.text,
            mitigation="See Bandit documentation for " + test_id + " and the linked institutional standard.",
            file_path=unit.filename, line_number=real, snippet=snippet, source="bandit",
            confidence=str(issue.confidence).upper(),
        ))
    return findings
