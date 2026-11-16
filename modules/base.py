"""
modules.base — shared validation + reporting glue for every module.

Keeps each module file down to "read inputs -> call engine -> print".
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from colorama import Fore

from core.ui import GREY, info, ok, warn
from core.report import export


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def normalize_url(value: str) -> str:
    """Add a scheme when the user typed a bare host, strip trailing slashes."""
    value = value.strip()
    if not value:
        raise ValueError("Empty URL")
    if "://" not in value:
        value = "https://" + value
    return value.rstrip("/")


def normalize_host(value: str) -> str:
    """Strip scheme/path so a pasted URL becomes a host."""
    value = value.strip()
    if not value:
        raise ValueError("Empty target")
    if "://" in value:
        value = value.split("://", 1)[1]
    return value.split("/", 1)[0].split(":", 1)[0]


def split_service_target(value: str, allowed: List[str]) -> tuple:
    """Parse 'mysql:10.0.0.5' -> ('mysql', '10.0.0.5')."""
    if ":" not in value:
        raise ValueError(f"Expected format service:host, e.g. {allowed[0]}:10.0.0.5")
    service, _, host = value.partition(":")
    service = service.strip().lower()
    if service not in allowed:
        raise ValueError(f"Service '{service}' not supported (choose {', '.join(allowed)})")
    return service, normalize_host(host)


# ---------------------------------------------------------------------------
# Result helpers
# ---------------------------------------------------------------------------

def vuln_to_dict(vuln: Any) -> Dict[str, Any]:
    """Normalize the different scanner dataclasses into one dict shape."""
    severity = getattr(vuln, "severity", "INFO")
    if hasattr(severity, "value"):
        severity = severity.value
    return {
        "name": getattr(vuln, "name", getattr(vuln, "vulnerability_type", "finding")),
        "severity": str(severity).upper(),
        "description": getattr(vuln, "description", ""),
        "remediation": getattr(vuln, "remediation", ""),
        "cvss": getattr(vuln, "cvss_score", 0.0),
        "target": getattr(vuln, "endpoint", ""),
    }


def print_vulns(vulns: List[Any], limit: int = 20) -> List[Dict[str, Any]]:
    """Print findings in a uniform block and return their dict form."""
    from core.ui import SEVERITY_STYLES, severity_line, _c

    rows = [vuln_to_dict(v) for v in vulns]
    if not rows:
        ok("No findings")
        return rows

    # Keep the block ordered worst-first so the top of the list is actionable.
    order = {name: i for i, name in enumerate(SEVERITY_STYLES)}
    rows.sort(key=lambda item: order.get(str(item["severity"]).upper(), len(order)))

    counts: Dict[str, int] = {}
    for item in rows:
        key = str(item["severity"]).upper()
        counts[key] = counts.get(key, 0) + 1
    summary = "  ".join(_c(f"{name}:{counts[name]}", SEVERITY_STYLES[name][0])
                       for name in order if name in counts)

    warn(f"{len(rows)} finding(s)  {summary}")
    for item in rows[:limit]:
        label = str(item["severity"]).upper()
        color = SEVERITY_STYLES.get(label, ("", ""))[0]
        print("  " + severity_line(label, item["name"]))
        if item["description"]:
            print(_c("        " + item["description"][:140], GREY))
        if item["remediation"]:
            print(f"        {_c('fix:', Fore.GREEN)} {item['remediation'][:140]}")
    if len(rows) > limit:
        info(f"... {len(rows) - limit} more not shown")
    return rows


def finish(number: int, name: str, target: str, result: Dict[str, Any], save: bool) -> Dict[str, Any]:
    """Optionally persist the result, then return it to the menu."""
    if save:
        path = export(result, number, name, target or "local")
        if path:
            ok(f"Report saved: {path}")
        else:
            warn("Could not write report file")
    return result


__all__ = [
    "normalize_url",
    "normalize_host",
    "split_service_target",
    "vuln_to_dict",
    "print_vulns",
    "finish",
    "Optional",
]
