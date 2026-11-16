"""
02 — Service Vulnerability Check
================================
TARGET : IP / Hostname
ENGINE : AdvancedReconScanner.port_scan + check_vulnerabilities
"""

from core import ask, confirm, info, kv, table, warn
from modules.base import finish, normalize_host, print_vulns
from modules import HOST
from scanner import AdvancedReconScanner

NUMBER = 2
NAME = "Service Vulnerability Check"
GROUP = "Reconnaissance"
SUMMARY = "Detect exposed/legacy services and rate their risk"
TARGET = HOST
NEEDS = ("target",)


def run(session, target: str = "", ports=None, save: bool = False) -> dict:
    print("  Target:  IP or hostname\n")

    target = normalize_host(target) if target else normalize_host(ask("Target host") or "")

    scanner = AdvancedReconScanner(target)
    info("Port scan ...")
    services = scanner.port_scan(ports)
    if not services:
        warn("No open services detected — nothing to check")
        return {"target": target, "services": [], "vulnerabilities": []}

    table(["Port", "Service"], [(s.port, s.service) for s in services])

    info("Correlating service exposures ...")
    vulns = scanner.check_vulnerabilities()
    findings = print_vulns(vulns)

    summary = scanner.get_summary()
    print()
    kv([
        ("Services", summary["total_services"]),
        ("Critical", summary["critical"]),
        ("High", summary["high"]),
        ("Medium", summary["medium"]),
        ("Low", summary["low"]),
    ])

    result = {
        "target": target,
        "services": [{"port": s.port, "service": s.service} for s in services],
        "vulnerabilities": findings,
        "summary": summary,
    }
    if save or confirm("Save report?", default=False):
        finish(NUMBER, NAME, target, result, True)
    return result
