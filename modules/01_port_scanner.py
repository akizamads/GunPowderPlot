"""
01 — Port Scanner
=================
TARGET : IP / Hostname
ENGINE : AdvancedReconScanner.port_scan / _identify_service
"""

from core import ask, ask_ports, confirm, err, info, ok, table, warn
from modules.base import finish, normalize_host
from modules import HOST
from scanner import AdvancedReconScanner

NUMBER = 1
NAME = "Port Scanner"
GROUP = "Reconnaissance"
SUMMARY = "Scan TCP ports, identify services and grab banners"
TARGET = HOST
NEEDS = ("target",)


def run(session, target: str = "", ports=None, timeout: int = 5, save: bool = False) -> dict:
    print("  Target:                IP or hostname, e.g. 10.0.0.5 or example.com")
    print("  Ports:                 comma list / ranges (blank = default 25 ports)\n")

    target = normalize_host(target) if target else normalize_host(ask("Target host") or "")
    if ports is None:
        ports = ask_ports("Ports", default="")
    if timeout is None:
        timeout = 5

    scanner = AdvancedReconScanner(target, timeout=timeout)
    info(f"Resolving {target} ...")
    dns = scanner.check_dns()
    if "error" in dns:
        err(dns["error"])
        return {"target": target, "error": dns["error"]}

    info(f"{target} -> {dns['ip']}  (reverse: {dns.get('reverse_dns') or 'n/a'})")
    info("Scanning ports ...")
    services = scanner.port_scan(ports)

    if services:
        ok(f"{len(services)} open port(s)")
        table(
            ["Port", "Service", "Protocol", "Banner/Version"],
            [(s.port, s.service, s.protocol, s.version) for s in services],
        )
    else:
        warn("No open ports found")

    if scanner.skipped_ports:
        warn(f"{len(scanner.skipped_ports)} port(s) skipped due to errors")

    result = {
        "target": target,
        "ip": dns["ip"],
        "reverse_dns": dns.get("reverse_dns"),
        "open_ports": [
            {"port": s.port, "service": s.service, "protocol": s.protocol, "banner": s.version}
            for s in services
        ],
        "skipped_ports": scanner.skipped_ports,
    }
    if save or confirm("Save report?", default=False):
        finish(NUMBER, NAME, target, result, True)
    return result
