"""
03 — Web Vulnerability Scan
===========================
TARGET : URL (http/https)
ENGINE : WebVulnerabilityScanner.scan_sql_injection / scan_xss
"""

from core import ask, ask_list, info, table
from modules.base import finish, normalize_url, print_vulns
from modules import URL
from web_scanner import WebVulnerabilityScanner

NUMBER = 3
NAME = "Web Vulnerability Scan"
GROUP = "Reconnaissance"
SUMMARY = "Test web endpoints for SQL injection and XSS"
TARGET = URL
NEEDS = ("target", "endpoints")

DEFAULT_ENDPOINTS = ["/login", "/search", "/api/users", "/submit"]


def run(session, target: str = "", endpoints=None, save: bool = False) -> dict:
    print("  Target:     full URL, e.g. https://10.0.0.5 or http://example.com")
    print("  Endpoints:  paths to test, comma separated\n")

    target = normalize_url(target) if target else normalize_url(ask("Target URL") or "")
    if endpoints is None:
        endpoints = ask_list("Endpoints", default=DEFAULT_ENDPOINTS)
    if not endpoints:
        endpoints = list(DEFAULT_ENDPOINTS)

    scanner = WebVulnerabilityScanner(target)
    info(f"Scanning {len(endpoints)} endpoint(s) on {target}")
    table(["#", "Endpoint"], [(i, e) for i, e in enumerate(endpoints, 1)])

    info("Testing SQL injection ...")
    sqli = scanner.scan_sql_injection(endpoints)
    info("Testing XSS ...")
    xss = scanner.scan_xss(endpoints)

    findings = print_vulns(sqli + xss)
    result = {"target": target, "endpoints": endpoints, "vulnerabilities": findings}
    finish(NUMBER, NAME, target, result, save)
    return result
