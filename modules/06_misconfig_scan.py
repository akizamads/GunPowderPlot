"""
06 — Web Misconfiguration Scan
==============================
TARGET : URL (http/https) + optional custom headers
ENGINE : MisconfigScanner.check_cors_misconfiguration / detect_information_disclosure
"""

from core import ask_optional, info, kv, table
from modules.base import finish, normalize_url, print_vulns
from modules import URL
from misconfig_scanner import MisconfigScanner

NUMBER = 6
NAME = "Web Misconfiguration Scan"
GROUP = "Reconnaissance"
SUMMARY = "Check CORS policy, verbose headers and missing security headers"
TARGET = URL
NEEDS = ("target",)


def run(session, target: str = "", headers=None, save: bool = False) -> dict:
    print("  Target:   URL to inspect for CORS / header hardening")
    print("  Headers:  optional extras as name:value,name:value\n")

    target = normalize_url(target) if target else normalize_url(input("  Target URL: ").strip())
    if headers is None:
        headers = _parse_headers(ask_optional("Extra response headers", default="")) or {}

    scanner = MisconfigScanner()
    info(f"Analysing header policy for {target}")
    if headers:
        table(["Header", "Value"], [(k, v) for k, v in headers.items()])
    else:
        info("No custom headers supplied — checking default policy expectations")

    cors = scanner.check_cors_misconfiguration(headers)
    disclosure = scanner.detect_information_disclosure(headers)
    findings = print_vulns(cors + disclosure)

    kv([
        ("Custom headers supplied", len(headers)),
        ("CORS findings", len(cors)),
        ("Disclosure findings", len(disclosure)),
    ])
    result = {"target": target, "headers": headers, "vulnerabilities": findings}
    finish(NUMBER, NAME, target, result, save)
    return result


def _parse_headers(raw: str) -> dict:
    headers = {}
    for chunk in raw.split(","):
        if ":" in chunk:
            key, _, value = chunk.partition(":")
            headers[key.strip()] = value.strip()
    return headers
