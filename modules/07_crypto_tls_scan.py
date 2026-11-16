"""
07 — Crypto / TLS Policy Scan
=============================
TARGET : IP / Hostname
ENGINE : CryptoScanner.check_tls_configuration
"""

from core import ask, info, kv, table
from modules.base import finish, normalize_host, print_vulns
from modules import HOST
from crypto_scanner import CryptoScanner

NUMBER = 7
NAME = "Crypto / TLS Policy Scan"
GROUP = "Reconnaissance"
SUMMARY = "Evaluate negotiated TLS version and cipher suite strength"
TARGET = HOST
NEEDS = ("target",)

DEFAULT_CIPHERS = ["AES-256-GCM", "AES-128-CBC", "RC4", "3DES", "NULL"]


def run(session, target: str = "", tls_version: str = "TLSv1.2", ciphers=None,
        save: bool = False) -> dict:
    print("  Target:       hostname or IP")
    print("  TLS version:  TLSv1.2 / TLSv1.3 / TLSv1.1 / TLSv1\n")

    target = normalize_host(target) if target else normalize_host(ask("Target host") or "")
    if ciphers is None:
        ciphers = list(DEFAULT_CIPHERS)

    scanner = CryptoScanner()
    info(f"Evaluating {tls_version} cipher policy on {target}")
    table(["#", "Cipher"], [(i, c) for i, c in enumerate(ciphers, 1)])

    vulns = scanner.check_tls_configuration(tls_version, ciphers)
    findings = print_vulns(vulns)

    kv([("TLS version", tls_version), ("Ciphers checked", len(ciphers)),
        ("Findings", len(findings))])
    result = {
        "target": target,
        "tls_version": tls_version,
        "ciphers": ciphers,
        "vulnerabilities": findings,
    }
    finish(NUMBER, NAME, target, result, save)
    return result
