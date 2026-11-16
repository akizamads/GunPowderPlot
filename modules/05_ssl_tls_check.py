"""
05 — SSL / TLS Certificate Check
================================
TARGET : IP / Hostname
ENGINE : AdvancedReconScanner.ssl_tls_check
"""

from core import ask, kv, warn
from modules.base import finish, normalize_host
from modules import HOST
from scanner import AdvancedReconScanner

NUMBER = 5
NAME = "SSL / TLS Certificate Check"
GROUP = "Reconnaissance"
SUMMARY = "Fetch certificate subject/issuer, TLS version and cipher"
TARGET = HOST
NEEDS = ("target",)


def run(session, target: str = "", save: bool = False) -> dict:
    print("  Target:  hostname or IP serving HTTPS on port 443\n")

    target = normalize_host(target) if target else normalize_host(ask("Target host") or "")
    scanner = AdvancedReconScanner(target)
    cert = scanner.ssl_tls_check()

    if "error" in cert:
        warn(f"TLS handshake failed: {cert['error']}")
        result = {"target": target, "error": cert["error"]}
    else:
        cipher = cert.get("cipher") or ("unknown", "", 0)
        kv([
            ("Subject", cert.get("subject", {})),
            ("Issuer", cert.get("issuer", {})),
            ("TLS version", cert.get("version", "unknown")),
            ("Cipher", cipher[0]),
            ("Key bits", cipher[2] if len(cipher) > 2 else "n/a"),
        ])
        if str(cert.get("version")) in ("TLSv1", "TLSv1.1"):
            warn("Legacy TLS version negotiated — upgrade to TLS 1.2+")
        result = {"target": target, "certificate": cert}

    finish(NUMBER, NAME, target, result, save)
    return result
