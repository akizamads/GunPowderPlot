"""
Cryptography vulnerability scanner
Detects weak ciphers, certificates, and encryption issues
"""

import re
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class CryptoVulnerability:
    name: str
    severity: str
    description: str
    remediation: str
    cvss_score: float


class CryptoScanner:
    """Detect cryptographic weaknesses"""

    # Weak algorithms
    WEAK_ALGORITHMS = {
        "MD5": {"severity": "CRITICAL", "cvss": 9.1},
        "SHA1": {"severity": "HIGH", "cvss": 7.5},
        "DES": {"severity": "CRITICAL", "cvss": 9.8},
        "RC4": {"severity": "HIGH", "cvss": 8.1},
        "RSA-512": {"severity": "CRITICAL", "cvss": 9.3},
        "RSA-1024": {"severity": "HIGH", "cvss": 7.5},
    }

    # Weak TLS versions
    WEAK_TLS_VERSIONS = {
        "SSLv2": "CRITICAL",
        "SSLv3": "CRITICAL",
        "TLSv1.0": "HIGH",
        "TLSv1.1": "MEDIUM",
    }

    # Weak ciphers
    WEAK_CIPHERS = {
        "NULL": "CRITICAL",
        "EXPORT": "CRITICAL",
        "anon": "CRITICAL",
        "DES": "CRITICAL",
        "RC4": "HIGH",
        "MD5": "HIGH",
    }

    def __init__(self):
        self.vulnerabilities: List[CryptoVulnerability] = []

    def check_certificate_strength(self, cert_info: Dict) -> List[CryptoVulnerability]:
        """Check SSL/TLS certificate strength"""
        cert_vulns = []

        # Check key size
        key_size = cert_info.get("key_size", 0)
        if key_size < 2048:
            vuln = CryptoVulnerability(
                name="Weak Certificate Key",
                severity="HIGH",
                description=f"Certificate uses weak {key_size}-bit key (minimum 2048-bit recommended)",
                remediation="Regenerate certificate with at least 2048-bit RSA or 256-bit ECDSA key",
                cvss_score=7.5,
            )
            cert_vulns.append(vuln)

        # Check signature algorithm
        sig_algo = cert_info.get("signature_algorithm", "").upper()
        if "MD5" in sig_algo or "SHA1" in sig_algo:
            vuln = CryptoVulnerability(
                name="Weak Certificate Signature",
                severity="HIGH",
                description=f"Certificate signed with weak algorithm: {sig_algo}",
                remediation="Regenerate certificate signed with SHA-256 or stronger",
                cvss_score=7.5,
            )
            cert_vulns.append(vuln)

        self.vulnerabilities.extend(cert_vulns)
        return cert_vulns

    def check_tls_configuration(self, tls_version: str, ciphers: List[str]) -> List[CryptoVulnerability]:
        """Check TLS configuration"""
        tls_vulns = []

        # Check TLS version
        if tls_version in self.WEAK_TLS_VERSIONS:
            severity = self.WEAK_TLS_VERSIONS[tls_version]
            vuln = CryptoVulnerability(
                name=f"Weak TLS Version: {tls_version}",
                severity=severity,
                description=f"Server supports deprecated {tls_version}",
                remediation="Disable legacy TLS versions. Use TLS 1.2 or 1.3 only",
                cvss_score=8.1 if severity == "CRITICAL" else 6.5,
            )
            tls_vulns.append(vuln)

        # Check ciphers
        for cipher in ciphers:
            for weak_cipher, severity in self.WEAK_CIPHERS.items():
                if weak_cipher.lower() in cipher.lower():
                    vuln = CryptoVulnerability(
                        name=f"Weak Cipher: {cipher}",
                        severity=severity,
                        description=f"Weak cipher suite enabled: {cipher}",
                        remediation="Disable weak ciphers. Use only strong, modern cipher suites",
                        cvss_score=8.1 if severity == "CRITICAL" else 6.5,
                    )
                    tls_vulns.append(vuln)
                    break

        self.vulnerabilities.extend(tls_vulns)
        return tls_vulns

    def check_algorithm_usage(self, algorithms: List[str]) -> List[CryptoVulnerability]:
        """Check for weak algorithms in use"""
        algo_vulns = []

        for algo in algorithms:
            for weak_algo, details in self.WEAK_ALGORITHMS.items():
                if weak_algo.lower() in algo.lower():
                    vuln = CryptoVulnerability(
                        name=f"Weak Algorithm: {weak_algo}",
                        severity=details["severity"],
                        description=f"Application uses weak cryptographic algorithm: {weak_algo}",
                        remediation=f"Replace {weak_algo} with modern alternatives (SHA-256, AES-256, RSA-2048+)",
                        cvss_score=details["cvss"],
                    )
                    algo_vulns.append(vuln)
                    break

        self.vulnerabilities.extend(algo_vulns)
        return algo_vulns
