"""
Misconfiguration and infrastructure vulnerability scanner
Detects CORS, headers, cloud misconfigs, and infrastructure issues
"""

import re
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class MisconfigVulnerability:
    name: str
    severity: str
    description: str
    component: str
    remediation: str
    cvss_score: float


class MisconfigScanner:
    """Detect misconfigurations and infrastructure vulnerabilities"""

    DANGEROUS_CORS_HEADERS = [
        "Access-Control-Allow-Origin: *",
        "Access-Control-Allow-Credentials: true",
    ]

    VERBOSE_HEADERS = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-Runtime",
    ]

    MISSING_SECURITY_HEADERS = {
        "Strict-Transport-Security": "HSTS enforcement",
        "X-Content-Type-Options": "MIME type sniffing protection",
        "X-Frame-Options": "Clickjacking protection",
        "Content-Security-Policy": "XSS/injection prevention",
        "Permissions-Policy": "Feature policy enforcement",
    }

    def __init__(self):
        self.vulnerabilities: List[MisconfigVulnerability] = []

    def check_cors_misconfiguration(self, cors_headers: Dict) -> List[MisconfigVulnerability]:
        """Detect CORS misconfigurations"""
        cors_vulns = []

        allow_origin = cors_headers.get("Access-Control-Allow-Origin", "")

        # Wildcard CORS
        if allow_origin == "*":
            vuln = MisconfigVulnerability(
                name="Unrestricted CORS",
                severity="HIGH",
                description="CORS allows requests from any origin (*)",
                component="CORS Configuration",
                remediation="Specify only trusted origins in CORS policy. Never use wildcard (*)",
                cvss_score=7.5,
            )
            cors_vulns.append(vuln)

        # Credentials with wildcard
        if allow_origin == "*" and cors_headers.get("Access-Control-Allow-Credentials") == "true":
            vuln = MisconfigVulnerability(
                name="CORS with Credentials Leakage",
                severity="CRITICAL",
                description="CORS allows credentials to be sent to any origin",
                component="CORS Configuration",
                remediation="Never combine wildcard CORS with credential sharing",
                cvss_score=9.1,
            )
            cors_vulns.append(vuln)

        self.vulnerabilities.extend(cors_vulns)
        return cors_vulns

    def detect_information_disclosure(self, response_headers: Dict) -> List[MisconfigVulnerability]:
        """Detect information disclosure through headers"""
        info_vulns = []

        for header in self.VERBOSE_HEADERS:
            if header in response_headers:
                value = response_headers[header]
                vuln = MisconfigVulnerability(
                    name=f"Information Disclosure: {header}",
                    severity="MEDIUM",
                    description=f"Server reveals sensitive information via {header}: {value}",
                    component="HTTP Headers",
                    remediation=f"Remove or obscure {header} header. Configure web server to hide version info.",
                    cvss_score=5.3,
                )
                info_vulns.append(vuln)

        self.vulnerabilities.extend(info_vulns)
        return info_vulns

    def check_security_headers(self, response_headers: Dict) -> List[MisconfigVulnerability]:
        """Check for missing security headers"""
        header_vulns = []

        for header_name, description in self.MISSING_SECURITY_HEADERS.items():
            if header_name not in response_headers:
                severity = "HIGH" if header_name in ["Strict-Transport-Security", "X-Frame-Options"] else "MEDIUM"
                vuln = MisconfigVulnerability(
                    name=f"Missing Security Header: {header_name}",
                    severity=severity,
                    description=f"Missing {header_name} header - {description}",
                    component="HTTP Headers",
                    remediation=f"Add {header_name} header to all HTTP responses",
                    cvss_score=7.5 if severity == "HIGH" else 5.3,
                )
                header_vulns.append(vuln)

        self.vulnerabilities.extend(header_vulns)
        return header_vulns

    def detect_cloud_misconfiguration(self, config: Dict) -> List[MisconfigVulnerability]:
        """Detect cloud service misconfigurations"""
        cloud_vulns = []

        # S3 bucket checks
        if config.get("service") == "s3":
            if config.get("public_read") or config.get("public_write"):
                severity = "CRITICAL" if config.get("public_write") else "HIGH"
                vuln = MisconfigVulnerability(
                    name="S3 Bucket Misconfiguration",
                    severity=severity,
                    description=f"S3 bucket {config.get('name')} is publicly accessible",
                    component=f"AWS S3: {config.get('name')}",
                    remediation="Disable public access. Use bucket policies and IAM roles for access control.",
                    cvss_score=9.1 if severity == "CRITICAL" else 7.5,
                )
                cloud_vulns.append(vuln)

        # Database checks
        if config.get("service") in ["rds", "dynamodb"]:
            if config.get("publicly_accessible"):
                vuln = MisconfigVulnerability(
                    name="Database Publicly Accessible",
                    severity="CRITICAL",
                    description=f"{config.get('service')} instance is publicly accessible",
                    component=f"AWS {config.get('service')}",
                    remediation="Disable public accessibility. Use VPC and security groups for access control.",
                    cvss_score=9.8,
                )
                cloud_vulns.append(vuln)

            if not config.get("encryption"):
                vuln = MisconfigVulnerability(
                    name="Database Encryption Disabled",
                    severity="HIGH",
                    description=f"{config.get('service')} is not encrypted at rest",
                    component=f"AWS {config.get('service')}",
                    remediation="Enable encryption at rest using KMS",
                    cvss_score=8.1,
                )
                cloud_vulns.append(vuln)

        self.vulnerabilities.extend(cloud_vulns)
        return cloud_vulns

    def detect_directory_traversal(self, paths: List[str]) -> List[MisconfigVulnerability]:
        """Detect directory traversal vulnerabilities"""
        dt_vulns = []

        traversal_patterns = [r"\.\./", r"\.\.\\", r"%2e%2e/", r"%252e%252e/"]

        for path in paths:
            for pattern in traversal_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    vuln = MisconfigVulnerability(
                        name="Directory Traversal",
                        severity="HIGH",
                        description=f"Path traversal pattern detected in: {path}",
                        component="Path Handling",
                        remediation="Validate and sanitize all file paths. Use allowlists for accessible directories.",
                        cvss_score=7.5,
                    )
                    dt_vulns.append(vuln)
                    break

        self.vulnerabilities.extend(dt_vulns)
        return dt_vulns

    def check_insecure_deserialization(self, data: str) -> List[MisconfigVulnerability]:
        """Detect insecure deserialization"""
        deser_vulns = []

        # Check for common serialization indicators
        if re.search(r"pickle|ObjectInputStream|readObject", data):
            vuln = MisconfigVulnerability(
                name="Insecure Deserialization",
                severity="CRITICAL",
                description="Application deserializes untrusted data using unsafe methods",
                component="Serialization",
                remediation="Use safe serialization formats (JSON). Validate and verify deserialized objects.",
                cvss_score=9.8,
            )
            deser_vulns.append(vuln)

        self.vulnerabilities.extend(deser_vulns)
        return deser_vulns
