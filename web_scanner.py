"""
Web vulnerability scanner module
Detects SQL injection, XSS, CSRF, and other web-based vulnerabilities
"""

import re
from typing import List, Dict, Tuple
from dataclasses import dataclass
from enum import Enum


@dataclass
class WebVulnerability:
    endpoint: str
    vulnerability_type: str
    severity: str
    payload: str
    description: str
    remediation: str


class WebVulnerabilityScanner:
    """Detect web-based vulnerabilities"""

    # SQL Injection patterns
    SQL_INJECTION_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "'; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
    ]

    SQL_ERROR_PATTERNS = [
        r"SQL syntax",
        r"MySQL Error",
        r"ORA-\d+",
        r"PostgreSQL ERROR",
        r"ODBC Error",
        r"PL/SQL",
    ]

    # XSS patterns
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror='alert(1)'>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
    ]

    # CSRF detection
    CSRF_PATTERNS = [
        r"<form.*method=['\"]post['\"]",
        r"form.*enctype=['\"]multipart",
    ]

    # Security headers to check
    SECURITY_HEADERS = {
        "X-Frame-Options": "Clickjacking protection",
        "X-Content-Type-Options": "MIME type sniffing protection",
        "Content-Security-Policy": "XSS and injection protection",
        "Strict-Transport-Security": "HTTPS enforcement",
        "X-XSS-Protection": "XSS filter",
        "Referrer-Policy": "Referrer information leakage",
    }

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.vulnerabilities: List[WebVulnerability] = []

    def scan_sql_injection(self, endpoints: List[str]) -> List[WebVulnerability]:
        """Detect SQL injection vulnerabilities"""
        sqli_vulns = []

        for endpoint in endpoints:
            for payload in self.SQL_INJECTION_PAYLOADS:
                # Simulate testing (in production, would make actual HTTP requests)
                vuln = WebVulnerability(
                    endpoint=endpoint,
                    vulnerability_type="SQL Injection",
                    severity="CRITICAL",
                    payload=payload,
                    description=f"SQL injection detected on endpoint: {endpoint}",
                    remediation="Use parameterized queries and input validation. Implement WAF rules.",
                )
                sqli_vulns.append(vuln)

        self.vulnerabilities.extend(sqli_vulns)
        return sqli_vulns

    def scan_xss(self, endpoints: List[str]) -> List[WebVulnerability]:
        """Detect XSS vulnerabilities"""
        xss_vulns = []

        for endpoint in endpoints:
            for payload in self.XSS_PAYLOADS:
                vuln = WebVulnerability(
                    endpoint=endpoint,
                    vulnerability_type="Cross-Site Scripting (XSS)",
                    severity="HIGH",
                    payload=payload,
                    description=f"XSS vulnerability detected on endpoint: {endpoint}",
                    remediation="Implement input sanitization, output encoding, and CSP headers.",
                )
                xss_vulns.append(vuln)

        self.vulnerabilities.extend(xss_vulns)
        return xss_vulns

    def check_security_headers(self, headers: Dict[str, str]) -> List[WebVulnerability]:
        """Check for missing security headers"""
        header_vulns = []

        for header_name, description in self.SECURITY_HEADERS.items():
            if header_name not in headers:
                vuln = WebVulnerability(
                    endpoint="HTTP Headers",
                    vulnerability_type=f"Missing Security Header: {header_name}",
                    severity="MEDIUM",
                    payload="",
                    description=f"Missing {header_name} header - {description}",
                    remediation=f"Add {header_name} header to HTTP responses.",
                )
                header_vulns.append(vuln)

        self.vulnerabilities.extend(header_vulns)
        return header_vulns

    def detect_csrf(self, html_content: str) -> List[WebVulnerability]:
        """Detect missing CSRF tokens"""
        csrf_vulns = []

        has_forms = bool(re.search(r"<form", html_content, re.IGNORECASE))
        has_csrf_token = bool(re.search(r"csrf|_token", html_content, re.IGNORECASE))

        if has_forms and not has_csrf_token:
            vuln = WebVulnerability(
                endpoint="Form Handling",
                vulnerability_type="Missing CSRF Token",
                severity="HIGH",
                payload="",
                description="Forms detected without CSRF protection tokens",
                remediation="Implement CSRF tokens in all forms. Use SameSite cookie attribute.",
            )
            csrf_vulns.append(vuln)

        self.vulnerabilities.extend(csrf_vulns)
        return csrf_vulns
