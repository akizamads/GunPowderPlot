"""
Authentication and API security scanner
Detects weak auth, API misconfigurations, and access control issues
"""

import re
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class AuthVulnerability:
    name: str
    severity: str
    description: str
    endpoint: str
    remediation: str
    cvss_score: float


class AuthScanner:
    """Detect authentication and authorization vulnerabilities"""

    # Common weak credentials
    WEAK_CREDENTIALS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("root", "root"),
        ("root", "password"),
        ("test", "test"),
        ("guest", "guest"),
    ]

    # Default credentials by service
    DEFAULT_CREDENTIALS = {
        "tomcat": [("tomcat", "tomcat"), ("admin", "s3cret")],
        "jboss": [("admin", "admin"), ("admin", "jboss")],
        "jenkins": [("admin", "admin")],
        "wordpress": [("admin", "admin"), ("admin", "")],
        "mysql": [("root", ""), ("root", "password")],
        "postgres": [("postgres", "postgres"), ("postgres", "password")],
        "mongodb": [("admin", ""), ("user", "")],
        "redis": [("", "")],  # Redis often has no auth
    }

    def __init__(self):
        self.vulnerabilities: List[AuthVulnerability] = []

    def check_default_credentials(self, service: str, endpoint: str) -> List[AuthVulnerability]:
        """Check for known default credentials"""
        auth_vulns = []

        if service.lower() in self.DEFAULT_CREDENTIALS:
            creds = self.DEFAULT_CREDENTIALS[service.lower()]
            for username, password in creds:
                vuln = AuthVulnerability(
                    name=f"Default Credentials: {service}",
                    severity="CRITICAL",
                    description=f"Service {service} may be using default credentials ({username}:{password})",
                    endpoint=endpoint,
                    remediation="Change default credentials immediately. Use strong, unique passwords.",
                    cvss_score=9.8,
                )
                auth_vulns.append(vuln)

        self.vulnerabilities.extend(auth_vulns)
        return auth_vulns

    def check_weak_password_policy(self, password_policy: str) -> List[AuthVulnerability]:
        """Check for weak password policies"""
        policy_vulns = []

        issues = []

        if not re.search(r"min.*length|minimum.*length", password_policy.lower()):
            issues.append("No minimum length requirement")

        if not re.search(r"special|symbol|character", password_policy.lower()):
            issues.append("No special character requirement")

        if not re.search(r"number|digit", password_policy.lower()):
            issues.append("No digit requirement")

        if not re.search(r"uppercase|upper", password_policy.lower()):
            issues.append("No uppercase requirement")

        if issues:
            vuln = AuthVulnerability(
                name="Weak Password Policy",
                severity="MEDIUM",
                description=f"Password policy is weak: {', '.join(issues)}",
                endpoint="Password Policy",
                remediation="Implement strong password policy: min 12 chars, uppercase, digits, special chars",
                cvss_score=6.5,
            )
            policy_vulns.append(vuln)

        self.vulnerabilities.extend(policy_vulns)
        return policy_vulns

    def detect_broken_authentication(self, auth_headers: Dict) -> List[AuthVulnerability]:
        """Detect broken authentication mechanisms"""
        auth_vulns = []

        # Check for missing authentication
        if not auth_headers or "authorization" not in [k.lower() for k in auth_headers.keys()]:
            vuln = AuthVulnerability(
                name="Missing Authentication",
                severity="CRITICAL",
                description="Endpoint is missing authentication mechanisms",
                endpoint="API Endpoint",
                remediation="Implement proper authentication (OAuth2, JWT, API keys)",
                cvss_score=9.1,
            )
            auth_vulns.append(vuln)

        # Check for basic auth without HTTPS
        auth_value = auth_headers.get("authorization", "").lower()
        if "basic" in auth_value:
            vuln = AuthVulnerability(
                name="HTTP Basic Authentication",
                severity="HIGH",
                description="Basic authentication detected - credentials transmitted in Base64 (easily decoded)",
                endpoint="API Endpoint",
                remediation="Use OAuth2, JWT, or API keys. Ensure HTTPS-only transmission.",
                cvss_score=8.1,
            )
            auth_vulns.append(vuln)

        self.vulnerabilities.extend(auth_vulns)
        return auth_vulns

    def check_api_security(self, endpoints: List[Dict]) -> List[AuthVulnerability]:
        """Check API security configurations"""
        api_vulns = []

        for endpoint in endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "").upper()
            auth = endpoint.get("auth", False)

            # Check for unauthenticated sensitive endpoints
            sensitive_keywords = ["admin", "user", "profile", "settings", "payment", "secret"]
            if not auth and any(keyword in path.lower() for keyword in sensitive_keywords):
                vuln = AuthVulnerability(
                    name="Unauthenticated Sensitive Endpoint",
                    severity="CRITICAL",
                    description=f"Sensitive endpoint {path} is unauthenticated",
                    endpoint=path,
                    remediation="Add authentication and authorization checks to all sensitive endpoints",
                    cvss_score=9.1,
                )
                api_vulns.append(vuln)

            # Check for missing rate limiting
            rate_limit = endpoint.get("rate_limit", None)
            if not rate_limit and method in ["POST", "PUT", "DELETE"]:
                vuln = AuthVulnerability(
                    name="Missing Rate Limiting",
                    severity="MEDIUM",
                    description=f"Endpoint {path} lacks rate limiting protection",
                    endpoint=path,
                    remediation="Implement rate limiting to prevent brute force and DoS attacks",
                    cvss_score=6.5,
                )
                api_vulns.append(vuln)

        self.vulnerabilities.extend(api_vulns)
        return api_vulns

    def detect_privilege_escalation(self, user_role: str, accessed_resources: List[str]) -> List[AuthVulnerability]:
        """Detect potential privilege escalation vulnerabilities"""
        privesc_vulns = []

        admin_resources = ["admin", "settings", "users", "logs", "config"]
        if user_role == "user" and any(res in accessed_resources for res in admin_resources):
            vuln = AuthVulnerability(
                name="Potential Privilege Escalation",
                severity="CRITICAL",
                description=f"User role accessed admin resources: {accessed_resources}",
                endpoint="Access Control",
                remediation="Implement proper role-based access control (RBAC). Validate permissions server-side.",
                cvss_score=9.8,
            )
            privesc_vulns.append(vuln)

        self.vulnerabilities.extend(privesc_vulns)
        return privesc_vulns
