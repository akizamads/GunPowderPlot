"""
Advanced Network Reconnaissance and Vulnerability Scanner
Main entry point with all scanning modules
"""

import socket
import re
import logging
from contextlib import closing
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from web_scanner import WebVulnerabilityScanner
from crypto_scanner import CryptoScanner
from auth_scanner import AuthScanner
from misconfig_scanner import MisconfigScanner
from dependency_scanner import DependencyScanner


logger = logging.getLogger(__name__)

PORT_SERVICES: Dict[int, Tuple[str, str]] = {
    21: ("FTP", "File Transfer Protocol"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Telnet Protocol"),
    25: ("SMTP", "Simple Mail Transfer Protocol"),
    53: ("DNS", "Domain Name System"),
    80: ("HTTP", "Hypertext Transfer Protocol"),
    110: ("POP3", "Post Office Protocol 3"),
    143: ("IMAP", "Internet Message Access Protocol"),
    443: ("HTTPS", "HTTP Secure"),
    445: ("SMB", "Server Message Block"),
    3306: ("MySQL", "MySQL Database"),
    3389: ("RDP", "Remote Desktop Protocol"),
    5432: ("PostgreSQL", "PostgreSQL Database"),
    5984: ("CouchDB", "CouchDB Database"),
    6379: ("Redis", "Redis Cache"),
    8080: ("HTTP-Alt", "HTTP Alternate"),
    9200: ("Elasticsearch", "Elasticsearch"),
    27017: ("MongoDB", "MongoDB Database"),
}

DEFAULT_SCAN_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
    1433, 3306, 3389, 5432, 5984, 6379, 8080, 8443, 9200, 27017, 28015,
]


class SeverityLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Vulnerability:
    name: str
    severity: SeverityLevel
    description: str
    remediation: str
    cvss_score: float = 0.0


SERVICE_VULNERABILITY_RULES: List[Dict] = [
    {
        "service": "FTP",
        "severity": SeverityLevel.HIGH,
        "name": "FTP Default Credentials",
        "description": "FTP service running - check for default credentials (admin/admin, anonymous)",
        "remediation": "Disable FTP, use SFTP instead. Implement strong authentication.",
        "cvss_score": 7.5,
    },
    {
        "service": "Telnet",
        "severity": SeverityLevel.CRITICAL,
        "name": "Insecure Telnet Protocol",
        "description": "Telnet transmits credentials in plaintext over the network",
        "remediation": "Replace Telnet with SSH",
        "cvss_score": 9.8,
    },
    {
        "service": "HTTP",
        "port": 80,
        "severity": SeverityLevel.HIGH,
        "name": "Unencrypted HTTP",
        "description": "HTTP (port 80) detected - no encryption",
        "remediation": "Use HTTPS/TLS encryption. Redirect HTTP to HTTPS.",
        "cvss_score": 7.5,
    },
    {
        "service": "MySQL",
        "severity": SeverityLevel.CRITICAL,
        "name": "Exposed Database Service",
        "description": "MySQL port 3306 exposed to network",
        "remediation": "Restrict database access to internal networks only",
        "cvss_score": 9.0,
    },
    {
        "service": "MongoDB",
        "severity": SeverityLevel.CRITICAL,
        "name": "Exposed MongoDB",
        "description": "MongoDB port 27017 exposed - possible unauthenticated access",
        "remediation": "Enable authentication, restrict network access",
        "cvss_score": 9.8,
    },
    {
        "service": "Redis",
        "severity": SeverityLevel.CRITICAL,
        "name": "Exposed Redis Cache",
        "description": "Redis port 6379 exposed - no built-in authentication",
        "remediation": "Use firewall rules, implement redis-auth, or use Redis cluster with authentication",
        "cvss_score": 8.6,
    },
]


@dataclass
class ServiceInfo:
    port: int
    protocol: str
    service: str
    version: str = "Unknown"
    vulnerabilities: Optional[List[Vulnerability]] = field(default_factory=list)


class AdvancedReconScanner:
    """Advanced vulnerability scanner with multiple detection modules"""

    def __init__(self, target: str, timeout: int = 5):
        self.target = target
        self.timeout = timeout
        self.services: List[ServiceInfo] = []
        self.vulnerabilities: List[Vulnerability] = []
        self.skipped_ports: List[Dict] = []

        # Initialize advanced scanners
        self.web_scanner = WebVulnerabilityScanner(target)
        self.crypto_scanner = CryptoScanner()
        self.auth_scanner = AuthScanner()
        self.misconfig_scanner = MisconfigScanner()
        self.dependency_scanner = DependencyScanner()

    def resolve_hostname(self) -> str:
        """Resolve target hostname to IP"""
        try:
            ip = socket.gethostbyname(self.target)
            return ip
        except socket.gaierror:
            raise ValueError(f"Could not resolve hostname: {self.target}")

    def check_dns(self) -> Dict:
        """Gather DNS information"""
        try:
            dns_info = {
                "hostname": self.target,
                "ip": self.resolve_hostname(),
                "reverse_dns": None,
            }
            try:
                reverse = socket.gethostbyaddr(dns_info["ip"])
                dns_info["reverse_dns"] = reverse[0]
            except socket.herror:
                pass
            return dns_info
        except Exception as e:
            return {"error": str(e)}

    def port_scan(self, ports: List[int] = None) -> List[ServiceInfo]:
        """Scan common ports for open services"""
        if ports is None:
            ports = list(DEFAULT_SCAN_PORTS)
        else:
            # Accept '80,443' / ['80'] / ['8000-8010'] from any caller, not just the menu.
            from core.prompt import parse_ports
            if isinstance(ports, str):
                ports = parse_ports(ports)
            elif isinstance(ports, (list, tuple, set)):
                text = ",".join(str(p) for p in ports)
                ports = parse_ports(text) or [int(p) for p in ports]
            else:
                ports = [int(ports)]
            if not ports:
                ports = list(DEFAULT_SCAN_PORTS)

        ip = self.resolve_hostname()
        open_services = []
        skipped_ports = []

        for port in ports:
            try:
                with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((ip, port))
                if result == 0:
                    service_info = self._identify_service(ip, port)
                    open_services.append(service_info)
            except OSError as e:
                skipped_ports.append({"port": port, "error": str(e)})
                logger.warning("Port %s scan on %s failed: %s", port, ip, e)

        self.services = open_services
        self.skipped_ports = skipped_ports
        return open_services

    def _identify_service(self, ip: str, port: int) -> ServiceInfo:
        """Identify service running on port"""
        service, _description = PORT_SERVICES.get(port, ("Unknown", "Unknown Service"))
        service_info = ServiceInfo(port=port, protocol="tcp", service=service)

        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
            if banner:
                service_info.version = banner[:100]
        except OSError as e:
            logger.debug("Banner grab on %s:%s failed: %s", ip, port, e)

        return service_info

    def _check_service_vulnerabilities(self, service: ServiceInfo) -> List[Vulnerability]:
        """Build the vulnerability list for a single detected service"""
        vulns: List[Vulnerability] = []
        for rule in SERVICE_VULNERABILITY_RULES:
            if rule["service"] != service.service:
                continue
            if rule.get("port") not in (None, service.port):
                continue
            vulns.append(Vulnerability(
                name=rule["name"],
                severity=rule["severity"],
                description=rule["description"],
                remediation=rule["remediation"],
                cvss_score=rule["cvss_score"],
            ))
        return vulns

    def check_vulnerabilities(self) -> List[Vulnerability]:
        """Check for common vulnerabilities"""
        all_vulns: List[Vulnerability] = []

        for service in self.services:
            vulns = self._check_service_vulnerabilities(service)
            service.vulnerabilities = vulns
            all_vulns.extend(vulns)

        self.vulnerabilities.extend(all_vulns)
        return all_vulns

    def run_advanced_scans(self, endpoints: List[str] = None, headers: Dict = None) -> Dict:
        """Run all advanced vulnerability scanners"""
        advanced_results = {
            "web_vulnerabilities": [],
            "crypto_vulnerabilities": [],
            "auth_vulnerabilities": [],
            "misconfig_vulnerabilities": [],
            "dependency_vulnerabilities": [],
        }

        # Web scanning
        if endpoints:
            sql_vulns = self.web_scanner.scan_sql_injection(endpoints)
            xss_vulns = self.web_scanner.scan_xss(endpoints)
            advanced_results["web_vulnerabilities"].extend(sql_vulns + xss_vulns)

        # Cryptography scanning
        tls_vulns = self.crypto_scanner.check_tls_configuration("TLSv1.2", ["AES-256-GCM"])
        advanced_results["crypto_vulnerabilities"].extend(tls_vulns)

        # Authentication scanning
        if not self.services:
            self.port_scan()
        for service in self.services:
            auth_vulns = self.auth_scanner.check_default_credentials(
                service.service, str(service.port)
            )
            advanced_results["auth_vulnerabilities"].extend(auth_vulns)

        # Misconfiguration scanning
        if headers:
            cors_vulns = self.misconfig_scanner.check_cors_misconfiguration(headers)
            info_vulns = self.misconfig_scanner.detect_information_disclosure(headers)
            advanced_results["misconfig_vulnerabilities"].extend(cors_vulns + info_vulns)

        return advanced_results

    def scan_dependencies(self, dependencies: List[Dict]) -> List:
        """Scan for vulnerable dependencies"""
        return self.dependency_scanner.check_dependencies(dependencies)

    def ssl_tls_check(self) -> Dict:
        """Check SSL/TLS certificate validity"""
        try:
            import ssl
            context = ssl.create_default_context()
            with socket.create_connection((self.resolve_hostname(), 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "subject": dict(x[0] for x in cert["subject"]),
                        "issuer": dict(x[0] for x in cert["issuer"]),
                        "version": ssock.version(),
                        "cipher": ssock.cipher(),
                    }
        except Exception as e:
            return {"error": str(e)}

    def get_summary(self) -> Dict:
        """Generate scan summary"""
        critical = sum(1 for v in self.vulnerabilities if v.severity == SeverityLevel.CRITICAL)
        high = sum(1 for v in self.vulnerabilities if v.severity == SeverityLevel.HIGH)
        medium = sum(1 for v in self.vulnerabilities if v.severity == SeverityLevel.MEDIUM)
        low = sum(1 for v in self.vulnerabilities if v.severity == SeverityLevel.LOW)

        return {
            "target": self.target,
            "total_services": len(self.services),
            "total_vulnerabilities": len(self.vulnerabilities),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        }
