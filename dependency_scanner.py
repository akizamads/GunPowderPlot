"""
Dependency and supply chain vulnerability scanner
Detects known vulnerabilities in libraries and components
"""

import re
from typing import List, Dict
from dataclasses import dataclass
from enum import Enum


@dataclass
class DependencyVulnerability:
    package: str
    version: str
    vulnerability_id: str
    severity: str
    description: str
    remediation: str
    cvss_score: float
    affected_versions: List[str]


class DependencyScanner:
    """Scan for vulnerable dependencies"""

    # Known vulnerable packages (simplified database)
    VULNERABLE_PACKAGES = {
        "log4j": {
            "2.14.0": [
                {
                    "id": "CVE-2021-44228",
                    "severity": "CRITICAL",
                    "description": "Remote Code Execution via JNDI injection",
                    "cvss": 10.0,
                    "affected": ["2.0", "2.14.1"],
                }
            ],
        },
        "struts2": {
            "2.3.15": [
                {
                    "id": "CVE-2017-5645",
                    "severity": "CRITICAL",
                    "description": "Remote Code Execution via REST plugin",
                    "cvss": 9.8,
                    "affected": ["2.3.0", "2.5.12"],
                }
            ],
        },
        "jquery": {
            "3.4.0": [
                {
                    "id": "CVE-2019-11358",
                    "severity": "MEDIUM",
                    "description": "Prototype pollution vulnerability",
                    "cvss": 6.1,
                    "affected": ["1.0", "3.4.0"],
                }
            ],
        },
        "django": {
            "2.2.0": [
                {
                    "id": "CVE-2019-6975",
                    "severity": "HIGH",
                    "description": "Denial of Service in Django",
                    "cvss": 7.5,
                    "affected": ["1.8", "2.2.7"],
                }
            ],
        },
        "jackson-databind": {
            "2.9.8": [
                {
                    "id": "CVE-2019-16335",
                    "severity": "CRITICAL",
                    "description": "Deserialization RCE",
                    "cvss": 9.8,
                    "affected": ["2.0", "2.9.10"],
                }
            ],
        },
    }

    def __init__(self):
        self.vulnerabilities: List[DependencyVulnerability] = []

    def check_dependencies(self, dependencies: List[Dict]) -> List[DependencyVulnerability]:
        """Check dependencies for known vulnerabilities"""
        dep_vulns = []

        for dep in dependencies:
            package = dep.get("name", "").lower()
            version = dep.get("version", "")

            if package in self.VULNERABLE_PACKAGES:
                vulns_by_version = self.VULNERABLE_PACKAGES[package]
                for vuln_version, vuln_list in vulns_by_version.items():
                    for vuln_entry in vuln_list:
                        if self._is_version_vulnerable(version, vuln_entry["affected"]):
                            vuln = DependencyVulnerability(
                                package=package,
                                version=version,
                                vulnerability_id=vuln_entry["id"],
                                severity=vuln_entry["severity"],
                                description=vuln_entry["description"],
                                remediation=f"Update {package} to latest patched version",
                                cvss_score=vuln_entry["cvss"],
                                affected_versions=vuln_entry["affected"],
                            )
                            dep_vulns.append(vuln)

        self.vulnerabilities.extend(dep_vulns)
        return dep_vulns

    def _is_version_vulnerable(self, current_version: str, affected_range: List[str]) -> bool:
        """Check if version is in affected range"""
        if not affected_range or len(affected_range) < 2:
            return False

        try:
            current = self._parse_version(current_version)
            min_ver = self._parse_version(affected_range[0])
            max_ver = self._parse_version(affected_range[-1])
            return min_ver <= current <= max_ver
        except Exception:
            return False

    def _parse_version(self, version: str) -> tuple:
        """Parse version string to tuple for comparison"""
        parts = re.findall(r"\d+", version)
        return tuple(int(p) for p in parts) if parts else (0,)

    def detect_outdated_packages(self, dependencies: List[Dict], latest_versions: Dict) -> List[DependencyVulnerability]:
        """Detect significantly outdated packages"""
        outdated_vulns = []

        for dep in dependencies:
            package = dep.get("name", "").lower()
            current_version = dep.get("version", "")

            if package in latest_versions:
                latest = latest_versions[package]
                current_tuple = self._parse_version(current_version)
                latest_tuple = self._parse_version(latest)

                # If multiple major versions behind
                if current_tuple and latest_tuple and current_tuple[0] < latest_tuple[0] - 1:
                    vuln = DependencyVulnerability(
                        package=package,
                        version=current_version,
                        vulnerability_id="OUTDATED",
                        severity="MEDIUM",
                        description=f"Package {package} is severely outdated (current: {current_version}, latest: {latest})",
                        remediation=f"Update {package} to version {latest} or latest stable release",
                        cvss_score=5.3,
                        affected_versions=[current_version, latest],
                    )
                    outdated_vulns.append(vuln)

        self.vulnerabilities.extend(outdated_vulns)
        return outdated_vulns
