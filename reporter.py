"""
Reporting module for vulnerability scan results
Generates formatted reports in multiple formats
"""

import json
from datetime import datetime
from typing import Dict, List
from tabulate import tabulate
from scanner import Vulnerability, SeverityLevel


class ReportGenerator:
    """Generate vulnerability scan reports"""

    def __init__(self, scan_data: Dict):
        self.scan_data = scan_data
        self.timestamp = datetime.now().isoformat()

    def generate_text_report(self) -> str:
        """Generate human-readable text report"""
        lines = []
        lines.append("=" * 80)
        lines.append("VULNERABILITY SCAN REPORT")
        lines.append("=" * 80)
        lines.append(f"Target: {self.scan_data['target']}")
        lines.append(f"Scan Date: {self.timestamp}")
        lines.append("")

        # Summary
        summary = self.scan_data.get('summary', {})
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Total Services Found: {summary.get('total_services', 0)}")
        lines.append(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        lines.append(f"  Critical: {summary.get('critical', 0)}")
        lines.append(f"  High: {summary.get('high', 0)}")
        lines.append(f"  Medium: {summary.get('medium', 0)}")
        lines.append(f"  Low: {summary.get('low', 0)}")
        lines.append("")

        # DNS Information
        if self.scan_data.get('dns_info'):
            lines.append("DNS INFORMATION")
            lines.append("-" * 80)
            dns = self.scan_data['dns_info']
            lines.append(f"Hostname: {dns.get('hostname', 'N/A')}")
            lines.append(f"IP Address: {dns.get('ip', 'N/A')}")
            lines.append(f"Reverse DNS: {dns.get('reverse_dns', 'N/A')}")
            lines.append("")

        # Services
        if self.scan_data.get('services'):
            lines.append("OPEN SERVICES")
            lines.append("-" * 80)
            services_table = []
            for svc in self.scan_data['services']:
                services_table.append([
                    svc['port'],
                    svc['protocol'],
                    svc['service'],
                    svc.get('version', 'Unknown')[:50]
                ])
            lines.append(tabulate(services_table, 
                                 headers=["Port", "Protocol", "Service", "Version"],
                                 tablefmt="grid"))
            lines.append("")

        # Vulnerabilities
        if self.scan_data.get('vulnerabilities'):
            lines.append("VULNERABILITIES")
            lines.append("-" * 80)
            for vuln in self.scan_data['vulnerabilities']:
                lines.append(f"\n[{vuln['severity']}] {vuln['name']} (CVSS: {vuln['cvss_score']})")
                lines.append(f"Description: {vuln['description']}")
                lines.append(f"Remediation: {vuln['remediation']}")

        lines.append("\n" + "=" * 80)
        return "\n".join(lines)

    def generate_json_report(self) -> str:
        """Generate JSON report"""
        report = {
            "metadata": {
                "scan_date": self.timestamp,
                "target": self.scan_data['target'],
            },
            "summary": self.scan_data.get('summary', {}),
            "dns_info": self.scan_data.get('dns_info', {}),
            "services": self.scan_data.get('services', []),
            "vulnerabilities": self.scan_data.get('vulnerabilities', []),
        }
        return json.dumps(report, indent=2)

    def generate_csv_report(self) -> str:
        """Generate CSV report"""
        lines = ["Port,Protocol,Service,Version,Vulnerabilities"]
        for svc in self.scan_data.get('services', []):
            vuln_count = len([v for v in self.scan_data.get('vulnerabilities', [])
                            if v.get('port') == svc['port']])
            lines.append(f"{svc['port']},{svc['protocol']},{svc['service']}"
                        f",\"{svc.get('version', 'Unknown')[:50]}\",{vuln_count}")
        return "\n".join(lines)

    def save_report(self, filename: str, format: str = "text"):
        """Save report to file"""
        if format == "json":
            content = self.generate_json_report()
        elif format == "csv":
            content = self.generate_csv_report()
        else:
            content = self.generate_text_report()

        with open(filename, 'w') as f:
            f.write(content)
        return filename
