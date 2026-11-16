"""
04 — Default Credentials Check
==============================
TARGET : service:host (mysql / postgres / mongodb / redis / tomcat / jenkins ...)
ENGINE : AuthScanner.check_default_credentials
"""

from core import ask, ask_int, info, kv
from modules.base import finish, print_vulns, split_service_target
from modules import DB
from auth_scanner import AuthScanner

NUMBER = 4
NAME = "Default Credentials Check"
GROUP = "Reconnaissance"
SUMMARY = "Check services for known vendor default credentials"
TARGET = DB
NEEDS = ("target",)

SUPPORTED = ["mysql", "postgres", "mongodb", "redis", "tomcat", "jboss", "jenkins", "wordpress"]


def run(session, target: str = "", port=None, save: bool = False) -> dict:
    print("  Target:  service:host — e.g. mysql:10.0.0.5, redis:db.internal")
    print(f"  Services: {', '.join(SUPPORTED)}\n")

    service, host = split_service_target(target or ask("service:host") or "", SUPPORTED)
    if port is None and not target:
        port = ask_int("Port (blank = service default)", default=None, minimum=1, maximum=65535)

    scanner = AuthScanner()
    endpoint = f"{host}:{port}" if port else host
    info(f"Checking {service} default credentials on {endpoint} ...")
    vulns = scanner.check_default_credentials(service, endpoint)

    findings = print_vulns(vulns)
    kv([
        ("Service", service),
        ("Endpoint", endpoint),
        ("Weak credential sets", len(scanner.DEFAULT_CREDENTIALS.get(service, []))),
        ("Findings", len(findings)),
    ])

    result = {"service": service, "endpoint": endpoint, "vulnerabilities": findings}
    finish(NUMBER, NAME, endpoint, result, save)
    return result
