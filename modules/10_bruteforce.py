"""
10 — Credential Brute Force
===========================
TARGET : service:host (ssh / ftp / mysql / postgresql)
ENGINE : CredentialBruteForcer.test_ssh / test_ftp / test_database
"""

from core import ask, ask_int, confirm, info, kv, table, warn
from modules.base import finish, split_service_target
from modules import SERVICE
from bruteforce_exploiter import CredentialBruteForcer

NUMBER = 10
NAME = "Credential Brute Force"
GROUP = "Exploitation"
SUMMARY = "Try common credentials against SSH, FTP and databases"
TARGET = SERVICE
NEEDS = ("target",)

SUPPORTED = ["ssh", "ftp", "mysql", "postgresql"]
DEFAULT_PORTS = {"ssh": 22, "ftp": 21, "mysql": 3306, "postgresql": 5432}


def run(session, target: str = "", attempts: int = 5, port=None, save: bool = False) -> dict:
    warn("Authorized testing only — this locks out real accounts when abused")
    print("  Target:   service:host — e.g. ssh:10.0.0.5, ftp:ftp.example.com")
    print("  Attempts: how many common credential pairs to try per service\n")

    service, host = split_service_target(target or ask("service:host") or "", SUPPORTED)
    attempts = attempts or ask_int("Max attempts", default=5, minimum=1, maximum=50) or 5
    port = port or DEFAULT_PORTS[service]

    brute = CredentialBruteForcer(max_attempts=attempts)
    info(f"Testing {service} on {host}:{port} with up to {attempts} pair(s) ...")

    if service == "ssh":
        results = brute.test_ssh(host, port)
    elif service == "ftp":
        results = brute.test_ftp(host, port)
    else:
        results = brute.test_database(host, port, service)

    valid = [r for r in results if r.success]
    if valid:
        warn(f"{len(valid)} working credential(s) found")
        table(["Username", "Password", "Method"],
              [(r.username, r.password, r.method) for r in valid])
    else:
        info("No weak credentials accepted")

    kv([("Attempts made", len(results)), ("Successful", len(valid))])
    result = {
        "service": service,
        "host": host,
        "port": port,
        "attempts": len(results),
        "successful": [r.__dict__ for r in valid],
    }
    if save or confirm("Save report?", default=False):
        finish(NUMBER, NAME, f"{service}:{host}", result, True)
    return result
