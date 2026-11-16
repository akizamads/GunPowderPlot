"""
16 — Global Country Scan
========================
TARGET : local machine (no target) — probes the public surface of every selected country
ENGINE : global_scan.scan_countries (prefix report -> sample host -> TCP/TLS probe)
"""

from core import ask_optional, confirm, info, kv, table, warn
from modules.base import finish
from modules import LOCAL
import global_scan

NUMBER = 16
NAME = "Global Country Scan"
GROUP = "Reconnaissance"
SUMMARY = "Probe the public web surface of every country (or a picked list)"
TARGET = LOCAL
NEEDS = ()


def run(session, countries: str = "", samples: int = 5, source: str = "", save: bool = False) -> dict:
    print("  Countries: ISO alpha-2 codes, e.g. PH,ID,JP — blank or 'all' = every country")
    print("  Samples:   how many prefixes per country to inspect (default 5)")
    print("  Authorization: only run against systems you are allowed to assess.\n")

    if not countries:
        countries = ask_optional("Countries (blank = all)", default="all") or "all"
    if samples in (None, ""):
        samples = 5
    samples = max(1, min(int(samples), 20))
    if not source:
        source = ask_optional("Prefix file (blank = download public route report)", default="")

    info(f"Selecting countries: {countries}")
    if not confirm(f"Probe up to {samples} prefix(es) per country?", default=False):
        warn("Cancelled")
        return {"cancelled": True}

    def progress(line: str) -> None:
        print("   " + line)

    report = global_scan.scan_countries(
        [] if countries.lower() == "all" else [countries],
        samples=samples,
        source=source or None,
        progress=progress,
    )

    rows = []
    for country in report["countries"]:
        rows.append((
            country["country"],
            country["name"],
            country["status"],
            country["samples"],
            country["reachable_hosts"],
        ))
    table(["Code", "Country", "Status", "Samples", "Reachable"], rows)

    kv([
        ("Countries requested", report["countries_requested"]),
        ("Countries with data", report["ok"]),
        ("Countries without data", report["no_data"]),
        ("Reachable hosts", report["reachable_hosts"]),
        ("Duration (s)", report["duration_seconds"]),
    ])

    if save or confirm("Save report?", default=False):
        finish(NUMBER, NAME, "global", report, True)
    return report
