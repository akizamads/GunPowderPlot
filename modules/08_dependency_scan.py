"""
08 — Dependency Vulnerability Scan
==================================
TARGET : local manifest (requirements.txt / package.json) or manual list
ENGINE : DependencyScanner.check_dependencies
"""

from core import ask_optional, confirm, info, kv, table
from modules.base import finish, print_vulns
from modules import LOCAL
from core.files import read_lines
from dependency_scanner import DependencyScanner

NUMBER = 8
NAME = "Dependency Vulnerability Scan"
GROUP = "Reconnaissance"
SUMMARY = "Match project dependencies against known vulnerable versions"
TARGET = LOCAL
NEEDS = ("manifest",)


def run(session, manifest: str = "", target: str = "local", save: bool = False) -> dict:
    print("  Manifest: path to requirements.txt / package.json (blank = manual list)\n")

    import os

    target_label = manifest or ask_optional("Manifest path", default="requirements.txt")
    if not target_label:
        target_label = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "requirements.txt")
    dependencies = _load_manifest(target_label)

    if not dependencies:
        info("No parsable dependencies found — enter them manually as name==version")
        raw = ask_optional("Dependencies (name==version, comma separated)")
        dependencies = _parse_pairs(raw or "")

    if not dependencies:
        table(["#", "Package", "Version"], [])
        return {"manifest": target_label, "dependencies": [], "vulnerabilities": []}

    table(["Package", "Version"], [(d["name"], d["version"]) for d in dependencies])

    scanner = DependencyScanner()
    info(f"Checking {len(dependencies)} dependency(ies) against the CVE table ...")
    vulns = scanner.check_dependencies(dependencies)
    findings = print_vulns(vulns)

    kv([("Manifest", target_label), ("Dependencies", len(dependencies)),
        ("Vulnerable packages", len(findings))])
    result = {
        "manifest": target_label,
        "dependencies": dependencies,
        "vulnerabilities": findings,
    }
    if save or confirm("Save report?", default=False):
        finish(NUMBER, NAME, target_label, result, True)
    return result


def _load_manifest(path: str) -> list:
    """Read requirements.txt or package.json into [{name, version}]."""
    if not path:
        return []
    try:
        lowered = path.lower()
        if lowered.endswith(".json"):
            import json
            from core.files import read_text
            payload = json.loads(read_text(path))
            deps = {}
            deps.update(payload.get("dependencies", {}))
            deps.update(payload.get("devDependencies", {}))
            return [{"name": k, "version": str(v).lstrip("^~=")} for k, v in deps.items()]
        return _parse_pairs(",".join(read_lines(path)))
    except FileNotFoundError:
        info(f"{path} not found — switching to manual entry")
        return []
    except Exception as exc:  # malformed manifest should not kill the menu
        info(f"Could not parse {path}: {exc}")
        return []


def _parse_pairs(raw: str) -> list:
    deps = []
    for chunk in raw.replace(";", ",").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        for sep in ("==", ">=", "~=", "="):
            if sep in chunk:
                name, _, version = chunk.partition(sep)
                deps.append({"name": name.strip(), "version": version.strip()})
                break
        else:
            deps.append({"name": chunk, "version": "unknown"})
    return deps
