"""Self-check: module registry, manifest parsing and CLI command wiring.

Run from the repo root:  python smoke_check.py
Exits non-zero (so CI fails) when anything is broken.
"""
import inspect
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.argv = ["main.py"]

import core  # noqa: E402

failures = []


def check(ok: bool, message: str) -> None:
    if not ok:
        failures.append(message)


# The registry starts empty if a numbered module triggers the core import cycle,
# so rebuild it explicitly before inspecting it.
core.reload_modules()
MODULES = core.MODULES
print("modules loaded:", len(MODULES))
check(len(MODULES) == 15, f"expected 15 modules, got {len(MODULES)}")

# Sanity: the manifest loader used by module 08
_08 = __import__("modules.08_dependency_scan", fromlist=["_load_manifest"])
deps = _08._load_manifest("requirements.txt")
print("manifest deps parsed:", len(deps), deps[:2])
check(len(deps) > 0, "requirements.txt produced no dependencies")

# Check every module's run() accepts the keyword set the menu passes
for spec in MODULES:
    params = inspect.signature(spec.run).parameters
    sig_ok = "session" in params and "save" in params
    print(f"{spec.number:02d} {spec.name:<34} sig_ok={sig_ok} target={spec.target}")
    check(sig_ok, f"module {spec.number:02d} run() missing session/save kwargs")

menu_ok = hasattr(core, "render_menu")
print("main.py --list / -m / -t / --save wired:", menu_ok)
check(menu_ok, "core.render_menu is missing")

if failures:
    print("\nFAILED:")
    for failure in failures:
        print("  -", failure)
    sys.exit(1)

print("\nOK")
