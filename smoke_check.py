import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.argv = ["main.py"]

import core  # noqa: E402

MODULES = core.MODULES
print("modules loaded:", len(MODULES))

# Sanity: the manifest loader used by module 08
_08 = __import__("modules.08_dependency_scan", fromlist=["_load_manifest"])
deps = _08._load_manifest("requirements.txt")
print("manifest deps parsed:", len(deps), deps[:2])

# Check every module's run() accepts the keyword set the menu passes
import inspect
for spec in MODULES:
    params = inspect.signature(spec.run).parameters
    ok = "session" in params and "save" in params
    print(f"{spec.number:02d} {spec.name:<34} sig_ok={ok} target={spec.target}")

print("main.py --list / -m / -t / --save wired:", hasattr(core, "render_menu"))
