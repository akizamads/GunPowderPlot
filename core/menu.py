"""
core.menu — numbered module registry and menu renderer.

Every file in modules/ exports:
    NUMBER  : int          menu position shown to the user
    NAME    : str          short menu label
    TARGET  : str          what this module acts on (host / URL / service / local)
    GROUP   : str          menu section (Recon, Exploitation, Advanced, ...)
    NEEDS   : tuple        required input keys, used by the menu to prompt
    SUMMARY : str          one-line description
    run(...) -> dict       never returns; prints results and returns a summary

The registry is discovered from files whose names start with two digits
(01_, 02_, ...), so adding a module is "drop in the next numbered file".
"""

from __future__ import annotations

import importlib
import pkgutil
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.ui import GREY, ORANGE, _c, banner
from colorama import Fore


@dataclass(frozen=True)
class ModuleSpec:
    number: int
    name: str
    target: str
    group: str
    needs: tuple
    summary: str
    module_path: str
    run: Any = field(compare=False, repr=False)

    @property
    def label(self) -> str:
        return f"{self.number:02d}"


_GROUP_ORDER = ["Reconnaissance", "Exploitation", "Post-Exploitation", "Advanced", "Utility"]

# Section headings get their own colour so the eye can jump straight to a group.
_GROUP_COLORS = {
    "Reconnaissance": Fore.CYAN,
    "Exploitation": Fore.RED,
    "Post-Exploitation": Fore.MAGENTA,
    "Advanced": ORANGE,
    "Utility": Fore.GREEN,
}
# Local-only modules are harmless; anything touching a remote host is highlighted.
_LOCAL_TAGS = ("local machine",)


def _discover() -> List[ModuleSpec]:
    import modules as modules_pkg  # local import: avoids import cycles

    specs: List[ModuleSpec] = []
    for mod_info in pkgutil.iter_modules(modules_pkg.__path__):
        if not re.match(r"^\d{2}_", mod_info.name):
            continue
        module = importlib.import_module(f"modules.{mod_info.name}")
        for attr in ("NUMBER", "NAME", "TARGET", "GROUP", "SUMMARY", "run"):
            if not hasattr(module, attr):
                raise ImportError(f"{mod_info.name} is missing required attribute '{attr}'")
        specs.append(ModuleSpec(
            number=int(module.NUMBER),
            name=module.NAME,
            target=module.TARGET,
            group=module.GROUP,
            needs=tuple(getattr(module, "NEEDS", ())),
            summary=module.SUMMARY,
            module_path=f"modules.{mod_info.name}",
            run=module.run,
        ))
    specs.sort(key=lambda s: s.number)

    numbers = [s.number for s in specs]
    duplicates = {n for n in numbers if numbers.count(n) > 1}
    if duplicates:
        raise ImportError(f"Duplicate module numbers: {sorted(duplicates)}")
    return specs


def _discover_safe() -> List[ModuleSpec]:
    """Discover modules without exploding on circular-import half-initialised packages.

    Importing a numbered module pulls in ``core`` (for its helpers), which re-enters
    this module. At that moment only the partially initialised module is visible, so
    ``_discover`` would fail. Deferring in that case lets the import chain finish; but
    callers (main.py / smoke_check.py) call :func:`reload_modules` explicitly.
    """
    try:
        return _discover()
    except ImportError:
        if any(_is_partial(name) for name in list(sys.modules) if name.startswith("modules.")):
            return []
        raise


def _is_partial(module_name: str) -> bool:
    module = sys.modules.get(module_name)
    return module is not None and getattr(module, "NUMBER", None) is None


MODULES: List[ModuleSpec] = _discover_safe()


def reload_modules() -> List[ModuleSpec]:
    """(Re)build MODULES once the whole import graph is initialised."""
    global MODULES
    MODULES = _discover()
    return MODULES


def get_module(number: int) -> Optional[ModuleSpec]:
    for spec in MODULES:
        if spec.number == number:
            return spec
    return None


def render_menu() -> None:
    """Print the banner and the numbered module list, grouped by section."""
    width = 78
    banner()
    print(_c(" MODULE CONSOLE", Fore.LIGHTWHITE_EX))
    print(_c("=" * width, Fore.CYAN))

    groups = {g: [m for m in MODULES if m.group == g] for g in _GROUP_ORDER}
    leftovers = sorted({m.group for m in MODULES} - set(_GROUP_ORDER))
    for group in leftovers:
        groups[group] = [m for m in MODULES if m.group == group]

    for group, items in groups.items():
        if not items:
            continue
        color = _GROUP_COLORS.get(group, Fore.LIGHTWHITE_EX)
        print()
        print(_c(f"  {group.upper()}", color))
        print(_c("  " + "-" * (width - 4), GREY))
        for spec in items:
            num = _c(f"[{spec.number:02d}]", color)
            label = spec.name.ljust(30)
            local = spec.target.startswith(_LOCAL_TAGS)
            target_color = Fore.GREEN if local else Fore.YELLOW
            print(f"   {num} {_c(label, Fore.LIGHTWHITE_EX)}"
                  f" {_c('target: ' + spec.target, target_color)}")

    print()
    print(_c("  " + "-" * (width - 4), GREY))
    print(f"   {_c('[h]', Fore.GREEN)} Help        {_c('[i]', Fore.GREEN)} Platform info    "
          f"{_c('[q]', Fore.GREEN)} Quit")
    print(_c("=" * width, Fore.CYAN))
