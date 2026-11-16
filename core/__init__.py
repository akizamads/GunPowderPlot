"""
core — shared infrastructure for the interactive VScan Pro console.

    core.ui      colored output helpers (err/ok/info/warn/print_header/table)
    core.prompt  interactive input helpers (ask/ask_int/ask_choice/confirm)
    core.menu    numbered menu engine + module registry
"""

from core.ui import (  # noqa: F401
    err,
    ok,
    info,
    warn,
    step,
    rule,
    print_header,
    table,
    kv,
    footer,
)
from core.prompt import (  # noqa: F401
    ask,
    ask_int,
    ask_optional,
    ask_choice,
    ask_list,
    ask_ports,
    parse_ports,
    confirm,
    pause,
)
import core.menu as _menu
from core.menu import (  # noqa: F401
    ModuleSpec,
    MODULES,
    get_module,
    render_menu,
    reload_modules,
)
from core.report import export  # noqa: F401


def __getattr__(name):
    """Resolve ``core.MODULES`` lazily so it always reflects the live module
    registry (it starts empty when a numbered module triggers the import)."""
    if name == "MODULES":
        return _menu.MODULES
    raise AttributeError(name)
