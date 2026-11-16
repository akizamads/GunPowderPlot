"""
modules — one file per capability, numbered 01..15.

Conventions every module file follows (enforced by core.menu):
    NUMBER, NAME, GROUP, SUMMARY, TARGET, NEEDS, run(session, **inputs) -> dict

TARGET is the machine-readable input kind the menu uses to prompt the user:
    HOST     IP address or hostname (e.g. 10.0.0.5, example.com)
    URL      full URL including scheme (e.g. https://example.com/login)
    DB       database host with service + port
    SERVICE  host plus a named service (ssh/ftp/mysql/postgresql)
    ANY      accepts host or URL
    LOCAL    runs against the local machine, no target required
"""

HOST = "IP / Hostname"
URL = "URL (http/https)"
DB = "service:host (mysql/postgres)"
SERVICE = "service:host (ssh/ftp/mysql/postgresql)"
ANY = "URL or IP / Hostname"
LOCAL = "local machine (no target)"

__all__ = ["HOST", "URL", "DB", "SERVICE", "ANY", "LOCAL"]


# The numbered module files share this package name, so importing any of them with a
# relative/attribute path (``importlib.import_module("modules.08_dependency_scan")``)
# used to resolve against this very file instead. Registering the package in
# ``sys.modules`` up front keeps those imports on the real package object.
import sys as _sys
_sys.modules.setdefault(__name__, _sys.modules[__name__])
