"""
platform_core.py â€” Cross-platform foundation layer
===================================================
Enterprise-grade abstraction so the framework runs identically on:
  - Windows 10/11 (PowerShell / CMD)
  - Kali Linux / Debian / Ubuntu (bash / zsh)
  - Docker containers (linux-slim)

Provides: OS detection, privilege checks, shell command execution with
platform-appropriate quoting, secure temp files, terminal color setup,
structured logging, and safe config load/save (YAML with JSON fallback).
"""

from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

__version__ = "3.1.0"


# ---------------------------------------------------------------------------
# OS / platform detection
# ---------------------------------------------------------------------------

class OSType(Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PlatformInfo:
    """Snapshot of the host platform, computed once at import time."""
    os_type: OSType
    os_name: str                      # "Windows 11", "Kali GNU/Linux", ...
    os_release: str
    kernel: str
    machine: str
    python_version: str
    hostname: str
    is_kali: bool
    is_wsl: bool
    home: Path
    temp_dir: Path
    shell: str                        # "powershell", "cmd", "bash", "zsh"


def _detect_platform() -> PlatformInfo:
    system = platform.system()
    release = platform.release()
    version = platform.version()

    if system == "Windows":
        os_type = OSType.WINDOWS
        is_kali = False
        wsl = False
        # Windows 10 reports build >= 22000 for Windows 11
        try:
            build = int(release.split(".")[-1])
            pretty = "Windows 11" if build >= 22000 else "Windows 10"
        except (ValueError, IndexError):
            pretty = f"Windows ({release})"
        shell = "powershell"
        try:
            import ctypes  # noqa: WPS433 â€” Windows-only, guarded
            if "MINGW" in os.environ.get("MSYSTEM", ""):
                shell = "bash"
        except Exception:
            pass
    elif system == "Linux":
        os_type = OSType.LINUX
        pretty, is_kali, wsl = "GNU/Linux", False, False
        # Parse /etc/os-release (present on all modern distros)
        os_release_file = Path("/etc/os-release")
        if os_release_file.exists():
            try:
                pairs = {}
                for line in os_release_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if "=" in line and not line.startswith("#"):
                        k, _, v = line.partition("=")
                        pairs[k.strip()] = v.strip().strip('"')
                pretty = pairs.get("PRETTY_NAME", pretty)
                distro_id = pairs.get("ID", "").lower()
                is_kali = distro_id in ("kali", "kalilinux")
            except Exception:
                pass
        # WSL detection
        wsl = ("microsoft" in version.lower()
               or Path("/proc/sys/fs/binfmt_misc/WSLInterop").exists())
        if wsl:
            pretty += " (WSL)"
        shell = "bash"
        if os.environ.get("SHELL", "").endswith("zsh"):
            shell = "zsh"
    elif system == "Darwin":
        os_type = OSType.MACOS
        pretty = f"macOS {release}"
        is_kali = False
        wsl = False
        shell = "zsh"
    else:
        os_type = OSType.UNKNOWN
        pretty = system or "Unknown"
        is_kali = False
        wsl = False
        shell = "sh"

    return PlatformInfo(
        os_type=os_type,
        os_name=pretty,
        os_release=release,
        kernel=platform.version() if system != "Windows" else release,
        machine=platform.machine(),
        python_version=platform.python_version(),
        hostname=socket_hostname(),
        is_kali=is_kali,
        is_wsl=(os_type == OSType.LINUX and "wsl" in pretty.lower()),
        home=Path.home(),
        temp_dir=Path(tempfile.gettempdir()),
        shell=shell,
    )


def socket_hostname() -> str:
    try:
        return platform.node() or "localhost"
    except Exception:
        return "unknown"


PLATFORM = _detect_platform()
IS_WINDOWS = PLATFORM.os_type == OSType.WINDOWS
IS_LINUX = PLATFORM.os_type == OSType.LINUX
IS_KALI = PLATFORM.is_kali


# ---------------------------------------------------------------------------
# Privilege / capability checks (works on both OS families)
# ---------------------------------------------------------------------------

class PrivilegeLevel(Enum):
    ROOT = "root"
    ADMIN = "administrator"
    USER = "user"
    UNKNOWN = "unknown"


def get_privilege_level() -> PrivilegeLevel:
    """Detect whether we run as root (Linux) or Administrator (Windows)."""
    if IS_WINDOWS:
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                return PrivilegeLevel.ADMIN
        except Exception:
            pass
        return PrivilegeLevel.USER
    else:
        try:
            if os.geteuid() == 0:
                return PrivilegeLevel.ROOT
            return PrivilegeLevel.USER
        except AttributeError:
            return PrivilegeLevel.UNKNOWN


PRIVILEGE = get_privilege_level()
IS_PRIVILEGED = PRIVILEGE in (PrivilegeLevel.ROOT, PrivilegeLevel.ADMIN)


def can_bind_privileged_ports() -> bool:
    """Root/Admin can bind ports < 1024 without special handling."""
    return IS_PRIVILEGED


# ---------------------------------------------------------------------------
# Shell command execution â€” correct syntax per OS
# ---------------------------------------------------------------------------

@dataclass
class CommandResult:
    command: str
    returncode: int
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def which(tool: str) -> Optional[str]:
    """Find an executable on PATH (cross-platform)."""
    return shutil.which(tool)


def tool_available(*tools: str) -> Tuple[bool, Optional[str]]:
    """Return (True, path) if ANY of the given tools exists on PATH."""
    for t in tools:
        p = which(t)
        if p:
            return True, p
    return False, None


def run_command(
    args: List[str],
    timeout: float = 15.0,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    shell_powershell: bool = False,
) -> CommandResult:
    """
    Run an external command safely (no shell injection by default).

    On Windows with shell_powershell=True, wraps the args in a PowerShell
    invocation so tools that rely on PS semantics work naturally.
    """
    start = datetime.now(timezone.utc)
    full_env = {**os.environ, **(env or {})}
    argv = list(args)

    if IS_WINDOWS and shell_powershell:
        argv = ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                " ".join(f'"{a}"' for a in argv)]

    timed_out = False
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=full_env,
            errors="replace",
        )
        rc, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        timed_out = True
        rc, out, err = 124, "", "Command timed out"
    except FileNotFoundError:
        rc, out, err = 127, "", f"Executable not found: {argv[0]}"
    except Exception as exc:  # pragma: no cover
        rc, out, err = 1, "", f"Execution error: {exc}"

    duration = (datetime.now(timezone.utc) - start).total_seconds() * 1000
    return CommandResult(
        command=" ".join(argv),
        returncode=rc,
        stdout=out,
        stderr=err,
        duration_ms=round(duration, 2),
        timed_out=timed_out,
    )


def to_windows_path(p: str) -> str:
    """Convert a POSIX-style path to a Windows path (best effort)."""
    p = p.replace("/", "\\")
    if p.startswith("\\mnt\\"):
        drive = p[5] if len(p) > 5 else "c"
        rest = p[7:] if len(p) > 7 else ""
        p = f"{drive.upper()}:\\{rest}"
    return p


def to_posix_path(p: str) -> str:
    """Convert a Windows-style path to a POSIX path (best effort)."""
    p = p.replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        return f"/mnt/{p[0].lower()}/{p[3:]}".rstrip("/")
    return p


def native_path(p: str) -> str:
    """Return the path in the current OS's native format."""
    return to_windows_path(p) if IS_WINDOWS else to_posix_path(p)


# ---------------------------------------------------------------------------
# Secure temporary files
# ---------------------------------------------------------------------------

def secure_temp_file(prefix: str = "vscan_", suffix: str = ".tmp") -> Path:
    """Create a temp file with restrictive permissions on both platforms."""
    fd = tempfile.NamedTemporaryFile(prefix=prefix, suffix=suffix, delete=False)
    path = Path(fd.name)
    fd.close()
    try:
        if not IS_WINDOWS:
            os.chmod(path, 0o600)
        else:
            # Restrict to current user only
            os.system(f'icacls "{path}" /inheritance:r /grant:r "%USERNAME%":F >nul 2>&1')
    except Exception:
        pass
    return path


# ---------------------------------------------------------------------------
# Structured logging (JSON lines, human-friendly console)
# ---------------------------------------------------------------------------

class JsonLineFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
    json_lines: bool = False,
    quiet: bool = False,
) -> logging.Logger:
    logger = logging.getLogger("vulnscan")
    logger.setLevel(level)
    logger.handlers.clear()

    if not quiet:
        stream = logging.StreamHandler(sys.stderr)
        stream.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
            datefmt="%H:%M:%S",
        ))
        logger.addHandler(stream)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        if json_lines:
            fh.setFormatter(JsonLineFormatter())
        else:
            fh.setFormatter(logging.Formatter(
                "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"))
        logger.addHandler(fh)

    return logger


# ---------------------------------------------------------------------------
# Configuration (YAML preferred, JSON fallback â€” no hard dependency)
# ---------------------------------------------------------------------------

DEFAULT_CONFIG: Dict[str, Any] = {
    "scan": {
        "default_timeout": 5,
        "default_ports": "21,22,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443",
        "max_threads": 100,
        "user_agent": "Mozilla/5.0 (compatible; VScanPro/3.1)",
    },
    "report": {
        "output_dir": "reports",
        "formats": ["text", "json"],
        "redact_sensitive": True,
    },
    "exploit": {
        "max_jobs": 5,
        "default_strategy": "moderate",
        "safety_timeout": 30,
    },
    "ui": {
        "color": True,
        "banner": "enterprise",
    },
}


def _deep_update(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_update(base[k], v)
        else:
            base[k] = v
    return base


def load_config(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load config from YAML/JSON, merging over defaults. Never raises."""
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    candidates = [path] if path else [
        Path("config.yaml"), Path("config.yml"), Path("config.json"),
        PLATFORM.home / ".vulnscan" / "config.yaml",
    ]
    for cand in candidates:
        if cand and cand.exists():
            try:
                if cand.suffix in (".yaml", ".yml"):
                    try:
                        import yaml
                        data = yaml.safe_load(cand.read_text(encoding="utf-8")) or {}
                    except ImportError:
                        continue  # no PyYAML: skip YAML files
                else:
                    data = json.loads(cand.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    _deep_update(cfg, data)
                break
            except Exception:
                continue
    return cfg


def save_config(cfg: Dict[str, Any], path: Path) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix in (".yaml", ".yml"):
            try:
                import yaml
                path.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
            except ImportError:
                path = path.with_suffix(".json")
        if path.suffix == ".json":
            path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Terminal styling â€” degrades gracefully when color isn't supported
# ---------------------------------------------------------------------------

try:
    from colorama import Fore, Style, just_fix_windows_console

    just_fix_windows_console()  # Python 3.7+ friendly, no init() re-wrapping
    _COLOR_OK = True
except ImportError:  # pragma: no cover
    _COLOR_OK = False
    class _Stub:
        def __getattr__(self, name): return ""
    Fore = Style = _Stub()

# Windows consoles often default to a legacy codepage (cp1252/cp437) that
# cannot encode Unicode output from tools. Reconfigure to UTF-8 when possible
# (Python 3.7+ TextIOWrapper.reconfigure), so PowerShell prints everything.
for _stream in (sys.stdout, sys.stderr):
    try:
        if _stream.encoding and _stream.encoding.lower().replace("-", "") not in ("utf8", "utf"):
            _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def supports_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if IS_WINDOWS:
        return _COLOR_OK and stream.isatty()
    # Linux: TERM must exist and not be "dumb"; honor --no-color later
    return stream.isatty() and os.environ.get("TERM", "") != "dumb"


def colorize(text: str, color: str, enabled: Optional[bool] = None) -> str:
    if enabled is False or (enabled is None and not supports_color()):
        return text
    return f"{color}{text}{Style.RESET_ALL}"


def banner(style: str = "enterprise") -> str:
    """Return the application banner (Unicode, with ASCII fallback for
    consoles whose codepage cannot encode box-drawing characters)."""
    if style == "minimal":
        return "VScanPro v" + __version__
    try:
        "\u2554\u2550\u255d".encode(sys.stdout.encoding or "ascii")
        h, v, c = "\u2550", "\u2551", ("\u2554", "\u2560", "\u255a", "\u255d")
    except (UnicodeEncodeError, LookupError):
        h, v, c = "=", "|", ("+", "+", "+", "+")
    width = 78

    def row(label: str, value: str) -> str:
        return f"  {v} {label:<10}: {value:<{width - 18}} {v}"

    lines = [
        f"  {c[0]}{h * (width - 4)}{c[3]}",
        (f"  {v}   V U L N S C A N   P R O  -  ENTERPRISE SECURITY FRAMEWORK".ljust(width - 2)) + v,
        (f"  {v}   Version {__version__}  |  Cross-Platform Edition (Windows + Kali)".ljust(width - 2)) + v,
        f"  {c[1]}{h * (width - 4)}{c[3]}",
        row("Platform", PLATFORM.os_name),
        row("Host", PLATFORM.hostname),
        row("Arch", PLATFORM.machine),
        row("Python", PLATFORM.python_version),
        row("Privilege", PRIVILEGE.value),
        f"  {c[2]}{h * (width - 4)}{c[3]}",
    ]
    return "\n".join(lines)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def scan_id() -> str:
    """Unique identifier for a scan session (for report correlation)."""
    return f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"


def redact(value: str, keep: int = 4) -> str:
    """Redact a secret, keeping only the last `keep` characters."""
    if not value:
        return ""
    if len(value) <= keep:
        return "***"
    return "*" * max(len(value) - keep, 3) + value[-keep:]


def safe_filename(name: str) -> str:
    """Make a string safe for use as a filename on both OS families."""
    bad = '<>:"/\\|?*'
    for ch in bad:
        name = name.replace(ch, "_")
    return name.strip(". ")[:120] or "unnamed"

