"""
core.ui — one place for every line the console prints.

All modules and the menu use these helpers, so output looks identical
everywhere and color support is decided once.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence

from colorama import Fore, Style

from platform_core import PLATFORM, colorize, supports_color

_COLOR = supports_color()

BANNER_NAME = "MUTIL VUL"
BANNER_VERSION = "v3.1"
BANNER_WARNING = "AUTHORIZED PENETRATION TESTING ONLY - UNAUTHORIZED USE IS ILLEGAL"

# colorama has no orange; a 256-color code gets us the classic hacker-orange look.
ORANGE = "\033[38;5;208m"
GREY = Fore.LIGHTBLACK_EX
RESET = Style.RESET_ALL

# Severity -> (label colour, ASCII tag). Single source of truth for every module.
SEVERITY_STYLES = {
    "CRITICAL": (Fore.RED, "!!"),
    "HIGH": (ORANGE, "! "),
    "MEDIUM": (Fore.YELLOW, "* "),
    "LOW": (Fore.CYAN, "- "),
    "INFO": (GREY, ". "),
}

# The classic figlet "big" face, turned into the message.
_BANNER_LETTERS = {
    "M": ["#     #", "##   ##", "# # # #", "#  #  #", "#     #", "#     #", "#     #"],
    "U": ["#     #", "#     #", "#     #", "#     #", "#     #", "#     #", " ##### "],
    "T": ["#######", "   #   ", "   #   ", "   #   ", "   #   ", "   #   ", "   #   "],
    "I": ["  ###  ", "   #   ", "   #   ", "   #   ", "   #   ", "   #   ", "  ###  "],
    "L": ["#      ", "#      ", "#      ", "#      ", "#      ", "#      ", "#######"],
    "V": ["#     #", "#     #", "#     #", " #   # ", " #   # ", "  # #  ", "   #   "],
    " ": ["   ", "   ", "   ", "   ", "   ", "   ", "   "],
}

# Gradient across the banner. One row of colour per banner line.
_BANNER_GRADIENT = [Fore.RED, ORANGE, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]


def _c(text: str, color: str) -> str:
    return colorize(text, color, enabled=_COLOR)


def _raw(text: str, color: str) -> str:
    """Colorize a string that may already contain escape codes."""
    return f"{color}{text}{RESET}" if _COLOR else text


def _ascii_name(name: str) -> List[str]:
    """Render a word as a list of block-art rows."""
    rows = [""] * 7
    for glyph in name.upper():
        block = _BANNER_LETTERS.get(glyph, _BANNER_LETTERS[" "])
        for index, piece in enumerate(block):
            rows[index] += piece + " "
    return [row.rstrip() for row in rows]


def banner(compact: bool = False) -> None:
    """Full startup banner: WILD TOOLS header + block art + usage warning."""
    width = 78
    print(_c("=" * width, Fore.CYAN))
    print(_c(f"  WILD TOOLS  |  {BANNER_NAME} {BANNER_VERSION}"
             f"  |  {PLATFORM.os_name}  |  shell: {PLATFORM.shell}", Fore.CYAN))
    print(_c("=" * width, Fore.CYAN))
    print()

    if not compact:
        for row, color in zip(_ascii_name(BANNER_NAME), _BANNER_GRADIENT):
            print(_raw("  " + row, color))
        print()

    print(_raw(f"  {BANNER_WARNING}", Fore.RED))
    print(_c(f"  Offensive-security console - modules 01-15, all output to reports/", GREY))
    print()


def severity_tag(severity: Any) -> str:
    """'[HIGH]' rendered in that severity's colour, ready to print."""
    label = str(getattr(severity, "value", severity)).upper()
    color, _ = SEVERITY_STYLES.get(label, (Fore.WHITE, "? "))
    return _c(f"[{label}]", color)


def severity_line(severity: Any, text: str) -> str:
    """'[HIGH] finding name' with the tag and the text both coloured."""
    label = str(getattr(severity, "value", severity)).upper()
    color, _ = SEVERITY_STYLES.get(label, (Fore.WHITE, "? "))
    return f"{_c(f'[{label}]', color)} {_c(text, color)}"


def err(msg: str) -> None:
    print(_c(f"[!] ERROR: {msg}", Fore.RED))


def ok(msg: str) -> None:
    print(_c(f"[+] {msg}", Fore.GREEN))


def info(msg: str) -> None:
    print(_c(f"[*] {msg}", Fore.CYAN))


def warn(msg: str) -> None:
    print(_c(f"[~] {msg}", Fore.YELLOW))


def step(msg: str) -> None:
    """Sub-step of a running module (indented)."""
    print(_c(f"    - {msg}", Fore.LIGHTBLACK_EX))


def rule(char: str = "-", width: int = 78) -> None:
    print(_c(char * width, Fore.LIGHTBLACK_EX))


def print_header(title: str = "", target: str = "") -> None:
    """Section header printed at the top of every module run."""
    print()
    print(_c("=" * 78, Fore.CYAN))
    print(_c(f" {BANNER_NAME} {BANNER_VERSION}  |  {PLATFORM.os_name}"
             f"  |  shell: {PLATFORM.shell}", Fore.CYAN))
    if title:
        # "MODULE 03 — Web Vulnerability Scan" -> number green, name white
        print(f" {_c(title, Fore.LIGHTWHITE_EX)}")
    if target:
        print(f" TARGET: {_c(target, Fore.GREEN)}")
    print(_c("=" * 78, Fore.CYAN))
    print()


def footer(msg: str = "") -> None:
    print()
    print(_c("=" * 78, Fore.CYAN))
    if msg:
        print(_c(f" {msg}", Fore.LIGHTWHITE_EX))
    print(_c("=" * 78, Fore.CYAN))


def kv(pairs: Sequence[tuple]) -> None:
    """Print aligned key/value rows."""
    if not pairs:
        return
    width = max(len(str(k)) for k, _ in pairs)
    for key, value in pairs:
        print(f"  {_c(str(key).ljust(width), Fore.LIGHTWHITE_EX)} : {value}")


def table(headers: Sequence[str], rows: Iterable[Sequence[Any]], max_width: int = 40) -> None:
    """Minimal dependency-free table printer."""
    rows = [[_truncate(str(cell), max_width) for cell in row] for row in rows]
    widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def _line(values: Sequence[str]) -> str:
        return "  " + " | ".join(v.ljust(widths[i]) for i, v in enumerate(values))

    print(_c(_line([str(h) for h in headers]), Fore.LIGHTWHITE_EX))
    print(_c("  " + "-+-".join("-" * w for w in widths), GREY))
    for row in rows:
        print(_line_with_status(row, widths))


def _line_with_status(row: Sequence[str], widths: Sequence[int]) -> str:
    """Colour status-like cells (severity / success / failed) and leave the rest plain."""
    cells = []
    for i, cell in enumerate(row):
        padded = cell.ljust(widths[i])
        key = cell.strip().upper()
        if key in SEVERITY_STYLES:
            cells.append(_c(padded, SEVERITY_STYLES[key][0]))
        elif key in ("SUCCESS", "DONE", "OPEN", "OK", "ONLINE", "CONFIRMED", "VULNERABLE"):
            cells.append(_c(padded, Fore.GREEN))
        elif key in ("FAILED", "ERROR", "OFFLINE", "CLOSED"):
            cells.append(_c(padded, Fore.RED))
        elif key in ("PENDING", "RUNNING", "QUEUED"):
            cells.append(_c(padded, Fore.YELLOW))
        else:
            cells.append(padded)
    return "  " + " | ".join(cells)


def _truncate(text: str, width: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[: width - 3] + "..."


def dict_preview(data: Dict[str, Any], indent: str = "  ") -> None:
    """Flat preview for heterogeneous result dicts."""
    for key, value in data.items():
        if isinstance(value, list):
            print(f"{indent}{key}: {len(value)} item(s)")
        elif isinstance(value, dict):
            print(f"{indent}{key}: {{{', '.join(list(value)[:4])}}}")
        else:
            print(f"{indent}{key}: {value}")


__all__ = [
    "BANNER_NAME",
    "BANNER_VERSION",
    "ORANGE",
    "GREY",
    "SEVERITY_STYLES",
    "banner",
    "severity_tag",
    "severity_line",
    "err",
    "ok",
    "info",
    "warn",
    "step",
    "rule",
    "print_header",
    "footer",
    "kv",
    "table",
    "dict_preview",
]
