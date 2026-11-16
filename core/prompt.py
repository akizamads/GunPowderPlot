"""
core.prompt — interactive input helpers with validation.

Every module gets its inputs through these calls so typing mistakes never
crash a scan (invalid numbers, empty hosts, unknown choices are re-asked).
"""

from __future__ import annotations

import re
from typing import Optional, Sequence

from core.ui import err, warn


def ask(
    label: str,
    default: Optional[str] = None,
    required: bool = True,
    allow_back: bool = True,
) -> Optional[str]:
    """Ask for a string. Returns None when the user types 'q' (back to menu)."""
    suffix = f" [{default}]" if default not in (None, "") else ""
    hint = " (q = back)" if allow_back else ""
    while True:
        try:
            line = input(f"  {label}{suffix}{hint}: ")
        except EOFError:
            print()
            return None
        raw = line.replace("\ufeff", "").strip(" \u200b")
        if allow_back and raw.lower() in ("q", "quit", "back", "exit"):
            return None
        if raw:
            return raw
        if default is not None:
            return str(default)
        if not required:
            return ""
        err(f"{label} is required.")


def ask_int(
    label: str,
    default: Optional[int] = None,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> Optional[int]:
    """Ask for an integer, re-asking until valid. 'q' returns None."""
    while True:
        raw = ask(label, default=None if default is None else str(default))
        if raw is None:
            return None
        try:
            value = int(raw)
        except ValueError:
            err(f"'{raw}' is not a number.")
            continue
        if minimum is not None and value < minimum:
            err(f"Value must be >= {minimum}.")
            continue
        if maximum is not None and value > maximum:
            err(f"Value must be <= {maximum}.")
            continue
        return value


def ask_optional(label: str, default: str = "") -> str:
    """Ask for a value that may be left empty."""
    value = ask(label, default=default, required=False)
    return "" if value is None else value


def ask_choice(label: str, choices: Sequence[str], default: Optional[str] = None) -> Optional[str]:
    """Ask the user to pick one of `choices` (case-insensitive, partial prefix allowed)."""
    shown = "/".join(choices)
    default = default or choices[0]
    while True:
        raw = ask(f"{label} ({shown})", default=default)
        if raw is None:
            return None
        value = raw.strip().lower()
        exact = [c for c in choices if c == value]
        if exact:
            return exact[0]
        prefix = [c for c in choices if c.startswith(value)]
        if len(prefix) == 1:
            return prefix[0]
        err(f"Choose one of: {shown}")


def parse_ports(text: str) -> Optional[list]:
    """Parse '80,443,8000-8010' into sorted ints. Empty / nothing valid => None."""
    if not text:
        return None
    ports: list = []
    for chunk in re.split(r"[,\s]+", str(text).strip()):
        if not chunk:
            continue
        if "-" in chunk:
            start, _, end = chunk.partition("-")
            try:
                ports.extend(range(int(start), int(end) + 1))
            except ValueError:
                warn(f"Ignoring invalid range '{chunk}'")
        else:
            try:
                ports.append(int(chunk))
            except ValueError:
                warn(f"Ignoring invalid port '{chunk}'")
    valid = sorted(set(p for p in ports if 0 < p < 65536))
    return valid or None


def ask_ports(label: str = "Ports", default: str = "") -> Optional[list]:
    """Ask for '80,443,8000-8010'. Returns a list of ints, or None for the default set."""
    raw = ask(label + " (e.g. 80,443,8000-8010)", default=default or None, required=False)
    if raw is None:
        return None
    ports = parse_ports(raw)
    if not ports:
        warn("No valid ports supplied — using the default port set.")
    return ports


def ask_list(label: str, default: Sequence[str] = ()) -> list:
    """Comma-separated list of strings."""
    default_text = ",".join(default)
    raw = ask(label + " (comma separated)", default=default_text or None, required=False)
    if raw is None:
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def confirm(label: str, default: bool = False) -> bool:
    """Yes/no question. Returns False when stdin is closed (never raises)."""
    default_text = "Y/n" if default else "y/N"
    try:
        raw = input(f"  {label} [{default_text}]: ").strip().lower()
    except EOFError:
        print()
        return False
    if not raw:
        return default
    return raw in ("y", "yes", "oo", "o")


def pause() -> None:
    try:
        input("\n  Press ENTER to return to the menu...")
    except EOFError:
        pass
