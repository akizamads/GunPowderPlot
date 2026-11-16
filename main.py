"""
main.py — VScan Pro interactive module console.

Run:  python main.py
Pick a module by number (01-15), provide the prompt's target, get results.

Non-interactive shortcuts:
    python main.py --list              print the module table
    python main.py --module 1 -t 10.0.0.5
    python main.py --module 3 -t https://example.com --save

The legacy Click CLI is still available via `python cli.py`.
"""

from __future__ import annotations

import argparse
import os
import sys
import traceback
from typing import Any, Dict, Optional

from core import (
    MODULES,
    ask,
    ask_choice,
    ask_optional,
    err,
    get_module,
    info,
    kv,
    pause,
    print_header,
    render_menu,
    rule,
    warn,
)
from platform_core import PLATFORM, PRIVILEGE, load_config, setup_logging
from modules import ANY, DB, HOST, LOCAL, SERVICE, URL

CONFIG = load_config()


# ---------------------------------------------------------------------------
# Target prompting (driven by each module's TARGET field)
# ---------------------------------------------------------------------------

_TARGET_PROMPTS = {
    HOST: ("Target host (IP or hostname)", None),
    URL: ("Target URL (http/https)", None),
    ANY: ("Target URL or host", None),
    DB: ("Target service:host (mysql/postgres/mongodb/redis/tomcat/jboss/jenkins/wordpress)", None),
    SERVICE: ("Target service:host (ssh/ftp/mysql/postgresql)", None),
    LOCAL: (None, None),
}


def collect_inputs(spec) -> Dict[str, Any]:
    """Prompt for everything a module needs. Returns {} when the user backs out."""
    inputs: Dict[str, Any] = {}

    if spec.target != LOCAL:
        label, default = _TARGET_PROMPTS.get(spec.target, ("Target", None))
        if spec.target == ANY:
            label = "Target host (IP / hostname — press ENTER to use this machine)"
        value = ask(label, default=default, required=(spec.target != ANY))
        if value is None:
            return {}
        inputs["target"] = value

    # Module-specific extras -- kept explicit so each module's screen is short.
    if spec.number == 1:
        from core import ask_ports
        inputs["ports"] = ask_ports("Ports (blank = defaults)")
    elif spec.number == 3:
        from core import ask_list
        inputs["endpoints"] = ask_list("Endpoints", default=["/login", "/search", "/submit"])
    elif spec.number == 9:
        parameter = ask("Parameter", default="id")
        if parameter is None:
            return {}
        inputs["parameter"] = parameter or "id"
    elif spec.number == 10:
        from core import ask_int
        attempts = ask_int("Max attempts", default=5, minimum=1, maximum=100)
        if attempts is None:
            return {}
        inputs["attempts"] = attempts
    elif spec.number == 11:
        inputs["payload_type"] = ask_choice(
            "Payload type", ["xss", "sqli", "command_injection", "path_traversal", "reverse_shell"])
        if inputs["payload_type"] is None:
            return {}
    elif spec.number == 12:
        technique = ask_choice("Technique", ["all", "case", "encode", "comment", "concat"])
        if technique is None:
            return {}
        inputs["technique"] = technique
    elif spec.number == 13:
        strategy = ask_choice("Strategy", ["aggressive", "moderate", "conservative"])
        if strategy is None:
            return {}
        inputs["strategy"] = strategy
    elif spec.number == 15:
        mode = ask_choice("Mode", ["server", "agent", "sessions", "task", "download"])
        if mode is None:
            return {}
        inputs["mode"] = mode
    elif spec.number == 8:
        manifest = ask_optional("Manifest path", default="requirements.txt")
        inputs["manifest"] = manifest

    if not inputs.get("target"):
        inputs["target"] = "local"
    return inputs


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_module(number: int, inputs: Optional[Dict[str, Any]] = None,
               save: bool = False) -> bool:
    spec = get_module(number)
    if spec is None:
        err(f"No module numbered {number} (available: {[m.number for m in MODULES]})")
        return False

    inputs = dict(inputs or {})
    target = inputs.get("target", "local")

    print_header(f"MODULE {spec.number:02d} — {spec.name}", target)
    print(f"  {spec.summary}")
    print(f"  Target type : {spec.target}")
    rule()

    started = None
    try:
        import time
        started = time.time()
        result = spec.run(session={"config": CONFIG, "save": save}, save=save, **inputs)
        elapsed = time.time() - started
        rule("=")
        _print_done(spec, result, elapsed)
        if isinstance(result, dict):
            result["_elapsed"] = round(elapsed, 3)
        return True
    except KeyboardInterrupt:
        warn("Interrupted by user")
        return False
    except EOFError:
        warn("Input stream closed — module aborted")
        return False
    except Exception as exc:  # a module failure must never kill the console
        err(f"{type(exc).__name__}: {exc}")
        if "--debug" in sys.argv:
            traceback.print_exc()
        return False


def _print_done(spec, result: Any, elapsed: float) -> None:
    from core.ui import ok
    ok(f"Module {spec.number:02d} finished in {elapsed:.2f}s")
    if isinstance(result, dict) and result:
        counts = {k: v for k, v in result.items() if isinstance(v, (int, float, str))}
        if counts:
            kv([(k.replace("_", " ").capitalize(), v) for k, v in list(counts.items())[:6]])


# ---------------------------------------------------------------------------
# Interactive loop
# ---------------------------------------------------------------------------

def interactive() -> None:
    while True:
        render_menu()
        try:
            choice = ask("Select module", allow_back=False)
        except EOFError:
            print()
            info("Bye.")
            return
        if choice is None:
            continue
        choice = choice.strip().lower()

        if choice in ("q", "quit", "exit"):
            info("Bye.")
            return
        if choice in ("", "restart", "back", "menu"):
            continue
        if choice == "h":
            _help()
            continue
        if choice == "i":
            _platform_info()
            continue

        number = _parse_number(choice)
        if number is None:
            err(f"'{choice}' is not a menu option")
            continue

        spec = get_module(number)
        if spec is None:
            err(f"No module {choice}")
            continue

        inputs = collect_inputs(spec)
        if not inputs and spec.target != LOCAL:
            info("Cancelled.")
            continue

        run_module(number, inputs, save=CONFIG.get("report", {}).get("save_by_default", False))
        pause()


def _parse_number(text: str) -> Optional[int]:
    try:
        return int(text)
    except ValueError:
        return None


def _help() -> None:
    print()
    kv([
        ("Module numbers", "01-15 as shown in the menu"),
        ("',q' anywhere in a prompt", "cancel and return to the menu"),
        ("Reports", f"written to {CONFIG['report'].get('output_dir', 'reports')}/"),
        ("Legacy CLI", "python cli.py --help"),
        ("Non-interactive", "python main.py --list  |  --module N -t TARGET"),
    ])
    print()


def _platform_info() -> None:
    print()
    kv([
        ("OS", PLATFORM.os_name),
        ("Kernel", PLATFORM.kernel),
        ("Arch", PLATFORM.machine),
        ("Shell", PLATFORM.shell),
        ("Python", PLATFORM.python_version),
        ("Hostname", PLATFORM.hostname),
        ("Privilege", PRIVILEGE.value),
        ("Modules", len(MODULES)),
    ])
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="main.py", description="VScan Pro module console")
    parser.add_argument("--list", "-l", action="store_true", help="list modules and exit")
    parser.add_argument("--module", "-m", type=int, default=None, help="module number to run")
    parser.add_argument("--target", "-t", default=None, help="target host / URL / service:host")
    parser.add_argument("--ports", default=None, help="module 01: ports, e.g. 80,443,8000-8010")
    parser.add_argument("--param", default=None, help="module 09: injectable parameter (default id)")
    parser.add_argument("--attempts", type=int, default=5, help="module 10: max credential pairs")
    parser.add_argument("--manifest", default="requirements.txt", help="module 08: manifest path")
    parser.add_argument("--payload-type", default="xss",
                        choices=["xss", "sqli", "command_injection", "path_traversal", "reverse_shell"],
                        help="module 11: payload type")
    parser.add_argument("--technique", default="all", choices=["all", "case", "encode", "comment", "concat"],
                        help="module 12: evasion technique")
    parser.add_argument("--strategy", default="moderate",
                        choices=["aggressive", "moderate", "conservative"], help="module 13: strategy")
    parser.add_argument("--mode", default="sessions", choices=["server", "agent", "sessions", "task", "download"],
                        help="module 15: C2 mode")
    parser.add_argument("--countries", default="all",
                        help="module 16: ISO alpha-2 list, e.g. PH,ID,JP (default all)")
    parser.add_argument("--samples", type=int, default=5, help="module 16: prefixes per country")
    parser.add_argument("--prefix-source", default=None,
                        help="module 16: local CIDR file instead of downloading the route report")
    parser.add_argument("--no-confirm", action="store_true",
                        help="do not prompt to save a report (implicit with --save)")
    parser.add_argument("--save", action="store_true", help="always write the report file")
    parser.add_argument("--log-file", default=None, help="write logs to this file")
    parser.add_argument("--debug", action="store_true", help="show tracebacks")
    return parser.parse_args()


def _noninteractive_inputs(args: argparse.Namespace) -> Dict[str, Any]:
    """Build a module's inputs from CLI flags, filling anything the user omitted."""
    inputs: Dict[str, Any] = {}
    if args.target:
        inputs["target"] = args.target
    if args.module == 1 and args.ports:
        from core import parse_ports
        inputs["ports"] = parse_ports(args.ports)
    elif args.module == 3:
        inputs["endpoints"] = ["/login", "/search", "/submit"]
    elif args.module == 9:
        inputs["parameter"] = args.param or "id"
    elif args.module == 10:
        inputs["attempts"] = args.attempts
    elif args.module == 11:
        inputs["payload_type"] = args.payload_type
    elif args.module == 12:
        inputs["technique"] = args.technique
    elif args.module == 13:
        inputs["strategy"] = args.strategy
    elif args.module == 15:
        inputs["mode"] = args.mode
    elif args.module == 8:
        inputs["manifest"] = args.manifest
    elif args.module == 16:
        inputs["countries"] = args.countries
        inputs["samples"] = args.samples
        inputs["source"] = args.prefix_source or ""
    return inputs


def main() -> int:
    args = _parse_args()
    if args.module is not None and (args.no_confirm or args.save):
        # Non-interactive runs must not block on prompts.
        os.environ["VSCAN_ASSUME_YES"] = "1"
    if args.log_file:
        setup_logging(log_file=__import__("pathlib").Path(args.log_file))

    if args.list:
        render_menu()
        return 0

    if args.module is not None:
        inputs = _noninteractive_inputs(args)
        if get_module(args.module) is None:
            err(f"Unknown module number {args.module}")
            return 2
        return 0 if run_module(args.module, inputs, save=args.save) else 1

    try:
        interactive()
    except (EOFError, KeyboardInterrupt):
        print()
        info("Bye.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
