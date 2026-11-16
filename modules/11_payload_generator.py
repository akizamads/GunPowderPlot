"""
11 — Payload Generator
======================
TARGET : local (attacker-controlled output) — reverse shell needs callback host
ENGINE : PayloadGenerator
"""

from core import ask, ask_choice, ask_int, confirm, info, kv, ok
from modules.base import finish
from modules import LOCAL
from payload_generator import PayloadGenerator

NUMBER = 11
NAME = "Payload Generator"
GROUP = "Exploitation"
SUMMARY = "Generate XSS/SQLi/RCE payloads and encoded reverse shells"
TARGET = LOCAL
NEEDS = ("payload_type",)

TYPES = ["xss", "sqli", "command_injection", "path_traversal", "reverse_shell"]
ENCODINGS = ["plain", "base64", "url", "hex"]


def run(session, payload_type: str = "", host: str = "", port: int = 4444,
        encoding: str = "plain", target: str = "local", save: bool = False) -> dict:
    print(f"  Types:     {', '.join(TYPES)}")
    print("  Host/port: only used for reverse_shell\n")

    payload_type = payload_type or ask_choice("Payload type", TYPES) or "xss"
    generator = PayloadGenerator()

    if payload_type == "reverse_shell":
        host = host or ask("Callback host (your IP)") or "127.0.0.1"
        port = port or ask_int("Callback port", default=4444, minimum=1, maximum=65535) or 4444
        encoding = ask_choice("Encoding", ENCODINGS, default=encoding) or encoding
        payload = generator.generate_reverse_shell("bash", host, port)
        if encoding == "base64":
            payload = generator.encode_base64(payload)
        elif encoding == "url":
            payload = generator.encode_url(payload)
        elif encoding == "hex":
            payload = generator.encode_hex(payload)
        payloads = [payload]
        kv([("Callback", f"{host}:{port}"), ("Encoding", encoding)])
    else:
        builders = {
            "xss": generator.generate_xss_payloads,
            "sqli": generator.generate_sql_injection_payloads,
            "command_injection": generator.generate_command_execution_payloads,
            "path_traversal": generator.generate_path_traversal_payloads,
        }
        payloads = builders[payload_type]()

    ok(f"{len(payloads)} payload(s) for {payload_type}")
    for index, payload in enumerate(payloads, 1):
        print(f"  {index:2d}. {payload}")
    print()

    result = {"payload_type": payload_type, "encoding": encoding, "payloads": payloads}
    if save or confirm("Save report?", default=False):
        finish(NUMBER, NAME, payload_type, result, True)
    return result
