"""
12 — WAF Detection & Bypass
===========================
TARGET : URL (http/https)
ENGINE : WAFDetector.detect_waf + WAFBypass.generate_all_bypasses
"""

from core import ask, ask_choice, confirm, info, kv, table, warn
from modules.base import finish, normalize_url
from modules import URL
from waf_bypass import WAFBypass, WAFDetector

NUMBER = 12
NAME = "WAF Detection & Bypass"
GROUP = "Advanced"
SUMMARY = "Fingerprint a WAF and produce filter-evasion variants"
TARGET = URL
NEEDS = ("target",)

TECHNIQUES = ["all", "case", "encode", "comment", "concat"]


def run(session, target: str = "", payload: str = "<script>alert(1)</script>",
        technique: str = "all", save: bool = False) -> dict:
    print("  Target:     URL to fingerprint")
    print("  Payload:    base payload used to build bypass variants\n")

    target = normalize_url(target) if target else normalize_url(ask("Target URL") or "")
    payload = payload or ask("Base payload", default="<script>alert(1)</script>") or "x"
    technique = ask_choice("Technique", TECHNIQUES, default=technique) or "all"

    info(f"Fingerprinting WAF on {target} ...")
    detection = WAFDetector(target).detect_waf()
    if detection.detected:
        warn(f"WAF detected: {detection.waf_type} "
             f"({detection.confidence * 100:.0f}% confidence)")
    else:
        info("No WAF signature matched")
    for indicator in detection.indicators[:6]:
        print(f"    - {indicator}")
    print()

    info(f"Generating {technique} bypass payloads for: {payload}")
    bypasses = WAFBypass.generate_all_bypasses(payload)
    selected = _select(bypasses, technique)
    table(["Technique", "Variant"],
          [(name, value) for name, values in selected.items() for value in values[:4]])

    result = {
        "target": target,
        "detection": detection.__dict__,
        "payload": payload,
        "technique": technique,
        "bypasses": selected,
    }
    if save or confirm("Save report?", default=False):
        finish(NUMBER, NAME, target, result, True)
    return result


def _select(bypasses: dict, technique: str) -> dict:
    mapping = {
        "case": ["case_variation"],
        "encode": ["url_encode", "double_url_encode", "hex_encode", "unicode_encode"],
        "comment": ["sql_comments"],
        "concat": ["sql_concat"],
    }
    if technique == "all":
        return bypasses
    keys = mapping.get(technique, list(bypasses))
    return {k: bypasses[k] for k in keys if k in bypasses}
