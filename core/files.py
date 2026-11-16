"""
core.files — safe input loading for modules that consume local files.

Used by the dependency and C2 module-file tools.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List


def read_text(path: str) -> str:
    return Path(path).expanduser().read_text(encoding="utf-8-sig", errors="ignore")


def read_json(path: str) -> Any:
    return json.loads(read_text(path))


def read_lines(path: str) -> List[str]:
    return [line.strip() for line in read_text(path).splitlines()
            if line.strip() and not line.strip().startswith("#")]
