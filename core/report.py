"""
core.report — shared export helper used by every module.

A module calls `export(result, target)` and gets JSON / text written under
reports/ when the user asked for it. No module writes files itself.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from platform_core import safe_filename


def export(
    data: Dict[str, Any],
    module_number: int,
    module_name: str,
    target: str,
    output_dir: str = "reports",
) -> Optional[Path]:
    """Write `data` to JSON under output_dir. Returns the path, or None on failure."""
    try:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = f"{module_number:02d}_{safe_filename(module_name)}_{safe_filename(target)}_{stamp}.json"
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / name
        path.write_text(
            json.dumps(
                {"module": module_name, "target": target, "timestamp": stamp, "data": data},
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
        return path
    except Exception:
        return None
