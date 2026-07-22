"""Create a public-safe dependency inventory from ``pip inspect`` JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from notug_protocol.submission import sanitize_dependency_inventory


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    loaded: Any = json.loads(args.input.read_text(encoding="utf-8-sig"))
    if not isinstance(loaded, dict):
        raise SystemExit("pip inspect inventory must be a JSON object")
    sanitized = sanitize_dependency_inventory(loaded)
    args.output.write_text(
        json.dumps(sanitized, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
