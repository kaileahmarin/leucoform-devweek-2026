"""Offline checker for relative Markdown links and local anchors."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*$")


def anchor(text: str) -> str:
    value = text.strip().casefold()
    value = re.sub(r"[`*_~]", "", value)
    value = re.sub(r"[^\w\- ]", "", value)
    return re.sub(r"\s+", "-", value)


def headings(path: Path) -> set[str]:
    result: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = HEADING_RE.match(line)
        if match:
            result.add(anchor(match.group(1)))
    return result


def main() -> int:
    failures: list[str] = []
    checked = 0
    markdown_files = sorted({*ROOT.glob("*.md"), *ROOT.glob("docs/*.md")})
    for source in markdown_files:
        text = source.read_text(encoding="utf-8")
        for raw_target in LINK_RE.findall(text):
            target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            checked += 1
            path_text, marker, fragment = target.partition("#")
            destination = (
                source if not path_text else (source.parent / unquote(path_text)).resolve()
            )
            try:
                destination.relative_to(ROOT)
            except ValueError:
                failures.append(f"{source.relative_to(ROOT)}: link escapes project: {target}")
                continue
            if not destination.is_file():
                failures.append(f"{source.relative_to(ROOT)}: missing target: {target}")
                continue
            if marker and fragment and anchor(unquote(fragment)) not in headings(destination):
                failures.append(f"{source.relative_to(ROOT)}: missing anchor: {target}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(
        f"Documentation links passed: {checked} relative links across {len(markdown_files)} files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
