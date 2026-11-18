#!/usr/bin/env python3
"""Read CHANGELOG.md (Keep a Changelog format).

Usage:
    scripts/changelog.py section VERSION   print the body of one release (release notes)
    scripts/changelog.py latest            print the newest released version

Distribution-neutral; packaging scripts import ``releases()``.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parents[1] / "CHANGELOG.md"
HEADING = re.compile(r"^## \[(?P<version>[^\]]+)\](?: - (?P<date>\d{4}-\d{2}-\d{2}))?\s*$")


@dataclass(frozen=True)
class Release:
    version: str
    date: str
    body: str


def releases(text: str | None = None, *, include_unreleased: bool = False) -> list[Release]:
    text = CHANGELOG.read_text(encoding="utf-8") if text is None else text
    found: list[Release] = []
    version = date = None
    lines: list[str] = []

    def flush():
        if version is not None and (include_unreleased or version != "Unreleased"):
            found.append(Release(version, date or "", "\n".join(lines).strip() + "\n"))

    for line in text.splitlines():
        match = HEADING.match(line)
        if match:
            flush()
            version, date, lines = match["version"], match["date"], []
        elif line.startswith("[") and "]: " in line:
            continue  # link reference definitions at the end
        elif version is not None:
            lines.append(line)
    flush()
    return found


def section(version: str, text: str | None = None) -> str:
    for release in releases(text):
        if release.version == version:
            return release.body
    raise KeyError(f"CHANGELOG.md has no section for {version}")


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "section":
        try:
            sys.stdout.write(section(argv[1]))
        except KeyError as exc:
            print(exc.args[0], file=sys.stderr)
            return 1
        return 0
    if argv == ["latest"]:
        print(releases()[0].version)
        return 0
    print(__doc__.strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
