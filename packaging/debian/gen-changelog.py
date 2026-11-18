#!/usr/bin/env python3
"""Render CHANGELOG.md as a Debian changelog on stdout.

Usage: packaging/debian/gen-changelog.py PACKAGE "NAME <EMAIL>"

CHANGELOG.md is the only changelog maintained by hand; the Debian file is
derived from it at build time so the two cannot drift.
"""

from __future__ import annotations

import re
import sys
import textwrap
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from changelog import releases  # noqa: E402


def _plain(text: str) -> str:
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = text.replace("`", "")
    return re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)


def _items(body: str) -> list[str]:
    items: list[str] = []
    category = ""
    for line in body.splitlines():
        if line.startswith("### "):
            category = line[4:].strip()
        elif line.startswith("- "):
            items.append(f"{category}: {line[2:].strip()}" if category else line[2:].strip())
        elif line.startswith("  ") and items:
            items[-1] += " " + line.strip()
    return [_plain(item) for item in items]


def _dates(items) -> list[datetime]:
    """Release dates, strictly increasing from oldest to newest.

    Debian requires every entry to be newer than the one before it.  Several
    releases can share a calendar day, so releases on the same day get
    increasing minutes past midnight, in release order.
    """
    dates: list[datetime] = []
    previous = None
    for release in reversed(items):
        date = datetime.strptime(release.date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if previous is not None and date <= previous:
            date = previous + timedelta(minutes=1)
        dates.append(date)
        previous = date
    return list(reversed(dates))


def render(package: str, maintainer: str) -> str:
    out = []
    items = releases()
    for release, date in zip(items, _dates(items)):
        out.append(f"{package} ({release.version}) unstable; urgency=medium\n")
        for item in _items(release.body):
            out.append(textwrap.fill(item, width=78, initial_indent="  * ", subsequent_indent="    "))
        out.append(f"\n -- {maintainer}  {format_datetime(date)}\n")
    return "\n".join(out)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        raise SystemExit(2)
    sys.stdout.write(render(sys.argv[1], sys.argv[2]))
