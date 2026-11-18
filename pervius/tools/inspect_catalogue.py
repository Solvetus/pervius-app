#!/usr/bin/env python3
"""Reproducible catalogue inspection (no NetworkManager interaction)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):  # direct execution: python3 pervius/tools/inspect_catalogue.py
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pervius.catalogue.validator import inspect_archive


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate and summarize a FastVPN catalogue ZIP")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--zip", type=Path, help="path to a local catalogue ZIP")
    source.add_argument("--url", help="HTTPS URL to download")
    args = parser.parse_args(argv)

    if args.zip:
        try:
            blob = args.zip.read_bytes()
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    else:
        from ..catalogue.fetcher import fetch_bytes

        try:
            blob = fetch_bytes(args.url)
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    try:
        print(json.dumps(inspect_archive(blob), indent=2, sort_keys=True))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
