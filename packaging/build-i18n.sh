#!/bin/sh
# Compile the translations and the translated desktop and AppStream files.
#
# Usage: packaging/build-i18n.sh [OUTDIR]      (default: build/i18n)
#
# Output, consumed by packaging/layout.tsv:
#   OUTDIR/locale/<lang>/LC_MESSAGES/pervius.mo
#   OUTDIR/com.solvetus.Pervius.desktop
#   OUTDIR/com.solvetus.Pervius.metainfo.xml
#
# Shared by every distribution. Needs GNU gettext's msgfmt and the AppStream
# ITS rules (package "appstream"). Compiled catalogues are never committed.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${1:-"$ROOT/build/i18n"}
APP_ID=com.solvetus.Pervius

rm -rf "$OUT"
mkdir -p "$OUT/locale"
while read -r lang; do
    [ -n "$lang" ] || continue
    mkdir -p "$OUT/locale/$lang/LC_MESSAGES"
    msgfmt --check --output-file="$OUT/locale/$lang/LC_MESSAGES/pervius.mo" "$ROOT/po/$lang.po"
done <"$ROOT/po/LINGUAS"
msgfmt --desktop --template="$ROOT/data/$APP_ID.desktop.in" -d "$ROOT/po" \
    --output-file="$OUT/$APP_ID.desktop"
msgfmt --xml --template="$ROOT/data/$APP_ID.metainfo.xml.in" -d "$ROOT/po" \
    --output-file="$OUT/$APP_ID.metainfo.xml"
