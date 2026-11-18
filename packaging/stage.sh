#!/bin/sh
# Stage the distribution-neutral install tree described by packaging/layout.tsv.
#
# Usage: packaging/stage.sh DESTDIR PYTHONDIR
#   DESTDIR    staging root (a package build root, e.g. an RPM buildroot)
#   PYTHONDIR  system Python module directory for this distribution
#
# Distribution packaging calls this, then adds its own metadata and docs.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 DESTDIR PYTHONDIR" >&2
    exit 2
fi
DESTDIR=$1
PYTHONDIR=$2
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TAB=$(printf '\t')

grep -v -e '^#' -e '^[[:space:]]*$' "$ROOT/packaging/layout.tsv" |
while IFS=$TAB read -r mode source destination; do
    destination=$(printf '%s\n' "$destination" | sed "s|{pythondir}|$PYTHONDIR|")
    case $mode in
        tree)
            (cd "$ROOT/$source" && find . -name __pycache__ -prune -o -type f ! -name '*.py[co]' -print) |
            while read -r file; do
                install -d -m 0755 "$DESTDIR$destination/$(dirname "$file")"
                install -m 0644 "$ROOT/$source/$file" "$DESTDIR$destination/$file"
            done
            ;;
        link)
            install -d -m 0755 "$DESTDIR$(dirname "$destination")"
            ln -s "$source" "$DESTDIR$destination"
            ;;
        [0-7][0-7][0-7][0-7])
            install -d -m 0755 "$DESTDIR$(dirname "$destination")"
            install -m "$mode" "$ROOT/$source" "$DESTDIR$destination"
            ;;
        *)
            echo "stage.sh: unknown mode '$mode' for $source" >&2
            exit 1
            ;;
    esac
done
