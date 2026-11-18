#!/bin/sh
# Regenerate po/pervius.pot from the sources and merge it into every .po.
#
# Usage: scripts/update-pot.sh [--pot-only]
#
# Maintainer tool. Needs GNU gettext (xgettext, msgmerge) and the AppStream
# ITS rules (package "appstream") for the metainfo file.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
POT=${POT:-po/pervius.pot}
VERSION=$(PYTHONPATH="$ROOT" python3 -c 'import pervius; print(pervius.__version__)')

python_files=$(grep -v -e '^#' -e '^[[:space:]]*$' po/POTFILES | grep '\.py$')
desktop_files=$(grep -v -e '^#' -e '^[[:space:]]*$' po/POTFILES | grep '\.desktop\.in$')
xml_files=$(grep -v -e '^#' -e '^[[:space:]]*$' po/POTFILES | grep '\.xml\.in$')

# shellcheck disable=SC2086 # file lists are word-split on purpose
xgettext --from-code=UTF-8 --language=Python \
    --keyword=_ --keyword=N_ --keyword=C_:1c,2 --keyword=ngettext:1,2 \
    --add-comments=Translators: --sort-by-file \
    --package-name=pervius --package-version="$VERSION" \
    --msgid-bugs-address=https://github.com/Solvetus/pervius-app/issues \
    --copyright-holder="Solvetus Labs" \
    -o "$POT" $python_files
# The desktop entry's Name stays "Pervius" in every language.
# shellcheck disable=SC2086
xgettext --join-existing --language=Desktop -k \
    --keyword=GenericName --keyword=Comment --keyword=Keywords \
    --add-comments=Translators: -o "$POT" $desktop_files
# shellcheck disable=SC2086
xgettext --join-existing --add-comments=Translators: -o "$POT" $xml_files

if [ "${1:-}" = "--pot-only" ]; then
    exit 0
fi
while read -r lang; do
    [ -n "$lang" ] || continue
    msgmerge --quiet --update --no-fuzzy-matching --backup=none "po/$lang.po" "$POT"
done <po/LINGUAS
