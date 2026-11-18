#!/bin/sh
# Build the Debian/Ubuntu package into dist/.
#
# Usage: packaging/debian/build.sh [--print-version]
#
# The install tree comes from the distribution-neutral packaging/stage.sh;
# this script only adds Debian metadata, maintainer scripts and docs.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
HERE="$ROOT/packaging/debian"
cd "$ROOT"

PACKAGE=pervius
PYTHONDIR=/usr/lib/python3/dist-packages

version() {
    PYTHONPATH="$ROOT" python3 -c 'import pervius; print(pervius.__version__)'
}

if [ "${1:-}" = "--print-version" ]; then
    version
    exit 0
fi

VERSION=$(version)
OUT_DIR=${DIST_DIR:-"$ROOT/dist"}
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/$PACKAGE-deb.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT INT TERM
chmod 0755 "$STAGE"

"$ROOT/packaging/stage.sh" "$STAGE" "$PYTHONDIR"

DOC="$STAGE/usr/share/doc/$PACKAGE"
install -d -m 0755 "$DOC"
install -m 0644 README.md "$DOC/README.md"
install -m 0644 docs/ARCHITECTURE.md "$DOC/ARCHITECTURE.md"
install -m 0644 "$HERE/copyright" "$DOC/copyright"
gzip -9n -c "$HERE/changelog" >"$DOC/changelog.Debian.gz"
chmod 0644 "$DOC/changelog.Debian.gz"

if find "$STAGE" -name __pycache__ -o -name '*.py[co]' | grep -q .; then
    echo "error: Python bytecode in the staged tree" >&2
    exit 1
fi

find "$STAGE/usr" -type d -exec chmod 0755 {} +

install -d -m 0755 "$STAGE/DEBIAN"
INSTALLED_SIZE=$(du -sk "$STAGE/usr" | cut -f1)
sed -e "s/@PACKAGE@/$PACKAGE/g" \
    -e "s/@VERSION@/$VERSION/g" \
    -e "s/@INSTALLED_SIZE@/$INSTALLED_SIZE/g" \
    "$HERE/control.in" >"$STAGE/DEBIAN/control"
chmod 0644 "$STAGE/DEBIAN/control"
for script in preinst postinst prerm postrm; do
    if [ -f "$HERE/$script" ]; then
        install -m 0755 "$HERE/$script" "$STAGE/DEBIAN/$script"
    fi
done
(
    cd "$STAGE"
    find . -type f ! -path './DEBIAN/*' -printf '%P\0' | LC_ALL=C sort -z | xargs -0 md5sum >DEBIAN/md5sums
)
chmod 0644 "$STAGE/DEBIAN/md5sums"

mkdir -p "$OUT_DIR"
OUTPUT="$OUT_DIR/${PACKAGE}_${VERSION}_all.deb"
rm -f "$OUTPUT"
dpkg-deb --build --root-owner-group "$STAGE" "$OUTPUT" >/dev/null
dpkg-deb --info "$OUTPUT" >/dev/null

printf 'built: %s\n' "$OUTPUT"
sha256sum "$OUTPUT"
