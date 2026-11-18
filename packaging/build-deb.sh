#!/bin/sh
# Build a pure-Python, architecture-independent Debian package.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

PKG=solvetus-vpn
ARCH=all
VERSION=$(PYTHONPATH="$ROOT" python3 -c 'from solvetus.config import VERSION; print(VERSION)')
OUT_DIR="$ROOT/dist"
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/solvetus-deb.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT INT TERM

install -d "$STAGE/DEBIAN"
install -d "$STAGE/usr/bin"
install -d "$STAGE/usr/lib/python3/dist-packages"
install -d "$STAGE/usr/share/applications"
install -d "$STAGE/usr/share/icons/hicolor/scalable/apps"
install -d "$STAGE/usr/share/metainfo"
install -d "$STAGE/usr/share/doc/$PKG"

# Python package.  Keep it in the system dist-packages path so the distro
# python3 (with its GI modules) can import it without a virtualenv.  The
# Debian source name contains a hyphen; the importable Python package is
# "solvetus".
cp -a solvetus "$STAGE/usr/lib/python3/dist-packages/solvetus"
find "$STAGE/usr/lib/python3/dist-packages/solvetus" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$STAGE/usr/lib/python3/dist-packages/solvetus" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete

install -m 0755 /dev/stdin "$STAGE/usr/bin/solvetus-vpn" <<'EOF'
#!/usr/bin/python3
from solvetus.ui.app import main

raise SystemExit(main())
EOF

install -m 0755 /dev/stdin "$STAGE/usr/bin/solvetus-vpn-proof" <<'EOF'
#!/usr/bin/python3
from solvetus.tools.proof_connect import main

raise SystemExit(main())
EOF

install -m 0755 /dev/stdin "$STAGE/usr/bin/solvetus-vpn-inspect" <<'EOF'
#!/usr/bin/python3
from solvetus.tools.inspect_catalogue import main

raise SystemExit(main())
EOF

install -m 0644 packaging/org.solvetus.VPNManager.desktop \
    "$STAGE/usr/share/applications/org.solvetus.VPNManager.desktop"
install -m 0644 packaging/org.solvetus.VPNManager.svg \
    "$STAGE/usr/share/icons/hicolor/scalable/apps/org.solvetus.VPNManager.svg"
install -m 0644 packaging/org.solvetus.VPNManager-connected.svg \
    "$STAGE/usr/share/icons/hicolor/scalable/apps/org.solvetus.VPNManager-connected.svg"
install -m 0644 packaging/org.solvetus.VPNManager-disconnected.svg \
    "$STAGE/usr/share/icons/hicolor/scalable/apps/org.solvetus.VPNManager-disconnected.svg"
install -m 0644 packaging/org.solvetus.VPNManager.metainfo.xml \
    "$STAGE/usr/share/metainfo/org.solvetus.VPNManager.metainfo.xml"
install -m 0644 README.md "$STAGE/usr/share/doc/$PKG/README.md"
install -m 0644 packaging/copyright "$STAGE/usr/share/doc/$PKG/copyright"
gzip -9n -c packaging/changelog > "$STAGE/usr/share/doc/$PKG/changelog.Debian.gz"
chmod 0644 "$STAGE/usr/share/doc/$PKG/changelog.Debian.gz"

INSTALLED_SIZE=$(du -sk "$STAGE/usr" | cut -f1)

cat > "$STAGE/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: Solvetus project <noreply@example.invalid>
Installed-Size: $INSTALLED_SIZE
Depends: python3 (>= 3.10), python3-gi, gir1.2-glib-2.0, gir1.2-gtk-4.0, gir1.2-adw-1, gir1.2-nm-1.0, gir1.2-secret-1, gir1.2-soup-3.0, network-manager, network-manager-openvpn, openvpn
Description: desktop manager for an existing OpenVPN subscription
 Solvetus VPN Manager is an independent GTK4/libadwaita front end that
 imports provider-supplied OpenVPN profiles through NetworkManager and
 its OpenVPN plugin. The application runs as an ordinary user;
 NetworkManager performs privileged network operations.
 .
 This is an early test build. It manages one reusable NetworkManager
 profile and does not implement a kill switch, auto-protect, DNS
 filtering, background reconnection, or a background resident service.
EOF

chmod 0644 "$STAGE/DEBIAN/control"

# Debian metadata checksum list (paths without a leading ./).
(
    cd "$STAGE"
    find . -type f ! -path './DEBIAN/*' -printf '%P\0' \
        | LC_ALL=C sort -z \
        | xargs -0 md5sum > DEBIAN/md5sums
)
chmod 0644 "$STAGE/DEBIAN/md5sums"

# Build-time guard: no bytecode or test material should ship.
if find "$STAGE/usr/lib/python3/dist-packages/solvetus" -type d -name __pycache__ | grep -q .; then
    echo "error: bytecode directories remain in the package" >&2
    exit 1
fi
if find "$STAGE/usr/lib/python3/dist-packages/solvetus" -type f -name '*.py[co]' | grep -q .; then
    echo "error: bytecode files remain in the package" >&2
    exit 1
fi

# Normalize modes: system payload is world-readable, wrappers are executable.
find "$STAGE/usr" -type d -exec chmod 0755 {} +
find "$STAGE/usr" -type f -exec chmod 0644 {} +
chmod 0755 "$STAGE/usr/bin/solvetus-vpn" \
    "$STAGE/usr/bin/solvetus-vpn-proof" \
    "$STAGE/usr/bin/solvetus-vpn-inspect"
chmod 0755 "$STAGE/DEBIAN"
chmod 0644 "$STAGE/DEBIAN/control" "$STAGE/DEBIAN/md5sums"
chmod 0755 "$STAGE"

mkdir -p "$OUT_DIR"
OUTPUT="$OUT_DIR/${PKG}_${VERSION}_${ARCH}.deb"
rm -f "$OUTPUT"
dpkg-deb --build --root-owner-group "$STAGE" "$OUTPUT"
dpkg-deb --info "$OUTPUT" >/dev/null

printf 'built: %s\n' "$OUTPUT"
sha256sum "$OUTPUT"
