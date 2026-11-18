#!/bin/sh
# Build one combined Debian package: desktop app + optional kill-switch service.
# The GUI stays unprivileged; the root service is idle until explicitly armed.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

PKG=solvetus-vpn
ARCH=all
VERSION=$(PYTHONPATH="$ROOT" python3 -c 'from solvetus.config import VERSION; print(VERSION)')
OUT_DIR="$ROOT/dist"
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/solvetus-combined-deb.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT INT TERM

install -d "$STAGE/DEBIAN"
install -d "$STAGE/usr/bin"
install -d "$STAGE/usr/lib/python3/dist-packages"
install -d "$STAGE/usr/lib/systemd/system"
install -d "$STAGE/usr/share/applications"
install -d "$STAGE/usr/share/icons/hicolor/scalable/apps"
install -d "$STAGE/usr/share/metainfo"
install -d "$STAGE/usr/share/dbus-1/system.d"
install -d "$STAGE/usr/share/dbus-1/system-services"
install -d "$STAGE/usr/share/polkit-1/actions"
install -d "$STAGE/usr/share/doc/$PKG"

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

install -m 0755 /dev/stdin "$STAGE/usr/bin/solvetus-killswitch" <<'EOF'
#!/usr/bin/python3
from solvetus.tools.killswitch_cli import main

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
install -m 0644 packaging/killswitch/solvetus-killswitchd.service \
    "$STAGE/usr/lib/systemd/system/solvetus-killswitchd.service"
install -m 0644 packaging/killswitch/org.solvetus.KillSwitch1.conf \
    "$STAGE/usr/share/dbus-1/system.d/org.solvetus.KillSwitch1.conf"
install -m 0644 packaging/killswitch/org.solvetus.KillSwitch1.service \
    "$STAGE/usr/share/dbus-1/system-services/org.solvetus.KillSwitch1.service"
install -m 0644 packaging/killswitch/org.solvetus.killswitch.policy \
    "$STAGE/usr/share/polkit-1/actions/org.solvetus.killswitch.policy"
install -m 0644 README.md "$STAGE/usr/share/doc/$PKG/README.md"
install -m 0644 docs/security-design.md "$STAGE/usr/share/doc/$PKG/security-design.md"
install -m 0644 packaging/copyright "$STAGE/usr/share/doc/$PKG/copyright"
gzip -9n -c packaging/changelog >"$STAGE/usr/share/doc/$PKG/changelog.Debian.gz"
chmod 0644 "$STAGE/usr/share/doc/$PKG/changelog.Debian.gz"

INSTALLED_SIZE=$(du -sk "$STAGE/usr" | cut -f1)

cat >"$STAGE/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: Solvetus project <noreply@example.invalid>
Installed-Size: $INSTALLED_SIZE
Depends: python3 (>= 3.10), python3-gi, gir1.2-glib-2.0, gir1.2-gtk-4.0, gir1.2-adw-1, gir1.2-nm-1.0, gir1.2-secret-1, gir1.2-soup-3.0, network-manager, network-manager-openvpn, openvpn, nftables, polkitd | policykit-1, dbus-broker | dbus-daemon | dbus, systemd
Conflicts: solvetus-vpn-killswitch (<< $VERSION)
Replaces: solvetus-vpn-killswitch (<< $VERSION)
Breaks: solvetus-vpn-killswitch (<< $VERSION)
Provides: solvetus-vpn-killswitch (= $VERSION)
Description: desktop manager for an existing OpenVPN subscription
 Solvetus VPN Manager is an independent GTK4/libadwaita front end that
 imports provider-supplied OpenVPN profiles through NetworkManager and
 its OpenVPN plugin. The application runs as an ordinary user;
 NetworkManager performs privileged network operations.
 .
 This combined test package also installs the optional kill-switch system
 service and CLI. The service is idle until explicitly armed through polkit;
 the GUI remains unprivileged.
 .
 This is an early test build. It manages one reusable NetworkManager
 profile and does not implement auto-protect or DNS filtering.
EOF
chmod 0644 "$STAGE/DEBIAN/control"

cat >"$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
if command -v busctl >/dev/null 2>&1; then
    busctl call org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus ReloadConfig >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 0755 "$STAGE/DEBIAN/postinst"

cat >"$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl stop solvetus-killswitchd.service >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 0755 "$STAGE/DEBIAN/prerm"

cat >"$STAGE/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
case "$1" in
    remove|purge)
        if command -v nft >/dev/null 2>&1; then
            nft delete table inet solvetus_ks >/dev/null 2>&1 || true
        fi
        rm -rf /run/solvetus
        ;;
esac
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
if command -v busctl >/dev/null 2>&1; then
    busctl call org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus ReloadConfig >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 0755 "$STAGE/DEBIAN/postrm"

(
    cd "$STAGE"
    find . -type f ! -path './DEBIAN/*' -printf '%P\0' \
        | LC_ALL=C sort -z \
        | xargs -0 md5sum >DEBIAN/md5sums
)
chmod 0644 "$STAGE/DEBIAN/md5sums"

if find "$STAGE/usr/lib/python3/dist-packages/solvetus" -type d -name __pycache__ | grep -q .; then
    echo "error: bytecode directories remain in the package" >&2
    exit 1
fi
if find "$STAGE/usr/lib/python3/dist-packages/solvetus" -type f -name '*.py[co]' | grep -q .; then
    echo "error: bytecode files remain in the package" >&2
    exit 1
fi

find "$STAGE/usr" -type d -exec chmod 0755 {} +
find "$STAGE/usr" -type f -exec chmod 0644 {} +
chmod 0755 "$STAGE/usr/bin/solvetus-vpn" \
    "$STAGE/usr/bin/solvetus-vpn-proof" \
    "$STAGE/usr/bin/solvetus-vpn-inspect" \
    "$STAGE/usr/bin/solvetus-killswitch"
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
