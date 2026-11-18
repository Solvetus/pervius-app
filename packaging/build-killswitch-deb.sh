#!/bin/sh
# Build the optional privileged kill-switch package.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

PKG=solvetus-vpn-killswitch
VERSION=$(PYTHONPATH="$ROOT" python3 -c 'from solvetus.config import VERSION; print(VERSION)')
OUT_DIR="$ROOT/dist"
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/solvetus-killswitch-deb.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT INT TERM

install -d "$STAGE/DEBIAN"
install -d "$STAGE/usr/bin"
install -d "$STAGE/usr/lib/systemd/system"
install -d "$STAGE/usr/share/dbus-1/system.d"
install -d "$STAGE/usr/share/dbus-1/system-services"
install -d "$STAGE/usr/share/polkit-1/actions"
install -d "$STAGE/usr/share/doc/$PKG"

install -m 0644 packaging/killswitch/solvetus-killswitchd.service \
    "$STAGE/usr/lib/systemd/system/solvetus-killswitchd.service"
install -m 0644 packaging/killswitch/org.solvetus.KillSwitch1.conf \
    "$STAGE/usr/share/dbus-1/system.d/org.solvetus.KillSwitch1.conf"
install -m 0644 packaging/killswitch/org.solvetus.KillSwitch1.service \
    "$STAGE/usr/share/dbus-1/system-services/org.solvetus.KillSwitch1.service"
install -m 0644 packaging/killswitch/org.solvetus.killswitch.policy \
    "$STAGE/usr/share/polkit-1/actions/org.solvetus.killswitch.policy"
install -m 0644 docs/security-design.md \
    "$STAGE/usr/share/doc/$PKG/security-design.md"
install -m 0644 packaging/killswitch/copyright \
    "$STAGE/usr/share/doc/$PKG/copyright"
gzip -9n -c packaging/killswitch/changelog >"$STAGE/usr/share/doc/$PKG/changelog.Debian.gz"
chmod 0644 "$STAGE/usr/share/doc/$PKG/changelog.Debian.gz"

install -m 0755 /dev/stdin "$STAGE/usr/bin/solvetus-killswitch" <<'EOF'
#!/usr/bin/python3
from solvetus.tools.killswitch_cli import main

raise SystemExit(main())
EOF

cat >"$STAGE/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Section: net
Priority: optional
Architecture: all
Maintainer: Solvetus project <noreply@example.invalid>
Installed-Size: $(du -sk "$STAGE/usr" | cut -f1)
Depends: solvetus-vpn (>= $VERSION), python3 (>= 3.10), python3-gi, gir1.2-glib-2.0, gir1.2-nm-1.0, nftables, polkitd | policykit-1, dbus-broker | dbus-daemon | dbus, systemd
Description: optional system-wide kill switch for Solvetus VPN Manager
 This package installs a small root-owned system service that applies a
 dedicated nftables table for the Solvetus managed VPN profile. The GUI
 remains an ordinary-user process; polkit authorizes arm and disarm
 requests over the system bus.
 .
 The service never flushes the global firewall, coexists with UFW, and
 never invokes a shell. It is optional: without this package the base
 application has no kill-switch switch.
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
chmod 0755 "$STAGE/DEBIAN" "$STAGE"

mkdir -p "$OUT_DIR"
OUTPUT="$OUT_DIR/${PKG}_${VERSION}_all.deb"
rm -f "$OUTPUT"
dpkg-deb --build --root-owner-group "$STAGE" "$OUTPUT"
dpkg-deb --info "$OUTPUT" >/dev/null

printf 'built: %s\n' "$OUTPUT"
sha256sum "$OUTPUT"
