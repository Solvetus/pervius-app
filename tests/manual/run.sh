#!/bin/sh
# Run the manual UI harnesses on a private Broadway display.
#
# Usage: tests/manual/run.sh [harness ...]   (default: all)
#
# Needs gtk4-broadwayd, the GTK/libadwaita/NM GI bindings, a running
# NetworkManager (read-only use) and a session bus.  Each harness gets its own
# temporary XDG directories; nothing is written to your real data directory.
set -u

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
DISPLAY_NUM=${BROADWAY_DISPLAY_NUM:-17}

if [ "$#" -eq 0 ]; then
    set -- account_dialog armed_switch connected_details favorites idle_details killswitch_ui location_search \
        notifications protocol_switch reconnect_state reconnect_switch \
        settings_dialogs smoke stale_location tray_sni window_tray
fi

gtk4-broadwayd ":$DISPLAY_NUM" >/dev/null 2>&1 &
BROADWAY_PID=$!
trap 'kill "$BROADWAY_PID" 2>/dev/null' EXIT INT TERM
sleep 1

failed=""
for name in "$@"; do
    sandbox=$(mktemp -d)
    mkdir -p "$sandbox/data" "$sandbox/cache" "$sandbox/config"
    GDK_BACKEND=broadway BROADWAY_DISPLAY=":$DISPLAY_NUM" \
        XDG_DATA_HOME="$sandbox/data" XDG_CACHE_HOME="$sandbox/cache" \
        XDG_CONFIG_HOME="$sandbox/config" PYTHONDONTWRITEBYTECODE=1 \
        timeout 60 python3 "$HERE/$name.py" >"$sandbox/out" 2>"$sandbox/err"
    status=$?
    grep -E '^(ok|FAIL|PASS)' "$sandbox/out"
    if [ "$status" -ne 0 ]; then
        failed="$failed $name"
        echo "FAIL $name (exit $status)"
        grep -v 'Gdk-WARNING' "$sandbox/err" | sed -n '/./p' | tail -n 15
    fi
    rm -rf "$sandbox"
done

if [ -n "$failed" ]; then
    echo "failed:$failed"
    exit 1
fi
echo "all harnesses passed"
