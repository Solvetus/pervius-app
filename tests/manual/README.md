# Manual UI harnesses

These scripts drive the real GTK window on a private
[Broadway](https://docs.gtk.org/gtk4/broadway.html) display and check what it
renders. They complement the unit tests (`python3 -m unittest discover -s tests -t .`)
for behaviour that needs a live GTK main loop. They are not run in CI because
they need a desktop session bus and a running NetworkManager.

## Run

```sh
tests/manual/run.sh            # all harnesses
tests/manual/run.sh smoke      # one harness
```

Requirements: `gtk4-broadwayd` (package `libgtk-4-bin` on Debian/Ubuntu), the
GTK 4, libadwaita, NM, Secret and Soup GObject-introspection bindings, a
running NetworkManager and a session D-Bus.

## Safety

`harness.py` refuses to run unless `XDG_DATA_HOME` is inside the system temp
directory (`run.sh` creates a fresh sandbox per harness). Inside the sandbox:

- the NetworkManager secret agent is **not** registered;
- the kill-switch client always reports a disarmed service, so the root
  service is never contacted;
- the public-IP lookup returns a documentation address (198.51.100.7);
- the upgrade migration is disabled, so the keyring and profile are never touched;
- the catalogue is synthetic: real city names, `example.com` hosts.

NetworkManager is used read-only (the window lists connections). No
connection is created, modified or activated.

## Harnesses

| Harness | Covers |
| --- | --- |
| `smoke` | window starts idle with the catalogue loaded |
| `idle_details` | details panel while disconnected (ISP IP, `—` fields, Switch IP disabled) |
| `connected_details` | exit IP, traffic totals from tunnel counters, Switch IP reconnect |
| `stale_location` | choosing a location updates the row and the status line |
| `location_search` | search by country name, alias, code and city |
| `favorites` | tray Favorites submenu, star toggles, favorites-only filter |
| `protocol_switch` | UDP/TCP exclusivity and the kill-switch lock |
| `killswitch_ui` | armed/off rendering, control locking, tray toggle, confirmation |
| `reconnect_state` | drop → reconnect, retry give-up, manual cancel, switch off |
| `reconnect_switch` | Reconnect automatically switch, including mid-retry |
| `notifications` | background notifications for a drop and a reconnect |
| `settings_dialogs` | Settings, Legal, About and Protocol Guide dialogs open |
| `window_tray` | StatusNotifierItem registration, menu layout, red/green icon |
| `tray_sni` | standalone SNI/DBusMenu properties; `--interactive` to click it |

Each harness prints `ok`/`FAIL` lines and exits non-zero on failure.
