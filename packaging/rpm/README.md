# Fedora (RPM) packaging — planned

Fedora packaging is planned but not built yet. Pervius currently ships only as
a Debian/Ubuntu `.deb`. This file lists what an RPM spec must do, so it can be
added without touching the application code.

## Files the spec must install

Everything comes from the shared table `packaging/layout.tsv`; `{pythondir}`
is `%{python3_sitelib}`. The simplest `%install` is:

```sh
packaging/stage.sh %{buildroot} %{python3_sitelib}
```

| Source | Destination |
| --- | --- |
| `pervius/` (whole package, no bytecode) | `%{python3_sitelib}/pervius/` |
| `data/bin/pervius` | `/usr/bin/pervius` (0755) |
| `data/bin/pervius-killswitch` | `/usr/bin/pervius-killswitch` (0755) |
| `data/bin/pervius-inspect` | `/usr/bin/pervius-inspect` (0755) |
| `data/bin/pervius-proof` | `/usr/bin/pervius-proof` (0755) |
| `data/com.solvetus.Pervius.desktop` | `/usr/share/applications/` |
| `data/com.solvetus.Pervius.metainfo.xml` | `/usr/share/metainfo/` |
| `data/icons/hicolor/scalable/apps/com.solvetus.Pervius{,-connected,-disconnected}.svg` | `/usr/share/icons/hicolor/scalable/apps/` |
| `data/systemd/pervius-killswitchd.service` | `/usr/lib/systemd/system/` (`%{_unitdir}`) |
| `data/dbus/com.solvetus.Pervius.KillSwitch1.conf` | `/usr/share/dbus-1/system.d/` |
| `data/dbus/com.solvetus.Pervius.KillSwitch1.service` | `/usr/share/dbus-1/system-services/` |
| `data/polkit/com.solvetus.pervius.killswitch.policy` | `/usr/share/polkit-1/actions/` |

Use `%license LICENSE NOTICE` and `%doc README.md CHANGELOG.md docs/ARCHITECTURE.md`.
Let `%py_byte_compile` / brp scripts compile the package as usual.

## Spec outline

- `Name: pervius`, `Version:` from `pervius/__init__.py`, `BuildArch: noarch`,
  `License: Apache-2.0`, `URL: https://github.com/Solvetus/pervius-app`.
- `Requires:` `python3-gobject`, `gtk4`, `libadwaita`, `NetworkManager`,
  `NetworkManager-libnm`, `NetworkManager-openvpn`, `openvpn`, `libsecret`,
  `libsoup3`, `nftables`, `polkit`, `systemd`, `dbus`.
- `BuildRequires:` `python3-devel`, `systemd-rpm-macros`,
  `desktop-file-utils`, `libappstream-glib` or `appstream` (to validate the
  desktop file and metainfo in `%check`), plus the runtime typelibs if
  `%check` runs the unit tests.
- Scriptlets: `%post`/`%postun`: `systemctl daemon-reload` and the bus policy
  reload (`busctl call org.freedesktop.DBus /org/freedesktop/DBus
  org.freedesktop.DBus ReloadConfig`); `%preun`: stop
  `pervius-killswitchd.service`; `%postun` on erase (`$1 -eq 0`): delete
  `inet pervius_ks` and `/run/pervius`. Do not enable the service; it is D-Bus
  activated. There is no 0.1.x RPM, so no upgrade guard is needed.

## To verify on Fedora before shipping

- **SELinux:** NetworkManager-openvpn must be able to read the CA file under
  `~/.local/share/pervius/certificates/nm-openvpn/`. Fedora's policy expects
  user certificates in `~/.cert` (`home_cert_t`); the import path may need to
  change or a label may be needed. Check for AVC denials on first connect.
- **firewalld:** confirm the `inet pervius_ks` table at priority -10 coexists
  with firewalld's tables and that a firewalld reload does not remove it.
- **dbus-broker:** confirm D-Bus activation and the policy reload (Fedora's
  default bus).
- **polkit:** confirm the action prompts as expected for active local users.
- Run the unit tests and `tests/manual/run.sh` on Fedora.
- Add an `rpm` job next to the `deb` job in `.github/workflows/ci.yml`, using a
  Fedora container, and attach the RPM in `release.yml`.
