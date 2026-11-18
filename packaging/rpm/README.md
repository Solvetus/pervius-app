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
| `build/i18n/com.solvetus.Pervius.desktop` (generated) | `/usr/share/applications/` |
| `build/i18n/com.solvetus.Pervius.metainfo.xml` (generated) | `/usr/share/metainfo/` |
| `build/i18n/locale/` (generated `.mo` files) | `/usr/share/locale/` (`%find_lang pervius`) |
| `data/icons/hicolor/scalable/apps/com.solvetus.Pervius.svg` | `/usr/share/icons/hicolor/scalable/apps/` |
| `data/icons/hicolor/scalable/status/com.solvetus.Pervius-{tray-off,tray-connected,tray-reconnecting,card-off}.svg` | `/usr/share/icons/hicolor/scalable/status/` |
| `data/icons/hicolor/symbolic/apps/com.solvetus.Pervius-symbolic.svg` | `/usr/share/icons/hicolor/symbolic/apps/` |
| `data/networkmanager/90-pervius-guard` | `/usr/lib/NetworkManager/dispatcher.d/` (0755) plus a link `pre-up.d/90-pervius-guard -> ../90-pervius-guard` |
| `data/systemd/pervius-killswitchd.service` | `/usr/lib/systemd/system/` (`%{_unitdir}`) |
| `data/dbus/com.solvetus.Pervius.KillSwitch1.conf` | `/usr/share/dbus-1/system.d/` |
| `data/dbus/com.solvetus.Pervius.KillSwitch1.service` | `/usr/share/dbus-1/system-services/` |
| `data/polkit/com.solvetus.pervius.killswitch.policy` | `/usr/share/polkit-1/actions/` |
| `data/man/man1/pervius*.1` | `/usr/share/man/man1/` (`%{_mandir}/man1`, compressed by brp) |

Use `%license LICENSE NOTICE` and `%doc README.md CHANGELOG.md docs/ARCHITECTURE.md`.
Let `%py_byte_compile` / brp scripts compile the package as usual.

## Spec outline

- `Name: pervius`, `Version:` from `pervius/__init__.py`, `BuildArch: noarch`,
  `License: Apache-2.0`, `URL: https://github.com/Solvetus/pervius-app`.
- `Requires:` `python3-gobject`, `python3-dns` (dnspython), `iso-codes`,
  `gtk4`, `libadwaita`, `NetworkManager` (which includes the dispatcher),
  `NetworkManager-libnm`, `NetworkManager-openvpn`, `openvpn`, `libsecret`,
  `libsoup3`, `nftables`, `polkit`, `systemd`, `dbus`.
- `BuildRequires:` `python3-devel`, `systemd-rpm-macros`, `gettext` (msgfmt),
  `appstream` (ITS rules for `msgfmt --xml`, and validation in `%check`),
  `desktop-file-utils`, plus the runtime typelibs if `%check` runs the unit
  tests.
- Scriptlets: `%post`/`%postun`: `systemctl daemon-reload` and the bus policy
  reload (`busctl call org.freedesktop.DBus /org/freedesktop/DBus
  org.freedesktop.DBus ReloadConfig`); `%preun`: stop
  `pervius-killswitchd.service`; `%postun` on erase (`$1 -eq 0`): delete
  `inet pervius_ks`, `inet pervius_v6` and `/run/pervius`. Do not enable the service; it is D-Bus
  activated. There is no 0.1.x RPM, so no upgrade guard is needed.

## To verify on Fedora before shipping

- **SELinux:** NetworkManager-openvpn must be able to read the CA file under
  `~/.local/share/pervius/certificates/nm-openvpn/`. Fedora's policy expects
  user certificates in `~/.cert` (`home_cert_t`); the import path may need to
  change or a label may be needed. Check for AVC denials on first connect.
- **firewalld:** confirm the `inet pervius_ks` and `inet pervius_v6` tables at
  priority -10 coexist with firewalld's tables and that a firewalld reload
  does not remove them.
- **SELinux and the dispatcher hook:** confirm `NetworkManager-dispatcher`
  may run `nft` from the hook (`NetworkManager_dispatcher_t`), and that the
  kill-switch service's `socket cgroupv2` DNS-window rule matches its cgroup.
- **dbus-broker:** confirm D-Bus activation and the policy reload (Fedora's
  default bus).
- **polkit:** confirm the action prompts as expected for active local users.
- Run the unit tests and `tests/manual/run.sh` on Fedora.
- Add an `rpm` job next to the `deb` job in `.github/workflows/ci.yml`, using a
  Fedora container, and attach the RPM in `release.yml`.
