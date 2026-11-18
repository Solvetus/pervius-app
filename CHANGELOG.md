# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Releases up to 0.1.19 were private test builds named "Solvetus VPN Manager".

## [Unreleased]

### Changed

- Renamed the project to **Pervius**, an unofficial Linux client for FastVPN
  published by Solvetus Labs. Every identifier changed: application ID
  `com.solvetus.Pervius`, Python package and Debian package `pervius`, commands
  `pervius`, `pervius-killswitch`, `pervius-inspect` and `pervius-proof`,
  D-Bus service `com.solvetus.Pervius.KillSwitch1`, polkit action
  `com.solvetus.pervius.killswitch.control`, systemd unit
  `pervius-killswitchd.service`, nftables table `inet pervius_ks`, runtime
  directory `/run/pervius`, NetworkManager profile "Pervius (managed)" (same
  reserved UUID).
- Licensed under the Apache License 2.0 (previously all rights reserved).
- Reorganised the repository for several Linux distributions: shared assets in
  `data/`, one install-path table in `packaging/layout.tsv`, Debian packaging in
  `packaging/debian/`. Fedora packaging is planned.
- `pervius/__init__.py` is the single version source.
- The About and Legal dialogs, AppStream metadata and package description
  state the licence and that Pervius is not affiliated with Namecheap, Inc.

### Added

- One-time upgrade migration from 0.1.x: settings and favorites, the ownership
  manifest, cached catalogue and CA file move to `~/.local/share/pervius`;
  saved passwords move to the new keyring schema and the old entries are
  deleted; the managed NetworkManager profile is renamed in place after the
  usual ownership checks.
- The Debian package replaces `solvetus-vpn` and `solvetus-vpn-killswitch`,
  and refuses to install over an armed 0.1.x kill switch when installed with
  `dpkg -i`. With `apt`, the 0.1.x package's own removal script removes its
  firewall table first, so disarm before upgrading.
- `pervius-killswitch diagnose` reports the system bus, firewall front ends,
  `nftables.service` and polkit rules directories.
- Continuous integration (unit tests, ruff, shellcheck, AppStream and desktop
  file validation, Debian build and lintian) and a release workflow that
  publishes the `.deb` and `SHA256SUMS` to GitHub Releases.
- Self-checking UI harnesses in `tests/manual/`.
- README, architecture, packaging, security and contributing documentation.

### Removed

- The superseded split build scripts for a base package and a separate
  kill-switch package.

## [0.1.19] - 2026-11-17

### Added

- An icon for the **Allow local network** row.

### Removed

- The "About this test build" group; the Security note and About dialog cover it.

## [0.1.18] - 2026-11-17

### Removed

- The banner after **Switch IP**; the exit-IP field now updates silently.

## [0.1.17] - 2026-11-17

### Changed

- The connection-details panel is always visible. While disconnected it shows
  the ISP IP and protocol, with `—` for the VPN exit IP and traffic, and
  **Switch IP** is disabled.

## [0.1.16] - 2026-11-17

### Added

- ISP IP and VPN exit IP on the status card, fetched only over HTTPS; the ISP
  lookup is skipped while the kill switch is armed and disconnected.
- **Switch IP**, which reconnects the VPN and reports the new exit IP.
- Live download/upload totals from the tunnel interface and the actual
  transport: `OpenVPN · UDP` or `OpenVPN · TCP`.

## [0.1.15] - 2026-11-17

### Changed

- Replaced the protocol dropdown with a compact linked UDP/TCP switch.

### Fixed

- Exactly one protocol stays selected; clicking the active side no longer
  leaves both off, and the kill-switch lock reverts changes while armed.

## [0.1.14] - 2026-11-17

### Changed

- More padding inside the status card.
- Replaced the stale "No kill switch" notice with the actual auto-protect
  limitation.

## [0.1.13] - 2026-11-17

### Added

- Kill-switch control in the GUI: service-backed status, confirmation prompts,
  **Allow local network**, and location/protocol locked while armed.
- Safe quit and close prompts while protection is armed.
- A **Kill switch** item in the tray menu.

## [0.1.12] - 2026-11-17

### Fixed

- polkit reply type: `CheckAuthorization` returns one struct, so the reply is
  `((bba{ss}))` and authorization is read from its first member.

## [0.1.11] - 2026-11-17

### Changed

- One combined package contains the desktop app and the kill-switch service.
  The GUI stays unprivileged; the service is idle until armed.

## [0.1.10] - 2026-11-17

### Fixed

- polkit `CheckAuthorization` details use `a{ss}`, not `a{sv}`.

## [0.1.9] - 2026-11-17

### Added

- Kill-switch groundwork: pure nftables rule generation, profile ownership
  validation, the D-Bus service, the polkit policy and a diagnostic CLI.

## [0.1.8] - 2026-11-17

### Added

- Favorite locations: star them, filter to favorites, and connect from a tray
  Favorites submenu; switching while connected asks for confirmation.
- Favorites change the one managed profile's location; they never duplicate
  profiles or certificates.

## [0.1.7] - 2026-11-17

### Added

- Red/green tray status icons for the disconnected and connected states.

## [0.1.6] - 2026-11-17

### Added

- A native StatusNotifierItem/DBusMenu tray icon with no extra Python
  dependency.
- A Settings dialog, a persisted notifications preference, and Help and Legal
  menus.

## [0.1.5] - 2026-11-17

### Added

- Desktop notifications for background events; clicking one brings the window
  back.
- **Forget Saved Password**, and a keyring self-test.

## [0.1.4] - 2026-11-17

### Added

- Bounded automatic reconnection after an established tunnel drops: retries
  after 2, 5, 10, 20, 30 and 60 seconds with a countdown and **Stop Retrying**;
  the profile and CA are verified before each retry; a **Reconnect
  automatically** switch.

## [0.1.3] - 2026-11-17

### Added

- Country flags and full country names; search by country, code, common
  aliases and city, accent-insensitive.
- An in-app TCP vs UDP guide.

### Fixed

- The selected-location line stayed stale after choosing a new location.

## [0.1.2] - 2026-11-17

### Fixed

- The VPN account name was used as the NetworkManager profile owner, so
  activation failed. Profile ownership now uses the local login, and saved
  passwords are looked up by VPN account name.

## [0.1.1] - 2026-11-17

### Fixed

- Catalogue download on the installed libsoup 3: request headers are read
  through `Soup.Message.get_request_headers()`; added a contract test against
  the real API.

## [0.1.0] - 2026-11-17

### Added

- First test build: GTK 4/libadwaita app, strict catalogue and profile
  validation, import through NetworkManager's OpenVPN plugin, ownership
  manifest, system-bus secret agent, Debian package.

[Unreleased]: https://github.com/Solvetus/pervius-app/compare/v0.1.19...HEAD
[0.1.19]: https://github.com/Solvetus/pervius-app/tree/v0.1.19
