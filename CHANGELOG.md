# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-11-19

1.0.0 — first public release.

### Added

- GTK 4/libadwaita desktop client for an existing FastVPN (OpenVPN)
  subscription. The provider's public server catalogue is downloaded over
  HTTPS and strictly validated; one app-owned NetworkManager profile is
  imported through the OpenVPN plugin and reused for every location.
- Passwords never enter the profile and are never shown: a NetworkManager
  secret agent supplies them on request, saving in the desktop keyring is
  optional, and the Account dialog only offers Replace and Forget.
- Leak protection while connected, with or without the kill switch and with
  or without the app running: all DNS goes through the tunnel and IPv6
  outside the IPv4-only tunnel is blocked, by a NetworkManager dispatcher
  hook. The profile is pinned to resolved server addresses.
- Optional kill switch (root service, nftables, polkit) that allows only the
  Pervius tunnel, the VPN servers and interfaces you choose, and still lets
  you change location or protocol while armed.
- Locations with flags, search by city, country, code or alias, favorites,
  and UDP/TCP.
- Bounded automatic reconnect after an established tunnel drops, with a
  countdown and Stop.
- Tray icon with status, connected time, connect, favorites, location and
  kill-switch actions; desktop notifications while the window is hidden.
- Connection details: ISP and exit IP (hidden until revealed), Switch IP,
  traffic totals, connected time and protocol.
- English, European Portuguese, French, Spanish and Italian; start at login
  hidden in the tray; the window remembers its size.
- Debian package with lintian-clean CI builds and published SHA-256 checksums.

[Unreleased]: https://github.com/Solvetus/pervius-app/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Solvetus/pervius-app/releases/tag/v1.0.0
