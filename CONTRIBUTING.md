# Contributing

Thanks for helping. Bug reports, fixes and documentation improvements are
welcome. For larger changes, please open an issue first so we can agree on the
approach.

## Development setup (Debian/Ubuntu)

```sh
sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 gir1.2-nm-1.0 \
    gir1.2-secret-1 gir1.2-soup-3.0 network-manager-openvpn shellcheck lintian
python3 -m unittest discover -s tests -t .     # unit tests
ruff check .                                    # lint (see ruff.toml)
packaging/debian/build.sh                       # build dist/pervius_<version>_all.deb
lintian --cfg packaging/debian/lintianrc --fail-on error dist/pervius_*_all.deb
tests/manual/run.sh                             # optional UI harnesses (Broadway)
```

Run the app from the source tree with `python3 -m pervius`.

## Guidelines

- Keep the GUI unprivileged. Anything that needs root belongs in the
  kill-switch service, behind polkit, with a narrow D-Bus API.
- Never log, print or store passwords or other secrets. Never add a plaintext
  password fallback.
- Fail closed: if a profile, CA file or ownership check is ambiguous, stop and
  explain.
- Keep `pervius/` distribution-neutral. See [`docs/PACKAGING.md`](docs/PACKAGING.md).
- Add or update tests with every change; use RFC 5737/3849 documentation
  addresses and `example.com` hosts in fixtures.
- Use [Conventional Commits](https://www.conventionalcommits.org/) and add an
  entry under `## [Unreleased]` in `CHANGELOG.md` for user-visible changes.
- Do not test against live networks or real accounts without being sure of
  the consequences; `pervius-proof` changes NetworkManager settings.

Security issues: please follow [`SECURITY.md`](SECURITY.md) instead of opening
an issue.

By contributing you agree that your contributions are licensed under the
Apache License 2.0.
