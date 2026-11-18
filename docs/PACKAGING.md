# Packaging

One repository serves every Linux distribution. The application, its assets
and the install layout are shared; only package metadata and build glue are
distribution-specific.

## Layout

```
pervius/                 application code (distribution-neutral)
data/                    shared assets installed by every package
  bin/                   command wrappers: pervius, pervius-killswitch, pervius-inspect, pervius-proof
  com.solvetus.Pervius.desktop
  com.solvetus.Pervius.metainfo.xml
  icons/hicolor/scalable/apps/
  man/man1/              manual pages for the four commands
  dbus/                  system bus policy and activation file for the kill-switch service
  polkit/                polkit action
  systemd/               pervius-killswitchd.service
packaging/
  layout.tsv             THE list of install paths (shared)
  stage.sh               stages layout.tsv into a build root (shared)
  debian/                Debian/Ubuntu only: build.sh, control.in, maintainer scripts,
                         copyright, lintianrc, gen-changelog.py
  rpm/                   Fedora (planned): README.md only
scripts/changelog.py     reads CHANGELOG.md (release notes, Debian changelog)
```

## Rules

- **Install paths live in one place:** `packaging/layout.tsv`. Every path in it
  is an FHS path that is the same on Debian/Ubuntu and Fedora, except the
  `{pythondir}` token, which each distribution fills in (Debian
  `/usr/lib/python3/dist-packages`, Fedora `%{python3_sitelib}`).
- **Stage with the shared script:** `packaging/stage.sh DESTDIR PYTHONDIR`
  installs every row of `layout.tsv` and skips Python bytecode.
- **Distribution packaging adds only its own metadata:** dependencies,
  maintainer scripts or scriptlets, documentation and licence locations.
- **No distribution assumptions in application code.** Nothing under
  `pervius/` may name distribution tools or paths, except
  `pervius/distro.py`, which holds the documented, report-only checks
  (system bus implementation, firewall front ends, `nftables.service`, polkit
  rules directories). `tests/test_distro.py` enforces this.
- **One version:** `pervius/__init__.py` `__version__`. Builds read it
  (`packaging/debian/build.sh --print-version`), and tests assert that the
  Debian version, the top CHANGELOG release and the top AppStream release
  match it.
- **Never commit packages.** Builds go to `dist/` (ignored); releases attach
  them to GitHub Releases.

## Debian/Ubuntu

```sh
packaging/debian/build.sh              # → dist/pervius_<version>_all.deb
DIST_DIR=/tmp/out packaging/debian/build.sh
lintian --cfg packaging/debian/lintianrc --fail-on error dist/pervius_*_all.deb
```

`build.sh` stages the shared tree, adds `/usr/share/doc/pervius` (README,
copyright and a Debian changelog generated from `CHANGELOG.md` by
`gen-changelog.py`), compresses the manual pages, writes the control file
from `control.in`, adds the maintainer scripts, and runs `dpkg-deb`. The
package needs no lintian overrides; `lintianrc` holds the lintian settings.

Debian-specific behaviour, all under `packaging/debian/`:

- `Depends` alternatives (`polkitd | policykit-1`, `dbus-broker | dbus-daemon | dbus`).
- `Conflicts`/`Replaces`/`Provides` for the pre-rename packages.
- `preinst` refuses to install over an armed 0.1.x kill switch (effective
  for `dpkg -i`; apt removes the old package first).
- `postinst`/`postrm` reload systemd and the system bus policy; `prerm` stops
  the service; `postrm` removes the `inet pervius_ks` table on removal.

## Adding a distribution

1. Create `packaging/<distro>/` with a `README.md` and the build files.
2. Install the shared tree with `packaging/stage.sh "$BUILDROOT" <python dir>`
   (or install each row of `layout.tsv` in the spec/recipe).
3. Map the dependencies: Python 3 with PyGObject, the GTK 4, libadwaita, NM,
   Secret and Soup 3 typelibs, NetworkManager with its OpenVPN plugin,
   OpenVPN, nftables, polkit, systemd and a D-Bus system bus.
4. Package scripts: after install and removal, run `systemctl daemon-reload`
   and reload the system bus policy (`busctl call org.freedesktop.DBus
   /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig`). Before removal,
   stop `pervius-killswitchd.service`; after removal, delete the
   `inet pervius_ks` table and `/run/pervius`. Do not enable the service; it is
   D-Bus activated.
5. If the distribution needs a runtime difference to be visible, add a
   report-only check to `pervius/distro.py` and document it there. Do not add
   distribution branches elsewhere in `pervius/`.
6. Add a separate CI job in `.github/workflows/ci.yml` (and, when ready, a
   release asset in `release.yml`) next to the `deb` job.
7. Update the supported-distributions table in `README.md`.
