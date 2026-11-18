## Summary

<!-- What does this change and why? Link related issues. -->

## Checklist

- [ ] Unit tests pass (`python3 -m unittest discover -s tests -t .`) and new behaviour is tested
- [ ] `ruff check .` is clean
- [ ] `packaging/debian/build.sh` builds and `lintian --fail-on error` passes (if packaging changed)
- [ ] `CHANGELOG.md` has an entry under `[Unreleased]` for user-visible changes
- [ ] No secrets, personal data or real IP addresses in code, tests or logs
- [ ] `pervius/` stays distribution-neutral (see `docs/PACKAGING.md`)
- [ ] Tested on (distribution, version, architecture):
