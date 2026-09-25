# Release Checklist

Per-package release workflow. Each package is independent; npm publish requires 2FA.

## am-i-compromised (next: 1.2.0)

- [ ] Verify heuristics work completes
- [ ] Update version in `apps/am-i-compromised/package.json`
- [ ] Dry-run: `mise run publish-dry-run`
- [ ] Publish: `mise run publish` (2FA required)
- [ ] Tag: `git tag am-i-compromised@1.2.0`
- [ ] GitHub release

## secure-semgrep (current: 1.0.1)

- [ ] Update version in `apps/secure-semgrep/package.json`
- [ ] Dry-run: `mise run publish-secure-semgrep-dry-run`
- [ ] Publish: `mise run publish-secure-semgrep` (2FA required)
- [ ] Tag: `git tag secure-semgrep@<version>`
- [ ] GitHub release

## am-i-being-recorded (current: 0.1.0)

- [ ] Update version in `apps/am-i-being-recorded/package.json`
- [ ] Dry-run: `mise run publish-am-i-being-recorded-dry-run`
- [ ] Publish: `mise run publish-am-i-being-recorded` (2FA required)
- [ ] Tag: `git tag am-i-being-recorded@<version>`
- [ ] GitHub release

## Pre-release checks (all packages)

```bash
# Run before any publish
mise run check
```

Ensures lint, format-check, and tests pass across all packages.

## Notes

- Tag format: `<package>@<version>` (matches existing `am-i-compromised@1.0.0`)
- All `mise run publish*` tasks check dependencies before running
- Publish tasks are in `mise.toml` — see there for package-specific dry-run options
- Package metadata (name, version, description, license, repository.directory, bin paths, files, engines) is publish-ready; verified with `npm pack --dry-run`
