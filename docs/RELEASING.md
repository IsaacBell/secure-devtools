# Releasing

Each package under `apps/` is released on its own. One script serves them all: it reads the
name and version from the package's `package.json`, so nothing is hardcoded per package.
npm publish needs 2FA.

## Release a package

1. Bump `version` in `apps/<package>/package.json` and add the entry to its `CHANGELOG.md`.
2. Check what ships:

   ```bash
   mise run publish-dry-run apps/<package>
   ```

3. Publish from a clean `main` (runs `mise run check` first, then `pnpm publish`, then tags
   `<name>@<version>`):

   ```bash
   mise run publish apps/<package>
   git push origin <name>@<version>
   ```

4. Create the GitHub release from the tag.

`scripts/release.sh` refuses a private package, a version already on npm, and any
`package.json` with lifecycle scripts (`prepare`, `prepack`, `postinstall` and the like) that
would run during pack, publish or install.

## Packages

| Package | Folder | Commands |
| --- | --- | --- |
| `am-i-hacked` | `apps/am-i-hacked` | `am-i-hacked`, `aih`, `am-i-compromised`, `aic` |
| `am-i-being-recorded` | `apps/am-i-being-recorded` | `am-i-being-recorded`, `aibr` |
| `secure-semgrep` | `apps/secure-semgrep` | `secure-semgrep` |

`am-i-hacked` was published as `am-i-compromised` up to 1.x. After a 2.x release, point users
at the new name:

```bash
pnpm deprecate am-i-compromised "Renamed to am-i-hacked. Run: pnpm dlx am-i-hacked"
```

## Public repository

The public repository is staged from an allowlist, `scripts/public-paths.txt`, as one fresh
commit:

```bash
mise run export-public "$(mktemp -d)"
```

The export copies only listed paths, removes `!` lines, refuses local files, and fails on any
personal-data pattern hit.
