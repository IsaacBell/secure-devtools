# Contributing to secure-devtools

Thanks for taking the time to contribute! This project aims to be small, simple, and
easy to audit — please keep changes in that spirit.

## Getting started

Requirements: [mise](https://mise.jdx.dev) (installs the pinned toolchain).

```sh
mise install      # node, pnpm, shellcheck, shfmt, ripgrep, jq, trivy
mise run setup    # JS deps; also installs the husky pre-commit hook
```

`mise run` on its own lists every task.

## Commands

Everything is driven by [mise tasks](mise.toml), which delegate to the canonical
`package.json` scripts:

| Task | What it does |
| --- | --- |
| `mise run` | list all tasks (default) |
| `mise run setup` | install JS deps and git hooks |
| `mise run check` | shellcheck + shfmt check + bats tests (all packages) |
| `mise run test` | run the bats test suite |
| `mise run lint` | run shellcheck |
| `mise run fmt` | format shell sources with shfmt |
| `mise run fmt-check` | verify formatting |
| `mise run gate` | run the security-gate scanner over the whole repo |
| `mise run publish-dry-run` | preview the npm tarball contents |
| `mise run publish` | publish `am-i-compromised` to npm |
| `mise run doctor` | diagnose the dev environment (`mise doctor`) |

The pre-commit hook runs `mise run check` (via `pnpm check`) on every commit.

## Making changes

- Shell code must pass `shellcheck` and be `shfmt`-formatted — enforced by CI and the
  pre-commit hook. Run `mise run fmt` before committing.
- The scanner is intentionally conservative. New detection patterns belong in
  `apps/am-i-compromised/bin/scanner.sh` **with** a corresponding test.
- Tests live in `apps/am-i-compromised/test/scanner.bats`. Add a test that proves the
  new pattern trips on a malicious sample and does *not* trip on a clean file.
- Malicious samples go in
  `apps/am-i-compromised/test/__security_gate_fixtures__/malicious/`. Treat everything
  there as real malware — never execute, import, or load it as configuration, and keep
  it quarantined (the scanner excludes it by default).
- Update the package README if user-visible behavior changes.

## Pull requests

- Keep PRs focused; one logical change per PR.
- Branch from `main` and open the PR against `main`.
- Make sure `mise run check` and `mise run gate` pass locally before pushing.
- CI runs the same checks plus a gitleaks secret scan and dependency review.

## Maintainers: CI secrets and variables

The CodeAnt AI scan
([`.github/workflows/codeant.yml`](.github/workflows/codeant.yml)) is opt-in and is
skipped unless the repository is configured. To enable it, add these in the GitHub
repository (or organization) settings under *Settings → Secrets and variables → Actions*:

| Setting | Type | Purpose |
| --- | --- | --- |
| `CODEANT_ENABLED` | Variable | Set to `true` to run the CodeAnt scan job; unset or any other value skips it |
| `CODEANT_API_TOKEN` | Secret | CodeAnt API token used by `CodeAnt-AI/codeant-ci-scan-action` |

`GITHUB_TOKEN` is a built-in secret and needs no setup.

## Releasing (npm)

The npm package lives in `apps/am-i-compromised`; the version is read from its
`package.json`. Releases are published from a maintainer's machine (there is no
publish CI job).

### Steps

1. **Bump the version** in `apps/am-i-compromised/package.json` and commit it on
   `main`. Version follows [semver](https://semver.org).
2. **Verify everything** from the repo root:
   ```sh
   mise run check   # lint + format + tests
   mise run gate    # the scanner must pass on its own repo
   ```
3. **Preview the tarball** (must contain only `bin/`, `README.md`, `LICENSE`):
   ```sh
   mise run publish-dry-run
   ```
4. **Tag the release commit** — the npm version tag must point at the exact
   commit being published:
   ```sh
   git tag -f am-i-compromised@<version>   # move tag to HEAD if re-releasing
   git push origin main --tags
   ```
5. **Publish**: `mise run publish` (runs `check`, then `pnpm publish`).
   Authenticate with `npm login` first; if 2FA is enabled, publish will prompt
   for a one-time password.
6. **Verify**: `npm view am-i-compromised version` shows the new version, and
   the [CI badge](../../README.md) on `main` is green.

Publishing requires npm write access for the `am-i-compromised` package name.

Small, well-tested changes are much more likely to be reviewed quickly than large
rewrites — when in doubt, start a discussion in an issue first.

## Reporting vulnerabilities

Do **not** open an issue for security problems. See [SECURITY.md](SECURITY.md).
