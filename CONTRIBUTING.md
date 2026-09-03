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

Small, well-tested changes are much more likely to be reviewed quickly than large
rewrites — when in doubt, start a discussion in an issue first.

## Reporting vulnerabilities

Do **not** open an issue for security problems. See [SECURITY.md](SECURITY.md).
