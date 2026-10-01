# Contributing to secure-devtools

Thanks for taking the time to contribute! This project aims to be small, simple, and
easy to audit — please keep changes in that spirit.

## Getting started

Requirements: [mise](https://mise.jdx.dev) (installs the pinned toolchain).

```sh
mise install      # node, pnpm, shellcheck, shfmt, ripgrep, jq
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
| `mise run publish-dry-run apps/<package>` | preview one package's npm tarball |
| `mise run publish apps/<package>` | publish one package to npm and tag it |
| `mise run doctor` | diagnose the dev environment (`mise doctor`) |

The pre-commit hook runs `mise run check` (via `pnpm check`) on every commit.

## Making changes

- Shell code must pass `shellcheck` and be `shfmt`-formatted — enforced by CI and the
  pre-commit hook. Run `mise run fmt` before committing.
- The scanner is intentionally conservative. New detection patterns belong in
  `apps/am-i-hacked/bin/scanner.sh` **with** a corresponding test.
- Tests live in `apps/am-i-hacked/test/scanner.bats`. Add a test that proves the
  new pattern trips on a malicious sample and does *not* trip on a clean file.
- Never commit a live malware sample. Write an inert sample in the test itself that
  carries only the indicator the pattern looks for.
- Update the package README if user-visible behavior changes.

## Pull requests

- Keep PRs focused; one logical change per PR.
- Branch from `main` and open the PR against `main`.
- Make sure `mise run check` and `mise run gate` pass locally before pushing.
- CI runs the same checks plus a gitleaks secret scan and dependency review.

## Releasing (npm)

Each package is released on its own from a maintainer's machine; there is no publish
CI job. See [docs/RELEASING.md](docs/RELEASING.md).

Small, well-tested changes are much more likely to be reviewed quickly than large
rewrites — when in doubt, start a discussion in an issue first.

## Reporting vulnerabilities

Do **not** open an issue for security problems. See [SECURITY.md](SECURITY.md).
