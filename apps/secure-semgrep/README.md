# secure-semgrep

[![npm version](https://img.shields.io/npm/v/secure-semgrep)](https://www.npmjs.com/package/secure-semgrep)
[![License: MIT](https://img.shields.io/npm/l/secure-semgrep)](LICENSE)
[![CI](https://github.com/IsaacBell/secure-devtools/actions/workflows/ci.yml/badge.svg)](https://github.com/IsaacBell/secure-devtools/actions/workflows/ci.yml)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](https://github.com/IsaacBell/secure-devtools/blob/main/CONTRIBUTING.md)

A thin Semgrep CLI that runs the **bundled rules you own** plus maintained
Semgrep **loadout packs** for the ecosystems you scan — in one command, in any
repo, locally or in CI.

It is the static-analysis sibling to
[`am-i-compromised`](https://www.npmjs.com/package/am-i-compromised): a plain
shell tool with **no npm runtime dependencies**. The only host requirement is
`semgrep`.

## What it scans

Bundled (in this package, under `rules/`) — you own and extend these:

- `rules/ai` — best-practice rules for AI/LLM agents: hardcoded provider API
  keys, missing max-tokens / refusal / moderation / user-id checks, system-prompt
  injection, MCP tool-handler injection & credential leaks, hook and skill-file
  abuse, and more (Python / TypeScript / Go / Java / Ruby / others).
- `rules/bash` — bash security & correctness: `IFS` tampering, unsafe `curl |
  bash`, `curl ... | eval`, and unquoted-expansion footguns.

Loadouts (pulled from Semgrep's registry at scan time, so you don't vendor
them): `py`, `js`, `ts`, `react`, `node`, `rust`.

> **Why not vendor hundreds of registry rules?** Semgrep already ships those in
> `p/default`, `p/security-audit`, and the per-language packs. Vendoring them
> bloats this package and collides with the packs. You own the *bespoke* rules;
> you *compose* the maintained ones.

## Requirements

| Dependency | Needed for | Install |
| --- | --- | --- |
| `semgrep` 1.0+ | running scans | `brew install semgrep` / `pipx install semgrep` |
| `bash` 4+ | running the CLI | preinstalled on macOS/Linux |

macOS and Linux are supported. `SEMGREP_BIN` overrides the `semgrep` on PATH.

## Try it now

No install required — fetch and run on demand:

```sh
npx secure-semgrep ./src            # npm
pnpm dlx secure-semgrep ./src       # pnpm
```

Runs the bundled AI + bash rules plus `p/default` and `p/security-audit`.
Exit code `0` = clean, `1` = findings to review.

## Install

Install as a dev dependency for a `web`/`security` script:

```sh
npm install --save-dev secure-semgrep
# or: pnpm add -D secure-semgrep
```

## Usage

```sh
# Scan the current directory with default combo (ai + bash + p/default + p/security-audit)
secure-semgrep .

# Pick loadouts for the stack you actually have
secure-semgrep --loadout react --loadout node --loadout py ./src
secure-semgrep -L py packages/api
secure-semgrep -L ts -L node apps/web

# Everything at once
secure-semgrep -L all .

# Report findings but exit 0 (review mode — useful as evidence before you gate)
secure-semgrep -e .

# Skip the two built-in registry packs and use only bundled rules
secure-semgrep -N .

# Pass extra flags through to semgrep
secure-semgrep -- --severity ERROR

# Inspect what a scan will load
secure-semgrep pack -L react

# Validate every bundled rule parses
secure-semgrep check
```

In `package.json`:

```json
{
  "scripts": {
    "build": "secure-semgrep ./src && vite build",
    "security": "secure-semgrep -L react -L node ."
  }
}
```

In CI:

```yaml
- uses: returntocorp/semgrep-action@v1  # or install semgrep yourself
- run: secure-semgrep -L react -L node .
```

### Loadouts

| Loadout | `--config` used |
| --- | --- |
| `ai` | `apps/.../rules/ai` (bundled) |
| `bash` | `apps/.../rules/bash` (bundled) |
| `py` | `p/python` |
| `js` | `p/javascript` |
| `ts` | `p/typescript` |
| `react` | `p/typescript` + `p/javascript` + `p/react` |
| `node` | `p/javascript` + `p/nodejs` |
| `rust` | `p/rust` |
| `all` | every pack-based loadout |

Bundled rules always run unless you call `append_loadout` differently — the
owned rules (ai + bash) are always present. Registry packs run *after* owned
rules so, on a rule-id collision, Semgrep keeps your owned definition.

### Exit codes (scan)

- `0` — no findings (or `-e` review mode)
- `1` — findings that block (default mode)
- `2` — usage/argument error before semgrep runs

Other non-zero codes are passed through from semgrep itself.

## Development

This package lives in the [`secure-devtools`](https://github.com/IsaacBell/secure-devtools)
monorepo. Toolchain is managed by [mise](https://mise.jdx.dev):

```sh
mise install
mise run setup    # installs deps + git hooks (== pnpm install)
mise run check    # shellcheck + shfmt + bats across every package
```

From the package directory:

```sh
pnpm test         # bats suite (hermetic — scans only with bundled rules, no network)
pnpm validate     # prove every bundled rule still parses
```

Add a rule: create `rules/<category>/<rule>.yaml` plus a sibling fixture
(e.g. `<rule>.py`) annotated `# ok: <id>` / `# ruleid: <id>`, then validate.

## Publishing

From the repo root, after committing and pushing to `main`:

```sh
mise run publish-secure-semgrep        # == pnpm --filter secure-semgrep publish
```

Preview first with `mise run publish-secure-semgrep-dry-run`. The package ships
only `bin/`, `rules/`, `README.md`, and `LICENSE` (see `files` in `package.json`).

## Contributing

Bug reports, feature ideas, and pull requests are welcome — see
[CONTRIBUTING.md](https://github.com/IsaacBell/secure-devtools/blob/main/CONTRIBUTING.md)
and the [issue tracker](https://github.com/IsaacBell/secure-devtools/issues).

## Sponsorship

If this tool keeps your projects safer, consider supporting the work:

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/ibell)

## Security

Report vulnerabilities via GitHub's private advisory mechanism — see
[SECURITY.md](https://github.com/IsaacBell/secure-devtools/blob/main/SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
