# Am I Compromised?

[![npm version](https://img.shields.io/npm/v/am-i-compromised)](https://www.npmjs.com/package/am-i-compromised)
[![npm downloads](https://img.shields.io/npm/dm/am-i-compromised)](https://www.npmjs.com/package/am-i-compromised)
[![License: MIT](https://img.shields.io/npm/l/am-i-compromised)](LICENSE)
[![CI](https://github.com/IsaacBell/secure-devtools/actions/workflows/ci.yml/badge.svg)](https://github.com/IsaacBell/secure-devtools/actions/workflows/ci.yml)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](https://github.com/IsaacBell/secure-devtools/blob/main/CONTRIBUTING.md)

## See it in action

![security-gate scan demo](https://raw.githubusercontent.com/IsaacBell/secure-devtools/main/apps/am-i-compromised/demo-security-gate.gif)

A tiny [IoC](https://en.wikipedia.org/wiki/Indicator_of_compromise) scanner that flags
source-level indicators of malicious or compromised code before you start a dev server or
merge a pull request.

It is a **heuristic pre-flight check**, not a malware scanner. It cannot prove a
repository is safe — it catches signals that *should* make you look closer.

> **Zero npm runtime dependencies.** The shipped tool is plain shell — there is no
> install-time dependency tree to audit. It only needs `bash`, `ripgrep`, and `jq` on the
> host.

## Try it now

No install required — fetch and run on demand:

```sh
npx am-i-compromised .       # npm
pnpm dlx am-i-compromised .  # pnpm
```

Scans the current directory for malicious patterns. Exit code `0` = nothing found,
`1` = findings to review. First run downloads the package; `rg` and `jq` must be
installed on the host (see [Requirements](#requirements)).

## Features

- Flags patterns associated with malware and obfuscated code:
  - dynamic code execution (`eval`, `new Function`, ...)
  - child-process execution (`child_process`, `spawn`, `execSync`, ...)
  - direct network module access
  - runtime global mutation
  - encoded/obfuscated payloads (`atob`, hex/unicode escapes, `_0x…` string tables, ...)
  - suspicious `package.json` scripts (scanned with `jq`)
  - unusually long source lines
- Scans JS/TS/Python/Rust/Ruby/C/C++/C# sources out of the box
- Excludes `node_modules`, build output, VCS dirs, and `.git`-adjacent noise
- Self-tests its own detection logic against quarantined malicious fixtures

## Requirements

| Dependency | Needed for | Install |
| --- | --- | --- |
| `bash` 4+ | running the scanner | preinstalled on macOS/Linux |
| `rg` (ripgrep) | source scanning | `brew install ripgrep` / `apt-get install ripgrep` |
| `jq` | inspecting `package.json` scripts | `brew install jq` / `apt-get install jq` |

macOS and Linux are supported.

## Install

Install it as a dev dependency so a `security-gate` script can run before your dev server:

```sh
npm install --save-dev am-i-compromised
# or: pnpm add -D am-i-compromised
```

The package exposes three names for the same scanner script:

- `am-i-compromised` — matches the package name, so `npx` / `pnpm dlx` can fetch and run
  it on demand with no install step
- `security-gate` — descriptive and collision-resistant; recommended for project-local
  scripts
- `scanner` — short alias (generic; may collide with other tools if installed globally)

Prefer `security-gate` inside a project and `npx`/`pnpm dlx` for one-off scans.

## Usage

```sh
# Scan the current directory (default)
security-gate

# Scan a specific directory
security-gate path/to/project

# Include the __security_gate_fixtures__ dir (self-test mode)
INCLUDE_FIXTURES=1 security-gate .
```

No-install, fetch-on-demand (first run downloads the package):

```sh
# npm
npx am-i-compromised .

# pnpm
pnpm dlx am-i-compromised .
```

Or invoke a specific bin explicitly:

```sh
npx --package am-i-compromised security-gate .
```

In `package.json`, run it before starting your dev server:

```json
{
  "scripts": {
    "dev": "security-gate . && next dev",
    "security": "security-gate ."
  }
}
```

In CI:

```yaml
- run: security-gate .
```

Exit code is `0` when nothing is flagged and `1` when it finds something to review.

### Reading the output

Each unique `file:line` is reported once with every indicator category that
matched it, so one suspicious location is easy to review instead of being
repeated under each category heading. Match snippets are width-capped — a
single minified line cannot flood the report. Output is plain (no ANSI) when
piped; colors are used only on a TTY (set `NO_COLOR` to disable). Findings
are listed sorted by path, then line.

If a finding is a false positive, **prefer changing the implementation** over
suppressing the scanner from inside the source file. Malicious test fixtures
should live outside the scanned tree (the scanner excludes directories named
`__security_gate_fixtures__` unless `INCLUDE_FIXTURES=1`).

## Development

This package lives in the [`secure-devtools`](https://github.com/IsaacBell/secure-devtools)
monorepo. Toolchain is managed by [mise](https://mise.jdx.dev); tasks are defined in the
root [`mise.toml`](https://github.com/IsaacBell/secure-devtools/blob/main/mise.toml).

```sh
mise install
mise run setup     # installs deps + git hooks (== pnpm install)
mise run check     # shellcheck + shfmt + bats — same as CI
mise run test      # bats only
```

`mise run` on its own lists all tasks.

Run the tests directly from this directory with:

```sh
pnpm test
```

The Bats suite lives in `test/` and includes a self-test that scans the quarantined
fixtures in `test/__security_gate_fixtures__/` — treat everything in that directory as
malware and never execute or import it.

## Publishing

From the repo root, after committing and pushing to `main`:

```sh
mise run publish     # == pnpm --filter am-i-compromised publish
```

Preview the tarball first with `mise run publish-dry-run`. The package ships only
`bin/`, `README.md`, and `LICENSE` (see `files` in `package.json`).

## Contributing

Bug reports, feature ideas, and pull requests are welcome — see
[CONTRIBUTING.md](https://github.com/IsaacBell/secure-devtools/blob/main/CONTRIBUTING.md)
and the [issue tracker](https://github.com/IsaacBell/secure-devtools/issues).

## Sponsorship

If this tool keeps your projects safe, consider supporting the work:

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/ibell)

## Security

Report vulnerabilities via GitHub's private advisory mechanism — see
[SECURITY.md](https://github.com/IsaacBell/secure-devtools/blob/main/SECURITY.md) or open
an advisory at <https://github.com/IsaacBell/secure-devtools/security/advisories/new>.

## License

MIT — see [LICENSE](LICENSE).
