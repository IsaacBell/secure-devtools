# Am I Compromised?

[![npm version](https://img.shields.io/npm/v/am-i-compromised)](https://www.npmjs.com/package/am-i-compromised)
[![npm downloads](https://img.shields.io/npm/dm/am-i-compromised)](https://www.npmjs.com/package/am-i-compromised)
[![License: ISC](https://img.shields.io/npm/l/am-i-compromised)](LICENSE)
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
  - editor/workspace config that runs code unprompted — a `.vscode/tasks.json` with
    `runOn: folderOpen`, `task.allowAutomaticTasks`, or an MCP `stdio` server that
    downloads and runs a payload
  - executable payloads disguised as binary assets (JavaScript inside a `.woff2`,
    `.png`, `.ttf`, `.svg`, and similar files)
- Scans JS/TS/Python/Rust/Ruby/C/C++/C# sources, editor config, and binary-asset
  extensions out of the box
- Excludes `node_modules`, build output, VCS dirs, and `.git`-adjacent noise
- Context-aware where a bare regex would be noisy: a decode primitive
  (`atob`, `Buffer.from`, ...) only trips the gate near an execution call or a
  long embedded literal; `execSync`/`spawn`/... only trips it when the command
  isn't a plain literal with a normal options object; `setTimeout`/`setInterval`
  only trip it on a string first argument, not a callback; hex/unicode escapes
  only trip it as a long adjacent run, not a lone ANSI color code
- Reviewed lines can be marked safe with `am-i-compromised-ignore: <reason>` —
  see [Suppressing a finding](#suppressing-a-finding)
- Self-tests its own detection logic against quarantined malicious fixtures
- Ships `safe-pull`, a guarded `git pull` that inspects incoming commits before
  anything reaches the working tree

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

Exit code is `0` when nothing unreviewed is flagged and `1` when it finds
something to review. A suppressed finding (see below) never affects the exit
code — only unreviewed findings do.

### Reading the output

Each unique `file:line` is reported once with every indicator category that
matched it, so one suspicious location is easy to review instead of being
repeated under each category heading. Match snippets are width-capped — a
single minified line cannot flood the report. Output is plain (no ANSI) when
piped; colors are used only on a TTY (set `NO_COLOR` to disable). Findings
are listed sorted by path, then line.

If a finding is a false positive because the *pattern* is too broad, that's a
scanner bug — please [open an issue](https://github.com/IsaacBell/secure-devtools/issues).
If the code itself can reasonably be rewritten to stop matching, **prefer
that** over suppressing. Malicious test fixtures should live outside the
scanned tree (the scanner excludes directories named `__security_gate_fixtures__`
unless `INCLUDE_FIXTURES=1`). For the remaining case — the match is accurate
and the code is genuinely fine as written — mark it reviewed instead:

### Suppressing a finding

Some findings are real matches on code that is genuinely safe — a giant
hardcoded string literal, a command built from a value that's already been
validated, and so on. For those, mark the line reviewed instead of
rewriting working code to dodge the pattern:

```js
const decoded = atob(header); // am-i-compromised-ignore: decodes a request header, not a payload
```

The marker is `am-i-compromised-ignore:` followed by a reason, on the
finding's own line or the line immediately before it (handy when the flagged
line is too long to comment on directly, like a huge literal):

```js
// am-i-compromised-ignore: bee movie script fixture, not obfuscated code
const script = "...49,000 characters...";
```

The reason is required — a marker with nothing after the colon does not
suppress anything, so an empty "make it go away" comment can't quietly defeat
the gate. The marker is recognized as plain text anywhere on the line; it
does not need to sit inside any particular comment syntax, since the scanner
reads half a dozen languages.

Suppressed findings are **never dropped silently**. They are counted and
listed in their own section of the report on every run, including a clean
one, so a suppression can't quietly go stale or hide a second, unrelated
issue on the same line:

```
security-gate: 1 finding suppressed by inline comment

  src/auth.ts:42
    const decoded = atob(header); // am-i-compromised-ignore: decodes a request header, not a payload
    → Encoded payload primitives (suppressed)
    reason: decodes a request header, not a payload
```

This marker is honored by `security-gate`/`scanner` only. **`safe-pull` does
not read it.** `safe-pull` inspects commits nobody has reviewed yet — that's
the entire point of the guard — so a marker written by whoever authored the
incoming diff must never be able to wave off their own payload.

## Guarded pull (`safe-pull`)

Scanning the working tree is too late for one class of attack: a commit that adds
a `.vscode/tasks.json` running on folder open, or an MCP `stdio` server that starts
with the editor, executes as soon as the code is checked out. `safe-pull` closes
that window by inspecting the incoming commits before anything is written:

```sh
safe-pull                 # fetch, inspect, then merge --ff-only
safe-pull --dry-run       # inspect only; never merge
safe-pull --allow-dirty   # proceed with a dirty working tree
safe-pull --force-update  # integrate despite a rewritten upstream history
```

What it checks in the incoming commits: a force-pushed (rewritten) upstream, an
author/committer mismatch, editor auto-run tasks, download-and-run editor
commands, executable payloads disguised as asset files, committed `.env` files,
and a `dotenv` plus `node-fetch`/`axios` dependency pair. The inspection uses
`git grep` against the fetched commit, so it reads blobs from the object store and
never writes files to disk. Plain `git fetch` is safe on its own — it executes
nothing.

Exit codes: `0` clean (and merged, unless `--dry-run`), `1` findings (nothing
merged), `2` usage or setup problem.

To use it as a git alias:

```sh
git config --global alias.safe-pull '!safe-pull'
```

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
