# am-i-hacked

[![npm version](https://img.shields.io/npm/v/am-i-hacked)](https://www.npmjs.com/package/am-i-hacked)
[![CI](https://github.com/IsaacBell/secure-devtools/actions/workflows/ci.yml/badge.svg)](https://github.com/IsaacBell/secure-devtools/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/npm/l/am-i-hacked)](LICENSE)

`am-i-hacked` checks the code you are about to run, and the machine you run it on, for signs of a supply-chain or dev-environment attack. It is an indicator-of-compromise scanner, not antivirus: a clean result means no warning signs were found, not that anything is proven safe.

```sh
pnpx am-i-hacked .        # or: npx am-i-hacked .
```

**Status:** 2.0.1, macOS and Linux. Formerly published as `am-i-compromised`; the old command name still works. Changes are in [CHANGELOG.md](CHANGELOG.md).

## Install and run

No install needed:

```sh
pnpx am-i-hacked .          # scan a folder (default: the current directory)
pnpx am-i-hacked --system   # also audit this machine
```

As a dev dependency:

```sh
pnpm add -D am-i-hacked     # or: npm install --save-dev am-i-hacked
```

| Scan | Needs |
| --- | --- |
| Folder (`am-i-hacked <dir>`) | `bash` 4.2+, `rg` (ripgrep), and `jq` to inspect `package.json` scripts |
| System (`--system`) | `bash` 3.2+, `jq`. Read-only; no ripgrep, root or sudo |

macOS ships bash 3.2, so the folder scan re-runs itself under a newer bash when one is installed (mise, nix, asdf, Homebrew, MacPorts, Linuxbrew) and otherwise says what to install. Get `rg` and `jq` with `brew install ripgrep jq` or `apt-get install ripgrep jq`.

Before a dev server:

```json
{ "scripts": { "dev": "am-i-hacked . && next dev" } }
```

In CI (GitHub Actions on `ubuntu-latest`; the runner has bash and jq but no pnpm and no ripgrep):

```yaml
- uses: pnpm/action-setup@v4
  with:
    version: 10
- run: sudo apt-get install -y ripgrep
- run: pnpx am-i-hacked@2 .
```

## What it checks

Both scans are read-only and make no network calls. Scanned source languages: JS/TS, Python, Rust, Ruby, C, C++, C#.

| Scan | Checks |
| --- | --- |
| Folder | Dynamic code execution, child processes, direct network module access, runtime global mutation; encoded or obfuscated payloads and unusually long lines; suspicious `package.json` scripts; editor config that runs code on folder open; download-and-run commands in editor config; executable payloads disguised as asset files; clipboard, keystroke or screen capture paired with an exfiltration endpoint; `.env` files in the git index; official Yarn releases verified by SHA256; Python virtualenvs (files that no longer match their package `RECORD` hashes, files no package owns, `.pth` or startup hooks that run code). |
| System (`--system`) | Login persistence (launchd on macOS; systemd user units and XDG autostart on Linux) and, on macOS, the code signature of what it launches; crontab; shell startup files; user-level and managed AI-tool config; running processes; and the "dark corners" where tooling installs code outside any project (`~/.venv`, tool and package caches, and the like), each scanned with the folder scan when present and skipped when not. |

The folder scan also checks its own AI-tool config (`.claude/settings*.json`, `.mcp.json`). It reads dot-directories and tracked files that `.gitignore` matches; `node_modules` and `.git` are always skipped. In bundled code (webpack/esbuild/ncc) only high-signal patterns are reported; routine dynamic-code and network patterns are counted but not flagged. Findings are `HIGH`, `MEDIUM` or `INFO`; `HIGH` and `MEDIUM` exit `1`.

## Flags

| Flag | Applies to | Meaning |
| --- | --- | --- |
| `<dir>` | folder | Directory to scan (default: the current directory). |
| `host` | folder | Check a folder's AI-tool config only: `am-i-hacked host [dir]`. |
| `--system` | both | Also audit the whole machine. Alias: `--full-system-scan`. |
| `--max-findings N` | folder | Maximum findings printed (default: 1000). The true total and a per-rule count are always shown. |
| `-v`, `--verbose` | system | Also list informational items and every persistence entry, with its signer. |
| `-h`, `--help` | both | Show usage. |

`--system` is shorthand for `host --system`. System-wide Linux units and `/etc/cron.*` are not covered yet.

## Suppressing a finding

When a match is accurate but the code is genuinely safe, mark the line reviewed instead of rewriting working code:

```js
const decoded = atob(header); // am-i-hacked-ignore: decodes a request header, not a payload
```

The marker is `am-i-hacked-ignore:` followed by a required reason, on the finding's own line or the line immediately before it. The pre-2.0 spelling, `am-i-compromised-ignore:`, is still honored. Suppressed findings are never dropped silently: they are counted and listed in their own section on every run, including a clean one. The marker is honored by the folder scan only — `safe-pull` deliberately does not read it, because it inspects commits nobody has reviewed.

For the system scan, accept a reviewed finding by adding `<finding id> | <reason>` to `~/.config/am-i-hacked/host-allow.txt` (create the folder first; override the path with `AIC_HOST_ALLOW`). Allowed findings are listed on every run.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Nothing found. |
| `1` | Findings to review, or a missing requirement (`bash` 4.2+, `rg`, or `jq`; the message names it). |
| `2` | Usage error. |

## Guarded pull (`safe-pull`)

`safe-pull` inspects incoming commits before anything is written to disk, then fast-forwards. It checks for a rewritten (force-pushed) upstream, an author/committer mismatch, editor auto-run tasks, download-and-run editor commands, executable payloads disguised as assets, committed `.env` files, and a `dotenv` plus `node-fetch`/`axios` dependency pair.

```sh
safe-pull                 # fetch, inspect, then merge --ff-only
safe-pull --dry-run       # inspect only; never merge
safe-pull --allow-dirty   # proceed with a dirty working tree
safe-pull --force-update  # integrate despite a rewritten upstream history
safe-pull --remote <name> --branch <name>   # inspect a specific remote branch
```

Exit codes: `0` clean, `1` findings (nothing merged), `2` usage or setup problem.

## Commands installed

`am-i-hacked` (the folder scan and `host`), `aih`, `am-i-compromised` and `aic` (the old name and its short form), `security-gate`, `scanner`, and `safe-pull`.

## Limits

It looks for warning signs. It is not antivirus, and it does not look up known viruses. A clean result means it found no warning signs; it does not prove the code or the machine is safe. Some checks also flag normal code, such as `eval`; when you have checked a line and it is fine, suppress it with a reason as above. The scanner runs entirely on your machine and sends nothing anywhere.

## Development

Requirements: `bash` 4.2+, `rg`, `jq`, `git`, `pnpm`, and, for lint and format, `shellcheck` and `shfmt`. `bin/system-scan.sh` is the system scanner; `bin/host-audit.sh` remains as an alias.

```sh
pnpm install
pnpm test     # bats suite
pnpm check    # shellcheck + shfmt + bats
```

The Bats suite scans the quarantined fixtures in `test/__security_gate_fixtures__/`; treat everything there as malware and never execute or import it.

## Contributing and security

Bug reports and pull requests: <https://github.com/IsaacBell/secure-devtools>. Report vulnerabilities privately via <https://github.com/IsaacBell/secure-devtools/security/advisories/new>. MIT licensed; see [LICENSE](LICENSE).
