# 🕵️ Am I Compromised?

[![npm version](https://img.shields.io/npm/v/am-i-compromised)](https://www.npmjs.com/package/am-i-compromised)
[![npm downloads](https://img.shields.io/npm/dm/am-i-compromised)](https://www.npmjs.com/package/am-i-compromised)
[![License: ISC](https://img.shields.io/npm/l/am-i-compromised)](LICENSE)
[![CI](https://github.com/IsaacBell/secure-devtools/actions/workflows/ci.yml/badge.svg)](https://github.com/IsaacBell/secure-devtools/actions/workflows/ci.yml)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](https://github.com/IsaacBell/secure-devtools/blob/main/CONTRIBUTING.md)

> *Check the code you're about to run, and the machine you're running it on.*

![security-gate scan demo](https://raw.githubusercontent.com/IsaacBell/secure-devtools/main/apps/am-i-compromised/demo-security-gate.gif)

## 🌟 Highlights

- **Two checks, one command.** Scan a project for malicious code, or audit *this machine* for
  the things source scans can't see: launch agents, shell startup files, AI-tool config, and
  running processes.
- **Catches clipboard and keystroke stealers.** Capture code paired with a Telegram, Discord,
  Slack or webhook endpoint is flagged, including the hidden LaunchAgent that starts it.
- **Watches your AI tools.** Flags a local proxy set as your model's base URL, hooks that run
  code from `node_modules` or a writable path, switched-off permission prompts, and plain-text keys.
- **Zero npm runtime dependencies.** Plain shell, so there is no install-time tree to audit.
- **Honest about noise.** Reviewed lines are marked safe with a reason, and suppressed findings
  are still listed on every run.
- **Fits your workflow.** Exit code `1` on findings, so it drops into a dev script or CI. A
  guarded `git pull` (`safe-pull`) is included.

## ℹ️ Overview

`am-i-compromised` is a small [indicator-of-compromise](https://en.wikipedia.org/wiki/Indicator_of_compromise)
checker. It is a **heuristic pre-flight check**, not a malware scanner: it cannot prove
anything is safe, it flags signals that *should* make you look closer.

It started after a clipboard-to-Telegram LaunchAgent ran on a developer's Mac for two weeks and
the old scanner, which only read source trees, never saw it. `host` exists because of that.

Part of the `secure-devtools` monorepo.

## 🚀 Usage

```sh
# Scan a project (defaults to the current directory)
npx am-i-compromised .

# Audit this machine (read-only, no root or sudo, does not need ripgrep).
# Also checks the AI-tool config of the current folder, or of a folder you name.
npx am-i-compromised host [path/to/project]
```

Exit code `0` means nothing found, `1` means findings to review. Add `--verbose` to `host` to
also list informational entries.

In `package.json`, run the scan before your dev server:

```json
{
  "scripts": {
    "dev": "security-gate . && next dev"
  }
}
```

In CI:

```yaml
- run: npx am-i-compromised .
```

More below: how to read the output, how to suppress a reviewed finding, the host audit, and
[safe-pull](#guarded-pull-safe-pull). System-wide Linux units and `/etc/cron.*` are not covered yet.

## ⬇️ Installation

No install needed with `npx` / `pnpm dlx`. To keep it in a project:

```sh
npm install --save-dev am-i-compromised   # or: pnpm add -D am-i-compromised
```

macOS and Linux. Requirements:

| Command | Needs |
| --- | --- |
| `am-i-compromised <dir>` | `bash` 4.2+, `rg` ([ripgrep](https://github.com/BurntSushi/ripgrep)), `jq` |
| `am-i-compromised host` | `bash` 3.2+ (the macOS default works). `jq` is optional but needed to read AI-tool hooks and MCP servers |

macOS ships bash 3.2. The project scan re-runs itself under a newer bash if you have one
(for example `brew install bash`) and otherwise tells you what to install. Install `rg` and `jq`
with `brew install ripgrep jq` or `apt-get install ripgrep jq`.

The package installs three names for the same scanner: `am-i-compromised`, `security-gate`
(good for project scripts) and `scanner` (short; may collide with other tools).

## 🔎 What the project scan detects

- Dynamic code execution (`eval`, `new Function`, ...), child-process execution, direct network
  module access, runtime global mutation
- Encoded or obfuscated payloads (`atob`, hex/unicode escapes, `_0x...` string tables), and
  unusually long source lines
- Suspicious `package.json` scripts (scanned with `jq`)
- Editor or workspace config that runs code unprompted: `.vscode/tasks.json` with
  `runOn: folderOpen`, `task.allowAutomaticTasks`, or an MCP `stdio` server that downloads and
  runs a payload
- Executable payloads disguised as binary assets (JavaScript inside a `.woff2`, `.png`, ...)
- Clipboard, keystroke or screen capture paired with exfiltration, see
  [below](#clipboardkeyloggerexfil-detection)

It scans JS/TS/Python/Rust/Ruby/C/C++/C# sources out of the box and skips `node_modules`, build
output and VCS dirs. Where a bare regex would be noisy it wants context: a decode call only
trips near an execution call or a long literal, and a lone ANSI color escape is not a payload.

## 🖥️ Host audit

`am-i-compromised host` checks the machine, read-only. It never changes anything and never
prints secret values.

| Area | What it looks for |
| --- | --- |
| Persistence | launchd (macOS), user systemd units and XDG autostart (Linux), and the user crontab: entries that capture the clipboard, keys or screen, or send to Telegram/Discord/webhooks; scripts in user-writable places; entries that point at a missing program; `com.apple.*` labels planted in your own directories; unreadable or unparsable plists |
| Shell startup files | piping a download to a shell, decoded payloads, `eval` of downloaded code, `DYLD_INSERT_LIBRARIES`, `NODE_OPTIONS --require`, disabled TLS checks, extra CA bundles, proxies, `sudo`/`ssh` aliases, and scripts sourced from writable dirs (one level deep) |
| AI-tool config | Claude, Codex, Cursor, Gemini, Kilo and OpenCode settings: a model base URL pointed at loopback or a non-vendor host, hooks that run code from a writable path or observe every prompt, disabled permission prompts, plain-text keys, unpinned MCP servers, TLS-off and preload variables |
| Processes | interpreters running from staging directories, and the full command of whatever listens on a suspicious local port |

Findings are `HIGH`, `MEDIUM` or `INFO`. `HIGH` and `MEDIUM` exit `1`. To accept something you
have reviewed, add its id and a reason to `~/.config/am-i-compromised/host-allow.txt`:

```text
agent:~/.claude/settings.json:base-url:3 | local LiteLLM gateway I run myself
```

It honors `CLAUDE_CONFIG_DIR` and `CODEX_HOME`. Toolchain files from nvm, rvm, cargo, conda and
friends are not flagged just for being sourced from a hidden directory.

## Reading the output

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

## Suppressing a finding

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

## Clipboard/keylogger/exfil detection

A scanner that only knows npm supply-chain patterns misses a whole class of
malware: a hidden script that reads the clipboard — or the keyboard, or the
screen — and forwards what it captures to a remote service. In September 2026 a
macOS LaunchAgent wrapper started a Node script that posted every clipboard
change to a Telegram bot, and no source scan could see it.

A capture API on its own is ordinary (clipboard managers, screenshot tools,
test helpers), so these signals are combined **per file**: a capture signal and
an exfiltration signal in the *same* file is reported as HIGH, while a few
decisive shapes stand alone as MEDIUM. The check covers `.js`, `.mjs`, `.cjs`,
`.ts`, `.py`, `.sh`, `.zsh`, `.bash`, `.rb`, `.swift`, `.plist`, and
extensionless scripts with a shebang.

| Signal group | Example indicators | Severity |
| --- | --- | --- |
| Clipboard read | `pbpaste`, `xclip`, `xsel`, `wl-paste`, `Get-Clipboard`, `clipboardy`, `clipboard-event`, `NSPasteboard`, `navigator.clipboard.readText`, `pyperclip` | context |
| Keystroke / screen capture | `CGEventTap`, `pynput`, `iohook`, `node-global-key-listener`, `keylogger`, `screencapture`, `screenshot-desktop`, `pyautogui.screenshot` | context |
| Exfiltration | `api.telegram.org`, `/sendMessage`, `/sendDocument`, `node-telegram-bot-api`, `telegraf`, Discord/Slack webhooks, `webhook.site`, `pastebin.com/api`, `transfer.sh`, `ngrok`, `nc`/`ncat` to a host, bot-token shape `[0-9]{8,10}:[A-Za-z0-9_-]{35}` | context |
| Capture **and** exfiltration in one file | any capture signal together with any exfiltration signal | HIGH |
| Hardcoded Telegram bot token | a `123456789:AAA…` token literal in any scanned file | MEDIUM |
| Background launcher wrapper | `nohup node <payload>.js >> <log> &` behind a pid-file lock | MEDIUM |
| …with a live payload | the named `<payload>.js` sits beside it and captures + exfiltrates | HIGH |
| Persistence beside capture | `launchctl load`, `~/Library/LaunchAgents`, `crontab -`, `~/.config/autostart` in a script that also captures | MEDIUM |
| Capture-shaped file name | name matching `(clip|key|screen)[-_ ]?(logger|monitor|spy|grab)` that reads the clipboard or input | MEDIUM |

Files under `node_modules`/`.cache`, build output, and the fixtures dir are
never scanned, so a README mention or a vendor's own clipboard-library source
with no exfiltration endpoint does not trip the gate. Reviewed matches can still
be marked safe with `am-i-compromised-ignore:` (see above).

`security-gate host` audits the machine itself for the persistence side of this
same class — launch agents, shell startup files, AI-tool config, and running
processes.

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
