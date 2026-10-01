# 🕵️ Am I Hacked?

[![npm version](https://img.shields.io/npm/v/am-i-hacked)](https://www.npmjs.com/package/am-i-hacked)
[![CI](https://github.com/IsaacBell/secure-devtools/actions/workflows/ci.yml/badge.svg)](https://github.com/IsaacBell/secure-devtools/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/npm/l/am-i-hacked)](LICENSE)

> *Check the code you're about to run, and the machine you're running it on.*

```sh
pnpx am-i-hacked .     # or: npx am-i-hacked .
```

**Status:** actively maintained; 2.0.0 is the current release. macOS and Linux. Formerly
published as `am-i-compromised`; the old command name still works. See
[Renamed from am-i-compromised](#renamed-from-am-i-compromised).

## 🌟 Highlights

- **Built from real, observed attacks.** The detections come from attacks seen in the wild,
  not guesses. The clipboard-stealer, editor auto-run, disguised-asset and persistence checks
  each model a specific attack chain. The generic rules (`eval`, child processes, obfuscation)
  flag the building blocks those attacks use, so they are broader and noisier.
- **Two modes, one tool.** Scan a project for malicious code, or audit *this machine* for the
  things source scans can't see: launch agents, shell startup files, AI-tool config, and
  running processes.
- **Catches clipboard and keystroke stealers.** Capture code paired with a Telegram, Discord,
  Slack or webhook endpoint is flagged, along with the LaunchAgent that starts it.
- **Watches your AI tools.** Flags a local proxy set as your model's base URL, hooks that run
  code from `node_modules` or a writable path, switched-off permission prompts, and plain-text keys.
- **Zero npm runtime dependencies.** Plain shell, so there is no install-time tree to audit.
- **Honest about noise.** Reviewed lines are marked safe with a reason, and suppressed findings
  are still listed on every run.
- **Fits your workflow.** Exit code `1` on findings, so it drops into a dev script or CI. A
  guarded `git pull` (`safe-pull`) is included.

## ℹ️ Overview

`am-i-hacked` is a small [indicator-of-compromise](https://en.wikipedia.org/wiki/Indicator_of_compromise)
checker. It looks for warning signs that should make you look closer. It is not antivirus,
and it does not look up known viruses. A clean result means it found no warning signs; it
does not prove the code or the machine is safe.

Some threats never touch a source tree. A clipboard stealer started by a hidden LaunchAgent
lives in your home directory, where a project scan cannot see it. `host` covers that side.

Why this one? It runs instantly with one command and no signup, account or API key, and it goes
into CI by copy-paste (below). And it catches what advisory scanners cannot. Tools such as
`npm audit` and OSV-Scanner match your dependencies against reported vulnerabilities. They cannot see an attack nobody has reported
yet, or one that lives in the repository itself: an editor task that runs when you open the
folder, a script saved as a font file, a stealer started at login. `am-i-hacked` reads the files
for those indicators before you open, install or run anything. Use both.

## 🚀 Usage

```sh
# Scan a project (defaults to the current directory)
pnpx am-i-hacked .          # npx am-i-hacked . works too

# Check a folder's AI-tool config (.claude/settings*.json, .mcp.json). Defaults to the current directory.
pnpx am-i-hacked host [path/to/folder]

# Audit the whole machine as well: login items and their code signatures, crontab,
# shell startup files, user-level AI-tool config, running processes.
# Read-only, no root or sudo, does not need ripgrep.
pnpx am-i-hacked --system   # same as: host --system [folder]
```

Exit code `0` means nothing found, `1` means findings to review or a missing requirement (bash
4.2+ or `rg`, or `jq` when a `package.json` is present; the message names it), `2` means a
usage error. Add
`--verbose` to `host` to also list informational entries and every login item with its signer.

In `package.json`, run the scan before your dev server:

```json
{
  "scripts": {
    "dev": "am-i-hacked . && next dev"
  }
}
```

In CI, for example a GitHub Actions job on `ubuntu-latest`. The runner has `bash` and `jq` but
no pnpm, and `ripgrep` is installed first in case the image lacks it:

```yaml
- uses: pnpm/action-setup@v4
  with:
    version: 10
- run: sudo apt-get install -y ripgrep
- run: pnpx am-i-hacked@2 .
```

More below: how to read the output, how to suppress a reviewed finding, the host audit, and
[safe-pull](#guarded-pull-safe-pull). System-wide Linux units and `/etc/cron.*` are not covered yet.

## ⬇️ Installation

No install needed with `pnpx` / `npx`. To keep it in a project:

```sh
pnpm add -D am-i-hacked   # or: npm install --save-dev am-i-hacked
```

macOS and Linux. Requirements:

| Command | Needs |
| --- | --- |
| `am-i-hacked <dir>` | `bash` 4.2+, `rg` ([ripgrep](https://github.com/BurntSushi/ripgrep)), `jq` (to inspect `package.json` scripts; without it the scan fails closed when a `package.json` is present) |
| `am-i-hacked host` | `bash` 3.2+ (the macOS default works). `jq` is optional but needed to read AI-tool hooks and MCP servers |
| `safe-pull` | `bash`, `git` |

macOS ships bash 3.2. The project scan re-runs itself under a newer bash if you have one, looking
first at the `bash` on your `PATH` (mise, nix, asdf) and then at the Homebrew, MacPorts and
Linuxbrew locations, and otherwise tells you what to install (for example `brew install bash`).
Install `rg` and `jq`
with `brew install ripgrep jq` or `apt-get install ripgrep jq`.

The package installs these commands:

| Command | What it runs |
| --- | --- |
| `am-i-hacked` | the scanner (and `host`, the machine audit) |
| `aih` | the same scanner (short command) |
| `am-i-compromised` | the same scanner, kept so existing scripts keep working |
| `aic` | the same scanner (short form of the old name) |
| `security-gate` | the same scanner (good for project scripts) |
| `scanner` | the same scanner (short; may collide with other tools) |
| `safe-pull` | the guarded `git pull` |

## 🔎 What the project scan detects

- Dynamic code execution (`eval`, `new Function`, ...), child-process execution, direct network
  module access, runtime global mutation
- Encoded or obfuscated payloads (`atob`, hex/unicode escapes, `_0x...` string tables), and
  unusually long source lines
- Suspicious `package.json` scripts (scanned with `jq`)
- Editor config that runs code unprompted: a `runOn` trigger or `task.allowAutomaticTasks: true`
  in `.vscode/*.json` or `.idea/tasks.json`, and download-and-run commands there (`curl | sh`,
  `powershell`, `osascript`, `base64 -d`), which covers an MCP `stdio` server that fetches and
  runs a payload
- Executable payloads disguised as binary assets (JavaScript inside a `.woff2`, `.png`, ...)
- Clipboard, keystroke or screen capture paired with exfiltration, see
  [below](#clipboardkeyloggerexfil-detection)
- Environment files (`.env`, `.env.*`) tracked in the git index

It scans JS/TS/Python/Rust/Ruby/C/C++/C# sources out of the box and skips `node_modules`, build
output and VCS dirs. Where a bare regex would be noisy it wants context: a decode call only
trips near an execution call or a long literal, and a lone ANSI color escape is not a payload.

## 🖥️ Host audit

`am-i-hacked host` is read-only. It never changes anything and never prints secret values.

By default it checks one folder (the argument, or the current directory): the AI-tool config in
that folder. `--system` (alias `--full-system-scan`) adds every row below. Login items are not
read unless you ask, because most runs are about the project in front of you.

| Area | What it looks for |
| --- | --- |
| Persistence (`--system`) | launchd (macOS), user systemd units and XDG autostart (Linux): entries that capture the clipboard, keys or screen, or send to Telegram/Discord/webhooks; scripts in user-writable places; entries that point at a missing program; entries that inject a library or turn off TLS checks; `com.apple.*` labels planted in your own directories; unreadable or unparsable plists. On macOS, also capture-tool folders in Application Support |
| Crontab (`--system`) | a remote script piped to a shell, and jobs that run from user-writable places |
| Code signatures (`--system`, macOS) | the binary each launchd entry runs, read with `codesign`: a vendor label (`com.google.*`, `ru.keepcoder.*`, ...) that is unsigned or signed by a Team ID that vendor does not use (`HIGH`). Expected IDs come from [`bin/vendor-teams.tsv`](bin/vendor-teams.tsv), then from your installed apps with the same bundle-id prefix; a signature that no longer verifies (`MEDIUM`); an unsigned or ad-hoc signed program in Application Support, `/tmp` or another writable place (`MEDIUM`, elsewhere `INFO`). `--verbose` prints each entry's signer, which is the name System Settings shows under Login Items |
| Shell startup files (`--system`) | piping a download to a shell, decoded payloads, `eval` of downloaded code, `DYLD_INSERT_LIBRARIES`, `NODE_OPTIONS --require`, disabled TLS checks, extra CA bundles, proxies, `sudo`/`ssh` aliases, and scripts sourced from writable dirs (one level deep) |
| AI-tool config (folder always; user-level and managed with `--system`) | Claude, Codex, Cursor, Gemini, Kilo and OpenCode settings: a model base URL pointed at loopback (with the command line of whatever listens on that port) or a non-vendor host, hooks that run code from a writable path or observe every prompt, disabled permission prompts, plain-text keys, unpinned MCP servers, TLS-off and preload variables |
| Processes (`--system`) | interpreters running from staging directories, and capture-named scripts that report out |

Findings are `HIGH`, `MEDIUM` or `INFO`. `HIGH` and `MEDIUM` exit `1`. To accept something you
have reviewed, add its id and a reason to `~/.config/am-i-hacked/host-allow.txt` (the tool
does not create that folder; run `mkdir -p ~/.config/am-i-hacked` first):

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

While it runs, the scan prints progress on stderr: one line per check with the elapsed time and
the findings so far, and `host --system` counts login items as it checks their signatures, which
is the slow part. Progress is on by default in a terminal; set `AIH_PROGRESS=1` to see it in CI
logs, or `AIH_PROGRESS=0` to turn it off. The report on stdout does not change.

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
const decoded = atob(header); // am-i-hacked-ignore: decodes a request header, not a payload
```

The marker is `am-i-hacked-ignore:` followed by a reason, on the
finding's own line or the line immediately before it (handy when the flagged
line is too long to comment on directly, like a huge literal):

```js
// am-i-hacked-ignore: bee movie script fixture, not obfuscated code
const script = "...49,000 characters...";
```

The pre-2.0 spelling, `am-i-compromised-ignore:`, is still honored.

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
am-i-hacked: 1 finding suppressed by inline comment

  src/auth.ts:42
    const decoded = atob(header); // am-i-hacked-ignore: decodes a request header, not a payload
    → Encoded payload primitives (suppressed)
    reason: decodes a request header, not a payload
```

This marker is honored by the project scan only. **`safe-pull` does
not read it.** `safe-pull` inspects commits nobody has reviewed yet — that's
the entire point of the guard — so a marker written by whoever authored the
incoming diff must never be able to wave off their own payload.

## Clipboard/keylogger/exfil detection

A scanner that only knows npm supply-chain patterns misses a whole class of
malware: a hidden script that reads the clipboard — or the keyboard, or the
screen — and forwards what it captures to a remote service. This detection
models a real, observed stealer class: a LaunchAgent starts a small shell
wrapper, the wrapper launches a Node script in the background, and the script
posts every clipboard change to a Telegram bot or a webhook.

A capture API on its own is ordinary (clipboard managers, screenshot tools,
test helpers), so these signals are combined **per file**: a capture signal and
an exfiltration signal in the *same* file is reported, and a few decisive shapes
are reported on their own. The check covers `.js`, `.mjs`, `.cjs`, `.ts`, `.py`,
`.sh`, `.zsh`, `.bash`, `.rb`, `.swift`, `.plist`, and extensionless scripts with
a shebang.

| Signal group | Example indicators | Reported as |
| --- | --- | --- |
| Clipboard read | `pbpaste`, `xclip`, `xsel`, `wl-paste`, `Get-Clipboard`, `clipboardy`, `clipboard-event`, `NSPasteboard`, `navigator.clipboard.readText`, `pyperclip` | context for the rows below |
| Keystroke / screen capture | `CGEventTap`, `pynput`, `iohook`, `node-global-key-listener`, `keylogger`, `screencapture`, `screenshot-desktop`, `pyautogui.screenshot` | context for the rows below |
| Exfiltration | `api.telegram.org`, `/sendMessage`, `/sendDocument`, `node-telegram-bot-api`, `telegraf`, Discord/Slack webhooks, `webhook.site`, `pastebin.com/api`, `transfer.sh`, `ngrok`, `nc`/`ncat` to a host, bot-token shape `[0-9]{8,10}:[A-Za-z0-9_-]{35}` | context for the rows below |
| Capture **and** exfiltration in one file | any capture signal together with any exfiltration signal | Clipboard/keystroke/screen capture with remote exfiltration |
| Hardcoded Telegram bot token | a `123456789:AAA…` token literal in a scanned file | Telegram bot token literal |
| Background launcher wrapper | `nohup node <payload>.js >> <log> &` behind a pid-file lock | Background node launcher with a pid-file lock |
| …with a live payload | the named `<payload>.js` sits beside it and captures + exfiltrates | Background node launcher wraps a capture-and-exfiltrate payload |
| Persistence beside capture | `launchctl load`, `~/Library/LaunchAgents`, `crontab -`, `~/.config/autostart` in a script that also captures | Persistence installed by a script that captures input |
| Capture-shaped file name | name matching `(clip\|key\|screen)[-_ ]?(logger\|monitor\|spy\|grab)` that reads the clipboard or input | Capture-named script reads the clipboard or input |

Files under `node_modules`/`.cache`, build output, and the fixtures dir are
never scanned, so a README mention or a vendor's own clipboard-library source
with no exfiltration endpoint does not trip the scan. Reviewed matches can still
be marked safe with `am-i-hacked-ignore:` (see above).

`am-i-hacked host` audits the machine itself for the persistence side of this
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
safe-pull --remote <name> --branch <name>   # inspect a specific remote branch
```

What it checks in the incoming commits: a force-pushed (rewritten) upstream, an
author/committer mismatch, a commit rewritten after authoring, editor auto-run
tasks, download-and-run editor commands, executable payloads disguised as asset
files, committed `.env` files, and a `dotenv` plus `node-fetch`/`axios` dependency
pair in a changed `package.json`. The inspection uses `git grep` against the fetched
commit, so it reads blobs from the object store and never writes files to disk.
Plain `git fetch` is safe on its own — it executes nothing.

Exit codes: `0` clean (and merged, unless `--dry-run`), `1` findings (nothing
merged), `2` usage or setup problem.

To use it as a git alias:

```sh
git config --global alias.safe-pull '!safe-pull'
```

## Renamed from am-i-compromised

Version 2.0.0 renames the package from `am-i-compromised` to `am-i-hacked`.

- `am-i-compromised`, `security-gate`, `scanner` and `safe-pull` still work.
- The project scan's report lines start with `am-i-hacked:` instead of `security-gate:`.
- Suppress with `am-i-hacked-ignore:`. The old `am-i-compromised-ignore:` marker is still honored.
- The host audit's allow file is `~/.config/am-i-hacked/host-allow.txt`.

See [CHANGELOG.md](CHANGELOG.md).

## Development

Requirements: `bash` 4.2+, `rg`, `jq`, `git`, [`pnpm`](https://pnpm.io), and, for `lint` and
`format`, `shellcheck` and `shfmt`.

```sh
pnpm install
pnpm test          # bats suite
pnpm check         # shellcheck + shfmt + bats
```

The Bats suite lives in `test/` and includes a self-test that scans the quarantined
fixtures in `test/__security_gate_fixtures__/` — treat everything in that directory as
malware and never execute or import it.

## Contributing

Bug reports, feature ideas, and pull requests are welcome. Open an issue or a pull request at
<https://github.com/IsaacBell/secure-devtools>.

## Sponsorship

If this tool keeps your projects safe, consider supporting the work:

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/ibell)

## Security

Report vulnerabilities via GitHub's private advisory mechanism:
<https://github.com/IsaacBell/secure-devtools/security/advisories/new>.

## License

MIT — see [LICENSE](LICENSE).
