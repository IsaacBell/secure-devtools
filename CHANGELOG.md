# Changelog

Newest first. One line per change. Default-behavior changes marked **CHANGED**. Package versions in brackets.

## 2026-10-10

### CI
- **CHANGED:** the security gate (`.github/workflows/gate.yml`) runs the latest stable `am-i-hacked` release from npm, pinned to an exact version, instead of the unreleased scanner on `main` (#6).

## 2026-10-09 [am-i-hacked 2.1.0]

**BLUF:** A security release: a scanned repository's `.git/config` can no longer make `am-i-hacked` or `safe-pull` run a command, and payloads in dot-directories, ignored folders and committed build output are now read. It also adds the dark-corner system scan, Python virtualenv integrity and `--max-findings`. There was no 2.0.1; its changes are in 2.1.0. The package changelog, [`apps/am-i-hacked/CHANGELOG.md`](apps/am-i-hacked/CHANGELOG.md), has the detail.

### am-i-hacked
- Security: the scan and `safe-pull` run git with `core.fsmonitor=false`, so a `.git/config` that ships inside an archive cannot run a command.
- **CHANGED:** the scan reads dot-directories, ignores `.ignore` and `.rgignore`, and scans tracked files that `.gitignore` matches and committed build output. Findings may appear in `dist/`, `.github/`, `.vscode/` and similar.
- **CHANGED:** 71 official Yarn releases in `.yarn/releases` are verified by SHA256.
- **CHANGED:** bundled code gets only high-signal checks, and embedded WebAssembly data: URLs are not flagged for line length.
- `--system` also scans a fixed list of dark corners (virtualenvs, package-manager caches, language bin folders), and reports a check it could not run instead of passing it.
- The folder scan verifies Python virtualenv integrity against each package's `RECORD` hashes.
- `--max-findings N` (default 1000, was 100). **CHANGED:** over the cap, the true total and a per-rule count are printed and higher-severity findings are kept first.
- **CHANGED:** hex and unicode escape findings inside installed dependency folders are one summary count. `bin/host-audit.sh` is now `bin/system-scan.sh`, with the old name kept as a shim.

### CI
- The security gate pins `am-i-hacked` 2.1.0.

## 2026-10-05

### Skills
- Added `skills/create-skill/SKILL.md`: write, check and publish an agent skill (a folder with a `SKILL.md`). Covers frontmatter, privacy and secret checks, third-party content, QA and the publish steps.
- Added `skills/skill-publish-review/SKILL.md`: review agent skills before they go into a public repository. Finds leaked personal or internal detail, broken frontmatter, unfinished work and text copied from somewhere else, runs independent reviewers in parallel and merges their verdicts.
- Added `skills/ssrf-safe-fetch/SKILL.md`: write or review server code that fetches a URL it did not get from its own fixed configuration. Validate the scheme, port and resolved address before the request, follow redirects by hand, and what to test.
- `skills/quarantine-review`, `skills/login-item-triage` and `skills/secure-skill-pull` frontmatter now parses as YAML: their descriptions are quoted, so a loader no longer skips them.

### secure-semgrep
- New `rules/ssrf` rules, all warnings: a request whose URL is not a fixed string and does not pass through a guard function; a client that follows redirects automatically for such a URL; and TLS certificate verification turned off (`rejectUnauthorized: false`, `verify=False`, `danger_accept_invalid_certs(true)`). JavaScript/TypeScript, Python and Rust.

## 2026-10-02

### Skills
- Added `skills/secure-skill-pull/SKILL.md`: vet a third-party agent skill, plugin or setup recipe before using it. Fetch it as data at a pinned commit, scan it, read it, record where it came from, and never run its installer.

## 2026-10-01 [am-i-hacked 2.0.0]

**BLUF:** `am-i-compromised` is renamed `am-i-hacked` and released as 2.0.0, the first npm release since 1.0.0. It includes everything below. The package changelog, [`apps/am-i-hacked/CHANGELOG.md`](apps/am-i-hacked/CHANGELOG.md), lists the full set of changes since 1.0.0.

### am-i-hacked
- **CHANGED:** renamed from `am-i-compromised`. The old command name, the `am-i-compromised-ignore:` marker and `AIC_HOST_*` variables still work.
- Progress for the project scan: one line per check on stderr with elapsed time and findings so far. On by default in a terminal; `AIH_PROGRESS=1` turns it on elsewhere (CI), `AIH_PROGRESS=0` turns it off. The report on stdout is unchanged.
- **CHANGED:** the host audit is folder-scoped by default. Machine-wide checks, now including code-signature checks on login items, need `--system`.
- **CHANGED:** `host` checks only the AI-tool config in the given folder (default `.`). Login items, crontab, shell startup files, user-level and managed AI-tool config, and processes run only with `--system`.
- Added `--system` and its alias `--full-system-scan`. `am-i-compromised --system` is shorthand for `host --system`.
- Folder runs print what was skipped and how to include it. A folder PASSED no longer implies the machine was checked.
- Added code-signature checks for launchd programs (macOS, `--system`). Reads the binary with `codesign`. Never writes.
- HIGH: a vendor-prefixed label signed by a Team ID the vendor does not use, or unsigned. Expected IDs come from `bin/vendor-teams.tsv` (21 vendors with 22 Team IDs, each read with `codesign` from a genuine app), then from installed apps with the same bundle-id prefix for any other vendor.
- MEDIUM instead of HIGH when the signer is the table vendor's own organization under an unlisted Team ID. Shared prefixes (`com.electron`, `com.github`, ...) are never inferred from apps.
- MEDIUM: a signature that fails `codesign --verify`. MEDIUM: unsigned or ad-hoc program in a user-writable location. INFO elsewhere.
- `--verbose` inventory shows each entry's signer and Team ID. The signer matches the name in System Settings > Login Items.
- Scripts, interpreters and SIP-protected system binaries skip the signature check. The payload checks judge scripts.
- Test seams `AIC_HOST_CODESIGN`, `AIC_HOST_APP_DIRS`, `AIC_HOST_VENDOR_FILE`. Tests stub `codesign` and log each call, which proves when it is not run.

### am-i-being-recorded
- TCC grant lines show the app's code signer and Team ID, or `unsigned` / `ad-hoc signed`. Context only. Not a finding.

### secure-semgrep
- New rule `persistence-install` (shell scripts): launchctl load/bootstrap/submit/enable, writes into LaunchAgents/LaunchDaemons, `systemctl --user enable`, XDG autostart, crontab installs. Read-only commands and commented lines do not match.

### Repository
- Added `skills/login-item-triage/SKILL.md`: the manual method behind the signature checks, for agents and responders.
- Added this changelog.
- Security gate moved to `.github/workflows/gate.yml`: the workflow, scanner and toolchain come from the base branch; the pull request is scanned as data.
- SECURITY.md rewritten: what counts, full scope, and reporting rules for people and for AI agents.

## 2026-09-27

### am-i-compromised
- Host audit ignores query and fragment when it reads a URL authority.
- Scanner prefers the `bash` on PATH when it re-runs under bash 4.2+.

## 2026-09-26

### am-i-compromised
- Host audit takes an optional folder argument for AI-tool config. Pending tests record known gaps.

## 2026-09-25 [am-i-compromised 1.2.0]

**BLUF:** Added the host audit, built from real-world attack patterns. It checks the machine itself for what a source scan cannot see, such as a clipboard stealer started by a LaunchAgent.

### am-i-compromised
- New `host` subcommand. Read-only audit of persistence, shell startup files, AI-tool config and processes.
- Clipboard, keystroke and screen-capture detection paired with exfiltration endpoints, in the project scan and the host audit.
- Honors ZDOTDIR and XDG_CONFIG_HOME. No false claim of persistence coverage on unsupported OSes. Fixed an empty-args crash on bash 3.2. Toolchain hooks are not flagged.
- Scanner needs bash 4.2 and re-runs under a newer bash when one is found. `host` runs on bash 3.2.
- README rewritten: highlights, overview, host audit section, corrected requirements.

### am-i-being-recorded
- Flagged shell expansions rewritten instead of suppressed. CI ignores `nosemgrep`.
- Severity-rank substitutions hoisted out of compound statements.

### CI
- Ignore markers on detector patterns. Fake bot tokens are built at runtime. Semgrep false positives fixed. HOME fallback.

## 2026-09-19 [am-i-being-recorded 0.1.0]

### am-i-being-recorded
- Initial release. Names the browser extension behind an OS capture indicator. Reports TCC grants and capture daemons as live context.

## 2026-09-17

### am-i-compromised
- Detects editor auto-run payloads: `.vscode/tasks.json` `runOn: folderOpen`, automatic tasks, MCP stdio servers that download and run code.
- Added `safe-pull`, a guarded `git pull`.

## 2026-09-05

- Dependency bumps: actions/checkout, gitleaks-action, mise-action.

## 2026-09-04

- Removed persistent semgrep setup artifacts.

## 2026-09-03 [am-i-compromised 1.0.0]

- Initial release of am-i-compromised.
- Scanner reporting improved, test suite hardened, demo added. npm release procedure documented.

