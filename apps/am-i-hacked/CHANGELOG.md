# Changelog

Newest first. Default-behavior changes are marked **CHANGED**.

## 2.0.1 - 2026-10-01

**BLUF:** A security release. The scan no longer trusts the tree it is reviewing: a scanned repo's `.git/config` could make it run a command, and payloads in dot-directories, in folders named in `.ignore` or `.rgignore`, in tracked files matched by `.gitignore`, and in tracked build output were not read. It also fixes a skip on extensionless scripts.

### Security
- **CHANGED:** the scan now reads dot-directories, no longer reads `.ignore` or `.rgignore`, and scans tracked files that `.gitignore` matches. Committed build output is now scanned, so findings may appear in `dist/`, `.github/`, `.vscode/` and similar. Untracked build output listed in `.gitignore` is still skipped, and `node_modules` and `.git` are always skipped.
- Payloads were not scanned when they sat in a dot-directory, in a folder named in `.ignore` or `.rgignore`, in a tracked file matched by `.gitignore`, or in a tracked build output folder. All of these are scanned now.
- A scanned repo's `.git/config` could make the scan run a command: `git ls-files` runs any `core.fsmonitor` hook the config names. The scan now runs git with `core.fsmonitor=false`.
- **CHANGED:** 71 official Yarn releases in `.yarn/releases` are verified by SHA256 checksum; a mismatch is a finding at line 1. Unverified or malicious Yarn files no longer pass silently.

### Changed
- **CHANGED:** bundled code (webpack/esbuild/ncc) identified by markers in the first 4096 bytes (`__webpack_require__`, `__nccwpck_require__`, `webpackBootstrap`, `__toESM(`, `__commonJS(`) receives only high-signal checks. Routine patterns in bundles (dynamic code execution, network modules, child process) are counted but not flagged; obfuscation, capture/exfiltration and bot tokens still are.
- **CHANGED:** embedded WebAssembly data: URLs (`data:application/(wasm|octet-stream);base64,AGFzbQ...`) on a single line are no longer flagged for line length, as they are expected to be long.

### Fixed
- An extensionless script inside a folder with a dot in its name (for example `.devcontainer/sync-agent`) was skipped. The extensionless check now tests the file name.

Upgrade: `pnpm add -D am-i-hacked@2.0.1`, or run the pinned version without installing: `pnpx am-i-hacked@2.0.1 .`

## 2.0.0 - 2026-10-01

**BLUF:** Renamed from `am-i-compromised` to `am-i-hacked`. The old command name still works. This is the first release that includes the host audit, `safe-pull` and the clipboard-stealer checks.

### Rename
- **CHANGED:** the package is now `am-i-hacked`, and `am-i-hacked` is the primary command.
- `am-i-compromised` stays as a second command for the same scanner, so existing scripts keep working. `security-gate`, `scanner` and `safe-pull` are unchanged.
- Short commands: `aih` (the scanner) and `aic` (short form of the old name).
- **CHANGED:** the project scan prints `am-i-hacked:` where it used to print `security-gate:` (`FAILED`, `PASSED`, suppression and `jq` notices). Update anything that matches on the old prefix.
- **CHANGED:** the suppression marker is `am-i-hacked-ignore: <reason>`. The old `am-i-compromised-ignore:` marker is still honored.
- **CHANGED:** the host audit's allow file is `~/.config/am-i-hacked/host-allow.txt`. `AIC_HOST_ALLOW` still overrides it.
- The package lives in the secure-devtools monorepo at `apps/am-i-hacked`: <https://github.com/IsaacBell/secure-devtools/tree/main/apps/am-i-hacked>.
- `package.json` now declares `MIT`, matching the `LICENSE` file.
- The host audit no longer tells you to run a separate tool for camera and microphone permissions.

### Added since 1.0.0
- `host` subcommand: a read-only audit of persistence, shell startup files, AI-tool config and running processes. `--system` (alias `--full-system-scan`) adds the machine-wide checks, `--verbose` adds informational entries.
- Code-signature checks for launchd programs (macOS, `--system`), with expected vendor Team IDs in `bin/vendor-teams.tsv`.
- Clipboard, keystroke and screen capture paired with an exfiltration endpoint, in the project scan and the host audit.
- Editor auto-run detection (`runOn`, `allowAutomaticTasks`, download-and-run commands in editor config) and executable payloads disguised as asset files.
- Detection of `.env` files tracked in the git index.
- Progress output: the project scan prints one line per check on stderr (`[ 3/19]  12s, 1 found so far  <check>`), and the host audit names each stage and counts login items as it checks their signatures. On by default when stderr is a terminal; `AIH_PROGRESS=1` turns it on elsewhere (CI), `AIH_PROGRESS=0` turns it off. The report on stdout is unchanged.
- `safe-pull`: a guarded `git pull` that inspects incoming commits before merging with `--ff-only`.
- The project scan re-runs itself under bash 4.2+ when it finds one; `host` runs on bash 3.2.

## 1.0.0 - 2026-09-03

- Initial release as `am-i-compromised`: a source-level indicator scanner for dynamic code execution, child processes, obfuscated payloads, suspicious `package.json` scripts and long lines, with quarantined self-test fixtures.
