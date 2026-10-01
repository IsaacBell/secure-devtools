# Changelog

Newest first. Default-behavior changes are marked **CHANGED**.

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
- `safe-pull`: a guarded `git pull` that inspects incoming commits before merging with `--ff-only`.
- The project scan re-runs itself under bash 4.2+ when it finds one; `host` runs on bash 3.2.

## 1.0.0 - 2026-09-03

- Initial release as `am-i-compromised`: a source-level indicator scanner for dynamic code execution, child processes, obfuscated payloads, suspicious `package.json` scripts and long lines, with quarantined self-test fixtures.
