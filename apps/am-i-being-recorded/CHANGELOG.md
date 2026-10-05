# Changelog

Newest first.

## 1.0.0 - 2026-10-05

- Initial release. Audits screen/tab capture surfaces and the browser extensions that can start them on macOS and Linux.
- Reads Chromium-family profile directories (Brave, Chrome, Chromium, Edge, Vivaldi) and flags extensions with `desktopCapture`, `tabCapture`, `debugger`, `nativeMessaging`, `userScripts`, or `management` permissions, each at a calibrated severity.
- Combination rules: `desktopCapture` + broad host permissions escalates to HIGH; any capture permission + `offscreen` escalates to HIGH (persistent-capture shape).
- Only the newest version directory of each extension is reported per profile; stale Chromium copies are skipped.
- Localised extension names (`__MSG_key__`) are resolved from `_locales`; unresolvable names fall back to `(unknown)`.
- Live context (not findings): macOS — `screensharingd` / `replayd` status and camera, microphone, and screen-recording TCC grants with code-signer and Team ID. Linux — which process holds a `/dev/video*` camera device via `lsof`.
- `--strict` gate mode: exits `1` when any finding at or above the severity floor is reported.
- `--min-severity LEVEL` floor filter (CRITICAL / HIGH / MEDIUM / LOW, default LOW).
- `--no-live` skips the platform live checks; used by the test suite.
- Zero npm runtime dependencies. Plain bash, `jq`, and optionally `sqlite3` / `lsof`.
- 23 bats tests covering the extension pass, combination rules, severity filtering, localisation, and error paths.

Install: `pnpm add -D am-i-being-recorded@1.0.0`, or run without installing: `pnpx am-i-being-recorded@1.0.0`
