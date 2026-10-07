# am-i-being-recorded

[![npm version](https://img.shields.io/npm/v/am-i-being-recorded)](https://www.npmjs.com/package/am-i-being-recorded)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/IsaacBell/secure-devtools/actions/workflows/ci.yml/badge.svg)](https://github.com/IsaacBell/secure-devtools/actions/workflows/ci.yml)

Find out **which browser extension is recording your screen** — and what else on
the machine can capture you.

```sh
npx am-i-being-recorded
```

The sibling of [`am-i-hacked`](https://www.npmjs.com/package/am-i-hacked):
that one audits your *code*, this one audits your *machine*.

macOS attributes an active capture to the *application*, never the tab or
extension responsible. A purple indicator that says "Brave Browser is recording
your screen" is accurate but not actionable. This tool turns that attribution
back into a name.

## Installation

Requires `jq` to read extension manifests. Everything else is preinstalled on
macOS and most Linux distros.

```sh
# macOS
brew install jq

# Debian/Ubuntu
apt-get install jq
```

Run without installing:

```sh
npx am-i-being-recorded
```

Install as a dev dependency:

```sh
npm install --save-dev am-i-being-recorded
```

## What it checks

**Browser extensions (macOS and Linux).** Reads Chromium-family profile
directories (Brave, Chrome, Chromium, Edge, Vivaldi) and flags extensions whose
permissions allow display capture, tab capture, or deep browser control:

| Permission | Severity | Why it matters |
| --- | --- | --- |
| `desktopCapture` | CRITICAL | Can record the entire display |
| `tabCapture` | HIGH | Can record the active tab's audio/video |
| `debugger` | HIGH | Full tab control over the DevTools protocol |
| `nativeMessaging` | MEDIUM | Can launch a native helper process |
| `userScripts` | MEDIUM | Can inject arbitrary scripts into pages |
| `management` | LOW | Can enable or disable other extensions |

Two combinations escalate:

- `desktopCapture` + access to every site (`<all_urls>`) — recordings can
  include any page you visit.
- any capture permission + `offscreen` — the stream can outlive the tab or
  window that requested it, which is the shape of a "stuck" indicator.

Only the newest installed version of an extension is reported once per profile;
Chromium leaves older version directories behind, and they are not loaded.

**Live context (not findings).** On macOS: whether `screensharingd` and
`replayd` are running, and which apps hold camera, microphone, and
screen-recording grants in the TCC privacy database, each with its code signer
and Team ID (`signed: Zoom Video Communications, Inc. [BJ4HAAB9B3]`,
`unsigned`, `ad-hoc signed`). An unsigned app holding a capture grant is worth
a look. On Linux: which process holds a `/dev/video*` camera device. These
lines are context for a human; findings come only from extension capabilities,
so there is no "known good app" allowlist to maintain.

## Usage

```sh
# Audit every detected browser profile on this machine
am-i-being-recorded

# Only the loud stuff
am-i-being-recorded --min-severity HIGH

# Gate mode: non-zero exit when anything at or above the floor is found
am-i-being-recorded --strict

# Scan a fixture tree instead of the live profiles (used by the tests)
am-i-being-recorded --root ./fixtures --no-live
```

The command is also installed as the short alias `aibr`.

Findings are severity-tagged and printed highest first. The default mode is
**evidence**: findings are reported and the exit status stays `0`. `--strict`
turns any reported finding into exit status `1`.

## Reading the output

A stuck capture is usually an extension holding a display stream. The finding
that explains the indicator names the extension, its ID, its version, and the
profile it lives in:

```text
  CRITICAL Example Screen Recorder (aaaabbbbccccddddeeeeffffgggghhhh) v1.2.3
           Google/Chrome/Default - Can capture the entire display (screen recording)
  HIGH     Example Screen Recorder (aaaabbbbccccddddeeeeffffgggghhhh) v1.2.3
           Google/Chrome/Default - Capture permission plus an offscreen document can outlive the visible tab
```

To stop the capture, disable or remove that extension in `chrome://extensions`
(or `brave://extensions`), then restart the browser so the indicator clears.
An extension installed in several profiles shows up once per profile.

## Limitations

- The extension pass reports *capability*, not proof of an active stream. A
  screen recorder you installed and use on purpose will (correctly) be flagged.
- Live context is best-effort. macOS Screen Recording grants need root or Full
  Disk Access to read; the TCC schema is undocumented and may change. The tool
  says so instead of guessing.
- Detection covers Chromium-family extensions. Safari and Firefox extensions,
  standalone recorder apps, and a page's own `getDisplayMedia` prompt are out of
  scope.
- This is not a malware scanner. Treat it as triage that names a suspect.

## Contributing

Bug reports and pull requests are welcome at
<https://github.com/IsaacBell/secure-devtools/issues>.

```sh
# Clone the monorepo and work inside this package
cd apps/am-i-being-recorded
pnpm test          # bats test suite (runs against synthetic fixtures, not your real browser data)
pnpm lint          # shellcheck
pnpm format:check  # shfmt
pnpm check         # all of the above
```

The test suite drives the filesystem pass against synthetic profile trees so it
runs without touching the host's real browser data and passes on Linux CI.

## License

MIT — see [LICENSE](LICENSE).
