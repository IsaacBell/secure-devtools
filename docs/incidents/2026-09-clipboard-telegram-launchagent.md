# Incident: clipboard-to-Telegram LaunchAgent (September 2026)

A developer workstation ran a hidden macOS LaunchAgent that forwarded every clipboard change to a Telegram bot.
`am-i-compromised` 1.1.0 did not detect it: the scanner only read source trees. This note records what the
malware looked like and which check now catches each part. It contains no names or home paths.

## What it looked like

| Part | Indicator |
| --- | --- |
| Persistence | `~/Library/LaunchAgents/<label>.plist`, label containing `clipboardmonitor`, `RunAtLoad` true |
| Launcher | `~/Library/Application Support/ClipboardMonitor/run_monitor.sh`: `cd` to its own folder, `nohup node clipboard_tg_monitor.js >> monitor.log &`, `monitor.pid` lock |
| Payload | Node script polling the clipboard and sending it to `api.telegram.org` with a bot token; output in `monitor.log` |
| Side channel | A local API proxy on a loopback port set as the AI tool's base URL, plus global hooks running code from a repo's `node_modules` |

Timeline: the LaunchAgent was installed about two weeks before discovery. Shell startup files were modified the
day after. The install vector was never identified. The owner deleted the payload before a copy was kept, so the
Node source could not be recovered; test fixtures are inert reconstructions.

## What now catches it

| Indicator | Check (`am-i-compromised host`) | Test group in `test/host-audit.bats` |
| --- | --- | --- |
| LaunchAgent label, wrapper path, payload name | launchd persistence + `RE_INCIDENT_IOC` | `plist:`, `incident:` |
| Wrapper follows to its Node payload | one-hop payload scan (capture + exfil) | `plist:` |
| Staged folder with script + log/pid | payload-directory check | `payloaddir:` |
| Loopback or unknown-remote base URL, any port | agent config base-URL check | `agent:` |
| Hook running code from a writable path | hook path check | `agent:` |
| Malicious rc-file lines, one level of sourcing | startup-file rules | `rc:` |

The source-tree scanner (`am-i-compromised`, `scanner`) also flags the payload class itself: clipboard, keystroke or
screen capture together with a Telegram, Discord, Slack or webhook exfil endpoint in the same file.

## If you find this on your machine

1. Copy the plist, launcher, script and log somewhere safe **before** deleting anything. The log shows what was sent.
2. Unload and remove the LaunchAgent, then confirm nothing is still running.
3. Treat everything copied since installation as exposed: rotate passwords, API keys, tokens and recovery codes from a clean device.
4. Report the bot token to Telegram (the script holds it). Reinstall the OS if you cannot establish the install vector.
