---
name: login-item-triage
description: 'Decide whether a macOS login item or background item is legitimate or planted. Use when a user sees a "Background Items Added" notification, an unfamiliar name under System Settings > Login Items, or asks "did I just get compromised?" about something that runs at login. Maps the displayed name to its launchd plist and binary, checks the code signature and Team ID against the vendor, reads any script payload without running it, and preserves evidence before anything is removed. Automated equivalent: `npx am-i-hacked --system --verbose`.'
version: 1.0.0
verified-against: "am-i-hacked 2.0.0"
---

# Login item triage (macOS)

**BLUF:** The name in System Settings is the code signer, not the plist label. Find the plist, read the program it runs, and verify that program's signature and Team ID against the vendor. A valid vendor signature on a vendor-labelled entry closes the case. Anything unsigned, ad-hoc signed, failing verification, or signed by the wrong team stays open until explained.

The audience includes security professionals. Show exact commands and raw evidence. Name every assumption. Never state "safe". State what was verified and what was not.

## Warn the user before these commands

Tell the user what a command will do on screen **before** running it. A surprise OS alert during an incident reads as a second incident.

| Command | What the user sees | Notes |
|---|---|---|
| `sfltool dumpbtm` | Admin prompt, and possibly a notification that a tool read background items | Needs root. Use it only when plists do not explain the item. Say so first. |
| `sqlite3` on `/Library/Application Support/com.apple.TCC/TCC.db` | Nothing, then a failure | Needs Full Disk Access. Do not ask the user to grant FDA to a terminal casually; that is a security-relevant change. |
| `spctl --assess -vv <app>` | Nothing | May contact Apple for a notarization ticket. Mention the network call. |
| `open "x-apple.systempreferences:..."` | System Settings opens | Only when the user asks to look. |
| `launchctl bootout`, `launchctl unload`, `rm` of a plist or binary | The item stops or disappears | Destructive. Only after evidence is preserved and the user confirms. |
| `codesign -dv`, `codesign --verify`, `plutil -p`, `stat`, `shasum`, `mdfind`, `launchctl print` | Nothing | Read-only and silent. No warning needed. |

Also say, before a full scan, that `npx am-i-hacked --system` reads shell startup files and AI-tool configs. They can hold secrets. The tool never prints secret values.

## 1. Map the displayed name to an entry

- System Settings > General > Login Items & Extensions groups entries by the **signing certificate's developer name** ("Google LLC"). An entry with no valid Developer ID shows as "Item from unidentified developer".
- "Background Items Added" fires whenever Background Task Management registers an item. Vendor updaters re-register after updates, so the alert alone is not an indicator.
- Enumerate the launchd directories. Most entries live here:

```sh
ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons
```

- Match on vendor prefix (`com.google.*`) or on recent mtime. If nothing matches, the item may be an app-embedded login item (`Contents/Library/LoginItems`) or an SMAppService registration. Only then use `sfltool dumpbtm` (warn first).

## 2. Read the entry, not the name

```sh
plutil -p <plist>
```

Record: `Label`, `Program` / `ProgramArguments[0]`, `RunAtLoad`, `KeepAlive`, `StartInterval`, `WatchPaths`, `EnvironmentVariables`, and `stat` mtime. Red flags that need no signature check:
- a `com.apple.*` label in a user or `/Library` directory (Apple ships its own in `/System`)
- `DYLD_INSERT_LIBRARIES`, `NODE_OPTIONS`, `NODE_TLS_REJECT_UNAUTHORIZED`, proxy or CA variables in `EnvironmentVariables`
- a program that no longer exists (cleanup after an incident looks like this)

## 3. Verify the program's signature

Only for a Mach-O binary. For `/bin/sh`, `/usr/bin/env node` and similar, the payload is the script: go to step 4.

```sh
codesign -dv --verbose=2 <program>            # Authority chain, TeamIdentifier, Identifier
codesign --verify --deep --strict <program>   # exit 0 = intact
```

Get the vendor's Team ID from a binary of theirs **already on the machine**, not from memory or a web page:

```sh
codesign -dv /Applications/<Vendor>.app 2>&1 | grep TeamIdentifier
```

Decision table (matches `am-i-hacked` severities):

| Evidence | Verdict |
|---|---|
| Vendor label, valid signature, vendor Team ID | Legitimate. Close. |
| Vendor label, other Team ID or unsigned | **HIGH.** Impersonation. Preserve and escalate. |
| Signature fails `--verify` | **MEDIUM.** Modified after signing. Compare with a fresh vendor copy. |
| Unsigned or ad-hoc, in Application Support, Caches, Downloads, `/tmp`, `/Users/Shared` | **MEDIUM.** Confirm the user built or installed it. |
| Unsigned or ad-hoc elsewhere (Homebrew services, tools built from source) | INFO. Usually developer tooling. |

Known Team IDs, read from shipped binaries: Google `EQHXZ8M8AV`, Microsoft `UBF8T346G9`, Zoom `BJ4HAAB9B3`. Re-verify before you rely on one.

## 4. Read script payloads without running them

For script programs and the files beside them, including one hop (`node x.js` inside a wrapper), look for capture (`pbpaste`, `NSPasteboard`, `CGEventTap`, `screencapture`) paired with exfiltration (`api.telegram.org`, Discord/Slack webhooks, `/sendMessage`, a bot-token shape). Capture plus exfiltration is HIGH regardless of signature. Never execute a suspect script to "see what it does".

## 5. Preserve evidence before any change

```sh
mkdir -p ~/ir-evidence && cp -p <plist> ~/ir-evidence/
cp -Rp "<program's folder>" ~/ir-evidence/
shasum -a 256 <plist> <program> > ~/ir-evidence/hashes.txt
stat -f '%Sm %N' <plist> <program> >> ~/ir-evidence/hashes.txt
```

Then, with user confirmation only: `launchctl bootout gui/$(id -u)/<label>`. If capture was confirmed, treat everything copied or typed since the plist's mtime as exposed. Rotate secrets from a different, clean device.

## 6. Automate the rest

```sh
npx am-i-hacked --system --verbose      # every login item with its signer
npx am-i-being-recorded                      # capture grants (TCC) with signers
```

A reviewed exception goes in `~/.config/am-i-hacked/host-allow.txt` as `<finding id> | <reason>`. Allowed findings stay listed on every run.

## Reporting to the user

Lead with the verdict and the one fact that decides it ("GoogleUpdater, signed by Google LLC, Team ID EQHXZ8M8AV, signature valid, plist dated before the alert"). Then list what was checked, what was not (no root, no FDA, no network), and any command that caused an on-screen prompt.
