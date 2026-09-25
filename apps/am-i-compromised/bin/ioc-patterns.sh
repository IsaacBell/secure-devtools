#!/usr/bin/env bash
# bin/ioc-patterns.sh
#
# Shared indicator-of-compromise definitions, sourced by `scanner.sh` (which
# needs ripgrep glob flags) and by `safe-pull.sh` (which needs git pathspecs).
# Keeping them in one file is the point: a rule added for one tool is enforced by
# the other, and the two can never drift apart.
#
# Each pattern entry is "TITLE<TAB>REGEX", split on the first tab. Regexes use
# POSIX extended syntax, which ripgrep and `git grep -E` both accept.
#
# Context for the rules that follow the editor and asset groups: in September
# 2026 an attacker with account credentials rewrote pushed history on two
# repositories and added a `.vscode/tasks.json` that ran on folder open,
# executing JavaScript that was stored in a file named like a web font. See
# docs/2026-09-payload-injection-and-pull-guard.md.

# Every definition in this file is consumed by a sourcing script, which shellcheck
# cannot see when it lints this file on its own.
# shellcheck disable=SC2034

# --- source-level indicators ---------------------------------------------------
#
# "Encoded payload primitives" and "Child-process execution" are deliberately
# NOT in this array even though they are source-level indicators: both need a
# little more than "does this regex match the line" to stay low-noise (see
# the context-aware rules below), so scanner.sh applies them with a small
# bespoke function instead of the generic per-pattern loop. Their regexes
# still live in this file so every rule stays defined in one place.

readonly IOC_CONTENT_PATTERNS=(
	$'Dynamic code execution\t(^|[^[:alnum:]_$])(eval|Function)[[:space:]]*\\('
	$'Dynamic timer execution\t(setTimeout|setInterval)[[:space:]]*\\([[:space:]]*(["\'`][^,]*|[A-Za-z_$][A-Za-z0-9_$]*)[[:space:]]*,[[:space:]]*[0-9]+[[:space:]]*\\)'
	$'Direct network module access\t(require|import)[^;]*["\'](http|https|net|tls|dgram)["\']'
	$'Runtime global mutation\t(^|[^[:alnum:]_$])global([.]|\\[)'
	$'Computed global properties\tglobal[[:space:]]*\\[[[:space:]]*["\']'
	$'Hex or Unicode string escapes\t(\\\\x[0-9a-fA-F]{2}){4,}|(\\\\u[0-9a-fA-F]{4}){4,}'
	$'Common string-table obfuscation\t(_0x[0-9a-fA-F]{3,}|_0X[0-9A-F]{3,})'
	$'Suspicious decoder/string-table helpers\t(fromCharCode|String[.]fromCharCode)[[:space:]]*\\('
	$'Runtime source construction\t(new[[:space:]]+Function|constructor[[:space:]]*\\[[[:space:]]*["\']constructor["\']\\])'
)

# --- context-aware source rules -------------------------------------------------
#
# A regex alone over-fires on these two shapes, so scanner.sh pairs them with
# a small amount of surrounding context (see scan_encoded_payload_primitives
# and scan_child_process in scanner.sh):
#
# Encoded payload primitives — decoding/encoding a runtime value (an auth
# header, a credential pair, a buffered response) is routine. It becomes a
# signal when the result is handed to something that executes, or when the
# call is decoding a sizeable literal blob baked into the source rather than
# a value computed elsewhere.
readonly IOC_ENCODED_PRIMITIVE_TITLE="Encoded payload primitives"
readonly IOC_ENCODED_PRIMITIVE_PATTERN='(atob|btoa|Buffer[.]from|Buffer[.]alloc|Buffer[.]concat)[[:space:]]*\('
readonly IOC_EXEC_NEARBY_PATTERN='(^|[^[:alnum:]_$])(eval|Function|execSync|execFileSync|execFile|exec|spawnSync|spawn)[[:space:]]*\(|(^|[^[:alnum:]_$])vm[.][A-Za-z]+[[:space:]]*\('
readonly IOC_LONG_BASE64_LITERAL_PATTERN=$'["\'`][A-Za-z0-9+/]{40,}={0,2}["\'`]'
readonly IOC_ENCODED_PRIMITIVE_WINDOW=3

# Child-process execution — a literal, hardcoded command is the ordinary
# shape of a build/import/CLI script, and a trailing Node-style options
# object (`{ encoding: ..., stdio: ..., cwd: ... }`) is a strong tell that
# this is a deliberate, ordinary child_process call rather than a quick
# injected one-liner. It stays a signal when the command is assembled at
# runtime (a bare variable, a template with interpolation, concatenation) or
# invoked with no options object at all.
readonly IOC_CHILD_PROCESS_TITLE="Child-process execution"
readonly IOC_CHILD_PROCESS_PATTERN='(child_process|execFile|execFileSync|execSync|spawn|spawnSync|fork)[[:space:]]*\('
readonly IOC_CHILD_PROCESS_SAFE_PATTERN=$'(execFile|execFileSync|execSync|spawn|spawnSync|fork)[[:space:]]*\\([[:space:]]*["\'][^"\'`+]*["\'][[:space:]]*[,)]'
readonly IOC_CHILD_PROCESS_OPTIONS_OBJECT_PATTERN=',[[:space:]]*\{'

# --- editor/workspace configuration -------------------------------------------
#
# Auto-run is matched on the key alone so new trigger values stay covered. The
# key is quoted in JSON, so a closing quote may sit between the key and the
# colon: `"task.allowAutomaticTasks": true`.
#
# The MCP rule flags download-and-run shapes only; `uvx`, `pnpm dlx`, and `node`
# servers are legitimate and must not be flagged.

readonly IOC_EDITOR_PATTERNS=(
	$'Editor auto-run task\t"runOn"[[:space:]]*:'
	$'Editor auto-run task\tallowAutomaticTasks["\']*[[:space:]]*:[[:space:]]*true'
	$'Download-and-run command in editor config\t((curl|wget)[^"]*\\|[[:space:]]*(sh|bash)|powershell|osascript|base64[[:space:]]+-d)'
)

readonly IOC_EDITOR_GLOBS=(
	--glob '**/.vscode/*.json'
	--glob '**/.idea/tasks.json'
)

readonly IOC_EDITOR_PATHSPEC=(
	':(glob)**/.vscode/*.json'
	':(glob)**/.idea/tasks.json'
)

# --- executable payloads disguised as assets ----------------------------------
#
# These extensions are expected to hold binary or opaque data. Source-shaped
# JavaScript inside one of them is the second half of the campaign: the payload
# was named `fa-solid-400.woff2` while containing plain-text JS.

readonly IOC_ASSET_PATTERNS=(
	$'Payload hidden in an asset file\t(require|eval|Function)[[:space:]]*\\(|_0x[0-9a-fA-F]{3,}|(execSync|spawn|child_process)|atob[[:space:]]*\\('
)

readonly IOC_ASSET_GLOBS=(
	--glob '*.woff'
	--glob '*.woff2'
	--glob '*.ttf'
	--glob '*.otf'
	--glob '*.eot'
	--glob '*.png'
	--glob '*.jpg'
	--glob '*.jpeg'
	--glob '*.gif'
	--glob '*.ico'
	--glob '*.svg'
	--glob '*.pdf'
	--glob '*.mp3'
	--glob '*.mp4'
)

readonly IOC_ASSET_PATHSPEC=(
	':(glob)**/*.woff'
	':(glob)**/*.woff2'
	':(glob)**/*.ttf'
	':(glob)**/*.otf'
	':(glob)**/*.eot'
	':(glob)**/*.png'
	':(glob)**/*.jpg'
	':(glob)**/*.jpeg'
	':(glob)**/*.gif'
	':(glob)**/*.ico'
	':(glob)**/*.svg'
	':(glob)**/*.pdf'
	':(glob)**/*.mp3'
	':(glob)**/*.mp4'
)

# --- committed environment files ----------------------------------------------

readonly IOC_ENV_PATHSPEC=(
	':(glob).env'
	':(glob).env.*'
	':(glob)**/.env'
	':(glob)**/.env.*'
	':(exclude,glob)**/*.example'
)

# --- clipboard / keystroke / screen capture + exfiltration ---------------------
#
# In September 2026 a macOS LaunchAgent wrapper launched a hidden Node script
# that polled the system clipboard and forwarded every copy to a Telegram bot,
# and no source scan could find it. The source scanner knew only npm
# supply-chain indicators, so it missed the whole class. See
# docs/incidents/2026-09-clipboard-telegram-launchagent.md.
#
# A capture API on its own is routine — a clipboard manager, a screenshot tool,
# a test helper — so it is only half of the signal. scanner.sh applies these per
# file (see scan_capture_exfil): a capture signal and an exfiltration signal in
# the SAME file is HIGH. A few decisive shapes stand alone as MEDIUM: a
# hardcoded bot token, the background-launcher wrapper, a persistence writer
# beside a capture call, or a capture-shaped file name that reads the clipboard.
# Plain README/markdown mentions, files under node_modules/.cache, and a
# clipboard library that never reaches an endpoint must stay unflagged.
#
# These regexes are plain POSIX ERE fragments, matched with grep -E / ripgrep.

readonly IOC_CAPTURE_CLIPBOARD_PATTERN='pbpaste|xclip|xsel|wl-paste|Get-Clipboard|clipboardy|clipboard-event|NSPasteboard|navigator\.clipboard\.readText|clipboard\.readText|pyperclip'
readonly IOC_CAPTURE_INPUT_PATTERN='CGEventTap|pynput|iohook|node-global-key-listener|keylogger|screencapture|screenshot-desktop|pyautogui\.screenshot'
readonly IOC_CAPTURE_TITLE="Clipboard/keystroke/screen capture with remote exfiltration"
readonly IOC_EXFIL_PATTERN='api\.telegram\.org|/sendMessage|/sendDocument|node-telegram-bot-api|telegraf|[0-9]{8,10}:[A-Za-z0-9_-]{35}|discord(app)?\.com/api/webhooks|hooks\.slack\.com/services|webhook\.site|pastebin\.com/api|transfer\.sh|ngrok|(^|[^[:alnum:]_])(nc|ncat)[[:space:]][^|;&<>]*[0-9]{2,5}([[:space:]]|$)'
readonly IOC_TELEGRAM_TOKEN_PATTERN='[0-9]{8,10}:[A-Za-z0-9_-]{35}'
readonly IOC_TELEGRAM_TOKEN_TITLE="Telegram bot token literal"
readonly IOC_PERSISTENCE_PATTERN='launchctl[[:space:]]+load|Library/LaunchAgents|crontab[[:space:]]+-|\.config/autostart'
readonly IOC_PERSISTENCE_CAPTURE_TITLE="Persistence installed by a script that captures input"
readonly IOC_CAPTURE_FILENAME_PATTERN='(clip|key|screen)[-_ ]?(logger|monitor|spy|grab)'
readonly IOC_CAPTURE_FILENAME_TITLE="Capture-named script reads the clipboard or input"
readonly IOC_WRAPPER_BG_PATTERN='nohup[[:space:]].*node[[:space:]].*\.js.*>>.*&'
readonly IOC_WRAPPER_PIDFILE_PATTERN='[A-Za-z0-9_.-]+\.pid'
readonly IOC_WRAPPER_TITLE="Background node launcher with a pid-file lock"
readonly IOC_WRAPPER_PAYLOAD_TITLE="Background node launcher wraps a capture-and-exfiltrate payload"

# Files a capture signal can live in: the capture-relevant source extensions,
# plus (added at scan time) extensionless scripts with a shebang. See
# IOC_CAPTURE_EXT_GLOBS and the second pass in scan_capture_exfil.
readonly IOC_CAPTURE_EXT_GLOBS=(
	--glob '*.js'
	--glob '*.mjs'
	--glob '*.cjs'
	--glob '*.ts'
	--glob '*.py'
	--glob '*.sh'
	--glob '*.zsh'
	--glob '*.bash'
	--glob '*.rb'
	--glob '*.swift'
	--glob '*.plist'
)

# Split a "TITLE<TAB>REGEX" entry into IOC_TITLE and IOC_PATTERN.
split_ioc_entry() {
	local entry="$1"
	IOC_TITLE="${entry%%$'\t'*}"
	IOC_PATTERN="${entry#*$'\t'}"
}
