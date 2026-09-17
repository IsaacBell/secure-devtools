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

readonly IOC_CONTENT_PATTERNS=(
	$'Dynamic code execution\t(^|[^[:alnum:]_$])(eval|Function)[[:space:]]*\\('
	$'Dynamic timer execution\t(setTimeout|setInterval)[[:space:]]*\\([^,]+,[[:space:]]*[0-9]+[[:space:]]*\\)'
	$'Child-process execution\t(child_process|execFile|execFileSync|execSync|spawn|spawnSync|fork)[[:space:]]*\\('
	$'Direct network module access\t(require|import)[^;]*["\'](http|https|net|tls|dgram)["\']'
	$'Runtime global mutation\t(^|[^[:alnum:]_$])global([.]|\\[)'
	$'Encoded payload primitives\t(atob|btoa|Buffer[.]from|Buffer[.]alloc|Buffer[.]concat)[[:space:]]*\\('
	$'Computed global properties\tglobal[[:space:]]*\\[[[:space:]]*["\']'
	$'Hex or Unicode string escapes\t\\\\x[0-9a-fA-F]{2}|\\\\u[0-9a-fA-F]{4}'
	$'Common string-table obfuscation\t(_0x[0-9a-fA-F]{3,}|_0X[0-9A-F]{3,})'
	$'Suspicious decoder/string-table helpers\t(charCodeAt|fromCharCode|String[.]fromCharCode)[[:space:]]*\\('
	$'Runtime source construction\t(new[[:space:]]+Function|constructor[[:space:]]*\\[[[:space:]]*["\']constructor["\']\\])'
)

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

# Split a "TITLE<TAB>REGEX" entry into IOC_TITLE and IOC_PATTERN.
split_ioc_entry() {
	local entry="$1"
	IOC_TITLE="${entry%%$'\t'*}"
	IOC_PATTERN="${entry#*$'\t'}"
}
