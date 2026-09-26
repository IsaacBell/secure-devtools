#!/usr/bin/env bash
set -euo pipefail

# Development security gate.
#
# This script is intentionally conservative. It is not a malware scanner and
# cannot prove that a repository is safe. Its purpose is to catch source-level
# indicators that should prevent a development server from starting.
#
# The checks focus on combinations of:
#   - dynamic code execution
#   - child-process creation
#   - direct network access
#   - runtime global mutation
#   - encoded or obfuscated payloads
#   - unusually large source lines
#   - clipboard/keystroke/screen capture paired with an exfiltration endpoint
#     (and the decisive single signals: a hardcoded bot token, the background
#     launcher, or a persistence writer beside a capture call)
#   - editor/workspace settings that execute code on folder open
#   - executable payloads disguised as binary asset files
#   - environment files committed to the git index
#
# Report model: each unique `file:line` is reported once, with the distinct
# indicator categories that matched it. Match snippets are width-capped so a
# single minified line can never flood the report. Colors are used only when
# stdout is a TTY (set NO_COLOR to force plain output).
#
# Keep known-malicious fixtures outside the trusted source tree rather than
# suppressing findings with comments in the source itself.
#
# A line already reviewed and confirmed safe can be marked with a comment
# carrying a required reason, on the finding's own line or the line before:
#
#   // am-i-compromised-ignore: ANSI color code, not an obfuscated payload
#
# Suppressed findings are never dropped silently: they are still counted and
# listed in their own section of the report, on every run, including a clean
# one. This marker is honored here only. safe-pull.sh deliberately does not
# read it — it inspects commits nobody has reviewed yet, so a marker written
# by whoever authored the incoming diff must not be able to wave off their
# own payload.

# `am-i-compromised host` audits this machine (persistence, shell startup files,
# AI-tool configuration, running processes) instead of a source tree. It needs no
# ripgrep, so it dispatches before the ripgrep check below.
if [[ "${1:-}" == "host" ]]; then
	shift
	exec bash "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/host-audit.sh" "$@"
fi

# The source scan uses associative arrays, which need bash 4+. macOS ships 3.2 as
# /bin/bash, so look for a newer bash and re-run under it, or say what to install.
if ((BASH_VERSINFO[0] < 4)); then
	for newer_bash in /opt/homebrew/bin/bash /usr/local/bin/bash /opt/local/bin/bash /home/linuxbrew/.linuxbrew/bin/bash; do
		if [[ -x "$newer_bash" ]] && "$newer_bash" -c '((BASH_VERSINFO[0] >= 4))' 2>/dev/null; then
			exec "$newer_bash" "${BASH_SOURCE[0]}" "$@"
		fi
	done
	echo "scanner: bash 4 or newer is required (this is bash ${BASH_VERSION%%(*})." >&2
	echo "scanner: install it (e.g. brew install bash), or run 'am-i-compromised host', which works on bash 3.2." >&2
	exit 1
fi

if ! command -v rg >/dev/null 2>&1; then
	echo "scanner: ripgrep (rg) is required but was not found on PATH." >&2
	echo "scanner: install it (e.g. brew install ripgrep, apt-get install ripgrep)." >&2
	exit 1
fi

ARG_ROOT="${1:-.}"

if [[ ! -d "$ARG_ROOT" ]]; then
	echo "scanner: '$ARG_ROOT' is not a directory" >&2
	echo "usage: scanner [<directory>]  (defaults to the current directory)" >&2
	exit 2
fi

ROOT="$(cd "$ARG_ROOT" && pwd)"

readonly MAX_SOURCE_LINE_LENGTH=4000
readonly MAX_SNIPPET=240
readonly MAX_FINDINGS=100

readonly SOURCE_GLOBS=(
	--glob '*.js'
	--glob '*.jsx'
	--glob '*.mjs'
	--glob '*.cjs'
	--glob '*.mts'
	--glob '*.cts'
	--glob '*.ts'
	--glob '*.tsx'
	--glob '*.py'
	--glob '*.rs'
	--glob '*.rb'
	--glob '*.c'
	--glob '*.h'
	--glob '*.cs'
	--glob '*.cpp'
)

EXCLUDE_GLOBS=(
	--glob '!**/node_modules/**'
	--glob '!**/.git/**'
	--glob '!**/.next/**'
	--glob '!**/.turbo/**'
	--glob '!**/dist/**'
	--glob '!**/build/**'
	--glob '!**/coverage/**'
	--glob '!**/out/**'
	--glob '!**/.cache/**'
)

readonly FIXTURES_DIRNAME="__security_gate_fixtures__"

# Indicator definitions live in one file, shared with safe-pull.sh.
# shellcheck source=bin/ioc-patterns.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ioc-patterns.sh"

# INCLUDE_FIXTURES=1 disables the fixtures-dir exclusion so the fixtures
# themselves can be scanned as a self-test of the detection logic. Default
# behavior (unset/0) excludes the fixtures dir, since it deliberately
# contains malicious samples that should never gate a real dev server run.
if [[ "${INCLUDE_FIXTURES:-0}" != "1" ]]; then
	EXCLUDE_GLOBS+=(
		--glob "!**/${FIXTURES_DIRNAME}/**"
	)
fi
readonly EXCLUDE_GLOBS

# --- color ---------------------------------------------------------------------

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
	C_BOLD=$'\033[1m'
	C_DIM=$'\033[2m'
	C_RED=$'\033[31m'
	C_GREEN=$'\033[32m'
	C_YELLOW=$'\033[33m'
	C_RESET=$'\033[0m'
else
	C_BOLD=""
	C_DIM=""
	C_RED=""
	C_GREEN=""
	C_YELLOW=""
	C_RESET=""
fi

# --- findings store -------------------------------------------------------------
#
# Every unique `path|line` is stored once (findings[]), along with the first
# snippet seen for it and the union of indicator categories that matched.

declare -a F_PATH=()
declare -a F_SNIP=()
declare -a F_TAGS=()
declare -A F_IDX=()
declare -A F_FILE_SEEN=()

# Suspicious package.json scripts are stored separately: a script entry has no
# meaningful source line, and we want each flagged script to stay distinct.
declare -a S_PATH=()
declare -a S_NAME=()
declare -a S_VAL=()

# Findings suppressed by an `am-i-compromised-ignore:` comment. Kept apart
# from F_* so the suppressed count can never quietly merge into (or vanish
# from) the real total — see suppression_reason() and render_suppressed().
declare -a SUP_PATH=()
declare -a SUP_SNIP=()
declare -a SUP_TAGS=()
declare -a SUP_REASON=()
declare -A SUP_IDX=()

# Set to 1 when package.json inspection could not run (jq missing).
missing_jq=0

# Cap a snippet so one enormous minified line cannot flood the report.
# Runs of whitespace are collapsed (preview only) so deeply indented or
# space-padded lines stay readable. Prints the snippet plus an overflow
# marker to stdout. The marker reflects the real source length.
cap_snippet() {
	local snippet="$1"
	local n="${#snippet}"
	local collapsed

	if ((n > MAX_SNIPPET)); then
		collapsed="$(printf '%s\n' "$snippet" | sed -E 's/[[:space:]]+/ /g')"
		printf '%s... (+%d more chars)' "${collapsed:0:MAX_SNIPPET}" "$((n - MAX_SNIPPET))"
	else
		printf '%s' "$snippet"
	fi
}

# --- suppression -----------------------------------------------------------
#
# A comment carrying `am-i-compromised-ignore: <reason>` on the finding's own
# line, or the line immediately before it, marks that finding reviewed and
# safe. The reason is required: a marker with nothing (or only whitespace)
# after the colon does not suppress anything, so an empty "make it go away"
# comment cannot silently defeat the gate. The marker is recognized as plain
# text anywhere on the candidate line — it does not need to sit inside a
# language-specific comment syntax, since the source files this scanner reads
# span half a dozen languages and the marker text itself is distinctive
# enough not to appear by accident.
readonly SUPPRESS_MARKER_RE='am-i-compromised-ignore:[[:space:]]*(.+)$'

# suppression_reason <path> <line> — on stdout, the trimmed reason text if
# `path` carries a valid marker on `line` or `line - 1`; exit status 0. No
# output and exit status 1 otherwise. Checks the finding's own line first.
suppression_reason() {
	local path="$1"
	local line="$2"
	local prev=$((line > 1 ? line - 1 : 0))
	local candidate reason

	[[ -f "$path" ]] || return 1

	# No `--` before the path: BSD sed (macOS) does not understand it as an
	# end-of-options marker and treats it as a filename, which fails and
	# trips set -e on the enclosing assignment. Safe without it: $path is
	# always the absolute $ROOT-rooted path built earlier in this script,
	# never a string that could be mistaken for an option.
	for candidate in \
		"$(sed -n "${line}p" "$path" 2>/dev/null)" \
		"$( ((prev > 0)) && sed -n "${prev}p" "$path" 2>/dev/null)"; do
		if [[ "$candidate" =~ $SUPPRESS_MARKER_RE ]]; then
			reason="${BASH_REMATCH[1]}"
			reason="${reason#"${reason%%[![:space:]]*}"}"
			reason="${reason%"${reason##*[![:space:]]}"}"
			if [[ -n "$reason" ]]; then
				printf '%s' "$reason"
				return 0
			fi
		fi
	done

	return 1
}

# Record one finding for path:line under an indicator category. A suppressed
# finding is rerouted into the SUP_* store instead of F_*: it never counts
# toward the exit code, but it is never dropped either.
record_finding() {
	local path="$1"
	local line="$2"
	local snippet="$3"
	local tag="$4"
	local pathrel pad key i trimmed reason

	pathrel="${path#"$ROOT"/}"
	if [[ -z "$pathrel" || "$pathrel" == "$path" ]]; then
		pathrel="$(basename "$path")"
	fi

	# Trim leading whitespace so heavily indented code does not eat the cap.
	trimmed="${snippet#"${snippet%%[![:space:]]*}"}"
	snippet="$(cap_snippet "$trimmed")"

	pad="$(printf '%08d' "$line")"
	key="${pathrel}|${pad}"

	if reason="$(suppression_reason "$path" "$line")"; then
		if [[ -v SUP_IDX[$key] ]]; then
			i="${SUP_IDX[$key]}"
			if [[ "${SUP_TAGS[i]}" != *"$tag"* ]]; then
				SUP_TAGS[i]+=", $tag"
			fi
		else
			SUP_IDX[$key]="${#SUP_PATH[@]}"
			SUP_PATH+=("$pathrel")
			SUP_SNIP+=("$snippet")
			SUP_TAGS+=("$tag")
			SUP_REASON+=("$reason")
		fi
		return
	fi

	if [[ -v F_IDX[$key] ]]; then
		i="${F_IDX[$key]}"
		if [[ "${F_TAGS[i]}" != *"$tag"* ]]; then
			F_TAGS[i]+=", $tag"
		fi
	else
		F_IDX[$key]="${#F_PATH[@]}"
		F_PATH+=("$pathrel")
		F_SNIP+=("$snippet")
		F_TAGS+=("$tag")
		F_FILE_SEEN[$pathrel]=1
	fi
}

# Split an rg `path:line:content` row into its parts (globals: P_PATH, P_LINE,
# P_SNIP). Column paths are rare on macOS/Linux, so splitting on the first two
# colons is safe enough and keeps awk out of the common path.
split_rg_row() {
	local row="$1"
	P_PATH="${row%%:*}"
	P_SNIP="${row#*:}"
	P_LINE="${P_SNIP%%:*}"
	P_SNIP="${P_SNIP#*:}"
}

scan_pattern() {
	local title="$1"
	local pattern="$2"
	local row

	while IFS= read -r row; do
		[[ -n "$row" ]] || continue
		split_rg_row "$row"
		record_finding "$P_PATH" "$P_LINE" "$P_SNIP" "$title"
	done < <(
		rg -n \
			--no-heading \
			--color never \
			"${SOURCE_GLOBS[@]}" \
			"${EXCLUDE_GLOBS[@]}" \
			"$pattern" \
			-- "$ROOT" 2>/dev/null || true
	)
}

# atob/btoa/Buffer.from/Buffer.alloc/Buffer.concat are routine on their own —
# decoding a header, encoding a credential pair, reading buffered output as
# utf8. They only get flagged when the match line (or a small window around
# it) also reaches for something that executes, or when the call is decoding
# a sizeable literal blob rather than a runtime value. See IOC_ENCODED_* in
# ioc-patterns.sh for the three regexes this combines.
scan_encoded_payload_primitives() {
	local row window_text start end

	while IFS= read -r row; do
		[[ -n "$row" ]] || continue
		split_rg_row "$row"

		if [[ "$P_SNIP" =~ $IOC_EXEC_NEARBY_PATTERN || "$P_SNIP" =~ $IOC_LONG_BASE64_LITERAL_PATTERN ]]; then
			record_finding "$P_PATH" "$P_LINE" "$P_SNIP" "$IOC_ENCODED_PRIMITIVE_TITLE"
			continue
		fi

		start=$((P_LINE > IOC_ENCODED_PRIMITIVE_WINDOW ? P_LINE - IOC_ENCODED_PRIMITIVE_WINDOW : 1))
		end=$((P_LINE + IOC_ENCODED_PRIMITIVE_WINDOW))
		# No `--`: see the note in suppression_reason(); $P_PATH is always
		# absolute here too.
		window_text="$(sed -n "${start},${end}p" "$P_PATH" 2>/dev/null)"
		if [[ "$window_text" =~ $IOC_EXEC_NEARBY_PATTERN ]]; then
			record_finding "$P_PATH" "$P_LINE" "$P_SNIP" "$IOC_ENCODED_PRIMITIVE_TITLE"
		fi
	done < <(
		rg -n \
			--no-heading \
			--color never \
			"${SOURCE_GLOBS[@]}" \
			"${EXCLUDE_GLOBS[@]}" \
			"$IOC_ENCODED_PRIMITIVE_PATTERN" \
			-- "$ROOT" 2>/dev/null || true
	)
}

# execFile/execFileSync/execSync/spawn/spawnSync/fork with a literal command
# and a trailing Node-style options object is the ordinary shape of a
# build/import/CLI script. It stays a signal when the command is assembled at
# runtime (a bare variable, a template with interpolation, concatenation) or
# invoked with no options object at all. See IOC_CHILD_PROCESS_* in
# ioc-patterns.sh.
scan_child_process() {
	local row safe

	while IFS= read -r row; do
		[[ -n "$row" ]] || continue
		split_rg_row "$row"

		safe=0
		if [[ "$P_SNIP" =~ $IOC_CHILD_PROCESS_SAFE_PATTERN && "$P_SNIP" =~ $IOC_CHILD_PROCESS_OPTIONS_OBJECT_PATTERN ]]; then
			safe=1
		fi
		((safe == 1)) || record_finding "$P_PATH" "$P_LINE" "$P_SNIP" "$IOC_CHILD_PROCESS_TITLE"
	done < <(
		rg -n \
			--no-heading \
			--color never \
			"${SOURCE_GLOBS[@]}" \
			"${EXCLUDE_GLOBS[@]}" \
			"$IOC_CHILD_PROCESS_PATTERN" \
			-- "$ROOT" 2>/dev/null || true
	)
}

# --- clipboard / keystroke / screen capture + exfiltration ---------------------
#
# A capture API on its own is ordinary — a clipboard manager, a screenshot tool,
# a test helper — so detection is file-level rather than line-level: a file is
# reported when it both reads the clipboard or input and reaches an exfiltration
# endpoint, or when it carries one of a few decisive single signals. See
# IOC_CAPTURE_* / IOC_EXFIL_* in ioc-patterns.sh.

# file_matches <file> <ere> — true when the file matches the extended regex.
file_matches() {
	local file="$1"
	local pattern="$2"

	grep -aEq -- "$pattern" "$file" 2>/dev/null
}

# file_has_capture <file> — true when the file reads the clipboard or captures
# keystrokes/screen.
file_has_capture() {
	file_matches "$1" "$IOC_CAPTURE_CLIPBOARD_PATTERN" ||
		file_matches "$1" "$IOC_CAPTURE_INPUT_PATTERN"
}

# first_match_line <file> <ere> — the first matching line number, or nothing.
first_match_line() {
	local file="$1"
	local pattern="$2"

	grep -anE -- "$pattern" "$file" 2>/dev/null | head -n 1 | cut -d: -f1 || true
}

# source_line <file> <line> — that line's text, for the finding snippet.
source_line() {
	sed -n "${2}p" "$1" 2>/dev/null || true
}

# is_shell_script <file> — a .sh/.bash/.zsh file, or a shebang script whose
# interpreter is a shell. Only a shell script can be the background launcher.
is_shell_script() {
	local file="$1"
	local first

	case "$file" in
	*.sh | *.bash | *.zsh) return 0 ;;
	esac
	first="$(head -n 1 "$file" 2>/dev/null || true)"
	[[ "$first" == '#!'* ]] || return 1
	[[ "$first" =~ (sh|bash|zsh) ]]
}

scan_capture_exfil() {
	local files=() file base capture_line token_line persist_line bgline js jsfile
	local first reported

	# Candidate files: the capture-relevant source extensions, plus extensionless
	# scripts with a shebang. rg --files honors EXCLUDE_GLOBS (node_modules,
	# build output, the fixtures dir), and the two passes are disjoint, so no file
	# is examined twice.
	while IFS= read -r -d '' file; do
		files+=("$file")
	done < <(
		rg --files --null "${IOC_CAPTURE_EXT_GLOBS[@]}" "${EXCLUDE_GLOBS[@]}" -- "$ROOT" 2>/dev/null || true
	)
	while IFS= read -r -d '' file; do
		first="$(head -n 1 "$file" 2>/dev/null || true)"
		if [[ "$first" == '#!'* ]]; then
			files+=("$file")
		fi
	done < <(
		rg --files --null --glob '!*.*' "${EXCLUDE_GLOBS[@]}" -- "$ROOT" 2>/dev/null || true
	)

	((${#files[@]} > 0)) || return 0

	for file in "${files[@]}"; do
		base="$(basename "$file")"
		capture_line="$(first_match_line "$file" "$IOC_CAPTURE_CLIPBOARD_PATTERN")"
		[[ -n "$capture_line" ]] || capture_line="$(first_match_line "$file" "$IOC_CAPTURE_INPUT_PATTERN")"

		reported=0

		# The incident shape: capture and exfiltration in the same file.
		if [[ -n "$capture_line" ]] && file_matches "$file" "$IOC_EXFIL_PATTERN"; then
			record_finding "$file" "$capture_line" "$(source_line "$file" "$capture_line")" "$IOC_CAPTURE_TITLE"
			reported=1
		fi

		# A hardcoded Telegram bot token stands alone, even with no capture code.
		if ((reported == 0)); then
			token_line="$(first_match_line "$file" "$IOC_TELEGRAM_TOKEN_PATTERN")"
			if [[ -n "$token_line" ]]; then
				record_finding "$file" "$token_line" "$(source_line "$file" "$token_line")" "$IOC_TELEGRAM_TOKEN_TITLE"
				reported=1
			fi
		fi

		# The wrapper from the incident: a shell script that backgrounds a Node
		# payload behind a pid-file lock. HIGH when the named payload beside it
		# itself captures and exfiltrates, MEDIUM otherwise.
		if is_shell_script "$file" &&
			file_matches "$file" "$IOC_WRAPPER_BG_PATTERN" &&
			file_matches "$file" "$IOC_WRAPPER_PIDFILE_PATTERN"; then
			bgline="$(first_match_line "$file" "$IOC_WRAPPER_BG_PATTERN")"
			js="$(source_line "$file" "$bgline" | grep -oE '[A-Za-z0-9_./-]+\.js' | head -n 1 || true)"
			jsfile=""
			if [[ -n "$js" ]]; then
				jsfile="$(dirname "$file")/$(basename "$js")"
			fi
			if [[ -n "$jsfile" && -f "$jsfile" ]] && file_has_capture "$jsfile" && file_matches "$jsfile" "$IOC_EXFIL_PATTERN"; then
				record_finding "$file" "$bgline" "$(source_line "$file" "$bgline")" "$IOC_WRAPPER_PAYLOAD_TITLE"
			elif [[ -n "$bgline" ]]; then
				record_finding "$file" "$bgline" "$(source_line "$file" "$bgline")" "$IOC_WRAPPER_TITLE"
			fi
		fi

		if ((reported == 1)); then
			continue
		fi

		# Persistence written by a script that also reads the clipboard or input.
		if [[ -n "$capture_line" ]] && file_matches "$file" "$IOC_PERSISTENCE_PATTERN"; then
			persist_line="$(first_match_line "$file" "$IOC_PERSISTENCE_PATTERN")"
			record_finding "$file" "$persist_line" "$(source_line "$file" "$persist_line")" "$IOC_PERSISTENCE_CAPTURE_TITLE"
			continue
		fi

		# A capture-shaped file name that reads the clipboard or input.
		if [[ -n "$capture_line" ]] && printf '%s' "$base" | grep -Eiq -- "$IOC_CAPTURE_FILENAME_PATTERN"; then
			record_finding "$file" "$capture_line" "$(source_line "$file" "$capture_line")" "$IOC_CAPTURE_FILENAME_TITLE"
		fi
	done
}

# scan_with_globs <title> <pattern> <glob...>
#
# Same contract as scan_pattern, but scoped to an explicit glob set rather than
# the source-file globs. `--text` makes ripgrep read files it would otherwise
# skip as binary, and `--hidden` makes it descend into dot-directories such as
# `.vscode` — both are required for the editor-config and asset checks.
scan_with_globs() {
	local title="$1"
	local pattern="$2"
	shift 2
	local row

	while IFS= read -r row; do
		[[ -n "$row" ]] || continue
		split_rg_row "$row"
		record_finding "$P_PATH" "$P_LINE" "$P_SNIP" "$title"
	done < <(
		rg -n \
			--no-heading \
			--color never \
			--text \
			--hidden \
			"$@" \
			"${EXCLUDE_GLOBS[@]}" \
			"$pattern" \
			-- "$ROOT" 2>/dev/null || true
	)
}

scan_long_lines() {
	local row content length

	while IFS= read -r row; do
		[[ -n "$row" ]] || continue

		# Strip rg's "file:line:" prefix before measuring the source line
		# itself. This makes MAX_SOURCE_LINE_LENGTH apply to the actual
		# source content. Reuse split_rg_row to get path/line/snippet.
		content="${row#*:}"
		content="${content#*:}"
		length="${#content}"

		if ((length > MAX_SOURCE_LINE_LENGTH)); then
			split_rg_row "$row"
			record_finding "$P_PATH" "$P_LINE" "$P_SNIP" "source line exceeds ${MAX_SOURCE_LINE_LENGTH} characters"
		fi
	done < <(
		rg -n \
			--no-heading \
			--color never \
			"${SOURCE_GLOBS[@]}" \
			"${EXCLUDE_GLOBS[@]}" \
			-- '.' "$ROOT" 2>/dev/null || true
	)
}

scan_package_scripts() {
	local package_files=()
	local file pathrel entry script_name script_value

	while IFS= read -r -d '' file; do
		package_files+=("$file")
	done < <(
		find "$ROOT" \
			-type f \
			-name 'package.json' \
			-not -path '*/node_modules/*' \
			-not -path '*/.git/*' \
			-print0
	)

	if ((${#package_files[@]} == 0)); then
		return
	fi

	if ! command -v jq >/dev/null 2>&1; then
		missing_jq=1
		return
	fi

	for file in "${package_files[@]}"; do
		pathrel="${file#"$ROOT"/}"
		[[ -n "$pathrel" ]] || pathrel="$(basename "$file")"

		while IFS= read -r entry; do
			[[ -n "$entry" ]] || continue
			script_name="${entry%%:*}"
			script_value="${entry#*:}"
			script_value="${script_value#"${script_value%%[![:space:]]*}"}"
			S_PATH+=("$pathrel")
			S_NAME+=("$script_name")
			S_VAL+=("$(cap_snippet "$script_value")")
			F_FILE_SEEN[$pathrel]=1
		done < <(
			jq -r '
				.scripts // {} |
				to_entries[] |
				select(
					.value |
					test(
						"curl|wget|powershell|child_process|node[[:space:]]+-e|base64|eval";
						"i"
					)
				) |
				"\(.key): \(.value)"
			' "$file" 2>/dev/null || true
		)
	done
}

render_findings() {
	local total_files="${#F_FILE_SEEN[@]}"
	local total_findings=$((${#F_PATH[@]} + ${#S_PATH[@]}))
	local sorted key path line snippet tags i count=0 num

	if ((total_findings == 0)); then
		return 0
	fi

	# Sort findings by (path, line). Lines are zero-padded in the key so a
	# plain byte sort yields numeric line order.
	sorted=()
	if ((${#F_IDX[@]} > 0)); then
		mapfile -t sorted < <(
			printf '%s\n' "${!F_IDX[@]}" | LC_ALL=C sort -t'|' -k1,1 -k2,2
		)
	fi

	local finding_word="finding"
	local file_word="file"
	if ((total_findings != 1)); then
		finding_word="findings"
	fi
	if ((total_files != 1)); then
		file_word="files"
	fi

	printf '\n%ssecurity-gate: FAILED — %d %s across %d %s%s\n' \
		"$C_RED" "$total_findings" "$finding_word" "$total_files" "$file_word" "$C_RESET"

	for key in "${sorted[@]}"; do
		if ((count == MAX_FINDINGS)); then
			printf '%s... (truncated: %s more findings not shown)%s\n' "$C_DIM" \
				"$((total_findings - count))" "$C_RESET"
			break
		fi

		i="${F_IDX[$key]}"
		path="${F_PATH[$i]}"
		num="${key##*|}"
		num="$((10#$num))"
		snippet="${F_SNIP[$i]}"
		tags="${F_TAGS[$i]}"

		printf '%s\n' ""
		printf '  %s%s:%d%s\n' "$C_BOLD" "$path" "$num" "$C_RESET"
		printf '    %s\n' "$snippet"
		printf '    %s→ %s%s\n' "$C_DIM" "$tags" "$C_RESET"

		count=$((count + 1))
	done

	# Suspicious package.json scripts (rare, always shown).
	for ((i = 0; i < ${#S_PATH[@]}; i++)); do
		printf '%s\n' ""
		printf '  %s%s:%s (script)%s\n' "$C_BOLD" "${S_PATH[$i]}" "${S_NAME[$i]}" "$C_RESET"
		printf '    %s\n' "${S_VAL[$i]}"
		printf '    %s→ suspicious package script%s\n' "$C_DIM" "$C_RESET"
	done

	return 1
}

# Findings suppressed by an `am-i-compromised-ignore:` comment. Shown on
# every run that has any — a FAILED run, and a PASSED one too — so a
# suppression can never quietly disappear from view.
render_suppressed() {
	local n="${#SUP_PATH[@]}"
	local word="finding"
	local sorted key i path num

	((n > 0)) || return 0
	((n == 1)) || word="findings"

	printf '\n%ssecurity-gate: %d %s suppressed by inline comment%s\n' \
		"$C_YELLOW" "$n" "$word" "$C_RESET"

	mapfile -t sorted < <(
		printf '%s\n' "${!SUP_IDX[@]}" | LC_ALL=C sort -t'|' -k1,1 -k2,2
	)

	for key in "${sorted[@]}"; do
		i="${SUP_IDX[$key]}"
		path="${SUP_PATH[$i]}"
		num="${key##*|}"
		num="$((10#$num))"

		printf '%s\n' ""
		printf '  %s%s:%d%s\n' "$C_DIM" "$path" "$num" "$C_RESET"
		printf '    %s\n' "${SUP_SNIP[$i]}"
		printf '    %s→ %s (suppressed)%s\n' "$C_DIM" "${SUP_TAGS[$i]}" "$C_RESET"
		printf '    %sreason: %s%s\n' "$C_DIM" "${SUP_REASON[$i]}" "$C_RESET"
	done
}

# Flag environment files that are present in the git index. An untracked local
# `.env` is normal and is never flagged; a committed one is an incident, because
# it is what the injected `dotenv` + `node-fetch` pair exists to read and send.
scan_tracked_env() {
	local file

	while IFS= read -r file; do
		[[ -n "$file" ]] || continue
		if [[ "$file" == *"${FIXTURES_DIRNAME}/"* && "${INCLUDE_FIXTURES:-0}" != "1" ]]; then
			continue
		fi
		record_finding "$ROOT/$file" 1 "$file (present in the git index)" "Tracked .env file"
	done < <(git -C "$ROOT" ls-files -- "${IOC_ENV_PATHSPEC[@]}" 2>/dev/null || true)
}

while IFS= read -r entry; do
	[[ -n "$entry" ]] || continue
	split_ioc_entry "$entry"
	scan_pattern "$IOC_TITLE" "$IOC_PATTERN"
done < <(printf '%s\n' "${IOC_CONTENT_PATTERNS[@]}")

scan_encoded_payload_primitives
scan_child_process

while IFS= read -r entry; do
	[[ -n "$entry" ]] || continue
	split_ioc_entry "$entry"
	scan_with_globs "$IOC_TITLE" "$IOC_PATTERN" "${IOC_EDITOR_GLOBS[@]}"
done < <(printf '%s\n' "${IOC_EDITOR_PATTERNS[@]}")

while IFS= read -r entry; do
	[[ -n "$entry" ]] || continue
	split_ioc_entry "$entry"
	scan_with_globs "$IOC_TITLE" "$IOC_PATTERN" "${IOC_ASSET_GLOBS[@]}"
done < <(printf '%s\n' "${IOC_ASSET_PATTERNS[@]}")

scan_capture_exfil
scan_long_lines
scan_tracked_env
scan_package_scripts

if ((${#F_PATH[@]} > 0 || ${#S_PATH[@]} > 0)); then
	# render_findings ends with `return 1` (there were findings) even though
	# nothing here reads that status — under `set -e` a bare call would abort
	# the script right here, silently skipping render_suppressed and the
	# footer below. `|| true` keeps that return value from being anything
	# other than documentation.
	render_findings || true
	render_suppressed || true

	if ((missing_jq == 1)); then
		printf '\n%ssecurity-gate: %s could not inspect package.json scripts (jq missing).%s\n' \
			"$C_YELLOW" "warning:" "$C_RESET"
	fi

	cat <<'EOF'

Review each flagged location above before starting the dev server. If a
finding is a real false positive, mark it reviewed instead of reflexively
rewriting working code:

  // am-i-compromised-ignore: <why this is safe>

on the flagged line or the line before it — the reason is required.
Suppressions are never silent: they are counted and listed above on every
run, including a clean one.

This scanner is a heuristic pre-flight check. A clean result does not prove
that the repository or its dependencies are safe.
EOF

	exit 1
fi

render_suppressed || true

if ((missing_jq == 1)); then
	printf '\n%ssecurity-gate: %s could not inspect package.json scripts (jq missing).%s\n' \
		"$C_YELLOW" "warning:" "$C_RESET"
	cat <<'EOF'

Install jq and run the security gate again. The gate stays closed until
package.json scripts can be checked.
EOF

	exit 1
fi

if ((${#SUP_PATH[@]} > 0)); then
	printf '%ssecurity-gate: PASSED%s — no indicators found (%d suppressed; scanned: %s)\n' \
		"$C_GREEN" "$C_RESET" "${#SUP_PATH[@]}" "$ARG_ROOT"
else
	echo "${C_GREEN}security-gate: PASSED${C_RESET} — no indicators found (scanned: ${ARG_ROOT})"
fi
exit 0
