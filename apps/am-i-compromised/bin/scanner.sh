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
#
# Report model: each unique `file:line` is reported once, with the distinct
# indicator categories that matched it. Match snippets are width-capped so a
# single minified line can never flood the report. Colors are used only when
# stdout is a TTY (set NO_COLOR to force plain output).
#
# Keep known-malicious fixtures outside the trusted source tree rather than
# suppressing findings with comments in the source itself.

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

# Record one finding for path:line under an indicator category.
record_finding() {
	local path="$1"
	local line="$2"
	local snippet="$3"
	local tag="$4"
	local pathrel pad key i trimmed

	pathrel="${path#"$ROOT"/}"
	if [[ -z "$pathrel" || "$pathrel" == "$path" ]]; then
		pathrel="$(basename "$path")"
	fi

	# Trim leading whitespace so heavily indented code does not eat the cap.
	trimmed="${snippet#"${snippet%%[![:space:]]*}"}"
	snippet="$(cap_snippet "$trimmed")"

	pad="$(printf '%08d' "$line")"
	key="${pathrel}|${pad}"

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

scan_pattern \
	"Dynamic code execution" \
	'(^|[^[:alnum:]_$])(eval|Function)[[:space:]]*\('

scan_pattern \
	"Dynamic timer execution" \
	'(setTimeout|setInterval)[[:space:]]*\([^,]+,[[:space:]]*[0-9]+[[:space:]]*\)'

scan_pattern \
	"Child-process execution" \
	'(child_process|execFile|execFileSync|execSync|spawn|spawnSync|fork)[[:space:]]*\('

scan_pattern \
	"Direct network module access" \
	'(require|import)[^;]*["'\''](http|https|net|tls|dgram)["'\'']'

scan_pattern \
	"Runtime global mutation" \
	'(^|[^[:alnum:]_$])global([.]|\[)'

scan_pattern \
	"Encoded payload primitives" \
	'(atob|btoa|Buffer[.]from|Buffer[.]alloc|Buffer[.]concat)[[:space:]]*\('

scan_pattern \
	"Computed global properties" \
	'global[[:space:]]*\[[[:space:]]*["'\'']'

scan_pattern \
	"Hex or Unicode string escapes" \
	'\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}'

scan_pattern \
	"Common string-table obfuscation" \
	'(_0x[0-9a-fA-F]{3,}|_0X[0-9A-F]{3,})'

scan_pattern \
	"Suspicious decoder/string-table helpers" \
	'(charCodeAt|fromCharCode|String[.]fromCharCode)[[:space:]]*\('

scan_pattern \
	"Runtime source construction" \
	'(new[[:space:]]+Function|constructor[[:space:]]*\[[[:space:]]*["'\'']constructor["'\'']\])'

scan_long_lines
scan_package_scripts

if ((${#F_PATH[@]} > 0 || ${#S_PATH[@]} > 0)); then
	render_findings

	if ((missing_jq == 1)); then
		printf '\n%ssecurity-gate: %s could not inspect package.json scripts (jq missing).%s\n' \
			"$C_YELLOW" "warning:" "$C_RESET"
	fi

	cat <<'EOF'

Review each flagged location above before starting the dev server. If a
finding is a false positive, prefer changing the implementation rather than
suppressing the scanner from inside the source file.

This scanner is a heuristic pre-flight check. A clean result does not prove
that the repository or its dependencies are safe.
EOF

	exit 1
fi

if ((missing_jq == 1)); then
	printf '\n%ssecurity-gate: %s could not inspect package.json scripts (jq missing).%s\n' \
		"$C_YELLOW" "warning:" "$C_RESET"
	cat <<'EOF'

Install jq and run the security gate again. The gate stays closed until
package.json scripts can be checked.
EOF

	exit 1
fi

echo "${C_GREEN}security-gate: PASSED${C_RESET} — no indicators found (scanned: ${ARG_ROOT})"
exit 0
