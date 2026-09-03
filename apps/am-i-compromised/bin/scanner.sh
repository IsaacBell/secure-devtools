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
# Keep known-malicious fixtures outside the trusted source tree rather than
# suppressing findings with comments in the source itself.

if ! command -v rg >/dev/null 2>&1; then
	echo "scanner: ripgrep (rg) is required but was not found on PATH." >&2
	echo "scanner: install it (e.g. brew install ripgrep, apt-get install ripgrep)." >&2
	exit 1
fi

ROOT="${1:-.}"

readonly MAX_SOURCE_LINE_LENGTH=4000

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

ROOT="$(cd "$ROOT" && pwd)"

found=0

print_header() {
	local title="$1"

	printf '\n=== %s ===\n' "$title"
}

report_matches() {
	local title="$1"
	local matches="$2"

	if [[ -z "$matches" ]]; then
		return
	fi

	print_header "$title"
	printf '%s\n' "$matches"
	found=1
}

scan_pattern() {
	local title="$1"
	local pattern="$2"

	local matches

	# Positive source globs come first. Exclusions come last because ripgrep
	# gives later matching globs precedence.
	matches="$(
		rg -n \
			--no-heading \
			--color never \
			"${SOURCE_GLOBS[@]}" \
			"${EXCLUDE_GLOBS[@]}" \
			"$pattern" \
			-- "$ROOT" 2>/dev/null || true
	)"

	report_matches "$title" "$matches"
}

scan_long_lines() {
	local matches count truncated_note

	# Strip rg's "file:line:" prefix before measuring the source line itself.
	# This makes MAX_SOURCE_LINE_LENGTH apply to the actual source content.
	matches="$(
		rg -n \
			--no-heading \
			--color never \
			"${SOURCE_GLOBS[@]}" \
			"${EXCLUDE_GLOBS[@]}" \
			-- '.' "$ROOT" 2>/dev/null |
			awk -F: -v limit="$MAX_SOURCE_LINE_LENGTH" '
        {
          line = $0
          sub(/^[^:]*:[0-9]+:/, "", line)

          if (length(line) > limit) {
            print
          }
        }
      ' || true
	)"

	if [[ -n "$matches" ]]; then
		count="$(printf '%s\n' "$matches" | wc -l | tr -d ' ')"

		if ((count > 100)); then
			# Do not use head here. With a large command-substitution payload,
			# printf can receive SIGPIPE when head exits after 100 lines.
			# sed consumes the complete input, so pipefail/set -e remain safe.
			truncated_note="... (truncated, ${count} total matches)"
			matches="$(printf '%s\n' "$matches" | sed -n '1,100p')
${truncated_note}"
		fi
	fi

	report_matches \
		"Source lines exceeding ${MAX_SOURCE_LINE_LENGTH} characters" \
		"$matches"
}

scan_package_scripts() {
	local package_files=()

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

	if [[ ${#package_files[@]} -eq 0 ]]; then
		return
	fi

	for file in "${package_files[@]}"; do
		if ! command -v jq >/dev/null 2>&1; then
			print_header "Unable to inspect package.json scripts"
			echo "jq is required to inspect package scripts."
			echo "Install jq and run the security gate again."
			found=1
			return
		fi

		local matches

		matches="$(
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
		)"

		if [[ -n "$matches" ]]; then
			print_header "Suspicious package scripts: ${file#"$ROOT"/}"
			printf '%s\n' "$matches"
			found=1
		fi
	done
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
	'(^|[^[:alnum:]_$])global([.[]|])'

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

if [[ "$found" -ne 0 ]]; then
	print_header "Security gate failed"

	cat <<'EOF'
Potentially unsafe source was found.

The development server has not been started.

Review the findings above. If a finding is legitimate, prefer changing
the implementation rather than suppressing the scanner from inside the
source file.

This scanner is a heuristic pre-flight check. A clean result does not
prove that the repository or its dependencies are safe.
EOF

	exit 1
fi

echo "Security gate passed."
