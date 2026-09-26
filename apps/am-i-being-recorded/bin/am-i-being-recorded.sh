#!/usr/bin/env bash
set -euo pipefail

# am-i-being-recorded: report the capture surfaces on this machine.
#
# An operating-system indicator such as "Brave Browser is recording your screen"
# names the whole application, never the tab, page, or extension responsible.
# This tool turns that attribution back into a specific extension.
#
# Two passes:
#
#   1. Browser extensions (macOS and Linux). Reads Chromium-family profile
#      directories and flags installed extensions whose permissions allow
#      display capture, tab capture, or deep browser control. This pass is
#      filesystem-only, so the test suite drives it against fixture trees with
#      --root.
#
#   2. Live state (best effort, per platform). On macOS it reports the capture
#      daemons and the camera/microphone/screen-recording grants in the TCC
#      privacy database. On Linux it reports which process holds a camera
#      device. Live lines are context, never findings.
#
# Findings therefore come only from extension capabilities, which keeps the
# report portable and free of a "known good app" allowlist that would rot.
#
# Report model: findings are severity-tagged (CRITICAL/HIGH/MEDIUM/LOW).
# Default mode is evidence: findings are printed and the exit status stays 0.
# --strict turns any finding at or above the severity floor into exit status 1.

readonly SCRIPT_NAME="${0##*/}"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
	readonly C_BOLD=$'\033[1m'
	readonly C_DIM=$'\033[2m'
	readonly C_RED=$'\033[31m'
	readonly C_YELLOW=$'\033[33m'
	readonly C_CYAN=$'\033[36m'
	readonly C_GREEN=$'\033[32m'
	readonly C_RESET=$'\033[0m'
else
	readonly C_BOLD="" C_DIM="" C_RED="" C_YELLOW="" C_CYAN="" C_GREEN="" C_RESET=""
fi

readonly SEVERITIES=(CRITICAL HIGH MEDIUM LOW)

# Browser data directories, relative to the platform's application-data root.
# macOS and Linux spellings are both listed; only existing directories match.
readonly BROWSER_RELS=(
	'BraveSoftware/Brave-Browser'
	'Google/Chrome'
	'Chromium'
	'Microsoft Edge'
	'Vivaldi'
	'google-chrome'
	'chromium'
	'microsoft-edge'
	'vivaldi'
)

# Permission to severity. Each entry is "SEVERITY<TAB>PERMISSION<TAB>DETAIL".
# Only permissions that can observe the user or drive the browser are listed;
# ordinary permissions (storage, tabs, alarms) are deliberately ignored so the
# report stays actionable.
readonly PERM_RULES=(
	$'CRITICAL\tdesktopCapture\tCan capture the entire display (screen recording)'
	$'HIGH\ttabCapture\tCan capture the active tab audio/video'
	$'HIGH\tdebugger\tCan attach to tabs over the DevTools protocol'
	$'MEDIUM\tnativeMessaging\tCan launch a native helper process'
	$'MEDIUM\tuserScripts\tCan inject arbitrary scripts into pages'
	$'LOW\tmanagement\tCan enable or disable other extensions'
)

readonly CAPTURE_PERMS=('desktopCapture' 'tabCapture')
readonly BROAD_HOSTS=('<all_urls>' '*://*/*' 'http://*/*' 'https://*/*')

MIN_SEVERITY='LOW'

declare -a F_SEV=() F_SCOPE=() F_SUBJECT=() F_DETAIL=()
declare -a NOTES=()
declare -A SEV_TOTAL=([CRITICAL]=0 [HIGH]=0 [MEDIUM]=0 [LOW]=0)

add_finding() {
	local severity="$1" scope="$2" subject="$3" detail="$4"
	F_SEV+=("$severity")
	F_SCOPE+=("$scope")
	F_SUBJECT+=("$subject")
	F_DETAIL+=("$detail")
	SEV_TOTAL["$severity"]=$((SEV_TOTAL["$severity"] + 1))
}

severity_rank() {
	case "$1" in
	CRITICAL) printf '0' ;;
	HIGH) printf '1' ;;
	MEDIUM) printf '2' ;;
	LOW) printf '3' ;;
	*) printf '9' ;;
	esac
}

total_findings() {
	# nosemgrep: apps.secure-semgrep.rules.bash.unquoted-variable-expansion-in-command -- already quoted or arithmetic; rule false positive
	printf '%s' "$((SEV_TOTAL[CRITICAL] + SEV_TOTAL[HIGH] + SEV_TOTAL[MEDIUM] + SEV_TOTAL[LOW]))"
}

# severity_at_or_above <severity> <floor> — true when <severity> is as bad as <floor> or worse.
severity_at_or_above() {
	local rank floor
	# nosemgrep: apps.secure-semgrep.rules.bash.unquoted-command-substitution-in-command -- already quoted; rule false positive
	rank="$(severity_rank "$1")"
	# nosemgrep: apps.secure-semgrep.rules.bash.unquoted-command-substitution-in-command -- already quoted; rule false positive
	floor="$(severity_rank "$2")"
	[[ "$rank" -le "$floor" ]]
}

# Count only the findings at or above the current severity floor.
reported_findings() {
	local total=0 sev
	for sev in "${SEVERITIES[@]}"; do
		if severity_at_or_above "$sev" "$MIN_SEVERITY"; then
			# nosemgrep: apps.secure-semgrep.rules.bash.unquoted-variable-expansion-in-command -- arithmetic expansion; rule false positive
			total=$((total + SEV_TOTAL[$sev]))
		fi
	done
	printf '%s' "$total"
}

severity_color() {
	case "$1" in
	CRITICAL | HIGH) printf '%s' "$C_RED" ;;
	MEDIUM) printf '%s' "$C_YELLOW" ;;
	*) printf '%s' "$C_CYAN" ;;
	esac
}

usage() {
	cat <<'EOF'
usage: am-i-being-recorded [options]

Audit screen/tab capture surfaces and the browser extensions that can start
them. Scans Chromium-family profiles (Brave, Chrome, Chromium, Edge, Vivaldi)
on macOS and Linux.

Options:
  --root DIR            application-data directory to scan for browser profiles
                        (default: platform-specific; used by tests)
  --min-severity LEVEL  only report findings at or above LEVEL
                        (CRITICAL|HIGH|MEDIUM|LOW, default: LOW)
  --no-live             skip the live platform checks (daemons, TCC, devices)
  --strict              exit 1 when any reported finding exists (gate mode)
  -h, --help            show this help

Severity: CRITICAL > HIGH > MEDIUM > LOW
EOF
}

default_root() {
	# nosemgrep: apps.secure-semgrep.rules.bash.unquoted-command-substitution-in-command -- already quoted or arithmetic; rule false positive
	case "$(uname -s)" in
	Darwin) printf '%s' "$HOME/Library/Application Support" ;;
	*) printf '%s' "${XDG_CONFIG_HOME:-$HOME/.config}" ;;
	esac
}

# list_has <needle> <newline-separated list>
list_has() {
	grep -qxF -- "$1" <<<"$2"
}

# Chromium stores localized manifest names as "__MSG_key__"; the value lives in
# _locales/<lang>/messages.json. Resolve to a human name when possible.
resolve_name() {
	local manifest="$1"
	local name extdir key msg resolved
	# nosemgrep: apps.secure-semgrep.rules.bash.unquoted-command-substitution-in-command -- already quoted or arithmetic; rule false positive
	name="$(jq -r '.name // empty' "$manifest" 2>/dev/null || true)"
	if [[ "$name" =~ ^__MSG_(.+)__$ ]]; then
		key="${BASH_REMATCH[1]}"
		# nosemgrep: apps.secure-semgrep.rules.bash.unquoted-command-substitution-in-command -- already quoted or arithmetic; rule false positive
		extdir="$(dirname "$manifest")"
		for msg in "$extdir"/_locales/en*/messages.json; do
			[[ -f "$msg" ]] || continue
			# nosemgrep: apps.secure-semgrep.rules.bash.unquoted-command-substitution-in-command -- already quoted or arithmetic; rule false positive
			resolved="$(jq -r --arg k "$key" '.[$k].message // empty' "$msg" 2>/dev/null || true)"
			if [[ -n "$resolved" ]]; then
				name="$resolved"
				break
			fi
		done
		# A localized name whose key is missing from _locales is not a name.
		if [[ "$name" == __MSG_*__ ]]; then
			# nosemgrep: apps.secure-semgrep.rules.bash.unquoted-variable-expansion-in-command -- already quoted or arithmetic; rule false positive
			name="(unknown)"
		fi
	fi
	[[ -n "$name" ]] || name="(unknown)"
	printf '%s' "$name"
}

audit_manifest() {
	local label="$1" extdir="$2" manifest="$3"
	local rest id name version subject
	rest="${manifest#"$extdir"/}"
	id="${rest%%/*}"
	name="$(resolve_name "$manifest")"
	version="$(jq -r '.version // "?"' "$manifest" 2>/dev/null || printf '?')"
	subject="$name ($id) v$version"

	local perms optional hosts
	perms="$(jq -r '(.permissions // []) | join("\n")' "$manifest" 2>/dev/null || true)"
	optional="$(jq -r '(.optional_permissions // []) | join("\n")' "$manifest" 2>/dev/null || true)"
	hosts="$(jq -r '(.host_permissions // []) | join("\n")' "$manifest" 2>/dev/null || true)"

	local rule sev perm detail
	for rule in "${PERM_RULES[@]}"; do
		IFS=$'\t' read -r sev perm detail <<<"$rule"
		if list_has "$perm" "$perms"; then
			add_finding "$sev" "$label" "$subject" "$detail"
		elif list_has "$perm" "$optional"; then
			add_finding "$sev" "$label" "$subject" "$detail (optional, granted at runtime)"
		fi
	done

	# A capture permission is worst when the extension can also read every site,
	# because the recording can include any page the user visits.
	local broad=0 pattern
	for pattern in "${BROAD_HOSTS[@]}"; do
		if list_has "$pattern" "$hosts"; then
			broad=1
			break
		fi
	done
	if [[ "$broad" -eq 1 ]] && list_has 'desktopCapture' "$perms"; then
		add_finding HIGH "$label" "$subject" \
			'Display capture plus access to every site: recordings can include any page'
	fi

	# An offscreen document keeps a capture stream alive after the tab or window
	# that requested it is gone, which is the shape of a "stuck" indicator.
	if list_has 'offscreen' "$perms"; then
		local capture
		for capture in "${CAPTURE_PERMS[@]}"; do
			if list_has "$capture" "$perms"; then
				add_finding HIGH "$label" "$subject" \
					'Capture permission plus an offscreen document can outlive the visible tab'
				break
			fi
		done
	fi
}

audit_profile() {
	local label="$1" profile="$2"
	local extdir="$profile/Extensions"
	[[ -d "$extdir" ]] || return 0
	local id_dir id version_dir manifest
	for id_dir in "$extdir"/*/; do
		[[ -d "$id_dir" ]] || continue
		id="$(basename "$id_dir")"
		# Chromium leaves older version directories behind after an update.
		# Only the newest one is loaded, so report it once instead of once per
		# stale copy.
		version_dir="$(printf '%s\n' "$id_dir"*/ | sort -V | tail -1)"
		manifest="${version_dir}manifest.json"
		[[ -f "$manifest" ]] || continue
		audit_manifest "$label" "$extdir" "$manifest"
	done
}

audit_browser() {
	local base="$1" rel="$2"
	local dir="$base/$rel"
	[[ -d "$dir" ]] || return 0
	local profile
	for profile in "$dir"/*/; do
		[[ -d "$profile" ]] || continue
		audit_profile "$rel/$(basename "$profile")" "${profile%/}"
	done
}

audit_extensions() {
	local base="$1" found=0 rel
	for rel in "${BROWSER_RELS[@]}"; do
		if [[ -d "$base/$rel" ]]; then
			found=1
			audit_browser "$base" "$rel"
		fi
	done
	if [[ "$found" -eq 0 ]]; then
		NOTES+=("no browser profiles found under $base")
	fi
}

live_check_macos() {
	if pgrep -x screensharingd >/dev/null 2>&1; then
		NOTES+=('screensharingd is running: screen sharing may be active')
	else
		NOTES+=('screensharingd is not running')
	fi
	if pgrep -x replayd >/dev/null 2>&1; then
		NOTES+=('replayd (system capture service) is running')
	fi

	# TCC is the macOS privacy database. Camera and microphone grants live in
	# the per-user database. Screen Recording grants live in the system database
	# and need root or Full Disk Access. Both are reported as context; the
	# schema is undocumented and may change between releases, so every read is
	# best-effort.
	local userdb="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
	if [[ -r "$userdb" ]] && command -v sqlite3 >/dev/null 2>&1; then
		local service client
		while IFS='|' read -r service client; do
			[[ -n "$client" ]] || continue
			NOTES+=("TCC $service granted to $client")
		done < <(sqlite3 "$userdb" \
			"select service, client from access where service in ('kTCCServiceCamera','kTCCServiceMicrophone') and auth_value=2 order by service, client;" \
			2>/dev/null || true)
	else
		NOTES+=('camera/microphone grants unavailable (TCC database not readable)')
	fi

	local sysdb='/Library/Application Support/com.apple.TCC/TCC.db'
	if [[ -r "$sysdb" ]] && command -v sqlite3 >/dev/null 2>&1; then
		local client
		while IFS='|' read -r client; do
			[[ -n "$client" ]] || continue
			NOTES+=("screen-recording grant: $client")
		done < <(sqlite3 "$sysdb" \
			"select client from access where service='kTCCServiceScreenCapture' and auth_value=2 order by client;" \
			2>/dev/null || true)
	else
		NOTES+=('screen-recording grants unavailable (system TCC needs root or Full Disk Access)')
	fi
}

live_check_linux() {
	local -a devices=()
	local device
	while IFS= read -r device; do
		[[ -n "$device" ]] && devices+=("$device")
	done < <(ls /dev/video* 2>/dev/null || true)

	if [[ "${#devices[@]}" -eq 0 ]]; then
		NOTES+=('no /dev/video* camera devices found')
		return 0
	fi

	if ! command -v lsof >/dev/null 2>&1; then
		NOTES+=('camera devices present; install lsof to see which process holds them')
		return 0
	fi

	local holders
	holders="$(lsof "${devices[@]}" 2>/dev/null | awk 'NR > 1 { print $1 " (pid " $2 ")" }' | sort -u || true)"
	if [[ -n "$holders" ]]; then
		while IFS= read -r device; do
			[[ -n "$device" ]] && NOTES+=("camera device in use by: $device")
		done <<<"$holders"
	else
		NOTES+=('no process is holding a camera device')
	fi
}

live_check() {
	case "$(uname -s)" in
	Darwin) live_check_macos ;;
	Linux) live_check_linux ;;
	*) NOTES+=("live checks skipped: unsupported platform $(uname -s)") ;;
	esac
}

print_section() {
	printf '\n%s%s%s\n' "$C_BOLD" "$1" "$C_RESET"
}

print_report() {
	print_section "Capture-surface findings"
	local floor reported
	floor="$(severity_rank "$MIN_SEVERITY")"
	reported="$(reported_findings)"
	if [[ "$reported" -eq 0 ]]; then
		printf '  %sno findings%s\n' "$C_GREEN" "$C_RESET"
	else
		local sev i color
		for sev in "${SEVERITIES[@]}"; do
			[[ "${SEV_TOTAL[$sev]}" -gt 0 ]] || continue
			[[ "$(severity_rank "$sev")" -le "$floor" ]] || continue
			color="$(severity_color "$sev")"
			for i in "${!F_SEV[@]}"; do
				[[ "${F_SEV[$i]}" == "$sev" ]] || continue
				printf '  %s%-8s%s %s\n' "$color" "$sev" "$C_RESET" "${F_SUBJECT[$i]}"
				printf '           %s%s - %s%s\n' "$C_DIM" "${F_SCOPE[$i]}" "${F_DETAIL[$i]}" "$C_RESET"
			done
		done
	fi

	print_section "Live context"
	if [[ "${#NOTES[@]}" -eq 0 ]]; then
		printf '  %snone%s\n' "$C_DIM" "$C_RESET"
	else
		local note
		for note in "${NOTES[@]}"; do
			printf '  %s\n' "$note"
		done
	fi

	printf '\n%sSummary%s: %s of %s finding(s) shown (CRITICAL %s, HIGH %s, MEDIUM %s, LOW %s); floor %s\n' \
		"$C_BOLD" "$C_RESET" "$reported" "$(total_findings)" \
		"${SEV_TOTAL[CRITICAL]}" "${SEV_TOTAL[HIGH]}" "${SEV_TOTAL[MEDIUM]}" "${SEV_TOTAL[LOW]}" \
		"$MIN_SEVERITY"
}

main() {
	local root="" strict=0 live=1
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--root)
			if [[ $# -lt 2 ]]; then
				echo "$SCRIPT_NAME: --root requires a directory" >&2
				exit 2
			fi
			root="$2"
			shift 2
			;;
		--min-severity)
			if [[ $# -lt 2 ]]; then
				echo "$SCRIPT_NAME: --min-severity requires a level" >&2
				exit 2
			fi
			case "$2" in
			CRITICAL | HIGH | MEDIUM | LOW) MIN_SEVERITY="$2" ;;
			*)
				echo "$SCRIPT_NAME: invalid severity '$2' (want CRITICAL, HIGH, MEDIUM, or LOW)" >&2
				exit 2
				;;
			esac
			shift 2
			;;
		--no-live)
			live=0
			shift
			;;
		--strict)
			strict=1
			shift
			;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			echo "$SCRIPT_NAME: unknown argument '$1'" >&2
			usage >&2
			exit 2
			;;
		esac
	done

	if ! command -v jq >/dev/null 2>&1; then
		echo "$SCRIPT_NAME: jq is required to read extension manifests but was not found on PATH." >&2
		exit 1
	fi

	if [[ -n "$root" && ! -d "$root" ]]; then
		echo "$SCRIPT_NAME: '$root' is not a directory" >&2
		exit 2
	fi
	[[ -n "$root" ]] || root="$(default_root)"

	local display_root
	display_root="$(cd "$root" 2>/dev/null && pwd || printf '%s' "$root")"
	printf '%s%s%s\n' "$C_BOLD" "$SCRIPT_NAME" "$C_RESET"
	printf '%sroot: %s%s\n' "$C_DIM" "$display_root" "$C_RESET"

	audit_extensions "$root"
	if [[ "$live" -eq 1 ]]; then
		live_check
	fi

	print_report

	if [[ "$strict" -eq 1 && "$(reported_findings)" -gt 0 ]]; then
		return 1
	fi
	return 0
}

main "$@"
