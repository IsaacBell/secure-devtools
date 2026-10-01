#!/usr/bin/env bash
# bin/host-audit.sh — run as `am-i-hacked host`.
#
# Is something on THIS machine persisting, capturing, or steering your tools?
#
# The repository scanner (scanner.sh) reads source trees, so it cannot see what
# lives outside them. In a real, observed clipboard-stealer class, a user
# LaunchAgent starts a shell wrapper from ~/Library/Application Support, which
# launches a Node script that sends every clipboard change to a Telegram bot. No
# repository contains any of it, so no source scan can find it.
#
# Read-only: it never modifies, deletes, or contacts anything. It checks:
#   - login persistence: launchd agents and daemons (macOS), systemd user units
#     and XDG autostart (Linux), and the user crontab
#   - the scripts those entries launch, and the script files beside them:
#     clipboard reads, keystroke or screen capture, and exfiltration endpoints
#   - shell startup files: piped remote scripts, injected libraries, hijacked
#     sudo/ssh, background launchers, redirected API base URLs
#   - AI-tool configuration: redirected API base URLs, permission bypass,
#     plain-text keys, MCP servers that run unpinned code, and every hook that
#     observes prompts and tool output
#   - running processes: interpreters running capture or staging-area scripts
#
# HIGH and MEDIUM findings make the exit status 1. INFO never does.
#
# A finding you reviewed and accept can be allowed with a reason, one per line
# in ~/.config/am-i-hacked/host-allow.txt (override with AIC_HOST_ALLOW):
#
#   <finding id> | <why this is expected>
#
# The reason is required. Allowed findings are listed on every run, never hidden.
#
# Test seams: AIC_HOST_HOME, AIC_HOST_PROJECT, AIC_HOST_OS, AIC_HOST_LAUNCH_DIRS
# (colon-separated), AIC_HOST_PS_FILE, AIC_HOST_CRONTAB_FILE, AIC_HOST_MANAGED_DIRS
# (colon-separated; the root-owned agent settings directories). CLAUDE_CONFIG_DIR
# and CODEX_HOME are honored as on a real machine.
#
# Written for bash 3.2 (the macOS system bash): no associative arrays, mapfile,
# or case-conversion expansions.

set -u

usage() {
	cat <<'EOF'
usage: am-i-hacked host [--system] [--verbose] [dir]

Read-only audit. By default it checks one folder: the AI-tool config in dir
(.claude/, .mcp.json). --system adds the machine: login persistence and the
code signatures of what it launches, the crontab, shell startup files,
user-level AI-tool configuration, and running processes. Exits 1 if anything
needs review.

  dir                    folder to check (default: the current directory)
  --system               also audit the whole machine (alias: --full-system-scan)
  -v, --verbose          also list informational items and every persistence entry
  -h, --help             show this help

No root or sudo is needed.

Allow a reviewed finding by adding "<finding id> | <reason>" to
~/.config/am-i-hacked/host-allow.txt (or the file named by AIC_HOST_ALLOW).
EOF
}

VERBOSE=0
SYSTEM=0
PROJECT_ARG=""
for arg in "$@"; do
	case "$arg" in
	-v | --verbose) VERBOSE=1 ;;
	--system | --full-system-scan) SYSTEM=1 ;;
	-h | --help)
		usage
		exit 0
		;;
	-*)
		echo "host-audit: unknown option '$arg'" >&2
		usage >&2
		exit 2
		;;
	*)
		if [[ -n "$PROJECT_ARG" ]]; then
			echo "host-audit: give one folder, not '$PROJECT_ARG' and '$arg'" >&2
			exit 2
		fi
		PROJECT_ARG="$arg"
		;;
	esac
done
if [[ -n "$PROJECT_ARG" && ! -d "$PROJECT_ARG" ]]; then
	echo "host-audit: '$PROJECT_ARG' is not a directory" >&2
	exit 2
fi

HOME_DIR="${AIC_HOST_HOME:-${HOME:-}}"
[[ -n "$HOME_DIR" ]] || HOME_DIR="$(cd ~ 2>/dev/null && pwd)" || HOME_DIR=""
if [[ -z "$HOME_DIR" ]]; then
	echo "host-audit: cannot determine the home directory (HOME is unset)." >&2
	exit 2
fi
if [[ -n "$PROJECT_ARG" ]]; then
	PROJECT_DIR="$(cd "$PROJECT_ARG" && pwd)"
else
	PROJECT_DIR="${AIC_HOST_PROJECT:-$PWD}"
fi
OS="${AIC_HOST_OS:-$(uname -s)}"
ALLOW_FILE="${AIC_HOST_ALLOW:-${XDG_CONFIG_HOME:-$HOME_DIR/.config}/am-i-hacked/host-allow.txt}"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
	C_RED=$'\033[31m' C_YELLOW=$'\033[33m' C_GREEN=$'\033[32m' C_DIM=$'\033[2m' C_BOLD=$'\033[1m' C_RESET=$'\033[0m'
else
	C_RED='' C_YELLOW='' C_GREEN='' C_DIM='' C_BOLD='' C_RESET=''
fi

# Progress: each stage, and a running count while login items are checked, on stderr. On by
# default only when stderr is a terminal; AIH_PROGRESS=1 forces it on (CI logs), AIH_PROGRESS=0
# turns it off. The report on stdout is unchanged either way.
if [[ "${AIH_PROGRESS:-}" == 1 || ("${AIH_PROGRESS:-}" != 0 && -t 2) ]]; then
	PROGRESS=1
else
	PROGRESS=0
fi
AUDIT_START=$SECONDS

stage() {
	[[ "$PROGRESS" == 1 ]] || return 0
	printf '%s[%3ds, %s found so far]%s %s\n' "$C_DIM" "$((SECONDS - AUDIT_START))" \
		"$(printf '%s' "$FINDINGS" | grep -c . || true)" "$C_RESET" "$1" >&2
}

# item_progress <n> <total> <label> — one line rewritten in place on a terminal, every tenth item
# (and the last) as its own line elsewhere.
item_progress() {
	[[ "$PROGRESS" == 1 ]] || return 0
	if [[ -t 2 ]]; then
		printf '\r  %d/%d %s\033[K' "$1" "$2" "$3" >&2
		[[ "$1" == "$2" ]] && printf '\n' >&2
	elif (($1 % 10 == 0 || $1 == $2)); then
		printf '  %d/%d %s\n' "$1" "$2" "$3" >&2
	fi
	return 0
}

readonly US=$'\037'
FINDINGS=""           # records: rank+sev US id US title US where US evidence US next
PERSISTENCE_CHECKED=1 # 0 when this OS has no persistence checks, so PASSED never claims one
ALLOWED=""            # the same, plus a trailing US reason
INVENTORY=""          # one line per persistence entry (shown with --verbose)
ENTRY_SIGNER=""       # signer of the launchd entry being assessed (macOS)
SEEN="|"              # ids already recorded
RC_SEEN="|"           # startup files already scanned, so a source loop cannot recurse
JQ_NOTED=0
CODESIGN="${AIC_HOST_CODESIGN:-codesign}"

# --- indicator definitions ------------------------------------------------------

# am-i-hacked-ignore: detector pattern definition, not a clipboard read
RE_CLIP_READ='pbpaste|NSPasteboard|generalPasteboard|clipboardy|pyperclip|xclip|xsel|wl-paste|Get-Clipboard|clipboard-listener'
RE_CAPTURE_WORD='clipboard|pasteboard|keylog|keystroke'
RE_KEYLOG='CGEventTap|kCGEventKeyDown|IOHIDManager|addGlobalMonitorForEvents|pynput|logkeys'
RE_SCREEN='screencapture[[:space:]]|CGDisplayCreateImage|CGWindowListCreateImage|scrot[[:space:]]|import[[:space:]]+-window[[:space:]]+root'
RE_EXFIL_URL='api\.telegram\.org|discord(app)?\.com/api/webhooks|hooks\.slack\.com/services|webhook\.site|pastebin\.com/api|transfer\.sh|requestbin|ngrok\.(io|app|dev)|/sendMessage([?/]|$)'
RE_EXFIL_WORD='telegram|discord|webhook'
RE_BG_LAUNCH='nohup[[:space:]].*&'
# Names used by capture-tool folders and by a known clipboard-stealer campaign. Kept
# narrow: these are names a capture tool gives itself, not generic words.
RE_CAPTURE_DIR_NAME='clipboard|pasteboard|keylog|screenshot|screencap|monitor'
RE_CAMPAIGN_IOC='clipboardmonitor|clipboard_tg_monitor|ClipboardMonitor/run_monitor\.sh|com\.sstar\.'
# Secret shapes, matched case-insensitively but never printed. The last is the
# Telegram bot-token shape.
RE_SECRET_SHAPE='sk-ant-[A-Za-z0-9_-]{10,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[bp]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|[0-9]{8,10}:[A-Za-z0-9_-]{35}'
# Env keys that redirect where a tool sends its traffic. *_HOST requires the
# underscore so a stray "host" key elsewhere is not swept in.
RE_AGENT_URL_KEY='([A-Za-z0-9_]+_BASE_URL|[A-Za-z0-9_]+_API_URL|[A-Za-z0-9_]+_ENDPOINT|[A-Za-z0-9_]+_HOST|base_url|api_url|endpoint|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY)'
# Absolute paths a hook should never be running code from.
RE_HOOK_BAD_PATH='node_modules/|/tmp/|/var/folders/|/private/tmp/|/\.cache/|Application Support/'

# Vendor Team IDs: bin/vendor-teams.tsv, then installed apps for unlisted prefixes.
VENDOR_FILE="${AIC_HOST_VENDOR_FILE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/vendor-teams.tsv}"
APP_DIRS="${AIC_HOST_APP_DIRS:-/Applications:$HOME_DIR/Applications}"
# Prefixes used by unrelated developers; no installed app can speak for them.
RE_SHARED_PREFIX='^(com\.apple|com\.electron|com\.github|io\.github|com\.todesktop|com\.example|org\.chromium)$'
INSTALLED_TEAMS="|" # cache: |prefix=teams|

# label_vendor <label> — the first two reverse-DNS parts ("com.google"), or nothing.
label_vendor() {
	case "$1" in *.*.*) ;; *) return 0 ;; esac
	local a="${1%%.*}" r="${1#*.}"
	printf '%s.%s' "$a" "${r%%.*}"
}

# scan_app_teams <prefix> — sets APP_TEAMS: Team IDs of installed apps whose bundle id
# starts with the prefix. Cached per prefix.
scan_app_teams() {
	local p="$1" d app id t dirs=()
	case "$INSTALLED_TEAMS" in
	*"|$p="*)
		APP_TEAMS="${INSTALLED_TEAMS#*|"$p"=}"
		APP_TEAMS="${APP_TEAMS%%|*}"
		return 0
		;;
	esac
	APP_TEAMS=""
	IFS=: read -r -a dirs <<<"$APP_DIRS"
	for d in "${dirs[@]}"; do
		for app in "$d"/*.app; do
			[[ -f "$app/Contents/Info.plist" ]] || continue
			id="$(plist_xml "$app/Contents/Info.plist" | plist_values CFBundleIdentifier 1)"
			[[ "$id" == "$p".* ]] || continue
			t="$("$CODESIGN" -dv "$app" 2>&1 | sed -n 's/^TeamIdentifier=//p' | head -n 1)"
			[[ -n "$t" && "$t" != "not set" && " $APP_TEAMS" != *" $t "* ]] && APP_TEAMS="$APP_TEAMS$t "
		done
	done
	INSTALLED_TEAMS="${INSTALLED_TEAMS}$p=$APP_TEAMS|"
}

# expected_teams <label> — sets EXPECT (Team IDs, space-separated), EXPECT_SRC and
# VENDOR_PREFIX. A listed vendor ignores installed apps, so a planted app cannot vouch for it.
expected_teams() {
	EXPECT="" EXPECT_SRC=""
	VENDOR_PREFIX="$(label_vendor "$1")"
	[[ -n "$VENDOR_PREFIX" ]] || return 0
	if [[ -r "$VENDOR_FILE" ]]; then
		EXPECT="$(awk -F'\t' -v p="$VENDOR_PREFIX" '$1 == p { printf "%s ", $2 }' "$VENDOR_FILE")"
		[[ -n "$EXPECT" ]] && EXPECT_SRC="vendor table" && return 0
	fi
	printf '%s' "$VENDOR_PREFIX" | grep -Eq "$RE_SHARED_PREFIX" && return 0
	scan_app_teams "$VENDOR_PREFIX"
	EXPECT="$APP_TEAMS"
	[[ -n "$EXPECT" ]] && EXPECT_SRC="installed apps"
	return 0
}

# --- small helpers -----------------------------------------------------------------

trim() {
	local s="$1"
	s="${s#"${s%%[![:space:]]*}"}"
	s="${s%"${s##*[![:space:]]}"}"
	printf '%s' "$s"
}

tilde() {
	local t='~'
	printf '%s' "${1/#$HOME_DIR/$t}"
}

# has <text> <regex> — case-insensitive extended-regex test on a short string.
has() { printf '%s' "$1" | grep -Eiq -- "$2"; }

# file_has <regex> <file>... — true if any file matches. Files only, never a pipe.
file_has() {
	local re="$1"
	shift
	[[ $# -gt 0 ]] && grep -aEiqs -- "$re" "$@"
}

# redact — strip obvious secret values from text on stdin before it is shown.
redact() {
	sed -E 's/(sk-|ghp_|xox[a-z]-)[A-Za-z0-9_-]{8,}/\1<redacted>/g; s/bot[0-9]{6,}:[A-Za-z0-9_-]{20,}/bot<redacted>/g; s/([Tt]oken|[Kk]ey|[Pp]assword|[Ss]ecret)([=:\/]+[[:space:]]*)[^[:space:]"'"'"']{6,}/\1\2<redacted>/g' | cut -c1-160
}

# GNU stat first: BSD stat rejects -c, while GNU stat -f means "filesystem", not "format".
mtime_epoch() {
	stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || echo 0
}

mtime_date() {
	local e
	e="$(mtime_epoch "$1")"
	date -r "$e" +%F 2>/dev/null || date -d "@$e" +%F 2>/dev/null || echo unknown
}

age_days() {
	local e now
	e="$(mtime_epoch "$1")"
	now="$(date +%s)"
	echo $(((now - e) / 86400))
}

# allow_reason <id> — the reviewed reason on stdout, status 0, if the id is allowed.
allow_reason() {
	local line id reason
	[[ -f "$ALLOW_FILE" ]] || return 1
	while IFS= read -r line || [[ -n "$line" ]]; do
		case "$line" in '' | '#'*) continue ;; esac
		[[ "$line" == *"|"* ]] || continue
		id="$(trim "${line%%|*}")"
		reason="$(trim "${line#*|}")"
		if [[ "$id" == "$1" && -n "$reason" ]]; then
			printf '%s' "$reason"
			return 0
		fi
	done <"$ALLOW_FILE"
	return 1
}

# finding <HIGH|MEDIUM|INFO> <id> <title> <where> <evidence> <next>
finding() {
	local rank reason
	case "$SEEN" in *"|$2|"*) return 0 ;; esac
	SEEN="${SEEN}$2|"
	case "$1" in HIGH) rank=3 ;; MEDIUM) rank=2 ;; *) rank=1 ;; esac
	if reason="$(allow_reason "$2")"; then
		ALLOWED="${ALLOWED}${rank}$1${US}$2${US}$3${US}$4${US}$5${US}$6${US}${reason}"$'\n'
		return 0
	fi
	FINDINGS="${FINDINGS}${rank}$1${US}$2${US}$3${US}$4${US}$5${US}$6"$'\n'
}

cksum_id() { printf '%s' "$1" | cksum | awk '{print $1}'; }

# staging_zone <path> — true for places malware stages in and legitimate services rarely run from.
staging_zone() {
	case "$1" in
	"$HOME_DIR"/Library/Application\ Support/* | "$HOME_DIR"/Library/Caches/* | "$HOME_DIR"/Downloads/* | "$HOME_DIR"/.* | "$HOME_DIR"/Public/*) return 0 ;;
	/tmp/* | /var/tmp/* | /private/tmp/* | /private/var/tmp/* | /var/folders/* | /private/var/folders/* | /Users/Shared/* | /dev/shm/*) return 0 ;;
	esac
	return 1
}

# is_interpreter <word> — true for an interpreter name. Uses parameter expansion,
# not basename: a login shell shows up as "-zsh", which basename treats as options
# and fails on. A leading dash is stripped.
is_interpreter() {
	local b="${1##*/}"
	b="${b#-}"
	case "$b" in node | python | python3* | python2* | ruby | perl | bash | sh | zsh | osascript | deno | bun) return 0 ;; esac
	return 1
}

is_script() {
	case "$1" in *.sh | *.bash | *.zsh | *.js | *.mjs | *.cjs | *.py | *.rb | *.pl | *.command | *.scpt | *.applescript) return 0 ;; esac
	[[ -f "$1" && "$(LC_ALL=C head -c 2 "$1" 2>/dev/null)" == '#!' ]]
}

# --- persistence entries ---------------------------------------------------------------

# collect_payload <program> <args...> — the files worth reading for one persistence
# entry: any script it names, plus the script files beside it. Vendor and system
# locations are skipped. Capped so one odd directory cannot stall the audit.
collect_payload() {
	local p dir f n=0 seen="|" size
	for p in "$@"; do
		[[ "$p" == /* && -f "$p" ]] || continue
		case "$p" in /usr/* | /bin/* | /sbin/* | /System/* | /Library/Apple/* | /Applications/* | /opt/homebrew/* | /Library/Frameworks/*) continue ;; esac
		dir="$(dirname "$p")"
		for f in "$p" "$dir"/*.sh "$dir"/*.js "$dir"/*.mjs "$dir"/*.cjs "$dir"/*.py "$dir"/*.rb "$dir"/*.pl "$dir"/*.command "$dir"/*.scpt; do
			[[ -f "$f" ]] || continue
			case "$seen" in *"|$f|"*) continue ;; esac
			# Test readability first: "<file" is opened by the shell before wc
			# runs, so a redirect to an unreadable root-only file prints its own
			# "Permission denied" that 2>/dev/null on wc cannot silence. Callers
			# turn the "!" marker into an INFO finding outside this subshell.
			if [[ ! -r "$f" ]]; then
				seen="${seen}${f}|"
				printf '!%s\n' "$f"
				continue
			fi
			size="$(wc -c <"$f" | tr -d ' ')"
			[[ "${size:-0}" -le 204800 ]] || continue
			((n < 30)) || return 0
			seen="${seen}${f}|"
			n=$((n + 1))
			printf '%s\n' "$f"
			# A script the entry names directly is not enough: only pull siblings for scripts.
			is_script "$p" || break
		done
	done
}

# collect_hop <file> — one level of indirection: the script files a shell wrapper
# launches (`node X.js`, `python3 Y.py`), resolved relative to the wrapper. A
# stealer's wrapper typically runs `node <payload>.js` from its own folder, so
# following that hop is what reaches the payload.
collect_hop() {
	local file="$1" dir tgt
	[[ -r "$file" ]] || return 0
	dir="$(dirname "$file")"
	while IFS= read -r tgt; do
		[[ -n "$tgt" ]] || continue
		case "$tgt" in
		'~'/*) tgt="$HOME_DIR/${tgt#'~'/}" ;;
		'[$]HOME'/*) tgt="$HOME_DIR/${tgt#'[$]HOME'/}" ;;
		*'[$]HOME'*) continue ;;
		/*) ;;
		*) tgt="$dir/$tgt" ;;
		esac
		[[ -f "$tgt" ]] || continue
		case "$tgt" in *.js | *.mjs | *.cjs | *.py | *.rb | *.pl | *.sh | *.bash | *.zsh) printf '%s\n' "$tgt" ;; esac
	done < <(sed -nE 's#.*(^|[^[:alnum:]_])(node|python3?|ruby|perl|bash|sh|zsh|osascript)[[:space:]]+([^[:space:];&|<>"'"'"']+[.](js|mjs|cjs|py|rb|pl|sh|bash|zsh)).*#\3#p' "$file" 2>/dev/null)
}

# assess_entry <id> <where> <label> <program> <args...>
assess_entry() {
	local id="$1" where="$2" label="$3" program="$4"
	shift 4
	local chain="$label $program $*" f a
	local files=() capture=0 exfil=0 exfil_url=0 zone=0 launcher=0 dangling=0 ioc=0
	local sigs="" sev="" title="" next="" date evidence

	while IFS= read -r f; do
		[[ -n "$f" ]] || continue
		case "$f" in
		'!'*)
			finding INFO "unreadable:$(cksum_id "${f#!}")" "A persistence file could not be read" "$(tilde "${f#!}")" "unreadable (permission denied)" "Only a root-owned file should be unreadable to you. Check who owns it: ls -l."
			;;
		*) files+=("$f") ;;
		esac
	done <<<"$(collect_payload "$program" "$@")"

	if [[ ${#files[@]} -gt 0 ]]; then
		local hop_seen="|" hf
		for f in "${files[@]}"; do hop_seen="${hop_seen}${f}|"; done
		while IFS= read -r hf; do
			[[ -n "$hf" ]] || continue
			case "$hop_seen" in *"|$hf|"*) continue ;; esac
			hop_seen="${hop_seen}${hf}|"
			files+=("$hf")
		done <<<"$(for f in "${files[@]}"; do collect_hop "$f"; done)"
	fi

	if has "$chain" "$RE_CAPTURE_WORD"; then
		capture=1
		sigs="${sigs}capture keyword in name or path; "
	fi
	if has "$chain" "$RE_EXFIL_WORD"; then
		exfil=1
		sigs="${sigs}messaging keyword in name or path; "
	fi
	# ProgramArguments often carry the payload inline (`sh -c "... pbpaste |
	# curl api.telegram.org ..."`). The chain text is judged with the same
	# capture and exfiltration signals as a script file would be.
	if has "$chain" "$RE_CLIP_READ"; then
		capture=1
		sigs="${sigs}reads the clipboard; "
	fi
	if has "$chain" "$RE_EXFIL_URL"; then
		exfil=1
		exfil_url=1
		sigs="${sigs}exfiltration endpoint; "
	fi
	if has "$chain" "$RE_CAMPAIGN_IOC"; then
		ioc=1
		sigs="${sigs}known campaign indicator;"
	fi

	if [[ ${#files[@]} -gt 0 ]]; then
		if file_has "$RE_CLIP_READ" "${files[@]}"; then
			capture=1
			sigs="${sigs}reads the clipboard; "
		fi
		if file_has "$RE_CAPTURE_WORD" "${files[@]}" && [[ "$capture" == 0 ]]; then
			capture=1
			sigs="${sigs}capture keyword in script; "
		fi
		if file_has "$RE_KEYLOG" "${files[@]}"; then
			capture=1
			sigs="${sigs}keystroke capture APIs; "
		fi
		if file_has "$RE_SCREEN" "${files[@]}"; then
			capture=1
			sigs="${sigs}screen capture; "
		fi
		if file_has "$RE_EXFIL_URL" "${files[@]}"; then
			exfil=1
			exfil_url=1
			sigs="${sigs}exfiltration endpoint; "
		elif file_has "$RE_EXFIL_WORD" "${files[@]}"; then
			exfil=1
			sigs="${sigs}messaging keyword in script; "
		fi
		if file_has "$RE_BG_LAUNCH" "${files[@]}"; then
			sigs="${sigs}background launcher; "
		fi
		if file_has '[0-9]{8,10}:[A-Za-z0-9_-]{35}' "${files[@]}"; then
			exfil=1
			exfil_url=1
			sigs="${sigs}messaging bot token in script; "
		fi
		if file_has "$RE_CAMPAIGN_IOC" "${files[@]}"; then
			ioc=1
			sigs="${sigs}known campaign indicator;"
		fi
	fi

	for a in "$program" "$@"; do
		[[ "$a" == /* ]] || continue
		staging_zone "$a" && zone=1
		is_script "$a" && launcher=1
	done
	is_interpreter "$program" && launcher=1
	[[ "$zone" == 1 && "$launcher" == 1 ]] && sigs="${sigs}script in a user-writable location; "
	[[ "$program" == /* && ! -e "$program" ]] && dangling=1

	date="$(mtime_date "$where")"
	if [[ "$capture" == 1 && ("$exfil" == 1 || ("$zone" == 1 && "$launcher" == 1)) ]]; then
		sev=HIGH
		if [[ "$exfil" == 1 ]]; then title="Capture tool that reports to a remote service"; else title="Capture tool launched from a user-writable location"; fi
		next="Copy the entry and its folder somewhere inert as evidence (do not run them), then unload it. Treat everything you copied or typed since $date as exposed; rotate it from a clean device."
	elif [[ "$exfil_url" == 1 ]]; then
		sev=MEDIUM
		title="Persistence entry references an exfiltration endpoint"
		next="Read the script. If you did not write it, preserve it and unload the entry."
	elif [[ "$zone" == 1 && "$launcher" == 1 ]]; then
		sev=MEDIUM
		title="Login script runs from a user-writable location"
		next="Confirm you installed it. Vendor software normally launches signed programs from /Applications."
	elif [[ "$dangling" == 1 ]]; then
		sev=MEDIUM
		title="Persistence entry points at a missing program"
		sigs="${sigs}program not found: $(tilde "$program"); "
		next="Remove the stale entry, or find out what deleted its program (cleanup after a compromise looks like this)."
	elif [[ "$(age_days "$where")" -le 30 && "$label" != com.apple.* ]]; then
		sev=INFO
		title="Persistence entry added or changed in the last 30 days"
		next="Confirm you know why."
	fi

	# A known IOC name or path is always high, whatever else matched.
	if [[ "$ioc" == 1 && "$sev" != HIGH ]]; then
		sev=HIGH
		[[ -n "$title" ]] || title="Persistence entry matches a known clipboard-exfiltration campaign"
		next="Treat this as a known clipboard-exfiltration campaign: preserve the files, unload the entry, and rotate anything copied since it first appeared."
	fi

	INVENTORY="${INVENTORY}  $label -> $(tilde "$program") (changed $date${ENTRY_SIGNER:+; $ENTRY_SIGNER})"$'\n'
	[[ -n "$sev" ]] || return 0
	evidence="$(trim "${sigs%; }")"
	if [[ -n "$evidence" ]]; then evidence="$evidence (changed $date)"; else evidence="changed $date"; fi
	finding "$sev" "$id" "$title" "$(tilde "$where") -> $(tilde "$program")" "$evidence" "$next"
}

plist_xml() {
	if command -v plutil >/dev/null 2>&1; then
		plutil -convert xml1 -o - "$1" 2>/dev/null || cat "$1"
	else
		cat "$1"
	fi
}

# plist_values <key> [limit] — the <string> values of a key (a string or an array of strings) from XML on stdin.
plist_values() {
	awk -v key="$1" -v lim="${2:-0}" '
		$0 ~ "<key>" key "</key>" { want = 1; next }
		want && /<array>/ { arr = 1; next }
		want && arr && /<\/array>/ { want = 0; arr = 0; next }
		want && /<string>/ {
			s = $0; sub(/.*<string>/, "", s); sub(/<\/string>.*/, "", s)
			q = sprintf("%c", 39)
			gsub(/&lt;/, "<", s); gsub(/&gt;/, ">", s); gsub(/&quot;/, "\"", s); gsub(/&apos;/, q, s); gsub(/&amp;/, "\\&", s)
			if (lim == 0 || n < lim) print s
			n++
			if (!arr) want = 0
			next
		}
		want && !arr && $0 !~ /^[[:space:]]*$/ { want = 0 }
	'
}

audit_plist() {
	local f="$1" xml label program args=() line userdir=0 a wa=0
	xml="$(plist_xml "$f")"
	case "$f" in "$HOME_DIR"/*) userdir=1 ;; esac

	# A plist that cannot be parsed is reported, never skipped: a binary or
	# damaged file in a launch directory is exactly where something hides.
	if [[ "$xml" != *"<dict"* ]]; then
		finding MEDIUM "plist:$(basename "$f" .plist):unparsable" "Login item could not be parsed" "$(tilde "$f")" "not readable as a plist (binary or damaged)" "Inspect it by hand: plutil -p, and strings if it is not XML."
		return 0
	fi

	label="$(printf '%s\n' "$xml" | plist_values Label 1)"
	[[ -n "$label" ]] || label="$(basename "$f" .plist)"

	# Apple's labels belong in system directories. The same label in a user
	# LaunchAgents folder is impersonation.
	if [[ "$userdir" == 1 && "$label" == com.apple.* ]]; then
		finding HIGH "launchagent:$label:impersonation" "An Apple label is planted in your own launch directory" "$(tilde "$f")" "Label $label in a user directory" "Apple does not install user agents here. Preserve the file and unload it."
	fi

	if printf '%s\n' "$xml" | grep -aqE '(DYLD_INSERT_LIBRARIES|LD_PRELOAD)'; then
		finding HIGH "launchagent:$label:inject" "A login item injects a library into every launch" "$(tilde "$f")" "EnvironmentVariables sets DYLD_INSERT_LIBRARIES or LD_PRELOAD" "Remove it. Legitimate software does not inject a library at login."
	fi

	if printf '%s\n' "$xml" | grep -aqE 'NODE_TLS_REJECT_UNAUTHORIZED'; then
		finding HIGH "launchagent:$label:tls-off" "A login item turns off TLS certificate checks" "$(tilde "$f")" "EnvironmentVariables sets NODE_TLS_REJECT_UNAUTHORIZED" "Remove it. Every HTTPS connection that job makes becomes forgeable."
	fi
	if printf '%s\n' "$xml" | grep -aqE '(NODE_EXTRA_CA_CERTS|SSL_CERT_FILE|SSL_CERT_DIR|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE|NODE_OPTIONS|HTTPS?_PROXY|ALL_PROXY)'; then
		finding MEDIUM "launchagent:$label:trust-env" "A login item changes certificate trust, proxy or Node options" "$(tilde "$f")" "EnvironmentVariables sets a CA, proxy or NODE_OPTIONS variable" "Confirm you know why. It can intercept the job's traffic or load code into it."
	fi

	while IFS= read -r line; do
		[[ -n "$line" ]] && args+=("$line")
	done <<<"$(printf '%s\n' "$xml" | plist_values ProgramArguments)"
	program="$(printf '%s\n' "$xml" | plist_values Program 1)"
	if [[ -z "$program" && ${#args[@]} -gt 0 ]]; then
		program="${args[0]}"
		args=("${args[@]:1}")
	fi
	[[ -n "$program" ]] || return 0

	# Repeating or event-triggered jobs that run a script from the user's own
	# files are a persistence pattern: unloading them once does not stop them.
	if printf '%s\n' "$xml" | grep -qE '<key>(StartInterval|StartCalendarInterval|WatchPaths)</key>'; then
		for a in "$program" ${args[@]+"${args[@]}"}; do
			[[ "$a" == /* ]] || continue
			staging_zone "$a" && wa=1
			case "$a" in "$HOME_DIR"/*) wa=1 ;; esac
		done
		if [[ "$wa" == 1 ]]; then
			finding MEDIUM "launchagent:$label:trigger" "A periodic job runs a script from your own files" "$(tilde "$f")" "StartInterval or WatchPaths runs $(tilde "$program")" "Confirm you installed it. Check the script before you unload the job."
		fi
	fi

	audit_signature "launchagent:$label" "$f" "$label" "$program"
	if [[ ${#args[@]} -gt 0 ]]; then
		assess_entry "launchagent:$label" "$f" "$label" "$program" "${args[@]}"
	else
		assess_entry "launchagent:$label" "$f" "$label" "$program"
	fi
	ENTRY_SIGNER=""
}

# is_macho <file> — thin or universal Mach-O. codesign reports any script as unsigned.
is_macho() {
	local magic
	[[ -f "$1" && -r "$1" ]] || return 1
	magic="$(LC_ALL=C head -c 4 "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n')"
	case "$magic" in cffaedfe | cefaedfe | feedfacf | feedface | cafebabe | bebafeca) return 0 ;; esac
	return 1
}

# sip_path <path> — true for SIP-sealed system locations. /usr/local is user-writable.
sip_path() {
	case "$1" in
	/usr/local/*) return 1 ;;
	/usr/* | /bin/* | /sbin/* | /System/*) return 0 ;;
	esac
	return 1
}

# audit_signature <id> <plist> <label> <program> — macOS. Sets ENTRY_SIGNER, the name
# System Settings > Login Items shows for the entry.
audit_signature() {
	local id="$1" where="$2" label="$3" program="$4"
	local info verify vrc team signer state expect loc vendor_name
	ENTRY_SIGNER=""
	[[ "$OS" == Darwin && "$program" == /* ]] || return 0
	# With /usr/bin/env or /bin/sh the payload is the script.
	sip_path "$program" && return 0
	command -v "$CODESIGN" >/dev/null 2>&1 || return 0
	is_macho "$program" || return 0

	info="$("$CODESIGN" -dv --verbose=2 "$program" 2>&1)"
	verify="$("$CODESIGN" --verify --deep --strict "$program" 2>&1)"
	vrc=$?
	team="$(printf '%s\n' "$info" | sed -n 's/^TeamIdentifier=//p' | head -n 1)"
	[[ "$team" == "not set" ]] && team=""
	signer="$(printf '%s\n' "$info" | sed -n 's/^Authority=//p' | head -n 1)"
	signer="${signer#Developer ID Application: }"
	signer="${signer% ("$team")}"

	if printf '%s\n%s\n' "$info" "$verify" | grep -q 'not signed at all'; then
		state=unsigned
		ENTRY_SIGNER="unsigned"
	elif printf '%s\n' "$info" | grep -q '^Signature=adhoc'; then
		state=adhoc
		ENTRY_SIGNER="ad-hoc signed"
	elif [[ "$vrc" -ne 0 ]]; then
		state=invalid
		ENTRY_SIGNER="signature invalid"
	else
		state=valid
		ENTRY_SIGNER="signed: ${signer:-unknown}${team:+ [$team]}"
	fi

	loc="$(tilde "$where") -> $(tilde "$program")"
	expected_teams "$label"
	if [[ -n "$EXPECT" && ("$state" != valid || " $EXPECT" != *" $team "*) ]]; then
		expect="${EXPECT% }"
		vendor_name=""
		[[ "$state" == valid && "$EXPECT_SRC" == "vendor table" ]] &&
			vendor_name="$(awk -F'\t' -v p="$VENDOR_PREFIX" '$1 == p { sub(/, from .*/, "", $3); print $3; exit }' "$VENDOR_FILE")"
		# Apple verifies Developer ID organization names, so the vendor's own name under an
		# unlisted team is a table gap to confirm, not impersonation.
		if [[ -n "$vendor_name" && "$(printf '%s' "$signer" | tr '[:upper:]' '[:lower:]')" == "$(printf '%s' "$vendor_name" | tr '[:upper:]' '[:lower:]')" ]]; then
			finding MEDIUM "$id:vendor-unlisted" "A login item is signed by a Team ID the vendor table does not list" "$loc" "label $label: table lists ${expect// / or }; binary is $ENTRY_SIGNER" "The signer name matches the vendor. Confirm with \`codesign -dv\` on the vendor's own app, then add the Team ID to vendor-teams.tsv."
		else
			finding HIGH "$id:vendor-mismatch" "A login item claims a vendor it is not signed by" "$loc" "label $label expects Team ID ${expect// / or } ($EXPECT_SRC); binary is $ENTRY_SIGNER" "Preserve the plist and the binary, unload the entry, and reinstall the vendor's software from its own site."
		fi
	elif [[ "$state" == invalid ]]; then
		verify="$(printf '%s\n' "$verify" | head -n 1)"
		finding MEDIUM "$id:bad-signature" "A login item's program fails its code-signature check" "$loc" "codesign --verify: ${verify#"$program: "}" "The binary changed after it was signed. Compare it with a fresh copy from the vendor before you trust it."
	elif [[ "$state" != valid ]] && staging_zone "$program"; then
		finding MEDIUM "$id:unsigned" "An unsigned program in a user-writable location runs at login" "$loc" "$ENTRY_SIGNER" "Confirm you built or installed it. Vendor updaters that run from Application Support are signed; staged malware usually is not."
	elif [[ "$state" != valid ]]; then
		finding INFO "$id:unsigned" "A login item runs an unsigned program" "$loc" "$ENTRY_SIGNER (System Settings shows it as an unidentified developer)" "Tools built from source are often unsigned. Confirm where it came from."
	fi
}

# audit_payload_dirs — capture-tool folders in Application Support that no
# LaunchAgent points at. A folder named for a capture tool, holding a script
# beside its own .log/.pid, is staged for something even before it runs.
audit_payload_dirs() {
	local base="$HOME_DIR/Library/Application Support" d name f flist=""
	local has_script=0 has_artifact=0
	[[ -d "$base" ]] || return 0
	for d in "$base"/*/; do
		[[ -d "$d" ]] || continue
		name="$(basename "$d")"
		has "$name" "$RE_CAPTURE_DIR_NAME" || continue
		has_script=0 has_artifact=0 flist=""
		for f in "$d"*.js "$d"*.mjs "$d"*.cjs "$d"*.sh "$d"*.py "$d"*.rb "$d"*.pl; do
			[[ -f "$f" ]] || continue
			has_script=1
			flist="${flist}${flist:+, }$(basename "$f")"
		done
		for f in "$d"*.log "$d"*.pid; do
			[[ -f "$f" ]] || continue
			has_artifact=1
			flist="${flist}${flist:+, }$(basename "$f")"
		done
		if [[ "$has_script" == 1 && "$has_artifact" == 1 ]]; then
			finding MEDIUM "payloaddir:$(cksum_id "$d")" "A capture-tool folder holds a script and its runtime files" "$(tilde "$d")" "contains $flist" "Read the script. If you did not install it, preserve the folder as evidence and remove it, then rotate anything it could have collected."
		fi
	done
}

audit_launchd() {
	local d f dirs
	local dir_list=()
	if [[ -n "${AIC_HOST_LAUNCH_DIRS:-}" ]]; then
		dirs="$AIC_HOST_LAUNCH_DIRS"
	else
		dirs="$HOME_DIR/Library/LaunchAgents:/Library/LaunchAgents:/Library/LaunchDaemons"
	fi
	IFS=: read -r -a dir_list <<<"$dirs"
	local plists=() n=0
	for d in "${dir_list[@]}"; do
		[[ -d "$d" ]] || continue
		for f in "$d"/*.plist; do
			[[ -f "$f" ]] && plists+=("$f")
		done
	done
	for f in ${plists[@]+"${plists[@]}"}; do
		n=$((n + 1))
		item_progress "$n" "${#plists[@]}" "$(basename "$f")"
		audit_plist "$f"
	done
}

# unit_command <file> <key-regex> — the command line a unit or autostart file runs.
unit_command() {
	awk -v re="$2" '$0 ~ re { sub(/^[^=]*=[-@+!]*/, ""); print; exit }' "$1"
}

audit_linux_units() {
	local f line prog
	for f in "$HOME_DIR"/.config/systemd/user/*.service; do
		[[ -f "$f" ]] || continue
		line="$(unit_command "$f" '^ExecStart=')"
		[[ -n "$line" ]] || continue
		# shellcheck disable=SC2086 # word splitting is the point: the unit line is a command line.
		set -- $line
		prog="$1"
		shift
		assess_entry "systemd:$(basename "$f")" "$f" "$(basename "$f" .service)" "$prog" "$@"
	done
	for f in "$HOME_DIR"/.config/autostart/*.desktop; do
		[[ -f "$f" ]] || continue
		line="$(unit_command "$f" '^Exec=')"
		[[ -n "$line" ]] || continue
		# shellcheck disable=SC2086
		set -- $line
		prog="$1"
		shift
		assess_entry "autostart:$(basename "$f")" "$f" "$(basename "$f" .desktop)" "$prog" "$@"
	done
}

audit_cron() {
	local tab line
	if [[ -n "${AIC_HOST_CRONTAB_FILE:-}" ]]; then
		tab="$(cat "$AIC_HOST_CRONTAB_FILE" 2>/dev/null)"
	else
		tab="$(crontab -l 2>/dev/null)"
	fi
	while IFS= read -r line; do
		case "$line" in '' | '#'*) continue ;; esac
		if has "$line" '(curl|wget)[^|]*\|[[:space:]]*(ba|z)?sh'; then
			finding HIGH "cron:$(cksum_id "$line")" "Cron job pipes a remote script to a shell" "user crontab" "$(printf '%s' "$line" | redact)" "Remove the entry and find out who added it."
		elif has "$line" '(Application Support|/tmp/|/var/tmp/|/private/tmp/|/[.][A-Za-z0-9_-]+/)'; then
			finding MEDIUM "cron:$(cksum_id "$line")" "Cron job runs from a user-writable location" "user crontab" "$(printf '%s' "$line" | redact)" "Confirm you added it."
		fi
	done <<<"$tab"
}

# --- shell startup files ---------------------------------------------------------------

# rc_rule <file> <display> <sev> <title> <regex> <next> — flag matching non-comment lines.
# RC_EXEMPT (regex, lowercase): toolchain paths removed from a line before it is matched,
# so they cannot hide another path on the same line.
rc_rule() {
	local n line
	while IFS= read -r n; do
		[[ -n "$n" ]] || continue
		line="$(sed -n "${n}p" "$1")"
		finding "$3" "rc:$2:$n" "$4" "$(tilde "$1"):$n" "$(printf '%s' "$line" | redact) (file changed $(mtime_date "$1"))" "$6"
	done <<<"$(RE="$5" EX="${RC_EXEMPT:-}" awk 'BEGIN { re = tolower(ENVIRON["RE"]); ex = ENVIRON["EX"] } { l = $0; sub(/^[ \t]+/, "", l); if (l ~ /^#/) next; t = tolower($0); if (ex != "") gsub(ex, "", t); if (t ~ re) print FNR }' "$1")"
}

# rc_rules <file> <display> — every startup-file indicator. High rules run first
# because a finding is keyed by file:line: the first match on a line wins.
rc_rules() {
	local f="$1" disp="$2"
	rc_rule "$f" "$disp" HIGH "Remote script piped to a shell in a startup file" '(curl|wget)[^|#]*[|][[:space:]]*(sudo[[:space:]]+)?(ba|z|k)?sh([[:space:]]|$)' "Remove it. Installers run once; they do not belong in a file that runs on every shell start."
	rc_rule "$f" "$disp" HIGH "Decoded payload run from a startup file" 'base64[[:space:]]+(-d|--decode)[^|#]*[|][[:space:]]*(ba|z)?sh' "Remove it and find out how it got there."
	# shellcheck disable=SC2016 # the backtick is a regex character, not a substitution
	rc_rule "$f" "$disp" HIGH "eval of a downloaded or decoded script" 'eval[[:space:]].*([$][(]|`)[^)`]*(curl|wget|base64|atob|decode)|eval[[:space:]]+["'"'"']?[$][(]?[[:space:]]*(curl|wget)' "Remove it and find out how it got there."
	rc_rule "$f" "$disp" HIGH "Library injection through the environment" '(dyld_insert_libraries|ld_preload)=' "Remove it. Legitimate tools do not set this globally."
	rc_rule "$f" "$disp" HIGH "TLS certificate checks disabled in a startup file" 'node_tls_reject_unauthorized[[:space:]]*=[[:space:]]*["'"'"']?0' "Remove it. Every TLS connection this shell makes becomes forgeable."
	rc_rule "$f" "$disp" HIGH "Node run with a forced preload module" 'node_options=.*--require' "Remove it. This loads attacker code into every Node process you start."
	rc_rule "$f" "$disp" HIGH "Clipboard or messaging exfiltration in a startup file" 'api[.]telegram[.]org|pbpaste[^#]*[|][^#]*(curl|nc|wget)' "Remove it, preserve the file, and rotate anything copied since it was added."
	rc_rule "$f" "$disp" MEDIUM "sudo, su or ssh replaced by an alias or function" 'alias[[:space:]]+(sudo|su|ssh|scp|git|npm|npx|security)=|^[[:space:]]*(function[[:space:]]+)?(sudo|su|ssh)[[:space:]]*[(][)]' "This is how passwords and tokens get captured. Confirm you wrote it."
	rc_rule "$f" "$disp" MEDIUM "Background launcher from a user-writable path" '(nohup|setsid|disown)[^#]*(application support|/tmp/|/var/tmp/|/private/tmp/|/var/folders/|/[.][[:alnum:]_-]+/)' "Confirm you wrote it."
	rc_rule "$f" "$disp" MEDIUM "PATH is prefixed with a writable directory" 'path=.*(/tmp|/var/tmp|/private/tmp|/var/folders|application support|/users/shared|/downloads|/[.]cache)/' "Confirm you added it. A writable directory early on PATH lets its contents run as you."
	RC_EXEMPT='/[.](cargo|deno|bun|rvm|nvm|pyenv|rbenv|sdkman|asdf|volta|fnm|ghcup|opam|orbstack|oh-my-zsh|zinit|zplug|antigen|zprezto|fzf|tmux|conda|local/bin|config/(fish|zsh|nvm|gh))/' \
		rc_rule "$f" "$disp" MEDIUM "A startup file loads a script from a writable or hidden directory" '(^|[^[:alnum:]_])(source|\.)[[:space:]]+[^#]*(([$]home|~)?/(tmp|var/tmp|private/tmp|var/folders|users/shared|downloads)/|application support|/[.][[:alnum:]_-]+/)' "Confirm you know this file. A sourced script runs with the same access you have."
	rc_rule "$f" "$disp" MEDIUM "AppleScript run from a startup file" 'osascript[[:space:]]+-e' "Confirm you wrote it."
	rc_rule "$f" "$disp" MEDIUM "AI-tool API base URL redirected in a startup file" '(anthropic|openai|gemini|openrouter|google)[a-z_]*(base_url|api_url|endpoint|host)[[:space:]]*=' "Model traffic and credentials go wherever this points. Confirm you set it."
	rc_rule "$f" "$disp" MEDIUM "Shell traffic routed through a proxy in a startup file" '(http_proxy|https_proxy|all_proxy)[[:space:]]*=' "Confirm you set this proxy. It can read and rewrite everything the shell sends."
	rc_rule "$f" "$disp" MEDIUM "An extra certificate authority is trusted in a startup file" '(node_extra_ca_certs|ssl_cert_file)[[:space:]]*=' "Confirm you added it. It lets that authority intercept your TLS traffic."
}

# audit_rc_file <file> <display> [depth] — rules, then one level of sourcing, then
# a recent-change INFO only when nothing else was found in the file.
audit_rc_file() {
	local f="$1" disp="$2" depth="${3:-0}" s sf
	rc_rules "$f" "$disp"

	if [[ "$depth" == 0 ]]; then
		while IFS= read -r s; do
			[[ -n "$s" ]] || continue
			# shellcheck disable=SC2016 # matching literal $HOME text found in the rc file
			case "$s" in
			'~'/*) sf="$HOME_DIR/${s#'~'/}" ;;
			'$HOME'/*) sf="$HOME_DIR/${s#'$HOME'/}" ;;
			'${HOME}'/*) sf="$HOME_DIR/${s#'${HOME}'/}" ;;
			/*) sf="$s" ;;
			*) sf="$(dirname "$f")/$s" ;;
			esac
			[[ -f "$sf" ]] || continue
			case "$RC_SEEN" in *"|$sf|"*) continue ;; esac
			RC_SEEN="${RC_SEEN}${sf}|"
			audit_rc_file "$sf" "$disp -> $(basename "$sf")" 1
		done <<<"$(sed -nE 's@^[[:space:]]*(source|\.)[[:space:]]+["'"'"']?([^"'"'"'[:space:];#]+).*@\2@p' "$f" 2>/dev/null)"
	fi

	case "$FINDINGS" in
	*"$US""rc:$disp:"*) return 0 ;;
	esac
	if [[ "$(age_days "$f")" -le 30 ]]; then
		finding INFO "rc:$disp:recent" "A startup file changed in the last 30 days" "$(tilde "$f")" "changed $(mtime_date "$f")" "Confirm you know why."
	fi
}

# zdotdir_from_zshenv — the last ZDOTDIR assignment in ~/.zshenv, with $HOME, ~ and
# XDG_CONFIG_HOME expanded. Empty when absent or built from anything else.
zdotdir_from_zshenv() {
	local v xdg="${XDG_CONFIG_HOME:-$HOME_DIR/.config}"
	[[ -f "$HOME_DIR/.zshenv" ]] || return 0
	v="$(sed -nE 's/^[[:space:]]*(export[[:space:]]+)?ZDOTDIR=["'"'"']?([^"'"'"'#[:space:]]+).*/\2/p' "$HOME_DIR/.zshenv" | tail -n 1)"
	# shellcheck disable=SC2016 # literal variable text from the file
	v="${v//'${XDG_CONFIG_HOME:-$HOME/.config}'/$xdg}"
	# shellcheck disable=SC2016
	v="${v//'${XDG_CONFIG_HOME}'/$xdg}"
	# shellcheck disable=SC2016
	v="${v//'$XDG_CONFIG_HOME'/$xdg}"
	# shellcheck disable=SC2016
	v="${v//'${HOME}'/$HOME_DIR}"
	# shellcheck disable=SC2016
	v="${v//'$HOME'/$HOME_DIR}"
	case "$v" in '~'/*) v="$HOME_DIR/${v#'~'/}" ;; esac
	case "$v" in /*) [[ "$v" == *'$'* ]] || printf '%s' "$v" ;; esac
}

audit_rc_files() {
	local f fd disp
	for f in "$HOME_DIR"/.zshrc "$HOME_DIR"/.zprofile "$HOME_DIR"/.zshenv "$HOME_DIR"/.zlogin "$HOME_DIR"/.bashrc "$HOME_DIR"/.bash_profile "$HOME_DIR"/.bash_login "$HOME_DIR"/.profile "$HOME_DIR"/.config/fish/config.fish; do
		[[ -f "$f" ]] || continue
		disp="${f#"$HOME_DIR"/}"
		audit_rc_file "$f" "$disp"
	done
	# zsh reads its startup files from ZDOTDIR; ~/.zshenv usually sets it, so this
	# process's environment may not have it.
	local zd="${ZDOTDIR:-}"
	[[ -n "$zd" ]] || zd="$(zdotdir_from_zshenv)"
	if [[ -n "$zd" && "$zd" != "$HOME_DIR" && -d "$zd" ]]; then
		for f in "$zd"/.zshrc "$zd"/.zprofile "$zd"/.zshenv "$zd"/.zlogin; do
			[[ -f "$f" ]] || continue
			audit_rc_file "$f" "ZDOTDIR/${f##*/}"
		done
	fi
	for fd in "$HOME_DIR"/.config/fish/conf.d/*.fish; do
		[[ -f "$fd" ]] || continue
		audit_rc_file "$fd" "${fd#"$HOME_DIR"/}"
	done
}

# --- AI-tool configuration -------------------------------------------------------------

# value_after_key <line> <key-regex> — the value assigned to a JSON/TOML/INI key
# on a line. Handles `"KEY": "v"`, `KEY = "v"` and `KEY=v`. The key regex must be
# a single group; the value is its first capture after it (group 2 of the match).
value_after_key() {
	printf '%s' "$1" | sed -nE "s#.*$2[^:=]*[:=][[:space:]]*\"?([^\",'[:space:]}]*).*#\2#p"
}

# url_host <value> — host portion of a URL or host[:port], lowercased, brackets
# removed so [::1] is seen the same as ::1.
url_host() {
	local h="$1"
	[[ "$h" == *://* ]] && h="${h#*://}"
	h="${h%%/*}"
	h="${h%%[?#]*}"
	h="${h##*@}"
	case "$h" in
	'['*']'*)
		h="${h#\[}"
		h="${h%%]*}"
		;;
	esac
	case "$h" in
	::1 | ::1:* | 0:0:0:0:0:0:0:1) printf '%s' "::1" ;;
	*:*) printf '%s' "${h%%:*}" ;;
	*) printf '%s' "$h" ;;
	esac
}

# url_port <url> — the port of the authority, or nothing. A colon in the path
# or in userinfo is not a port.
url_port() {
	local h="$1" p=""
	[[ "$h" == *://* ]] && h="${h#*://}"
	h="${h%%/*}"
	h="${h%%[?#]*}"
	h="${h##*@}"
	case "$h" in
	'['*']:'*) p="${h##*]:}" ;;
	'['*) ;;
	*:*:*) ;;
	*:*) p="${h##*:}" ;;
	esac
	case "$p" in
	'' | *[!0-9]*) return 0 ;;
	esac
	printf '%s' "$p"
}

# is_loopback_host <host> — every shape of "this machine" that a proxy can bind.
is_loopback_host() {
	local h
	h="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
	case "$h" in
	localhost | localhost.* | 127.* | 0.0.0.0 | ::1 | :: | host.docker.internal) return 0 ;;
	esac
	return 1
}

# is_vendor_host <host> — the API hosts a tool is allowed to talk to.
is_vendor_host() {
	local h
	h="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
	case "$h" in
	api.anthropic.com | api.openai.com | generativelanguage.googleapis.com | openrouter.ai) return 0 ;;
	esac
	return 1
}

# looks_like_host <value> — a URL, host:port or dotted name; not a bare word.
looks_like_host() {
	local v="$1"
	[[ "$v" == *://* ]] && return 0
	case "$v" in
	localhost | localhost:* | host.docker.internal | host.docker.internal:* | 127.* | 0.0.0.0 | ::1 | *.* | *:*) return 0 ;;
	esac
	return 1
}

# listener_for_port <port> — who holds a local port, shown as the FULL command
# line (`ps -o command=`), not the truncated process name.
listener_for_port() {
	command -v lsof >/dev/null 2>&1 || return 0
	local pid cmd
	pid="$(lsof -nP -iTCP:"$1" -sTCP:LISTEN -Fp 2>/dev/null | sed -n 's/^p//p' | head -n1)"
	[[ -n "$pid" ]] || return 0
	cmd="$(ps -o command= -p "$pid" 2>/dev/null | head -n1)"
	[[ -n "$cmd" ]] || cmd="$(lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | awk 'NR == 2 { print $1 }')"
	[[ -n "$cmd" ]] || return 0
	printf 'pid %s: %s' "$pid" "$(printf '%s' "$cmd" | redact)"
}

audit_agent_text() {
	local f="$1" disp="$2" n line url host port who key label
	# (a) Any base-URL-like key, in any case, pointing at loopback in any form,
	# at a bare host:port, or at a remote host that is not a known vendor.
	while IFS=: read -r n line; do
		[[ -n "$n" ]] || continue
		url="$(value_after_key "$line" "$RE_AGENT_URL_KEY")"
		[[ -n "$url" ]] || continue
		looks_like_host "$url" || continue
		host="$(url_host "$url")"
		if is_loopback_host "$host"; then
			port=$(url_port "$url")
			who=""
			[[ -n "$port" ]] && who="$(listener_for_port "$port")"
			finding HIGH "agent:$disp:base-url:$n" "Model traffic is routed through a local proxy" "$disp:$n" "$(printf '%s' "$url" | redact); listener: ${who:-none found}" "Find out what listens on that port and who installed it. It sees every prompt, file and key your tool sends."
		elif ! is_vendor_host "$host"; then
			finding MEDIUM "agent:$disp:base-url:$n" "Model traffic is sent to a non-official host" "$disp:$n" "$(printf '%s' "$url" | redact)" "Confirm you configured this gateway. It sees every prompt, file and key your tool sends."
		fi
	done <<<"$(grep -nEi "$RE_AGENT_URL_KEY" "$f" 2>/dev/null)"

	# (c) Permission bypass, in the forms JSON and TOML configs use.
	if grep -Eiq '"defaultMode"[[:space:]]*:[[:space:]]*"bypassPermissions"|dangerously-skip-permissions|skipDangerousModePermissionPrompt"?[[:space:]]*:[[:space:]]*true|approval_policy[[:space:]]*=[[:space:]]*"?never"?|sandbox_mode[[:space:]]*=[[:space:]]*"?danger-full-access"?' "$f" 2>/dev/null; then
		finding HIGH "agent:$disp:bypass" "Permission prompts are switched off by default" "$disp" "bypassPermissions, approval_policy=never, or sandbox_mode=danger-full-access is set" "Remove it. Every tool call then runs without asking, including anything a poisoned file tells the agent to do."
	fi
	if grep -Eiq 'enableAllProjectMcpServers"?[[:space:]]*:[[:space:]]*true' "$f" 2>/dev/null; then
		finding MEDIUM "agent:$disp:mcp-all" "Every project can turn on its own MCP servers" "$disp" "enableAllProjectMcpServers is true" "Approve MCP servers per project instead."
	fi
	if grep -Eiq '"apiKeyHelper"[[:space:]]*:' "$f" 2>/dev/null; then
		finding MEDIUM "agent:$disp:key-helper" "A command runs whenever the tool needs a key" "$disp" "apiKeyHelper is set" "Confirm you configured it and read the command."
	fi

	# (d) A named key env var set to a literal, then a shape-only sweep so a
	# secret is reported wherever it is written. Values are never printed.
	while IFS=: read -r n line; do
		key="$(printf '%s' "$line" | sed -nE 's#.*"?((ANTHROPIC|OPENAI|OPENROUTER|GEMINI|GOOGLE)[A-Z_]*(API_KEY|AUTH_TOKEN))"?[[:space:]]*[:=].*#\1#p')"
		[[ -n "$key" ]] || continue
		finding MEDIUM "agent:$disp:key:$key" "API key stored in plain text" "$disp:$n" "$key is set to a literal value (not shown)" "Move it to a secret manager and rotate it: any process running as you can read this file."
	done <<<"$(grep -nEi '"?(ANTHROPIC|OPENAI|OPENROUTER|GEMINI|GOOGLE)[A-Z_]*(API_KEY|AUTH_TOKEN)"?[[:space:]]*[:=][[:space:]]*"[^"$]{12,}"' "$f" 2>/dev/null)"
	while IFS=: read -r n line; do
		[[ -n "$n" ]] || continue
		label=""
		case "$line" in
		*sk-ant-*) label="an Anthropic key" ;;
		*ghp_* | *github_pat_*) label="a GitHub token" ;;
		*AKIA*) label="an AWS access key" ;;
		*xoxb-* | *xoxp-*) label="a Slack token" ;;
		*)
			if has "$line" '[0-9]{8,10}:[A-Za-z0-9_-]{35}'; then label="a Telegram bot token"; elif has "$line" 'sk-[A-Za-z0-9]{20,}'; then label="an API key"; fi
			;;
		esac
		[[ -n "$label" ]] || continue
		finding MEDIUM "agent:$disp:secret:$n" "A secret is stored in plain text" "$disp:$n" "$label (value not shown)" "Move it to a secret manager and rotate it: any process running as you can read this file."
	done <<<"$(grep -nE "$RE_SECRET_SHAPE" "$f" 2>/dev/null)"

	# (f) Trust and injection variables in the tool's env block: they weaken TLS,
	# redirect it, or load code, for every process the tool starts.
	if grep -Eiq '"?NODE_TLS_REJECT_UNAUTHORIZED"?[[:space:]]*[:=][[:space:]]*"?0' "$f" 2>/dev/null; then
		finding HIGH "agent:$disp:tls-off" "TLS certificate checks are disabled for the tool" "$disp" "NODE_TLS_REJECT_UNAUTHORIZED is 0" "Remove it. Every HTTPS connection the tool makes becomes forgeable."
	fi
	if grep -Eiq '"?(NODE_EXTRA_CA_CERTS|SSL_CERT_FILE|SSL_CERT_DIR|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE)"?[[:space:]]*[:=]' "$f" 2>/dev/null; then
		finding MEDIUM "agent:$disp:ca-trust" "The tool trusts an extra certificate authority" "$disp" "a CA bundle variable is set" "Confirm you added it. It lets that authority read the tool's HTTPS traffic."
	fi
	if grep -Eiq '"?NODE_OPTIONS"?[[:space:]]*[:=][[:space:]]*"[^"]*--(require|import|loader)|"?(DYLD_INSERT_LIBRARIES|LD_PRELOAD)"?[[:space:]]*[:=]' "$f" 2>/dev/null; then
		finding HIGH "agent:$disp:preload" "The tool loads extra code into its processes" "$disp" "NODE_OPTIONS --require/--import or a library preload is set" "Remove it and find out how it got there."
	fi
}

# hook_dangerous_path <command> — true when a hook runs code from a place a
# normal tool does not: node_modules, temp, caches, or your own dot-directories.
hook_dangerous_path() {
	local cmd="$1"
	if printf '%s' "$cmd" | grep -Eq "$RE_HOOK_BAD_PATH"; then
		return 0
	fi
	# Language-toolchain bin directories (pipx, cargo, bun, ...) are removed before the
	# hidden-directory check, so they cannot hide another path in the same command.
	cmd="$(printf '%s' "$cmd" | sed -E 's#/\.(local/bin|cargo/bin|bun/bin|volta/bin|nvm/versions|pnpm)/##g')"
	if printf '%s' "$cmd" | sed -E 's#/\.(claude|codex|cursor|gemini|config)/##g' | grep -Eq '/\.[[:alnum:]_-]+/'; then
		return 0
	fi
	case "$cmd" in
	*"$HOME_DIR"/*)
		case "$cmd" in
		*"/.claude/"* | *"/.codex/"* | *"/.cursor/"* | *"/.gemini/"*) ;;
		*) return 0 ;;
		esac
		;;
	esac
	return 1
}

audit_agent_json() {
	local f="$1" disp="$2" scope="$3" rows cmd events sev title next cmdline name mtype murl
	if ! command -v jq >/dev/null 2>&1; then
		if [[ "$JQ_NOTED" == 0 ]]; then
			JQ_NOTED=1
			finding MEDIUM "agent:jq-missing" "Agent hooks and MCP servers were not inspected" "$disp" "jq was not found on PATH" "Install jq and run again. The audit stays open rather than reporting a check it could not perform."
		fi
		return 0
	fi

	rows="$(jq -r '(.hooks // {}) | to_entries[] | .key as $e | (.value // [])[] | (.hooks // [])[] | select(.type == "command") | "\($e)\t\(.command)"' "$f" 2>/dev/null |
		awk -F'\t' '{ c = $2; for (i = 3; i <= NF; i++) c = c "\t" $i; if (!(c in ev)) order[++n] = c; ev[c] = ev[c] (ev[c] == "" ? "" : ",") $1 } END { for (i = 1; i <= n; i++) print order[i] "\t" ev[order[i]] }')"
	while IFS=$'\t' read -r cmd events; do
		[[ -n "$cmd" ]] || continue
		sev="" title="" next="Read the command and confirm you installed it."
		# (b) A hook that runs code from a user-writable place is high: it is
		# attacker-controlled code running on every matching event.
		if hook_dangerous_path "$cmd"; then
			sev=HIGH
			title="Hook runs code from a user-writable location"
			next="Preserve the command and the file it runs, then remove the hook. Confirm nothing it could have read or changed."
		elif has "$cmd" 'api\.telegram|pbpaste|discord(app)?\.com/api/webhooks'; then
			sev=HIGH
			title="Hook reports to a remote service"
		elif has "$cmd" '(^|[^[:alnum:]_])(curl|wget|nc|ncat|socat|base64|osascript|nohup)([^[:alnum:]_]|$)'; then
			sev=MEDIUM
			title="Hook runs a network or obfuscation primitive"
		elif [[ "$scope" == user ]] && has "$events" 'UserPromptSubmit|PreToolUse|PostToolUse|SessionStart|PreCompact|Stop|Subagent|SessionEnd'; then
			sev=MEDIUM
			title="Global hook observes your prompts and tool calls"
			has "$events" 'UserPromptSubmit|SessionStart' && next="It can also add text to what the model reads, in every project. $next"
		elif [[ "$VERBOSE" == 1 ]]; then
			sev=INFO
			title="Project hook"
		fi
		[[ -n "$sev" ]] || continue
		finding "$sev" "hook:$scope:$(cksum_id "$cmd")" "$title" "$disp" "on $events: $(printf '%s' "$cmd" | redact)" "$next"
	done <<<"$rows"

	while IFS=$'\037' read -r name mtype murl cmdline; do
		[[ -n "$name" ]] || continue
		if [[ -n "$murl" ]] && has "$murl" '^https?://|^wss?://'; then
			finding MEDIUM "mcp:$disp:$name" "MCP server is a remote URL" "$disp ($name)" "type ${mtype:-unknown}: $(printf '%s' "$murl" | redact)" "Confirm who runs that service. Anything the tool sends, including file contents, reaches it."
		elif has "$cmdline" '(curl|wget)[^|]*[|][[:space:]]*(ba|z)?sh'; then
			finding HIGH "mcp:$disp:$name" "MCP server downloads and runs code" "$disp ($name)" "$(printf '%s' "$cmdline" | redact)" "Remove it."
		elif has "$cmdline" '(^|[[:space:]/])(npx|bunx|uvx|pnpm[[:space:]]+dlx|npm[[:space:]]+exec|pipx[[:space:]]+run)([[:space:]]|$)' &&
			! has "$cmdline" '@[0-9]+[.][0-9]+|==[0-9]|#[0-9a-f]{7,40}'; then
			finding MEDIUM "mcp:$disp:$name" "MCP server runs unpinned code" "$disp ($name)" "$(printf '%s' "$cmdline" | redact)" "Pin an exact version or commit. Today's latest release, or the repository's HEAD, runs with your permissions."
		fi
	done <<<"$(jq -r '(.mcpServers // {}) | to_entries[] | "\(.key)\u001f\(.value.type // "")\u001f\(.value.url // "")\u001f\(.value.command // "") \((.value.args // []) | map(tostring) | join(" "))"' "$f" 2>/dev/null)"
}

# audit_agent_file <file> — one user-scope AI-tool config file.
audit_agent_file() {
	local f="$1" disp
	[[ -f "$f" ]] || return 0
	disp="$(tilde "$f")"
	audit_agent_text "$f" "$disp"
	audit_agent_json "$f" "$disp" user
}

audit_agent_config() {
	local f d
	local claude_dir="${CLAUDE_CONFIG_DIR:-$HOME_DIR/.claude}"
	local codex_dir="${CODEX_HOME:-$HOME_DIR/.codex}"
	local managed="${AIC_HOST_MANAGED_DIRS:-/Library/Application Support/ClaudeCode:/etc/claude-code}"
	local md_dirs=()

	for f in \
		"$claude_dir/settings.json" "$claude_dir/settings.local.json" \
		"$HOME_DIR/.claude.json" \
		"$HOME_DIR/.gemini/settings.json" "$HOME_DIR/.gemini"/*.json \
		"$HOME_DIR/.cursor/mcp.json" "$HOME_DIR/.cursor"/*.json \
		"$HOME_DIR/.kilocode" "$HOME_DIR/.kilocode"/*.json \
		"$HOME_DIR/.config/opencode/opencode.json" "$HOME_DIR/.config/opencode"/*.json \
		"$codex_dir/config.toml" "$codex_dir/hooks.json"; do
		audit_agent_file "$f"
	done

	# Managed (root-installed) settings, with a test seam for their directories.
	IFS=: read -r -a md_dirs <<<"$managed"
	for d in "${md_dirs[@]}"; do
		[[ -d "$d" ]] || continue
		for f in "$d"/*.json; do
			audit_agent_file "$f"
		done
	done
}

# audit_folder_agent_config — the whole of the default (folder) run.
audit_folder_agent_config() {
	local f disp
	for f in "$PROJECT_DIR/.claude/settings.json" "$PROJECT_DIR/.claude/settings.local.json" "$PROJECT_DIR/.mcp.json"; do
		[[ -f "$f" ]] || continue
		# --system already read the home folder's .claude settings as user-level config.
		[[ "$SYSTEM" == 1 && "$PROJECT_DIR" == "$HOME_DIR" && "$f" == */.claude/* ]] && continue
		disp="./${f#"$PROJECT_DIR"/}"
		audit_agent_text "$f" "$disp"
		audit_agent_json "$f" "$disp" project
	done
}

# --- running processes -----------------------------------------------------------------

# proc_staging <path> — narrower than staging_zone: hidden home directories are where
# version managers and dev tools live, so processes there are not flagged by place alone.
proc_staging() {
	case "$1" in
	*"/Application Support/"* | */Library/Caches/* | */Downloads/* | /tmp/* | /var/tmp/* | /private/tmp/* | /var/folders/* | /private/var/folders/* | /Users/Shared/*) return 0 ;;
	esac
	return 1
}

proc_cwd() {
	command -v lsof >/dev/null 2>&1 || return 0
	lsof -a -p "$1" -d cwd -Fn 2>/dev/null | awk '/^n/ { print substr($0, 2); exit }'
}

audit_processes() {
	local rows pid user cmd script path
	if [[ -n "${AIC_HOST_PS_FILE:-}" ]]; then
		rows="$(cat "$AIC_HOST_PS_FILE" 2>/dev/null)"
	else
		rows="$(ps -axo pid=,user=,command= 2>/dev/null)"
	fi
	while read -r pid user cmd; do
		[[ -n "$cmd" ]] || continue
		case "$cmd" in *host-audit.sh* | *"am-i-hacked host"* | *"am-i-compromised host"*) continue ;; esac
		is_interpreter "${cmd%% *}" || continue
		script="$(printf '%s' "$cmd" | awk '{ for (i = 2; i <= NF; i++) if ($i !~ /^-/) { print $i; exit } }')"
		[[ -n "$script" ]] || continue
		path="$script"
		if [[ "$script" != /* ]]; then
			path="$(proc_cwd "$pid")"
			[[ -n "$path" ]] && path="$path/$script"
		fi
		if has "$script" "$RE_CAPTURE_WORD" && has "$script" 'tg|telegram|discord|webhook|exfil|upload|send'; then
			finding HIGH "proc:$(cksum_id "$cmd")" "Running process looks like a capture tool that reports out" "pid $pid ($user)" "$(printf '%s' "$cmd" | redact)" "Do not kill it yet if you need evidence: note its pid, working directory (lsof -p $pid) and open connections, then stop it."
		elif [[ -n "$path" && "$path" != *"/node_modules/"* ]] && proc_staging "$path"; then
			finding MEDIUM "proc:$(cksum_id "$cmd")" "Interpreter running a script from a user-writable location" "pid $pid ($user)" "$(printf '%s' "$cmd" | redact)" "Confirm you started it."
		fi
	done <<<"$rows"
}

# --- report ------------------------------------------------------------------------------------

render() {
	local sorted line sev id title where evidence next reason nh nm ni count color
	nh=0 nm=0 ni=0
	sorted="$(printf '%s' "$FINDINGS" | LC_ALL=C sort -r)"
	while IFS="$US" read -r sev id title where evidence next; do
		[[ -n "$sev" ]] || continue
		case "$sev" in 3*) nh=$((nh + 1)) ;; 2*) nm=$((nm + 1)) ;; *) ni=$((ni + 1)) ;; esac
	done <<<"$sorted"

	if ((nh + nm > 0)); then
		printf '\n%shost-audit: FAILED — %d high, %d medium%s%s\n' "$C_RED" "$nh" "$nm" "$([[ $ni -gt 0 ]] && printf ', %d informational' "$ni")" "$C_RESET"
	fi
	while IFS="$US" read -r sev id title where evidence next; do
		[[ -n "$sev" ]] || continue
		sev="${sev#?}"
		[[ "$sev" == INFO && "$VERBOSE" != 1 ]] && continue
		case "$sev" in HIGH) color="$C_RED" ;; MEDIUM) color="$C_YELLOW" ;; *) color="$C_DIM" ;; esac
		printf '\n  %s%-6s%s %s%s%s\n' "$color" "$sev" "$C_RESET" "$C_BOLD" "$title" "$C_RESET"
		printf '         id: %s\n' "$id"
		printf '         %s\n' "$where"
		# An empty evidence line would leave a bare indent under the arrow.
		[[ -n "$evidence" ]] && printf '         %s\n' "$evidence"
		printf '         %s→ %s%s\n' "$C_DIM" "$next" "$C_RESET"
	done <<<"$sorted"

	count="$(printf '%s' "$ALLOWED" | grep -c . || true)"
	if [[ "${count:-0}" -gt 0 ]]; then
		printf '\n%shost-audit: %d finding(s) allowed by %s%s\n' "$C_YELLOW" "$count" "$(tilde "$ALLOW_FILE")" "$C_RESET"
		while IFS="$US" read -r sev id title where evidence next reason; do
			[[ -n "$sev" ]] || continue
			printf '\n  %s%s%s (allowed)\n         %s\n         reason: %s\n' "$C_DIM" "$id" "$C_RESET" "$title" "$reason"
		done <<<"$ALLOWED"
	fi

	if [[ "$VERBOSE" == 1 && -n "$INVENTORY" ]]; then
		printf '\n%sPersistence entries:%s\n%s' "$C_DIM" "$C_RESET" "$INVENTORY"
	fi

	if [[ "$SYSTEM" != 1 ]]; then
		printf '\n%sfolder scope: %s — machine-wide checks skipped (login items, signatures, crontab, shell startup files, user-level AI-tool config, processes). Run with --system to include them.%s\n' "$C_DIM" "$(tilde "$PROJECT_DIR")" "$C_RESET"
	fi

	if ((nh + nm > 0)); then
		cat <<'EOF'

Do not delete anything yet if you may need evidence: copy suspicious files
somewhere inert first. If a real capture tool was running, assume everything it
could see is exposed, and rotate secrets from a different, clean device.

Not a malware scanner: a clean result does not prove the machine is safe. This
audit does not read microphone, camera, screen or input-monitoring permissions;
review those in your system privacy settings.
EOF
		return 1
	fi
	if [[ "$SYSTEM" != 1 ]]; then
		printf '%shost-audit: PASSED%s — no indicators found in the folder'"'"'s AI-tool configuration\n' "$C_GREEN" "$C_RESET"
		return 0
	fi
	if [[ "$PERSISTENCE_CHECKED" == 0 ]]; then
		printf '%shost-audit: PASSED%s — no indicators found, but persistence was not checked (no login-item checks for %s). Checked: shell startup files, AI-tool configuration, running processes\n' "$C_YELLOW" "$C_RESET" "$OS"
		return 0
	fi
	printf '%shost-audit: PASSED%s — no indicators found (checked: persistence, shell startup files, AI-tool configuration, running processes)\n' "$C_GREEN" "$C_RESET"
	return 0
}

if [[ "$PROGRESS" == 1 && "$SYSTEM" == 1 ]]; then
	printf 'host-audit: auditing this machine and %s\n' "$(tilde "$PROJECT_DIR")" >&2
elif [[ "$PROGRESS" == 1 ]]; then
	printf 'host-audit: auditing %s\n' "$(tilde "$PROJECT_DIR")" >&2
fi
if [[ "$SYSTEM" == 1 ]]; then
	case "$OS" in
	Darwin)
		stage "Login items and their code signatures"
		audit_launchd
		stage "Payload folders"
		audit_payload_dirs
		;;
	Linux)
		stage "systemd user units and autostart entries"
		audit_linux_units
		;;
	*) PERSISTENCE_CHECKED=0 ;;
	esac
	stage "Crontab"
	audit_cron
	stage "Shell startup files"
	audit_rc_files
	stage "User-level AI-tool configuration"
	audit_agent_config
fi
stage "AI-tool configuration in $(tilde "$PROJECT_DIR")"
audit_folder_agent_config
if [[ "$SYSTEM" == 1 ]]; then
	stage "Running processes"
	audit_processes
fi
if [[ "$PROGRESS" == 1 ]]; then
	printf 'host-audit: checks done in %ds\n' "$((SECONDS - AUDIT_START))" >&2
fi
render
