#!/usr/bin/env bash
set -euo pipefail

# secure-semgrep — run the secure-devtools bundled Semgrep rules against a
# target directory (or any path), locally or in CI.
#
# Owned rules live under $PACKAGE/rules. Loadouts layer Semgrep's free registry
# "p/..." packs for a technology on top of the bundled rules so you get
# maintained community coverage without vendoring it into this package.
#
# Design mirrors apps/am-i-compromised: plain shell, no runtime npm deps.
# Only requirement on the host is `semgrep` (>= 1.0) on PATH.

PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES_DIR="${PACKAGE_DIR}/rules"

SEMGREP_BIN="${SEMGREP_BIN:-semgrep}"
readonly PACKAGE_DIR RULES_DIR SEMGREP_BIN

usage() {
	cat <<'EOF'
secure-semgrep — run the bundled Semgrep rules (+ loadout packs) on targets.

usage:
  secure-semgrep [subcommand] [options] [TARGET ...]

subcommands:
  scan     Run semgrep over TARGET (default ".").                 [default]
  check    Validate that every bundled rule file parses. Exit 0 if valid.
  pack     Print the --config list that `scan` would use.

scan / pack options:
  -L, --loadout NAME   Add loadout NAME (repeatable). See LOADOUTS below.
  -N, --no-default     Do NOT add the p/default and p/security-audit packs.
  -e, --no-error       Report findings but exit 0 (default exits 1 on findings).
  -h, --help           Show this help and exit.
  -v, --version        Show version and exit.

Pass extra semgrep flags after -- (scan only):
  secure-semgrep scan -- --severity ERROR

LOADOUTS (bundled rules ai + bash always run):
  ai      AI-agent / LLM-provider best-practice rules (bundled)
  bash    Bash security & correctness rules (bundled)
  py      Semgrep p/python
  js      Semgrep p/javascript
  ts      Semgrep p/typescript
  react   Semgrep p/typescript + p/javascript + p/react
  node    Semgrep p/javascript + p/nodejs
  rust    Semgrep p/rust
  all     Every pack-based loadout above (ai + bash stay local)

Multiple -L flags combine, e.g.:
  secure-semgrep -L react -L py ./src

Without any TARGET, `.` (the current directory) is scanned.
EOF
}

version() {
	local v
	v="$(grep -m1 '"version"' "${PACKAGE_DIR}/package.json" | sed -E 's/.*: *"([^"]+)".*/\1/')"
	echo "secure-semgrep ${v}"
}

require_semgrep() {
	if ! command -v "${SEMGREP_BIN}" >/dev/null 2>&1; then
		echo "secure-semgrep: '${SEMGREP_BIN}' is required but was not found on PATH." >&2
		echo "secure-semgrep: install Semgrep (semgrep.dev) or set SEMGREP_BIN=/path/to/semgrep." >&2
		exit 1
	fi
}

# append_loadout NAME -> appends config entries to the GLOBAL configs array.
# Owned rule dirs are emitted before registry packs so that, on collision,
# Semgrep keeps our owned definition (earliest config wins).
append_loadout() {
	local name="$1"
	case "$name" in
	ai) configs+=("${RULES_DIR}/ai") ;;
	bash) configs+=("${RULES_DIR}/bash") ;;
	py) configs+=("p/python") ;;
	js) configs+=("p/javascript") ;;
	ts) configs+=("p/typescript") ;;
	react)
		configs+=("p/typescript")
		configs+=("p/javascript")
		configs+=("p/react")
		;;
	node)
		configs+=("p/javascript")
		configs+=("p/nodejs")
		;;
	rust) configs+=("p/rust") ;;
	all)
		configs+=("p/typescript")
		configs+=("p/javascript")
		configs+=("p/nodejs")
		configs+=("p/react")
		configs+=("p/python")
		configs+=("p/rust")
		;;
	*)
		echo "secure-semgrep: unknown loadout '$name' (see --help)." >&2
		exit 2
		;;
	esac
}

cmd="scan"
targets=()
loadouts=("ai" "bash")
use_default=1
do_error=1
extra=()

# Consume the optional leading subcommand token.
case "${1:-}" in
scan | check | pack)
	cmd="$1"
	shift
	;;
esac

# Parse options (shared between scan and pack; -e is only meaningful for scan).
while [[ $# -gt 0 ]]; do
	case "$1" in
	-L | --loadout)
		if [[ $# -lt 2 ]]; then
			echo "secure-semgrep: option '$1' requires an argument." >&2
			exit 2
		fi
		loadouts+=("$2")
		shift 2
		;;
	-N | --no-default)
		use_default=0
		shift
		;;
	-e | --no-error)
		do_error=0
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	-v | --version)
		version
		exit 0
		;;
	--)
		shift
		extra+=("$@")
		break
		;;
	-*)
		echo "secure-semgrep: unknown option '$1' (see --help)." >&2
		exit 2
		;;
	*)
		targets+=("$1")
		shift
		;;
	esac
done

require_semgrep

# Expand the selected loadouts into a resolved config list.
configs=()
for l in "${loadouts[@]}"; do
	append_loadout "$l"
done
if [[ "$use_default" -eq 1 ]]; then
	configs+=("p/default")
	configs+=("p/security-audit")
fi

case "$cmd" in
check)
	# Validate only the rules we own. Registry packs are Semgrep's to maintain.
	"${SEMGREP_BIN}" scan --config "${RULES_DIR}" --validate
	;;
pack)
	for c in "${configs[@]}"; do
		printf '%s\n' "$c"
	done
	;;
scan)
	if [[ "${#targets[@]}" -eq 0 ]]; then targets+=("."); fi
	config_args=()
	for c in "${configs[@]}"; do config_args+=(--config "$c"); done
	error_flag=()
	if [[ "$do_error" -eq 1 ]]; then error_flag=("--error"); fi
	set -- "${config_args[@]}" "${error_flag[@]}" "${extra[@]}" "${targets[@]}"
	exec "${SEMGREP_BIN}" scan "$@"
	;;
esac
