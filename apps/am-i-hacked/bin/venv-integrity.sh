#!/usr/bin/env bash
# SC2094: findings name the RECORD being read; they never write to it.
# shellcheck disable=SC2094
set -euo pipefail
# bin/venv-integrity.sh — Python virtualenv integrity check.
#
# Verifies that the files in a virtualenv's site-packages match what each
# `*.dist-info/RECORD` claims, and flags the quiet ways a venv can be tampered
# with: a changed file, a file no RECORD claims, a `.pth` or startup module that
# executes code, and an unusual installer. It never reads outside site-packages
# (a RECORD path with `..` or a leading `/` is a finding, not a file to open).
#
# Run standalone:  bash venv-integrity.sh <venv-dir>
# Used by scanner.sh: it sources this file and calls scan_venv_integrity "$ROOT",
# which records findings through the scanner's `record_finding` when present.
#
# Written for bash 3.2 (the macOS system bash): no associative arrays, mapfile,
# or case-conversion expansions. Hashing is sharded with xargs -P 4.

VI_US=$'\037'

# --- color ---------------------------------------------------------------------

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
	VI_BOLD=$'\033[1m'
	VI_DIM=$'\033[2m'
	VI_RESET=$'\033[0m'
else
	VI_BOLD=""
	VI_DIM=""
	VI_RESET=""
fi

# --- findings store (standalone mode) ------------------------------------------

VI_FINDINGS=()
VI_HASH_QUEUE=()
VI_REC_F=()
VI_REC_EXP=()
VI_CLAIMED_REL=()
VI_BIN_CLAIMED="|"

# vi_trim <text> — leading/trailing whitespace removed.
vi_trim() {
	local s="$1"
	s="${s#"${s%%[![:space:]]*}"}"
	s="${s%"${s##*[![:space:]]}"}"
	printf '%s' "$s"
}

# vi_emit_lines <elem...> — print each element on its own line (nothing for none).
vi_emit_lines() {
	local e
	for e in "$@"; do
		printf '%s\n' "$e"
	done
}

# vi_sha256_hex <file> — sha256 hex digest, via sha256sum or shasum.
vi_sha256_hex() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" 2>/dev/null | cut -d' ' -f1
	else
		shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1
	fi
}

# vi_sha256_url <file> — the digest as RECORD writes it: urlsafe base64, no
# padding. Prefers openssl (binary digest straight to base64, single line); falls
# back to hex -> xxd -> base64 when openssl is missing.
vi_sha256_url() {
	local f="$1" b64 hex

	if command -v openssl >/dev/null 2>&1; then
		b64="$(openssl dgst -sha256 -binary "$f" 2>/dev/null | openssl base64 -A 2>/dev/null)"
		if [[ -n "$b64" ]]; then
			printf '%s' "$b64" | tr '+/' '-_' | tr -d '=\n'
			return 0
		fi
	fi

	hex="$(vi_sha256_hex "$f")" || return 1
	[[ -n "$hex" ]] || return 1
	printf '%s' "$hex" | xxd -r -p 2>/dev/null | base64 2>/dev/null |
		tr -d '[:space:]' | tr '+/' '-_' | tr -d '='
}

# vi_hash_worker <record> — one xargs shard: prints "<idx><US><digest>".
vi_hash_worker() {
	local rec="$1" idx f got
	idx="${rec%%"$VI_US"*}"
	f="${rec#*"$VI_US"}"
	got="$(vi_sha256_url "$f" 2>/dev/null)" || got=""
	printf '%s%s%s\n' "$idx" "$VI_US" "$got"
}

# vi_record <path> <line> <snippet> <tag> — route to the scanner's store when
# sourced, or to the standalone store otherwise.
vi_record() {
	local path="$1" line="$2" snippet="$3" tag="$4" pathrel pad

	if [[ "$(type -t record_finding 2>/dev/null)" == "function" ]]; then
		record_finding "$path" "$line" "$snippet" "$tag"
		return 0
	fi

	pathrel="${path#"$VROOT"/}"
	if [[ -z "$pathrel" || "$pathrel" == "$path" ]]; then
		pathrel="$(basename "$path")"
	fi
	pad="$(printf '%08d' "$line")"
	VI_FINDINGS+=("${pathrel}${VI_US}${pad}${VI_US}${snippet}${VI_US}${tag}")
}

# --- per-RECORD parsing ---------------------------------------------------------

# vi_inside_venv <relative-path> — succeeds when a RECORD path stays in
# site-packages, or climbs exactly to the venv root (../../../ from
# venv/lib/pythonX.Y/site-packages) and goes down from there, as console scripts
# do (../../../bin/<name>). Any other `..` fails. Never touches the filesystem.
vi_inside_venv() {
	local rest="$1"
	case "$rest" in
	../../../*) rest="${rest#../../../}" ;;
	esac
	case "/$rest/" in
	*/../*) return 1 ;;
	esac
	return 0
}

# vi_process_record <record> <site-packages>
vi_process_record() {
	local record="$1" sp="$2"
	local line_no=0 line path hash_field target idx

	while IFS= read -r line; do
		line_no=$((line_no + 1))
		[[ -n "$line" ]] || continue

		path="${line%%,*}"
		case "$path" in
		'"'*)
			path="${path#\"}"
			path="${path%\"}"
			;;
		esac

		# A RECORD path that leaves the venv is a finding on its own. Console scripts
		# legitimately live at ../../../bin/<name>, so a path may climb out of
		# site-packages as long as it stays inside the venv.
		# The ../../../ climb only means "venv root" when site-packages really sits at
		# <venv>/lib/pythonX.Y/site-packages.
		if [[ "$path" == /* ]] || ! vi_inside_venv "$path" ||
			{ [[ "$path" == ../* ]] && [[ "$sp" != "$VROOT"/lib/*/site-packages ]]; }; then
			vi_record "$record" "$line_no" "$line" "HIGH: RECORD path points outside the package"
			continue
		fi

		hash_field="${line#*,}"
		hash_field="${hash_field%%,*}"
		case "$hash_field" in
		sha256=*) hash_field="${hash_field#sha256=}" ;;
		*) hash_field="" ;;
		esac
		hash_field="${hash_field%%=*}"

		target="$sp/$path"
		VI_CLAIMED_REL+=("$path")
		case "$path" in
		../../../bin/*) VI_BIN_CLAIMED="${VI_BIN_CLAIMED}${path#../../../bin/}|" ;;
		esac

		if [[ -L "$target" ]]; then
			vi_record "$target" 1 "$path" "MEDIUM: RECORD lists a symlink; not followed"
			continue
		fi
		if [[ ! -f "$target" ]]; then
			vi_record "$target" 1 "$path" "LOW: RECORD lists a file that is missing"
			continue
		fi
		[[ -n "$hash_field" ]] || continue

		idx=${#VI_REC_F[@]}
		VI_REC_F+=("$target")
		VI_REC_EXP+=("$hash_field")
		VI_HASH_QUEUE+=("${idx}${VI_US}${target}")
	done <"$record"
}

# vi_hash_all — hash every queued RECORD file in parallel, then compare.
vi_hash_all() {
	((${#VI_HASH_QUEUE[@]} > 0)) || return 0
	local jobs=4 res idx got exp f

	export VI_US
	export -f vi_sha256_hex vi_sha256_url vi_hash_worker

	while IFS= read -r res; do
		[[ -n "$res" ]] || continue
		idx="${res%%"$VI_US"*}"
		got="${res#*"$VI_US"}"
		exp="${VI_REC_EXP[idx]}"
		f="${VI_REC_F[idx]}"
		# An empty digest means the file could not be read; that is never a clean result.
		if [[ -z "$got" ]]; then
			vi_record "$f" 1 "${f#"$VROOT"/}" "HIGH: file listed in RECORD could not be read or hashed"
			continue
		fi
		if [[ "$got" != "$exp" ]]; then
			vi_record "$f" 1 "sha256 $got != RECORD $exp" "HIGH: venv file hash differs from its RECORD"
		fi
	done < <(
		# shellcheck disable=SC2016
		printf '%s\0' "${VI_HASH_QUEUE[@]}" |
			xargs -0 -n64 -P"$jobs" bash -c 'for rec in "$@"; do vi_hash_worker "$rec"; done' _ |
			LC_ALL=C sort -t"$VI_US" -k1,1n
	)
}

# --- site-packages checks -------------------------------------------------------

# vi_check_unclaimed <site-packages> — files no RECORD claims.
vi_check_unclaimed() {
	local sp="$1" f rel base
	local -a on_disk
	on_disk=()

	while IFS= read -r -d '' f; do
		base="${f##*/}"
		case "$base" in
		_virtualenv.py | _virtualenv.pth | distutils-precedence.pth | __editable__*) continue ;;
		esac
		rel="${f#"$sp"/}"
		# A newline in a name would split into two lines in the comparison below and
		# could hide the file; report it directly instead.
		if [[ "$rel" == *$'\n'* ]]; then
			vi_record "$f" 1 "${rel//$'\n'/\\n}" "MEDIUM: file in site-packages has a newline in its name"
			continue
		fi
		on_disk+=("$rel")
	done < <(
		find "$sp" -type d \( -name '__pycache__' -o -name '*.dist-info' -o -name '*.egg-info' \) -prune -o -type f -print0 2>/dev/null
	)

	while IFS= read -r rel; do
		[[ -n "$rel" ]] || continue
		vi_record "$sp/$rel" 1 "$rel" "MEDIUM: file in site-packages not claimed by any RECORD"
	done < <(
		LC_ALL=C comm -23 \
			<(vi_emit_lines ${on_disk[@]+"${on_disk[@]}"} | LC_ALL=C sort -u) \
			<(vi_emit_lines ${VI_CLAIMED_REL[@]+"${VI_CLAIMED_REL[@]}"} | LC_ALL=C sort -u)
	)
}

# vi_check_pth <site-packages> — .pth files that run code on import.
vi_check_pth() {
	local sp="$1" f rel base line_no line t

	while IFS= read -r -d '' f; do
		rel="${f#"$sp"/}"
		base="${f##*/}"
		case "$base" in
		_virtualenv.pth | distutils-precedence.pth | __editable__*) continue ;;
		esac
		case "$rel" in */*.egg-info/*) continue ;; esac

		line_no=0
		while IFS= read -r line; do
			line_no=$((line_no + 1))
			t="$(vi_trim "$line")"
			if [[ "$t" == "import "* || "$t" == *"exec("* ]]; then
				vi_record "$f" "$line_no" "$line" "MEDIUM: venv .pth file executes code"
			fi
		done <"$f"
	done < <(find "$sp" -type f -name '*.pth' -print0 2>/dev/null)
}

# vi_check_startup <site-packages> — sitecustomize.py / usercustomize.py.
vi_check_startup() {
	local sp="$1" f

	while IFS= read -r -d '' f; do
		vi_record "$f" 1 "${f#"$sp"/}" "MEDIUM: venv startup module present"
	done < <(find "$sp" -type f \( -name 'sitecustomize.py' -o -name 'usercustomize.py' \) -print0 2>/dev/null)
}

# vi_check_distinfos <site-packages> — missing RECORD, unexpected INSTALLER.
vi_check_distinfos() {
	local sp="$1" dist installer

	while IFS= read -r -d '' dist; do
		if [[ ! -f "$dist/RECORD" ]]; then
			vi_record "$dist" 1 "${dist#"$sp"/}" "LOW: dist-info directory has no RECORD"
		fi
		if [[ -f "$dist/INSTALLER" ]]; then
			installer="$(vi_trim "$(sed -n '1p' "$dist/INSTALLER" 2>/dev/null)")"
			if [[ -n "$installer" && "$installer" != "uv" && "$installer" != "pip" ]]; then
				vi_record "$dist/INSTALLER" 1 "INSTALLER is $installer" "LOW: venv INSTALLER is not uv or pip"
			fi
		fi
	done < <(find "$sp" -type d -name '*.dist-info' -print0 2>/dev/null)
}

# vi_check_bin <venv-root> — scripts in bin/ no RECORD claims.
# Console scripts are claimed by RECORD lines of the form ../../../bin/<name>.
vi_check_bin() {
	local root="$1" f base

	[[ -d "$root/bin" ]] || return 0
	while IFS= read -r -d '' f; do
		base="${f##*/}"
		case "$base" in
		activate* | python* | pip* | *.bat) continue ;;
		esac
		case "$VI_BIN_CLAIMED" in *"|$base|"*) continue ;; esac
		vi_record "$f" 1 "${f#"$root"/}" "LOW: venv bin file not claimed by any RECORD"
	done < <(find "$root/bin" -type f -print0 2>/dev/null)
}

# --- entry point -----------------------------------------------------------------

# scan_venv_integrity <dir> — scan a virtualenv. Returns immediately when the
# folder has no `*.dist-info/RECORD`.
scan_venv_integrity() {
	local root="${1:-.}" record sp walk_err venv_root
	local -a sp_dirs
	local seen_sp="|" seen_vroot="|"

	VROOT="$(cd -- "$root" 2>/dev/null && pwd)" || {
		echo "am-i-hacked: venv integrity: cannot open $root" >&2
		return 1
	}

	sp_dirs=()
	while IFS= read -r -d '' record; do
		sp="$(dirname "$(dirname "$record")")"
		case "$seen_sp" in *"|$sp|"*) continue ;; esac
		seen_sp="${seen_sp}${sp}|"
		sp_dirs+=("$sp")
	done < <(find "$VROOT" -type f -name RECORD -path '*/*.dist-info/RECORD' -print0 2>/dev/null)

	((${#sp_dirs[@]} > 0)) || return 0

	for sp in "${sp_dirs[@]}"; do
		# The checks below hide find errors so output stays clean; an unreadable folder
		# must still show up, never read as a clean result.
		walk_err="$(find "$sp" 2>&1 >/dev/null)" || true
		if [[ -n "$walk_err" ]]; then
			vi_record "$sp" 1 "${walk_err%%$'\n'*}" "MEDIUM: part of site-packages could not be read"
		fi
		VI_CLAIMED_REL=()
		while IFS= read -r -d '' record; do
			vi_process_record "$record" "$sp"
		done < <(find "$sp" -type f -name RECORD -path '*/*.dist-info/RECORD' -print0 2>/dev/null)

		vi_check_unclaimed "$sp"
		vi_check_pth "$sp"
		vi_check_startup "$sp"
		vi_check_distinfos "$sp"

		case "$sp" in
		*/lib/*/site-packages)
			venv_root="${sp%/lib/*/site-packages}"
			case "$seen_vroot" in *"|$venv_root|"*) ;; *)
				seen_vroot="${seen_vroot}${venv_root}|"
				vi_check_bin "$venv_root"
				;;
			esac
			;;
		esac
	done

	vi_hash_all
	return 0
}

# --- standalone report -----------------------------------------------------------

vi_render() {
	local n="${#VI_FINDINGS[@]}" line pathrel pad snippet tag num

	if ((n == 0)); then
		echo "am-i-hacked: venv integrity: PASSED"
		return 0
	fi

	printf 'am-i-hacked: venv integrity: FAILED — %d finding' "$n"
	((n == 1)) || printf 's'
	printf '\n'

	while IFS= read -r line; do
		[[ -n "$line" ]] || continue
		pathrel="${line%%"$VI_US"*}"
		line="${line#*"$VI_US"}"
		pad="${line%%"$VI_US"*}"
		line="${line#*"$VI_US"}"
		snippet="${line%%"$VI_US"*}"
		tag="${line#*"$VI_US"}"
		num="$((10#$pad))"

		printf '\n  %s%s:%s%s\n' "$VI_BOLD" "$pathrel" "$num" "$VI_RESET"
		printf '    %s\n' "$snippet"
		printf '    %s→ %s%s\n' "$VI_DIM" "$tag" "$VI_RESET"
	done < <(vi_emit_lines "${VI_FINDINGS[@]}" | LC_ALL=C sort -t"$VI_US" -k1,1 -k2,2)

	return 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	VI_ROOT_ARG="${1:-.}"
	if [[ ! -d "$VI_ROOT_ARG" ]]; then
		echo "venv-integrity: '$VI_ROOT_ARG' is not a directory" >&2
		echo "usage: venv-integrity <venv-dir>" >&2
		exit 2
	fi
	scan_venv_integrity "$VI_ROOT_ARG"
	vi_render || exit 1
	exit 0
fi
