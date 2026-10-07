#!/usr/bin/env bash
# SC2094: findings name the RECORD being read; they never write to it.
# shellcheck disable=SC2094
set -euo pipefail
# bin/venv-integrity.sh — Python virtualenv integrity check.
#
# Verifies that the files in a virtualenv's site-packages match what each
# `*.dist-info/RECORD` claims, and flags the quiet ways a venv can be tampered
# with: a changed file, a file no RECORD claims, a `.pth` or startup module that
# executes code, and an unusual installer. It never reads outside the venv (a
# RECORD path with `..`, a leading `/` or a symlinked folder on the way is a
# finding, not a file to open).
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
# Absolute paths of console scripts claimed by a RECORD, "|"-joined. Keyed by
# path, not name, so a claim in one venv never covers a file in another.
VI_BIN_CLAIMED="|"
# Venv root of the site-packages being scanned; empty when it is not at
# <venv>/lib/<python>/site-packages.
VI_SP_ROOT=""

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

# vi_venv_root <site-packages> — print the venv root when the folder is exactly
# <venv>/lib/<one folder>/site-packages; fail otherwise.
vi_venv_root() {
	local sp="$1" lib
	[[ "${sp##*/}" == site-packages ]] || return 1
	lib="${sp%/site-packages}"
	[[ -n "${lib##*/}" ]] || return 1
	lib="${lib%/*}"
	[[ "${lib##*/}" == lib ]] || return 1
	printf '%s' "${lib%/lib}"
}

# vi_symlinked_dir <base> <relative-path> — succeeds when a folder on the way
# from <base> to the file is a symlink. find never descends one, but opening
# "$base/$rel" would follow it out of the venv.
vi_symlinked_dir() {
	local base="$1" dir="$2"
	[[ "$dir" == */* ]] || return 1
	dir="${dir%/*}"
	while :; do
		[[ -L "$base/$dir" ]] && return 0
		[[ "$dir" == */* ]] || return 1
		dir="${dir%/*}"
	done
}

# vi_process_record <record> <site-packages>
vi_process_record() {
	local record="$1" sp="$2"
	local line_no=0 line path hash_field target idx base rel

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
			{ [[ "$path" == ../* ]] && [[ -z "$VI_SP_ROOT" ]]; }; then
			vi_record "$record" "$line_no" "$line" "HIGH: RECORD path points outside the package"
			continue
		fi

		case "$path" in
		../../../*) base="$VI_SP_ROOT" rel="${path#../../../}" ;;
		*) base="$sp" rel="$path" ;;
		esac
		if vi_symlinked_dir "$base" "$rel"; then
			vi_record "$record" "$line_no" "$line" "HIGH: RECORD path goes through a symlinked folder; not followed"
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
		../../../bin/*'|'*)
			# "|" separates claims; a name holding one would claim other names too.
			vi_record "$record" "$line_no" "$line" "HIGH: RECORD console script name contains |"
			continue
			;;
		../../../bin/*) VI_BIN_CLAIMED="${VI_BIN_CLAIMED}${VI_SP_ROOT}/${rel}|" ;;
		esac

		if [[ -L "$target" ]]; then
			vi_record "$target" 1 "$path" "MEDIUM: RECORD lists a symlink; not followed"
			continue
		fi
		if [[ ! -f "$target" ]]; then
			vi_record "$target" 1 "$path" "LOW: RECORD lists a file that is missing"
			continue
		fi
		if [[ -z "$hash_field" ]]; then
			# Installers leave the hash empty only for RECORD itself, its signatures and
			# bytecode compiled after install. Anywhere else the file goes unverified.
			case "$path" in
			*.dist-info/RECORD | *.dist-info/RECORD.jws | *.dist-info/RECORD.p7s | *.pyc) ;;
			*) vi_record "$record" "$line_no" "$line" "LOW: RECORD entry has no sha256 hash; file not verified" ;;
			esac
			continue
		fi

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

# vi_check_unclaimed <site-packages> — files and symlinks no RECORD claims.
vi_check_unclaimed() {
	local sp="$1" f rel base
	local -a on_disk links
	on_disk=()
	links=()

	while IFS= read -r -d '' f; do
		rel="${f#"$sp"/}"
		links+=("${rel//$'\n'/\\n}")
	done < <(
		find "$sp" -type d \( -name '__pycache__' -o -name '*.dist-info' -o -name '*.egg-info' \) -prune -o -type l -print0 2>/dev/null
	)
	while IFS= read -r rel; do
		[[ -n "$rel" ]] || continue
		vi_record "$sp/$rel" 1 "$rel" "MEDIUM: symlink in site-packages not claimed by any RECORD"
	done < <(
		LC_ALL=C comm -23 \
			<(vi_emit_lines ${links[@]+"${links[@]}"} | LC_ALL=C sort -u) \
			<(vi_emit_lines ${VI_CLAIMED_REL[@]+"${VI_CLAIMED_REL[@]}"} | LC_ALL=C sort -u)
	)

	while IFS= read -r -d '' f; do
		rel="${f#"$sp"/}"
		# virtualenv and uv write these two at the top of site-packages with no RECORD;
		# vi_check_pth checks the .pth content instead. setuptools' RECORD claims
		# distutils-precedence.pth, so that one is no exception.
		case "$rel" in
		_virtualenv.py | _virtualenv.pth | __editable__*) continue ;;
		esac
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
		_virtualenv.pth)
			# The stock file is one line; it has no RECORD to hash against.
			if [[ "$rel" != _virtualenv.pth || "$(vi_trim "$(LC_ALL=C tr -d '\000' <"$f" 2>/dev/null)")" != "import _virtualenv" ]]; then
				vi_record "$f" 1 "$rel" "MEDIUM: _virtualenv.pth is not the stock one-line file"
			fi
			continue
			;;
		distutils-precedence.pth | __editable__*) continue ;;
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
			# pip and uv always write RECORD in a venv; a missing one hides edits.
			if [[ -n "$VI_SP_ROOT" && -f "$VI_SP_ROOT/pyvenv.cfg" ]]; then
				vi_record "$dist" 1 "${dist#"$sp"/}" "MEDIUM: venv dist-info directory has no RECORD"
			else
				vi_record "$dist" 1 "${dist#"$sp"/}" "LOW: dist-info directory has no RECORD"
			fi
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
# Only the exact names venv and virtualenv write are skipped, so a planted
# python3-helper is still reported. pip's scripts are claimed by pip's own
# RECORD, so an unclaimed pip is reported too.
vi_check_bin() {
	local root="$1" f base

	[[ -d "$root/bin" ]] || return 0
	while IFS= read -r -d '' f; do
		base="${f##*/}"
		case "$base" in
		activate | activate.bash | activate.csh | activate.fish | activate.nu | activate.ps1 | Activate.ps1 | \
			activate.xsh | activate_this.py | activate.bat | deactivate.bat | pydoc.bat | \
			python | python3 | python3.[0-9] | python3.[0-9][0-9] | pythonw | pypy | pypy3 | pypy3.[0-9] | pypy3.[0-9][0-9])
			continue
			;;
		esac
		case "$VI_BIN_CLAIMED" in *"|$f|"*) continue ;; esac
		vi_record "$f" 1 "${f#"$root"/}" "LOW: venv bin file not claimed by any RECORD"
	done < <(find "$root/bin" \( -type f -o -type l \) -print0 2>/dev/null)
}

# --- entry point -----------------------------------------------------------------

# scan_venv_integrity <dir> — scan a virtualenv. Returns immediately when the
# folder has no `*.dist-info/RECORD`.
scan_venv_integrity() {
	local root="${1:-.}" found sp walk_err venv_root records
	local -a sp_dirs venv_roots cands
	local seen_sp="|" seen_vroot="|"

	VROOT="$(cd -- "$root" 2>/dev/null && pwd)" || {
		echo "am-i-hacked: venv integrity: cannot open $root" >&2
		return 1
	}

	# A folder with a RECORD is scanned, and so is a venv's site-packages whose
	# RECORD files are all gone: deleting them must not make a venv look clean.
	sp_dirs=()
	while IFS= read -r -d '' found; do
		cands=()
		case "${found##*/}" in
		RECORD) cands=("$(dirname "$(dirname "$found")")") ;;
		pyvenv.cfg)
			# The venv's own config survives when every dist-info folder is deleted.
			for sp in "$(dirname "$found")"/lib/*/site-packages; do
				[[ -d "$sp" ]] && cands+=("$sp")
			done
			;;
		*)
			sp="$(dirname "$found")"
			venv_root="$(vi_venv_root "$sp")" || continue
			[[ -f "$venv_root/pyvenv.cfg" ]] || continue
			cands=("$sp")
			;;
		esac
		for sp in ${cands[@]+"${cands[@]}"}; do
			case "$seen_sp" in *"|$sp|"*) continue ;; esac
			seen_sp="${seen_sp}${sp}|"
			sp_dirs+=("$sp")
		done
	done < <(find "$VROOT" \( \( -type f -name RECORD -path '*/*.dist-info/RECORD' \) -o \
		\( -type d -name '*.dist-info' -path '*/site-packages/*.dist-info' \) -o \
		\( -type f -name pyvenv.cfg \) \) -print0 2>/dev/null)

	((${#sp_dirs[@]} > 0)) || return 0

	venv_roots=()
	for sp in "${sp_dirs[@]}"; do
		VI_SP_ROOT="$(vi_venv_root "$sp")" || VI_SP_ROOT=""
		# The checks below hide find errors so output stays clean; an unreadable folder
		# must still show up, never read as a clean result.
		walk_err="$(find "$sp" 2>&1 >/dev/null)" || true
		if [[ -n "$walk_err" ]]; then
			vi_record "$sp" 1 "${walk_err%%$'\n'*}" "MEDIUM: part of site-packages could not be read"
		fi
		VI_CLAIMED_REL=()
		records=0
		while IFS= read -r -d '' found; do
			records=$((records + 1))
			vi_process_record "$found" "$sp"
		done < <(find "$sp" -type f -name RECORD -path '*/*.dist-info/RECORD' -print0 2>/dev/null)

		# With no RECORD at all every file would read as unclaimed; the missing
		# RECORD findings from vi_check_distinfos say it once per package instead.
		((records == 0)) || vi_check_unclaimed "$sp"
		if ((records == 0)) && [[ -n "$VI_SP_ROOT" && -f "$VI_SP_ROOT/pyvenv.cfg" ]] &&
			[[ -z "$(find "$sp" -maxdepth 1 -name '*.dist-info' -print -quit 2>/dev/null)" ]] &&
			[[ -n "$(find "$sp" -type f ! -name '_virtualenv.py' ! -name '_virtualenv.pth' ! -path '*/__pycache__/*' -print -quit 2>/dev/null)" ]]; then
			vi_record "$sp" 1 "${sp#"$VROOT"/}" "MEDIUM: venv site-packages holds files but no package records"
		fi
		vi_check_pth "$sp"
		vi_check_startup "$sp"
		vi_check_distinfos "$sp"

		if [[ -n "$VI_SP_ROOT" ]]; then
			case "$seen_vroot" in *"|$VI_SP_ROOT|"*) ;; *)
				seen_vroot="${seen_vroot}${VI_SP_ROOT}|"
				venv_roots+=("$VI_SP_ROOT")
				;;
			esac
		fi
	done

	# After every site-packages, so a venv with two of them has all its claims.
	for venv_root in ${venv_roots[@]+"${venv_roots[@]}"}; do
		vi_check_bin "$venv_root"
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
