#!/usr/bin/env bash
set -euo pipefail

# scripts/export-public.sh <dest-dir>
#
# Stage the public secure-devtools repository with exactly one commit, so none of
# the private history is published. Only the paths in scripts/public-paths.txt are
# copied; add a tool or skill there once it has passed review. A line starting with
# `!` removes that path from the copy (for example, live malware samples).
#
#   scripts/export-public.sh "$(mktemp -d)"
#
# Refuses a non-empty destination, never copies node_modules, VCS folders, local
# settings, logs or env files, runs the personal-data pattern check over the copy
# and fails on any hit, then `git init -b main` and one commit,
# "Initial public release". It never adds a remote and never pushes.
#
# Patterns come from scripts/silver-gate-patterns.json in the enclosing workspace
# (found by walking up from this repo). Override with PII_PATTERNS_JSON=<file>.
# The check fails closed: a missing file, a missing tool or a pattern that does not
# compile is a failure, not a pass.
#
# Needs: git, jq, rsync, rg (ripgrep built with PCRE2; the patterns use look-ahead).

die() {
	echo "export-public: $*" >&2
	exit 1
}

[[ $# -eq 1 && -n "$1" ]] || {
	echo "usage: export-public.sh <dest-dir>" >&2
	exit 2
}

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$SRC/scripts/public-paths.txt"
DEST_ARG="$1"

for tool in git jq rg rsync; do
	command -v "$tool" >/dev/null 2>&1 || die "$tool is required but was not found on PATH"
done
[[ -f "$MANIFEST" ]] || die "missing $MANIFEST"

# --- destination: must be empty (or absent), and outside the source folder -----------

if [[ -e "$DEST_ARG" && ! -d "$DEST_ARG" ]]; then
	die "'$DEST_ARG' exists and is not a directory"
fi
if [[ -d "$DEST_ARG" && -n "$(ls -A "$DEST_ARG")" ]]; then
	die "'$DEST_ARG' is not empty; refusing to export into it"
fi
mkdir -p "$DEST_ARG"
DEST="$(cd "$DEST_ARG" && pwd)"
case "$DEST/" in
"$SRC"/*) die "destination must be outside $SRC" ;;
esac

# --- personal-data patterns -----------------------------------------------------------

find_patterns_json() {
	local dir="$SRC"
	if [[ -n "${PII_PATTERNS_JSON:-}" ]]; then
		printf '%s' "$PII_PATTERNS_JSON"
		return 0
	fi
	while [[ "$dir" != "/" ]]; do
		if [[ -f "$dir/scripts/silver-gate-patterns.json" ]]; then
			printf '%s' "$dir/scripts/silver-gate-patterns.json"
			return 0
		fi
		dir="$(dirname "$dir")"
	done
	return 1
}

PATTERNS_JSON="$(find_patterns_json)" || die "no scripts/silver-gate-patterns.json above $SRC; set PII_PATTERNS_JSON"
[[ -f "$PATTERNS_JSON" ]] || die "pattern file '$PATTERNS_JSON' does not exist"

WORK="$(mktemp -d)"
cleanup() {
	local status=$?
	rm -rf "$WORK"
	# A copy that failed a check must not be left behind to be published by hand.
	if ((status != 0)) && [[ -d "$DEST" ]]; then
		find "$DEST" -mindepth 1 -delete 2>/dev/null || true
	fi
}
trap cleanup EXIT

# Block-severity personal and secret patterns, email and personal-profile URLs,
# plus the name, internal-framing and family-reference groups. Warn-level shapes
# that fire on ordinary code (IP addresses, dates, ZIP codes) are left out.
jq -r '
	(.pii[] | select(.severity == "block" or .name == "Email Address" or .name == "Personal URL")),
	.internal_framing[],
	.family_references[]
	| .pattern
' "$PATTERNS_JSON" >"$WORK/patterns.txt" || die "could not read patterns from $PATTERNS_JSON"
[[ -s "$WORK/patterns.txt" ]] || die "no patterns were read from $PATTERNS_JSON"

# --- copy the manifest -------------------------------------------------------------------

excluded=()
while IFS= read -r path || [[ -n "$path" ]]; do
	[[ -z "$path" || "$path" == \#* ]] && continue
	if [[ "$path" == !* ]]; then
		excluded+=("${path#!}")
		continue
	fi
	[[ "$path" != /* && "$path" != *..* ]] || die "unsafe manifest path: $path"
	[[ -e "$SRC/$path" ]] || die "manifest lists $path, which does not exist"
	mkdir -p "$DEST/$(dirname "$path")"
	rsync -a \
		--exclude node_modules --exclude .git --exclude .jj --exclude .DS_Store \
		--exclude '.env*' --exclude settings.local.json --exclude '*.log' --exclude reports \
		"$SRC/$path" "$DEST/$(dirname "$path")/"
done <"$MANIFEST"

for path in ${excluded[@]+"${excluded[@]}"}; do
	[[ "$path" != /* && "$path" != *..* && -n "$path" ]] || die "unsafe exclusion: $path"
	rm -rf "${DEST:?}/$path"
	[[ ! -e "$DEST/$path" ]] || die "could not remove excluded path $path"
done

forbidden="$(find "$DEST" \( -name node_modules -o -name .git -o -name .jj -o -name reports -o -name '.env*' -o -name 'settings.local.json' -o -name '*.log' \) -print)"
[[ -z "$forbidden" ]] || die "refusing to publish local files:
$forbidden"

# --- personal-data check on the copy ----------------------------------------------------

# Matched text that is allowed to ship: each package author's own contact address
# (published on purpose) and placeholder addresses on reserved domains used by the
# tests. Every other hit fails the export.
AUTHOR_EMAILS="$(find "$DEST" -name package.json -not -path '*/node_modules/*' -exec jq -r '(.author // "") | if type == "string" then (capture("<(?<e>[^>]+)>").e // empty) else (.email // empty) end' {} \; | sort -u)"
PLACEHOLDER_EMAIL='^[^@]+@(example\.(com|org|net)|[A-Za-z0-9.-]+\.(test|invalid|example))$'

rc=0
rg --pcre2 -o -n --no-heading --hidden --color never \
	-f "$WORK/patterns.txt" -- "$DEST" >"$WORK/hits.txt" 2>"$WORK/rg.err" || rc=$?
if ((rc == 2)); then
	cat "$WORK/rg.err" >&2
	die "the pattern check could not run (is rg built with PCRE2? does a pattern compile?); nothing was exported"
fi

# rg -o prints path:line:matched-text; judge the matched text only.
hits="$(AUTHORS="$AUTHOR_EMAILS" OK="$PLACEHOLDER_EMAIL" awk '
	BEGIN { n = split(ENVIRON["AUTHORS"], a, "\n"); for (i = 1; i <= n; i++) if (a[i] != "") allowed[a[i]] = 1 }
	{
		text = $0
		sub(/^[^:]*:[0-9]+:/, "", text)
		if (text in allowed) next
		if (text ~ ENVIRON["OK"]) next
		print
	}
' "$WORK/hits.txt")"
if [[ -n "$hits" ]]; then
	printf '%s\n' "$hits" | sed "s#$DEST/##" >&2
	die "personal-data pattern hits in the copy (listed above); nothing was exported"
fi

# --- one commit ----------------------------------------------------------------------------

git -C "$DEST" init -q -b main
git -C "$DEST" add -A
# Hooks off: a global hooks path from another project must not run here.
git -C "$DEST" -c core.hooksPath=/dev/null commit -q -m "Initial public release"

[[ "$(git -C "$DEST" rev-list --count HEAD)" == "1" ]] || die "expected exactly one commit"
[[ "$(git -C "$DEST" log -1 --format=%B | sed '/^$/d')" == "Initial public release" ]] || die "commit message is not exactly the subject"
[[ -z "$(git -C "$DEST" remote)" ]] || die "unexpected git remote"

echo "export-public: staged $(git -C "$DEST" ls-files | wc -l | tr -d ' ') files as one commit in $DEST"
echo "export-public: no remote added, nothing pushed"
