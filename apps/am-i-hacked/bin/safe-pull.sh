#!/usr/bin/env bash
set -euo pipefail

# bin/safe-pull.sh
#
# A guarded `git pull`. Incoming commits are inspected before anything reaches
# the working tree, because that is the step where a malicious repository turns
# into an executable one: a `.vscode/tasks.json` runs on folder open, an MCP
# `stdio` server starts with the editor, and a `postinstall` script runs on the
# next install.
#
# `git fetch` is safe — it writes compressed objects under `.git/objects` and
# executes nothing. `git merge` is where the risk starts. This script therefore
# fetches, inspects the incoming tree with git plumbing only (no checkout), and
# merges `--ff-only` only when every check is clean.
#
# Checks, in order:
#   1. working tree is clean (override: --allow-dirty)
#   2. the upstream tip descends from HEAD — a force-pushed upstream is itself an
#      indicator of compromise (override: --force-update)
#   3. author/committer mismatch in the incoming commits
#   4. editor/workspace configuration that runs code unprompted
#   5. executable payloads disguised as asset files
#   6. environment files committed to the incoming tree
#   7. a `dotenv` + `node-fetch`/`axios` dependency pair in a changed package.json
#
# Exit status: 0 clean (and merged unless --dry-run), 1 findings, 2 usage/setup.
#
# Usage: safe-pull [--remote <name>] [--branch <name>] [--allow-dirty]
#                  [--force-update] [--dry-run] [--help]

usage() {
	sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
	printf '\nusage: safe-pull [--remote <name>] [--branch <name>] [--allow-dirty] [--force-update] [--dry-run]\n'
	exit 2
}

REMOTE="origin"
BRANCH=""
ALLOW_DIRTY=0
FORCE_UPDATE=0
DRY_RUN=0

while [ $# -gt 0 ]; do
	case "$1" in
	--remote)
		REMOTE="${2:-}"
		[ -n "$REMOTE" ] || usage
		shift 2
		;;
	--branch)
		BRANCH="${2:-}"
		[ -n "$BRANCH" ] || usage
		shift 2
		;;
	--allow-dirty)
		ALLOW_DIRTY=1
		shift
		;;
	--force-update)
		FORCE_UPDATE=1
		shift
		;;
	--dry-run)
		DRY_RUN=1
		shift
		;;
	-h | --help) usage ;;
	*)
		printf 'safe-pull: unknown option %s\n' "$1" >&2
		usage
		;;
	esac
done

if ! command -v git >/dev/null 2>&1; then
	printf 'safe-pull: git is required\n' >&2
	exit 2
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	printf 'safe-pull: not inside a git working tree\n' >&2
	exit 2
fi

ROOT="$(git rev-parse --show-toplevel)"

# shellcheck source=bin/ioc-patterns.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ioc-patterns.sh"

# --- findings store -----------------------------------------------------------

declare -a FIND_TITLE=()
declare -a FIND_LOCATION=()
declare -a FIND_DETAIL=()

record_finding() {
	FIND_TITLE+=("$1")
	FIND_LOCATION+=("$2")
	FIND_DETAIL+=("${3:-}")
}

# --- 1. working tree ----------------------------------------------------------

if [ "$ALLOW_DIRTY" -eq 0 ] && [ -n "$(git -C "$ROOT" status --porcelain)" ]; then
	printf 'safe-pull: working tree has uncommitted changes; commit, stash, or pass --allow-dirty\n' >&2
	exit 2
fi

# --- 2. upstream --------------------------------------------------------------

if [ -z "$BRANCH" ]; then
	BRANCH="$(git -C "$ROOT" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
	if [ -z "$BRANCH" ]; then
		printf 'safe-pull: the current branch has no upstream; pass --branch <name>\n' >&2
		exit 2
	fi
	REMOTE="${BRANCH%%/*}"
else
	BRANCH="$REMOTE/$BRANCH"
fi

printf 'safe-pull: fetching %s\n' "$REMOTE"
git -C "$ROOT" fetch --quiet "$REMOTE"

if ! git -C "$ROOT" rev-parse --verify --quiet "$BRANCH" >/dev/null; then
	printf 'safe-pull: %s does not exist after fetch\n' "$BRANCH" >&2
	exit 2
fi

HEAD_SHA="$(git -C "$ROOT" rev-parse HEAD)"
UPSTREAM_SHA="$(git -C "$ROOT" rev-parse "$BRANCH")"

if [ "$HEAD_SHA" = "$UPSTREAM_SHA" ]; then
	printf 'safe-pull: already up to date (%s)\n' "${UPSTREAM_SHA:0:7}"
	exit 0
fi

INCOMING="$(git -C "$ROOT" rev-list --count "HEAD..$BRANCH")"
printf 'safe-pull: %s incoming commit(s) on %s\n' "$INCOMING" "$BRANCH"

if git -C "$ROOT" merge-base --is-ancestor HEAD "$BRANCH"; then
	:
elif [ "$FORCE_UPDATE" -eq 1 ]; then
	printf 'safe-pull: upstream history was rewritten; --force-update given, continuing\n' >&2
else
	record_finding \
		"Rewritten upstream history" \
		"$BRANCH" \
		"the upstream tip is not a descendant of HEAD; review the diff before integrating"
fi

# --- 3. commit metadata -------------------------------------------------------

while IFS='|' read -r sha author_email committer_email author_date committer_date subject; do
	[ -n "$sha" ] || continue
	if [ "$author_email" != "$committer_email" ]; then
		record_finding \
			"Author/committer mismatch" \
			"$sha" \
			"author $author_email, committer $committer_email — $subject"
	elif [ "$author_date" != "$committer_date" ] && [ -n "$author_date" ] && [ -n "$committer_date" ]; then
		record_finding \
			"Commit rewritten after authoring" \
			"$sha" \
			"authored $author_date, committed $committer_date — $subject"
	fi
done < <(git -C "$ROOT" log --format='%h|%ae|%ce|%ad|%cd|%s' --date=short "HEAD..$BRANCH" 2>/dev/null || true)

# --- 4-5. content rules over the incoming tree --------------------------------
#
# `git grep <pattern> <tree>` reads blobs from the object store, so hidden paths
# are covered by construction and nothing is written to disk.

run_ref_rule() {
	local title="$1"
	local pattern="$2"
	shift 2
	local row location

	while IFS= read -r row; do
		[ -n "$row" ] || continue
		row="${row#"$BRANCH":}"
		location="${row%%:*}"
		record_finding "$title" "$location" "matched in the incoming tree"
	done < <(git -C "$ROOT" grep -n -E -I "$pattern" "$BRANCH" -- "$@" 2>/dev/null || true)
}

while IFS= read -r entry; do
	[ -n "$entry" ] || continue
	split_ioc_entry "$entry"
	run_ref_rule "$IOC_TITLE" "$IOC_PATTERN" "${IOC_EDITOR_PATHSPEC[@]}"
done < <(printf '%s\n' "${IOC_EDITOR_PATTERNS[@]}")

while IFS= read -r entry; do
	[ -n "$entry" ] || continue
	split_ioc_entry "$entry"
	run_ref_rule "$IOC_TITLE" "$IOC_PATTERN" "${IOC_ASSET_PATHSPEC[@]}"
done < <(printf '%s\n' "${IOC_ASSET_PATTERNS[@]}")

# --- 6. committed environment files -------------------------------------------

while IFS= read -r file; do
	[ -n "$file" ] || continue
	record_finding "Tracked .env file" "$file" "environment file present in the incoming tree"
done < <(git -C "$ROOT" grep -l -E -I '.' "$BRANCH" -- "${IOC_ENV_PATHSPEC[@]}" 2>/dev/null || true)

# --- 7. dependency pair -------------------------------------------------------

while IFS= read -r file; do
	[ -n "$file" ] || continue
	blob="$(git -C "$ROOT" show "$BRANCH:$file" 2>/dev/null || true)"
	if [[ "$blob" == *dotenv* && ("$blob" == *node-fetch* || "$blob" == *axios*) ]]; then
		record_finding \
			"Suspicious dependency pair" \
			"$file" \
			"dotenv together with a bare HTTP client — the shape used to read and POST a .env file"
	fi
done < <(git -C "$ROOT" diff --name-only "HEAD..$BRANCH" -- ':(glob)**/package.json' 2>/dev/null || true)

# --- report -------------------------------------------------------------------

if [ "${#FIND_TITLE[@]}" -gt 0 ]; then
	printf '\nsafe-pull: REFUSED — %d finding(s) in the incoming commits on %s\n' "${#FIND_TITLE[@]}" "$BRANCH"
	for i in "${!FIND_TITLE[@]}"; do
		printf '\n  %s\n' "${FIND_TITLE[$i]}"
		printf '    %s\n' "${FIND_LOCATION[$i]}"
		[ -n "${FIND_DETAIL[$i]}" ] && printf '    %s\n' "${FIND_DETAIL[$i]}"
	done
	cat <<'EOF'

Nothing was merged and no file was written to the working tree. If the findings
are genuine, stop and treat the account and the machine as compromised. If they
are false positives, re-run with --force-update only after reviewing the diff,
and prefer fixing the upstream commit over suppressing this guard.
EOF
	exit 1
fi

if [ "$DRY_RUN" -eq 1 ]; then
	printf '\nsafe-pull: clean (dry run) — %s incoming commit(s), nothing merged\n' "$INCOMING"
	exit 0
fi

printf '\nsafe-pull: clean, merging %s\n' "$BRANCH"
git -C "$ROOT" merge --ff-only "$BRANCH"
