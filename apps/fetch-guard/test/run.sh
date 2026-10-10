#!/usr/bin/env bash
# Tests the reference-transaction hook against real git commands in throwaway repos.
# Usage: test/fetch-guard.sh <empty-or-new-work-dir>
# The hook is wired per command with `-c core.hooksPath`, so no global git config is touched.
set -uo pipefail

WORK="${1:?usage: fetch-guard.sh <work-dir>}"
HOOKS="$(cd "$(dirname "${BASH_SOURCE[0]}")/../git-hooks" && pwd)"
mkdir -p "$WORK" && WORK="$(cd "$WORK" && pwd)"
pass=0 fail=0

g() { git -c user.name=t -c user.email=t@example.com -c commit.gpgsign=false -c core.hooksPath="$HOOKS" "$@"; }
plain() { git -c user.name=t -c user.email=t@example.com -c commit.gpgsign=false "$@"; }
check() { # check <name> <want: allow|block> <command...>
  local name="$1" want="$2" out rc; shift 2
  out="$("$@" 2>&1)"; rc=$?
  if { [[ "$want" == allow && $rc -eq 0 ]] || [[ "$want" == block && $rc -ne 0 && "$out" == *"BLOCKED by fetch-guard"* ]]; }; then
    echo "PASS $want: $name"; pass=$((pass + 1))
  else
    echo "FAIL $want: $name (rc=$rc) $out"; fail=$((fail + 1))
  fi
}
advance() { echo "$1" >"$WORK/other/f"; plain -C "$WORK/other" commit -qam "$1" && plain -C "$WORK/other" push -q origin main; }

plain init -q --bare "$WORK/origin.git"
plain init -q -b main "$WORK/w"
plain -C "$WORK/w" remote add origin "$WORK/origin.git"
echo a >"$WORK/w/f"; plain -C "$WORK/w" add f; plain -C "$WORK/w" commit -qm init
check "push moves refs/remotes" allow g -C "$WORK/w" push -q -u origin main
plain clone -q "$WORK/origin.git" "$WORK/other"

advance b
check "ls-remote" allow g -C "$WORK/w" ls-remote origin
check "fetch" block g -C "$WORK/w" fetch -q
check "pull --ff-only" block g -C "$WORK/w" pull -q --ff-only
check "remote update" block g -C "$WORK/w" remote update
check "clone" block g clone -q "$WORK/origin.git" "$WORK/clone-blocked"
check "safe-pull style fetch (SAFE_PULL=1)" allow env SAFE_PULL=1 git -c core.hooksPath="$HOOKS" -C "$WORK/w" fetch -q

advance c
printf '#!/usr/bin/env bash\necho "BLOCKED by fetch-guard: repo hook ran" >&2\nexit 1\n' >"$WORK/w/.git/hooks/reference-transaction"
chmod +x "$WORK/w/.git/hooks/reference-transaction"
check "repo-local hook still runs (chained)" block g -C "$WORK/w" commit --allow-empty -qm x

echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
