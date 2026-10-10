#!/usr/bin/env bash
set -euo pipefail

# bin/install-fetch-guard.sh
#
# Installs the git reference-transaction hook (git-hooks/reference-transaction) for every repo of the current
# user, so a raw `git fetch`, `pull` or `clone` cannot move remote-tracking refs. safe-pull.sh stays the way in.
#
# It copies the hook to ~/.config/git/fetch-guard-hooks and points the global `core.hooksPath` there, so an edit
# to the checkout never changes the installed guard. A global hooksPath replaces each repo's own hooks
# directory, so the installer also writes a pass-through shim for every standard hook name.
#
# This changes global git configuration: run it yourself, not through an agent.
# Usage: install-fetch-guard.sh [--uninstall]

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../git-hooks" && pwd)"
DEST="${XDG_CONFIG_HOME:-$HOME/.config}/git/fetch-guard-hooks"
STANDARD_HOOKS=(applypatch-msg pre-applypatch post-applypatch pre-commit pre-merge-commit prepare-commit-msg
  commit-msg post-commit pre-rebase post-checkout post-merge pre-push pre-receive update post-receive
  post-update push-to-checkout pre-auto-gc post-rewrite sendemail-validate fsmonitor-watchman p4-pre-submit
  post-index-change)

current="$(git config --global --get core.hooksPath || true)"

if [[ "${1:-}" == "--uninstall" ]]; then
  [[ "$current" == "$DEST" ]] && git config --global --unset core.hooksPath
  rm -rf "$DEST"
  echo "fetch-guard removed"
  exit 0
fi

if [[ -n "$current" && "$current" != "$DEST" ]]; then
  echo "install-fetch-guard: core.hooksPath is already set to $current; merge by hand, nothing changed" >&2
  exit 2
fi

mkdir -p "$DEST"
install -m 755 "$SRC/reference-transaction" "$DEST/reference-transaction"
for name in "${STANDARD_HOOKS[@]}"; do
  printf '#!/usr/bin/env bash\nhook="$(git rev-parse --git-path hooks/%s)"\n[[ -x "$hook" ]] && exec "$hook" "$@"\nexit 0\n' \
    "$name" >"$DEST/$name"
  chmod 755 "$DEST/$name"
done
git config --global core.hooksPath "$DEST"
echo "fetch-guard installed: core.hooksPath=$DEST"
