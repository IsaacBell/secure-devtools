#!/usr/bin/env bats
# test/safe-pull.bats
#
# Test suite for the guarded pull script (bin/safe-pull.sh).
#
# Every test builds a throwaway bare "origin" plus a working clone, pushes an
# incoming change from a second clone, and then runs the guard in the working
# clone. The contract under test is that nothing reaches the working tree until
# every check is clean.
#
# The host toolchain (bash, git) must be installed.

setup() {
  bats_require_minimum_version 1.5.0
  local node_modules_dir
  node_modules_dir="$(cd "$BATS_TEST_DIRNAME/.." && pnpm root)"
  BATS_LIB_PATH="${BATS_LIB_PATH:-}:${node_modules_dir}"
  bats_load_library bats-support
  bats_load_library bats-assert

  SCRIPT="$BATS_TEST_DIRNAME/../bin/safe-pull.sh"

  TMP="$(mktemp -d)"
  ORIGIN="$TMP/origin.git"
  WORK="$TMP/work"
  OTHER="$TMP/other"

  git init -q --bare "$ORIGIN"

  git init -q -b main "$WORK"
  git -C "$WORK" config user.name "Test"
  git -C "$WORK" config user.email "test@example.com"
  git -C "$WORK" config commit.gpgsign false
  git -C "$WORK" remote add origin "$ORIGIN"
  printf 'console.log("clean")\n' >"$WORK/index.js"
  git -C "$WORK" add -A
  GIT_AUTHOR_NAME="Test" GIT_AUTHOR_EMAIL="test@example.com" \
    GIT_COMMITTER_NAME="Test" GIT_COMMITTER_EMAIL="test@example.com" \
    git -C "$WORK" commit -qm "init"
  git -C "$WORK" push -q -u origin main

  git init -q -b main "$OTHER"
  git -C "$OTHER" config user.name "Test"
  git -C "$OTHER" config user.email "test@example.com"
  git -C "$OTHER" config commit.gpgsign false
  git -C "$OTHER" remote add origin "$ORIGIN"
  git -C "$OTHER" fetch -q origin main
  git -C "$OTHER" checkout -q -B main FETCH_HEAD
}

teardown() {
  rm -rf "$TMP"
}

# Hermetic identity: a git hook (husky) exports GIT_AUTHOR_* into the
# environment, which would otherwise leak into the throwaway commits and trip the
# author/committer mismatch rule being tested elsewhere.
run_git_as_test() {
  GIT_AUTHOR_NAME="Test" GIT_AUTHOR_EMAIL="test@example.com" \
    GIT_COMMITTER_NAME="Test" GIT_COMMITTER_EMAIL="test@example.com" \
    git "$@"
}

# commit_and_push <repo> <message> pushes the current state of a clone.
commit_and_push() {
  local repo="$1"
  local message="$2"
  git -C "$repo" add -A
  run_git_as_test -C "$repo" commit -qm "$message"
  git -C "$repo" push -q origin main
}

pull_guard() {
  run bash "$SCRIPT" "$@"
}

# -------------------------------------------------------------------------------
# Happy path
# -------------------------------------------------------------------------------

@test "installed entrypoint: safe-pull symlink finds sibling rules" {
  ln -s "$SCRIPT" "$TMP/safe-pull"
  cd "$WORK"
  run "$TMP/safe-pull" --dry-run
  assert_success
  assert_output --partial "already up to date"
}

@test "clean incoming commit is merged (fast-forward)" {
  printf 'console.log("feature")\n' >"$OTHER/feature.js"
  commit_and_push "$OTHER" "add feature"

  cd "$WORK"
  pull_guard
  assert_success
  assert_output --partial "safe-pull: clean, merging origin/main"
  [ -f "$WORK/feature.js" ]
}

@test "already up to date exits 0 without merging" {
  cd "$WORK"
  pull_guard
  assert_success
  assert_output --partial "already up to date"
}

@test "dry run reports clean and merges nothing" {
  printf 'console.log("feature")\n' >"$OTHER/feature.js"
  commit_and_push "$OTHER" "add feature"

  cd "$WORK"
  pull_guard --dry-run
  assert_success
  assert_output --partial "clean (dry run)"
  [ ! -f "$WORK/feature.js" ]
}

@test "core.fsmonitor from the working tree's .git/config does not run" {
  printf 'console.log("feature")\n' >"$OTHER/feature.js"
  commit_and_push "$OTHER" "add feature"

  cd "$WORK"
  # Set after setup, which would run the hook itself. The marker sits outside
  # the working tree so it cannot dirty it.
  git -C "$WORK" config core.fsmonitor "touch '$TMP/ran'; false"
  pull_guard --dry-run
  if [[ -e "$TMP/ran" ]]; then
    fail "core.fsmonitor from the working tree ran during safe-pull"
  fi
  assert_success
  assert_output --partial "clean (dry run)"
}

# -------------------------------------------------------------------------------
# Refusals
# -------------------------------------------------------------------------------

@test "editor auto-run payload is refused and never checked out" {
  mkdir -p "$OTHER/.vscode" "$OTHER/design/fonts"
  printf '%s\n' '{"tasks":[{"label":"lint","command":"node ./design/fonts/fa-solid-400.woff2","runOptions":{"runOn":"folderOpen"}}]}' \
    >"$OTHER/.vscode/tasks.json"
  printf '%s\n' 'global.i="A9";const _0x44ceab="x";require("http");' \
    >"$OTHER/design/fonts/fa-solid-400.woff2"
  commit_and_push "$OTHER" "refactoring"

  cd "$WORK"
  pull_guard
  assert_failure
  assert_equal "$status" 1
  assert_output --partial "REFUSED"
  assert_output --partial "Editor auto-run task"
  assert_output --partial "Payload hidden in an asset file"
  [ ! -e "$WORK/.vscode/tasks.json" ]
  [ ! -e "$WORK/design/fonts/fa-solid-400.woff2" ]
}

# Synthetic Git histories for content inspection and integration checks.
# Fixture contents are read as data, never executed.
@test "regression: a font payload added then deleted is still refused" {
  local before flagged_commit
  before="$(git -C "$WORK" rev-parse HEAD)"
  mkdir -p "$OTHER/public/fonts"
  printf '%s\n' 'const _0x123abc = "inert regression marker";' >"$OTHER/public/fonts/sample.woff2"
  commit_and_push "$OTHER" "add font"
  flagged_commit="$(git -C "$OTHER" rev-parse HEAD)"
  rm "$OTHER/public/fonts/sample.woff2"
  commit_and_push "$OTHER" "delete font"

  cd "$WORK"
  pull_guard
  assert_equal "$status" 1
  assert_output --partial "Payload hidden in an asset file"
  assert_output --partial "$flagged_commit"
  [ "$(git rev-parse HEAD)" = "$before" ]
  [ ! -e public/fonts/sample.woff2 ]
}

@test "regression: a NUL byte cannot hide JavaScript in a renamed eot font" {
  local before
  before="$(git -C "$WORK" rev-parse HEAD)"
  mkdir -p "$OTHER/public/fonts"
  printf '/*\000 inert padding */\nconst _0x456def = "inert regression marker";\n' >"$OTHER/public/fonts/renamed.eot"
  commit_and_push "$OTHER" "add font"

  cd "$WORK"
  pull_guard
  assert_equal "$status" 1
  assert_output --partial "Payload hidden in an asset file"
  [ "$(git rev-parse HEAD)" = "$before" ]
  [ ! -e public/fonts/renamed.eot ]
}

@test "regression: an editor trigger removed before the tip is still refused" {
  mkdir -p "$OTHER/.vscode"
  printf '%s\r\n' '{"task.allowAutomaticTasks":true}' >"$OTHER/.vscode/settings.json"
  commit_and_push "$OTHER" "add editor settings"
  rm "$OTHER/.vscode/settings.json"
  commit_and_push "$OTHER" "delete editor settings"

  cd "$WORK"
  pull_guard --dry-run
  assert_equal "$status" 1
  assert_output --partial "Editor auto-run task"
  [ ! -e .vscode/settings.json ]
}

@test "regression: ordinary documentation added then removed remains allowed" {
  printf '%s\n' '# Notes' >"$OTHER/notes.md"
  commit_and_push "$OTHER" "add notes"
  rm "$OTHER/notes.md"
  commit_and_push "$OTHER" "delete notes"

  cd "$WORK"
  pull_guard
  assert_success
  [ "$(git rev-parse HEAD)" = "$(git -C "$OTHER" rev-parse HEAD)" ]
}

@test "regression: a payload on a merged side branch is refused even with a clean merge tree" {
  local flagged_commit before
  before="$(git -C "$WORK" rev-parse HEAD)"
  git -C "$OTHER" checkout -qb side
  mkdir -p "$OTHER/public/fonts"
  printf '%s\n' 'const _0x456def = "inert regression marker";' >"$OTHER/public/fonts/side.eot"
  git -C "$OTHER" add -A
  run_git_as_test -C "$OTHER" commit -qm "side branch font"
  flagged_commit="$(git -C "$OTHER" rev-parse HEAD)"
  git -C "$OTHER" checkout -q main
  run_git_as_test -C "$OTHER" merge -q --no-ff -s ours side -m "merge with clean tree"
  git -C "$OTHER" push -q origin main

  cd "$WORK"
  pull_guard
  assert_equal "$status" 1
  assert_output --partial "$flagged_commit"
  assert_output --partial "Payload hidden in an asset file"
  [ "$(git rev-parse HEAD)" = "$before" ]
}

@test "committed .env file is refused" {
  printf 'API_KEY=placeholder\n' >"$OTHER/.env"
  commit_and_push "$OTHER" "add env"

  cd "$WORK"
  pull_guard
  assert_failure
  assert_output --partial "Tracked .env file"
  [ ! -e "$WORK/.env" ]
}

@test "regression: a Git content inspection error blocks integration" {
  local actual_git before
  actual_git="$(command -v git)"
  before="$(git -C "$WORK" rev-parse HEAD)"
  printf '%s\n' '# Clean documentation' >"$OTHER/notes.md"
  commit_and_push "$OTHER" "add notes"
  mkdir "$TMP/mockbin"
  cat >"$TMP/mockbin/git" <<'EOF'
#!/usr/bin/env bash
for arg do
  if [[ "$arg" == grep ]]; then exit 2; fi
done
exec "$REAL_GIT" "$@"
EOF
  chmod +x "$TMP/mockbin/git"

  cd "$WORK"
  run env PATH="$TMP/mockbin:$PATH" REAL_GIT="$actual_git" bash "$SCRIPT"
  assert_equal "$status" 1
  assert_output --partial "Git content inspection failed"
  [ "$(git rev-parse HEAD)" = "$before" ]
  [ ! -e notes.md ]
}

@test "dotenv plus node-fetch in a changed package.json is refused" {
  printf '%s\n' '{"dependencies":{"dotenv":"^8","node-fetch":"^3"}}' >"$OTHER/package.json"
  commit_and_push "$OTHER" "add deps"

  cd "$WORK"
  pull_guard
  assert_failure
  assert_output --partial "Suspicious dependency pair"
}

@test "rewritten upstream history is refused" {
  printf 'console.log("changed")\n' >"$OTHER/index.js"
  git -C "$OTHER" add -A
  GIT_AUTHOR_NAME="Test" GIT_AUTHOR_EMAIL="test@example.com" \
    GIT_COMMITTER_NAME="Test" GIT_COMMITTER_EMAIL="test@example.com" \
    git -C "$OTHER" commit -q --amend -m "init rewritten"
  git -C "$OTHER" push -q --force origin main

  cd "$WORK"
  pull_guard
  assert_failure
  assert_output --partial "Rewritten upstream history"
  assert_output --partial "REFUSED"
}

@test "author/committer mismatch in an incoming commit is refused" {
  printf 'console.log("feature")\n' >"$OTHER/feature.js"
  git -C "$OTHER" add -A
  GIT_AUTHOR_NAME="Test" GIT_AUTHOR_EMAIL="test@example.com" \
    GIT_COMMITTER_NAME="Attacker" GIT_COMMITTER_EMAIL="attacker@example.com" \
    git -C "$OTHER" commit -qm "feature with mismatched identities"
  git -C "$OTHER" push -q origin main

  cd "$WORK"
  pull_guard
  assert_failure
  assert_output --partial "Author/committer mismatch"
}

# -------------------------------------------------------------------------------
# Preconditions
# -------------------------------------------------------------------------------

@test "dirty working tree exits 2 before fetching" {
  printf 'uncommitted\n' >>"$WORK/index.js"

  cd "$WORK"
  pull_guard
  assert_failure
  assert_equal "$status" 2
  assert_output --partial "uncommitted changes"
}

@test "unknown option exits 2 with usage" {
  cd "$WORK"
  pull_guard --nonsense
  assert_failure
  assert_equal "$status" 2
  assert_output --partial "usage"
}
