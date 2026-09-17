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
# The host toolchain (bash, git) is provided by mise — see ../mise.toml.

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

@test "committed .env file is refused" {
  printf 'API_KEY=placeholder\n' >"$OTHER/.env"
  commit_and_push "$OTHER" "add env"

  cd "$WORK"
  pull_guard
  assert_failure
  assert_output --partial "Tracked .env file"
  [ ! -e "$WORK/.env" ]
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
