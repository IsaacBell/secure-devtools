#!/usr/bin/env bats
# test/secure-semgrep.bats
#
# Test suite for the secure-semgrep CLI (bin/secure-semgrep.sh).
#
# The tests are hermetic on purpose: they run scan with --no-default (-N) so
# they only exercise the Bundled rules in rules/ and never hit the network for
# Semgrep's p/... packs. Registry loadouts (react, ts, node, py, rust) are
# asserted only by `pack`, whose resolution does not require a scan.
#
# Requires `semgrep` on PATH (provided by mise / the semgrep container). Bats
# helper libraries come from the package devDependencies.

setup() {
  bats_require_minimum_version 1.5.0
  local node_modules_dir
  node_modules_dir="$(cd "$BATS_TEST_DIRNAME/.." && pnpm root)"
  BATS_LIB_PATH="${BATS_LIB_PATH:-}:${node_modules_dir}"
  bats_load_library bats-support
  bats_load_library bats-assert

  SCRIPT="$BATS_TEST_DIRNAME/../bin/secure-semgrep.sh"
  TMP="$(mktemp -d)"
}

teardown() {
  rm -rf "$TMP"
}

need_semgrep() {
  if ! command -v semgrep >/dev/null 2>&1; then
    skip "semgrep is not on PATH"
  fi
}

# --- helpers -----------------------------------------------------------------

write_file() {
  # write_file <relpath> <contents...>
  local rel="$1"
  shift
  mkdir -p "$TMP/$(dirname "$rel")"
  printf '%s\n' "$@" >"$TMP/$rel"
}

# -------------------------------------------------------------------------------
# CLI contract
# -------------------------------------------------------------------------------
@test "--version echoes the package version" {
  run bash "$SCRIPT" --version
  assert_success
  assert_output --regexp '^secure-semgrep [0-9]+\.[0-9]+\.[0-9]+'
}

@test "--help prints usage and exits 0" {
  run bash "$SCRIPT" --help
  assert_success
  assert_output --partial "LOADOUTS"
}

@test "missing semgrep yields a clear error and exit 1" {
  SEMGREP_BIN=/no/such/semgrep run bash "$SCRIPT" -N "$TMP"
  assert_failure
  assert_output --partial "SEMGREP_BIN"
}

# -------------------------------------------------------------------------------
# pack resolution (hermetic — no scan performed)
# -------------------------------------------------------------------------------
@test "pack -N lists only the owned rule dirs" {
  run bash "$SCRIPT" pack -N
  assert_success
  assert_output --partial "rules/ai"
  assert_output --partial "rules/bash"
}

@test "pack adds registry loadout packs when requested" {
  run bash "$SCRIPT" pack -N --loadout react --loadout py
  assert_success
  assert_output --partial "p/react"
  assert_output --partial "p/python"
}

@test "pack includes p/default and p/security-audit unless --no-default" {
  run bash "$SCRIPT" pack
  assert_success
  assert_output --partial "p/default"
  assert_output --partial "p/security-audit"
}

# -------------------------------------------------------------------------------
# bundled rules load and scan cleanly
# -------------------------------------------------------------------------------
@test "check validates every bundled rule" {
  need_semgrep
  run bash "$SCRIPT" check
  assert_success
  assert_output --partial "Configuration is valid"
}

@test "clean target exits 0" {
  need_semgrep
  write_file "ok.py" 'x = 1' 'print("hi")'
  run bash "$SCRIPT" -N "$TMP"
  assert_success
  assert_output --partial "0 findings"
}

@test "vulnerable bash target exits 1 with the expected rule" {
  need_semgrep
  write_file "bad/setup.sh" '#!/bin/bash' 'IFS=","'
  run bash "$SCRIPT" -N "$TMP"
  assert_failure
  assert_output --partial "ifs-tampering"
}

@test "--no-error reports findings but exits 0" {
  need_semgrep
  write_file "bad/setup.sh" '#!/bin/bash' 'IFS=","'
  run bash "$SCRIPT" -N --no-error "$TMP"
  assert_success
  assert_output --partial 'ifs-tampering'
}

@test "unknown loadout exits 2" {
  run bash "$SCRIPT" pack -N --loadout bogus
  assert_failure 2
  assert_output --partial "unknown loadout"
}

@test "nonexistent target is reported by semgrep (nonzero)" {
  need_semgrep
  run bash "$SCRIPT" -N "$TMP/does-not-exist"
  assert_failure
}
