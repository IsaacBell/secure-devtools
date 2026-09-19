#!/usr/bin/env bats
# test/am-i-being-recorded.bats
#
# Test suite for am-i-being-recorded (bin/am-i-being-recorded.sh).
#
# The filesystem pass is driven against synthetic Chromium profile trees.
# Every case passes --no-live, so the platform checks never run and the suite
# behaves identically on macOS and Linux CI.
#
# The host toolchain (bash, jq) is provided by mise — see ../mise.toml.

setup() {
  bats_require_minimum_version 1.5.0
  local node_modules_dir
  node_modules_dir="$(cd "$BATS_TEST_DIRNAME/.." && pnpm root)"
  BATS_LIB_PATH="${BATS_LIB_PATH:-}:${node_modules_dir}"
  bats_load_library bats-support
  bats_load_library bats-assert

  SCRIPT="$BATS_TEST_DIRNAME/../bin/am-i-being-recorded.sh"
  TMP="$(mktemp -d)"
}

teardown() {
  rm -rf "$TMP"
}

# --- helpers ---------------------------------------------------------------------

audit() {
  run bash "$SCRIPT" --root "$TMP" --no-live "$@"
}

# write_extension <browser_rel> <profile> <id> <version> <manifest-json>
write_extension() {
  local rel="$1" profile="$2" id="$3" version="$4" manifest="$5"
  local dir="$TMP/$rel/$profile/Extensions/$id/$version"
  mkdir -p "$dir"
  printf '%s\n' "$manifest" >"$dir/manifest.json"
}

# write_locale <browser_rel> <profile> <id> <version> <key> <message>
write_locale() {
  local rel="$1" profile="$2" id="$3" version="$4" key="$5" message="$6"
  local dir="$TMP/$rel/$profile/Extensions/$id/$version/_locales/en"
  mkdir -p "$dir"
  printf '{"%s":{"message":"%s"}}\n' "$key" "$message" >"$dir/messages.json"
}

BENIGN_ID="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

# --- CLI contract ----------------------------------------------------------------

@test "prints usage with --help" {
  run bash "$SCRIPT" --help
  assert_success
  assert_output --partial "usage: am-i-being-recorded"
}

@test "rejects an unknown argument" {
  run bash "$SCRIPT" --nope
  assert_failure 2
  assert_output --partial "unknown argument"
}

@test "rejects a --root that is not a directory" {
  run bash "$SCRIPT" --root "$TMP/missing"
  assert_failure 2
  assert_output --partial "is not a directory"
}

@test "requires a value for --root" {
  run bash "$SCRIPT" --root
  assert_failure 2
  assert_output --partial "--root requires a directory"
}

@test "rejects an invalid --min-severity" {
  run bash "$SCRIPT" --min-severity LOUD
  assert_failure 2
  assert_output --partial "invalid severity"
}

# --- detection -------------------------------------------------------------------

@test "a benign extension produces no findings" {
  write_extension "BraveSoftware/Brave-Browser" "Default" "$BENIGN_ID" "1.0.0" \
    '{"name":"Tabs Helper","version":"1.0.0","permissions":["storage","tabs","alarms"]}'
  audit
  assert_success
  assert_output --partial "no findings"
}

@test "desktopCapture is reported as CRITICAL" {
  write_extension "BraveSoftware/Brave-Browser" "Default" "$BENIGN_ID" "4.4.44" \
    '{"name":"Awesome Screen Recorder","version":"4.4.44","permissions":["desktopCapture"]}'
  audit
  assert_success
  assert_output --partial "CRITICAL"
  assert_output --partial "Can capture the entire display"
}

@test "Linux browser profile layouts are scanned" {
  write_extension "google-chrome" "Default" "$BENIGN_ID" "1.0.0" \
    '{"name":"Recorder","version":"1.0.0","permissions":["desktopCapture"]}'
  audit
  assert_output --partial "CRITICAL"
  assert_output --partial "google-chrome/Default"
}

@test "browser and profile are named in the finding scope" {
  write_extension "Google/Chrome" "Profile 2" "$BENIGN_ID" "1.0.0" \
    '{"name":"Capture Thing","version":"1.0.0","permissions":["desktopCapture"]}'
  audit
  assert_output --partial "Google/Chrome/Profile 2"
}

@test "only the newest version of a multi-version extension is reported" {
  write_extension "BraveSoftware/Brave-Browser" "Default" "$BENIGN_ID" "1.0.0" \
    '{"name":"Recorder","version":"1.0.0","permissions":["desktopCapture"]}'
  write_extension "BraveSoftware/Brave-Browser" "Default" "$BENIGN_ID" "2.0.0" \
    '{"name":"Recorder","version":"2.0.0","permissions":["desktopCapture"]}'
  audit
  assert_output --partial "v2.0.0"
  refute_output --partial "v1.0.0"
}

@test "--strict exits 1 when findings exist" {
  write_extension "BraveSoftware/Brave-Browser" "Default" "$BENIGN_ID" "1.0.0" \
    '{"name":"Recorder","version":"1.0.0","permissions":["desktopCapture"]}'
  run bash "$SCRIPT" --root "$TMP" --no-live --strict
  assert_failure 1
}

@test "--strict exits 0 when there are no findings" {
  run bash "$SCRIPT" --root "$TMP" --no-live --strict
  assert_success
}

@test "--min-severity hides findings below the floor" {
  write_extension "BraveSoftware/Brave-Browser" "Default" "$BENIGN_ID" "1.0.0" \
    '{"name":"Tab Grabber","version":"1.0.0","permissions":["tabCapture"]}'
  run bash "$SCRIPT" --root "$TMP" --no-live --min-severity CRITICAL
  assert_output --partial "no findings"
  assert_output --partial "floor CRITICAL"
}

@test "--min-severity CRITICAL also lowers the strict exit code" {
  write_extension "BraveSoftware/Brave-Browser" "Default" "$BENIGN_ID" "1.0.0" \
    '{"name":"Tab Grabber","version":"1.0.0","permissions":["tabCapture"]}'
  run bash "$SCRIPT" --root "$TMP" --no-live --min-severity CRITICAL --strict
  assert_success
}

@test "desktopCapture with offscreen and all-urls reports both combinations" {
  write_extension "BraveSoftware/Brave-Browser" "Default" "$BENIGN_ID" "1.0.0" \
    '{"name":"Recorder","version":"1.0.0","permissions":["desktopCapture","offscreen"],"host_permissions":["<all_urls>"]}'
  audit
  assert_output --partial "recordings can include any page"
  assert_output --partial "outlive the visible tab"
}

@test "tabCapture alone does not trigger the all-urls combination" {
  write_extension "BraveSoftware/Brave-Browser" "Default" "$BENIGN_ID" "1.0.0" \
    '{"name":"Tab Grabber","version":"1.0.0","permissions":["tabCapture"],"host_permissions":["<all_urls>"]}'
  audit
  refute_output --partial "recordings can include any page"
}

@test "offscreen alone does not trigger the persistent-capture combination" {
  write_extension "BraveSoftware/Brave-Browser" "Default" "$BENIGN_ID" "1.0.0" \
    '{"name":"Offscreen Helper","version":"1.0.0","permissions":["offscreen"]}'
  audit
  refute_output --partial "outlive the visible tab"
}

@test "optional permissions are flagged as runtime-granted" {
  write_extension "BraveSoftware/Brave-Browser" "Default" "$BENIGN_ID" "1.0.0" \
    '{"name":"Maybe Debug","version":"1.0.0","permissions":[],"optional_permissions":["debugger"]}'
  audit
  assert_output --partial "optional, granted at runtime"
}

@test "localized extension names are resolved from _locales" {
  write_extension "Google/Chrome" "Profile 1" "$BENIGN_ID" "2.0.0" \
    '{"name":"__MSG_extName__","version":"2.0.0","permissions":["tabCapture"]}'
  write_locale "Google/Chrome" "Profile 1" "$BENIGN_ID" "2.0.0" "extName" "Sneaky Capture"
  audit
  assert_output --partial "Sneaky Capture"
}

@test "an unresolved localized name falls back to a placeholder" {
  write_extension "Google/Chrome" "Profile 1" "$BENIGN_ID" "1.0.0" \
    '{"name":"__MSG_missing__","version":"1.0.0","permissions":["tabCapture"]}'
  audit
  assert_output --partial "(unknown)"
}

@test "an unreadable manifest is skipped without failing the run" {
  write_extension "BraveSoftware/Brave-Browser" "Default" "$BENIGN_ID" "1.0.0" \
    'not json at all'
  write_extension "BraveSoftware/Brave-Browser" "Default" "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" "1.0.0" \
    '{"name":"Recorder","version":"1.0.0","permissions":["desktopCapture"]}'
  audit
  assert_success
  assert_output --partial "Recorder"
}

@test "non-profile directories under a browser are ignored" {
  mkdir -p "$TMP/BraveSoftware/Brave-Browser/GrShaderCache"
  write_extension "BraveSoftware/Brave-Browser" "Default" "$BENIGN_ID" "1.0.0" \
    '{"name":"Recorder","version":"1.0.0","permissions":["desktopCapture"]}'
  audit
  assert_output --partial "CRITICAL"
  refute_output --partial "GrShaderCache"
}

@test "a root with no browser profiles is reported as context" {
  run bash "$SCRIPT" --root "$TMP" --no-live
  assert_success
  assert_output --partial "no browser profiles found"
}
