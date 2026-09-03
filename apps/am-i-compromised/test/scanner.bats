#!/usr/bin/env bats
# test/scanner.bats

setup() {
  bats_require_minimum_version 1.5.0
  local node_modules_dir
  node_modules_dir="$(cd "$BATS_TEST_DIRNAME/.." && pnpm root)"
  BATS_LIB_PATH="${BATS_LIB_PATH:-}:${node_modules_dir}"
  bats_load_library bats-support
  bats_load_library bats-assert

  SCRIPT="$BATS_TEST_DIRNAME/../bin/scanner.sh"
  TMP="$(mktemp -d)"
}

teardown() {
  rm -rf "$TMP"
}

@test "clean repo passes" {
  echo 'console.log("hello")' > "$TMP/index.js"
  run bash "$SCRIPT" "$TMP"
  assert_success
}

@test "eval() on a config file is flagged" {
  echo 'eval(atob("...")); ' > "$TMP/config.js"
  run bash "$SCRIPT" "$TMP"
  assert_failure
}

@test "fixtures dir is excluded by default" {
  mkdir -p "$TMP/__security_gate_fixtures__"
  cp "$BATS_TEST_DIRNAME/__security_gate_fixtures__/malicious/quarantined-tailwind.config.js" \
     "$TMP/__security_gate_fixtures__/"
  run bash "$SCRIPT" "$TMP"
  assert_success   # excluded, so the gate should NOT trip on it
}

@test "fixtures dir is scanned when INCLUDE_FIXTURES=1 (self-test)" {
  mkdir -p "$TMP/__security_gate_fixtures__"
  cp "$BATS_TEST_DIRNAME/__security_gate_fixtures__/malicious/quarantined-tailwind.config.js" \
     "$TMP/__security_gate_fixtures__/"
  INCLUDE_FIXTURES=1 run bash "$SCRIPT" "$TMP"
  assert_failure   # proves detection logic actually still works
}

@test "line length limit triggers on oversized source line" {
  python3 -c "print('var x = \"' + 'A'*5000 + '\";')" > "$TMP/big.js"
  run bash "$SCRIPT" "$TMP"
  assert_failure
}

@test "long line over limit is flagged" {
  printf 'var x = "%s";\n' "$(printf 'A%.0s' $(seq 1 5000))" > "$TMP/big.js"
  run bash "$SCRIPT" "$TMP"
  assert_failure
  assert_output --partial "exceeding"
}

@test "long line output is truncated with a count when huge" {
  local long_string
  long_string="$(printf 'A%.0s' $(seq 1 5000))"
  for i in $(seq 1 150); do
    printf 'var x%d = "%s";\n' "$i" "$long_string" >> "$TMP/big.js"
  done
  run bash "$SCRIPT" "$TMP"
  assert_failure
  assert_output --partial "truncated"
}

@test "excluded dirs (node_modules) are never scanned" {
  mkdir -p "$TMP/node_modules/evil"
  echo 'eval(atob("bad"))' > "$TMP/node_modules/evil/index.js"
  run bash "$SCRIPT" "$TMP"
  assert_success
}

@test "exit code is 0 on clean repo, 1 on flagged repo" {
  echo 'console.log(1)' > "$TMP/clean.js"
  run bash "$SCRIPT" "$TMP"
  assert_equal "$status" 0

  echo 'eval(atob("bad"))' > "$TMP/dirty.js"
  run bash "$SCRIPT" "$TMP"
  assert_equal "$status" 1
}
