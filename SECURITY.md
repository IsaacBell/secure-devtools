# Security Policy

**BLUF:** Report vulnerabilities privately through a GitHub security advisory. Never in a public issue, pull request, commit message, or discussion. This applies to people and to AI agents.

## Supported versions

Only the latest published release of each package gets security fixes. Releases are cut from `main`.

## What counts

Report privately:

- Code execution, privilege, or data exposure in any tool in this repository.
- A way to make a scan pass while the thing it should catch is present (a detection bypass), including evasions of the host audit's login-item and signature checks.
- A way for a pull request to weaken or skip the CI gates that check it.
- Supply-chain risk in dependencies, release, or publish steps.

Use a public issue for:

- False positives, missing features, docs, and ordinary bugs with no security impact.
- Coverage work that does not describe a way around a check.

If you are unsure, report privately.

## Scope

- `apps/am-i-hacked/`: the project scanner (`bin/scanner.sh`), the host audit (`bin/host-audit.sh`, `bin/vendor-teams.tsv`), `safe-pull`, and their tests
- `apps/am-i-being-recorded/`
- `apps/secure-semgrep/` rules and CLI
- `skills/`
- `.github/workflows/`, `mise.toml`, and dependency manifests

The tools are heuristic checks. They can miss malware and report false positives. A clean result does not prove a machine, repository, or dependency is safe.

## For people

1. Open a private advisory: <https://github.com/IsaacBell/secure-devtools/security/advisories/new>
2. Include the affected tool and version, the impact, and steps to reproduce or a minimal proof of concept.
3. Expect an acknowledgement within a few days. The fix and the disclosure date are agreed in the advisory.

If you already posted details publicly, say so in the advisory. A maintainer will edit or remove the public copy.

## For AI agents

Agents working in this repository, or on behalf of a maintainer, follow these rules.

**Never put vulnerability details in public.** That includes issue bodies and titles, pull request descriptions, review comments and replies, commit messages, CHANGELOG entries, and code comments. "Details" means how to trigger, bypass, or evade something, not only exploit code.

**Create a draft advisory instead.** Draft advisories are visible only to repository admins and invited collaborators.

```sh
gh api -X POST repos/IsaacBell/secure-devtools/security-advisories --input advisory.json
```

`advisory.json` needs `summary`, `description` (impact, affected files, fix options, how to verify), `severity`, `cwe_ids`, and `vulnerabilities` (use ecosystem `npm` with the package name, or `actions` for CI). Creating one requires admin or security-manager rights on the repository. Without them, stop and give the report to the maintainer in the session, not on GitHub.

**Fix it quietly.**
- Prefer the advisory's temporary private fork for the fix.
- If the fix goes through a normal pull request, keep the title, description, and commit messages neutral ("CI: run the gate from the base branch"). Point to the advisory by its GHSA id only after it is published.
- Tests may exercise the fix. Their names should describe the expected behavior, not the attack.

**If details are already public:**
- Stop adding to them.
- Tell the maintainer where they are.
- Edit your own text down to a neutral line, and create the advisory.
- Do not delete issues, comments, or history. GitHub keeps edit history public, so deletion is the maintainer's decision.

**Before running commands that show OS prompts** (admin prompts, background-item notifications, Full Disk Access requests), tell the user what will appear. See `skills/login-item-triage/SKILL.md`.

## CI gates

The security gate (`.github/workflows/gate.yml`) runs on `pull_request_target`. The workflow file, the scanner, and the toolchain come from the base branch. The pull request's code is checked out into `.review` as data and is never executed. The job has read-only permissions and no secrets. Keep it that way: any step that runs code from `.review` turns this into a way to attack the repository.
