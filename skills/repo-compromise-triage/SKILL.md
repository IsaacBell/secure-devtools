---
name: repo-compromise-triage
description: "Use when a hosted repository or its account may have been tampered with: a pushed commit differs from the one made locally, a config file grew, a scanner flags a branch, or someone says 'check the repo for a malicious commit'. Read-only investigation using git history, the hosting API, the account security log and a code scanner, without building or running anything. Produces a confirmed / not known report and a fix order."
version: 1.0.0
verified-against: "git 2.51, GitHub CLI 2.75, am-i-hacked 2.0.1 (main)"
---

# Repo compromise triage

**BLUF:** Treat the repository as data. Never install, build, test, run or open it in an editor. Compare, count and search with git and the hosting API, scan saved copies, and report what is confirmed and what is not known. Never say "safe".

Related: `quarantine-review` (inspect or salvage a local folder), `secure-skill-pull` (third-party skills), `process-data` (narrowing large output).

## 1. Signals that start a triage

- A pushed commit has the same author, time and parent as a local commit but a different hash. The commit was rewritten after it was made.
- A tool config file (`tailwind.config.*`, `postcss.config.*`, `eslint.config.*`, `next.config.*`, `vite.config.*`) is far larger than it should be. A clean one is usually under 1 KB.
- A commit's author date and committer date are weeks apart, or its message does not match what it changed.
- A scanner flags a branch, or a security check in CI has never actually run.

## 2. Read-only steps, in order

1. **Compare the pair.** `git log -1 --format='%h %an %cn %ad parents=%p' <ref>` for the local and pushed commit, then `git diff --stat <local> <pushed>`. Read the difference, not the files.
2. **Size every tip.** For each remote branch, `git cat-file -s <ref>:<config-file>` for the config files above. One size outlier across branches finds the spread in seconds.
3. **Search without checking out.** `git grep -l -F '<marker>' <ref>` and `git log -S'<marker>' --reverse -- <path>`. Search every branch tip and open pull-request branch, not only the default.
4. **Test the detector.** Save the bad blob and a clean blob as plain files (`git show <ref>:<path> > file`) in a working folder, and run the scanner (`npx am-i-hacked <folder>`) on each. It must flag the first and pass the second before you trust a clean result elsewhere.
5. **Check what the code could reach.** With the hosting CLI, read only: how many workflow runs happened since the first bad commit; the names (never values) of repository secrets in scope; collaborators and their roles; webhook hosts and deploy keys.
6. **Read the account security log.** Export it from the account settings. Look for: second-factor recovery, sign-ins from new devices, country changes, password or key changes, token and application authorization churn. Bisect by date around the bad commits (see `process-data`).
7. **Check the machine.** Scan the working tree, then run the host scan. If a scan hangs or prints nothing, say the machine is not confirmed clean.

## 3. Cautions

- A fetch writes objects and runs nothing. The risk starts at checkout, merge, install, build, test or opening the folder in an editor. A project can still choose a stricter rule: if one says never fetch from a compromised remote, follow it and use `git ls-remote` (names and commit ids only). A guarded pull exists in this repository: `am-i-hacked`'s `safe-pull.sh`.
- Do not run, deobfuscate by execution or paste a payload. Count its size and markers, name the file and the commit, and stop there.
- Commit authorship and dates are claims, not proof. Unsigned commits can carry any author. The hosting API's event list shows which account pushed and when, within its limits (recent events only).
- An export may lack IP addresses and locations, and git pushes may not appear in the account log. An absent field is not an absent event.
- If the same file is infected on the default branch and everywhere else, the spread predates any single commit. Date the earliest one with `git log -S`.

## 4. The fix order

1. Stop anything that builds or runs the repository, including CI on open pull requests and any agent.
2. Rotate, from a clean device, every secret the workflows could read, plus account tokens and keys. Use the secret names from step 5.
3. Remove unknown collaborators and review webhooks and deploy keys.
4. Restore the clean files from a known-good local commit in a pull request. The bad history stays. Removing it needs a history rewrite and a force push, which many teams ban; the alternative is a fresh repository with clean history.
5. Add the scanner as a required check so a config file this large fails the build.

## 5. Report

1. **Confirmed**: each fact with the command that proves it.
2. **Not known**: how the commit was altered, what the payload does, whether the machine is clean.
3. **Exposure**: runs, secrets in scope, collaborators, webhooks.
4. **Timeline**: bad commit dates against the account security log.
5. **What you did that you should not have**: for example a fetch against a stricter rule.
6. **Fix order** from section 4.
