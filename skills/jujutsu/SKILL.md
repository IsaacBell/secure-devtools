---
name: jujutsu
description: Use Jujutsu (jj) for version control safely and non-interactively, especially as an AI agent. Use when a repo has a `.jj` directory, when git shows a detached HEAD or phantom changes, when committing, pushing, undoing, splitting or squashing, when recovering a conflicted or divergent history, or when a git habit does not map to jj. Built from real agent incidents, not from the manual. Version-stamped; jj changes fast, so check the stamp before trusting a command.
version: 2026-09-29
verified-against: jj 0.43.0
docs: https://docs.jj-vcs.dev/latest/
---

# Jujutsu (jj)

## Freshness: read this first

jj is pre-1.0. Commands, flags and defaults get renamed or removed between releases. This skill was written on **2026-09-29** against **jj 0.43.0**. Every command below was run on that version, except where marked "not re-run".

Before relying on it:

1. Run `jj --version`.
2. If the version is newer than 0.43.0, or this skill is more than about three months old, run `jj <command> --help` for any flag you use and read the docs at the URL above. The installed binary's help is the authority.
3. If a command errors with "unrecognized" or "unexpected argument", stop guessing. Read `jj help <command>`.

Never invent a flag.

## The model

- **The working copy is a commit, called `@`.** Edits are snapshotted into it the next time any jj command runs. There is no staging area and no `add`.
- **`@-` is its parent.** Change IDs stay stable when a change is rewritten; commit IDs do not. Refer to changes by change ID.
- **Bookmarks are static labels, not branches.** A git branch advances when you commit. A jj bookmark stays where it is until you move it. `@` roams freely.
- **Undo is built in.** Every operation is recorded.
- **Dirty is normal.** The habit is: edit freely, then shape history with `jj new`, `jj split`, `jj squash`.

## Git shows a detached HEAD and changes you never made

In a colocated repo (a `.git` directory beside `.jj`, the default for new repos on 0.43.0), git's HEAD is parked on `@-`. `git status` therefore reports "not on any branch" and lists the contents of `@` as uncommitted changes. Nothing is wrong.

- Confirm with `ls -d .jj` and `jj --version`.
- Look with `jj st` and `jj log`.
- **Do not fix it with git.** `git checkout` refuses ("local changes would be overwritten") and `git stash` fails ("not uptodate"), and `git update-index --refresh` changes nothing. Use jj.

Nested repositories: jj ignores a directory that has its own `.git`, while git treats it as a gitlink. Push a nested repo with git from inside that directory, not with jj from the parent.

## Rules for agents (each one came from a real failure)

1. **Always pass `--no-pager` on reads** (`jj --no-pager log`). Without it `log`, `status`, `show` and `diff` can open `less` and hang a non-interactive shell. `PAGER=cat` does not reliably stop it.
2. **Never run jj mutations in parallel.** `restore`, `new`, `edit`, `squash`, `rebase`, `commit`, `bookmark move` and `abandon` each need exclusive access to the working copy. Parallel calls fail with `Concurrent checkout` and can leave divergent working-copy heads. Reads (`log`, `diff`, `status`, `file list`) are safe to batch. If you see `Concurrent checkout`, stop and reassess. Do not retry while another mutation is running.
3. **A bookmark is not the current state.** `main` can point at an old tree while `@` holds all the work. Before saying "main is clean" or "deployable", compare trees: `jj file list -r main` against `jj file list -r @`.
4. **Trust content, not commit messages.** A commit described as a small change can hold a full-tree snapshot. Before abandoning or keeping a commit, look at `jj show --stat <rev>` or `jj diff --name-only -r <rev>`.
5. **Deduplicate by path before restoring from several revisions.** Restoring one path from two commits makes a conflict. Decide which revision wins first.
6. **"Clean" is not "correct".** No conflicts says nothing about whether the right commit is checked out.
7. **Verify a count before trusting a zero.** Some revset or template mistakes return `0` silently. Use `--no-graph` for scripted output, otherwise graph characters pollute IDs: `jj log --no-graph -T 'change_id.short() ++ "\n"'`.

## Never open an editor

An agent cannot drive an interactive editor. Always give the message or skip the step.

| Goal | Non-interactive form |
| --- | --- |
| Describe the working copy | `jj describe -m "message"` |
| Commit and start a new change | `jj commit -m "message"` |
| New empty change with a message | `jj new -m "message"` |
| Squash into the parent, keep its message | `jj squash -u` |
| Squash with a new message | `jj squash -m "message"` |
| Split named paths into their own change | `jj split -m "message" <paths>` |

`jj split -m "message" <paths>` puts the named paths in the first change with that message and leaves the rest in the second. Avoid `jj split` without paths, `jj diffedit`, `jj arrange`, `jj resolve` and any `-i` form unless a person is at the terminal.

## Daily loop

```
jj --no-pager st
jj --no-pager diff
jj --no-pager log -n 10
jj describe -m "message"
jj new
jj commit -m "message"
```

Keep one logical change per working copy. When it grows too broad, peel a piece out with `jj split`. Start the next task with `jj new`.

## Push a new branch end to end

```
jj describe -m "message"                 # a change must have a description to be pushed
jj bookmark set <name> -r @              # or push by change instead, below
jj git push -b <name>
```

Or let jj create the bookmark from the change: `jj git push -c @` (`--change`). Then open the pull request with `gh pr create`. In some repos, remote pushes and ref-rewriting jj commands need explicit approval by a hook. Read the repo's instructions and do not work around a block.

Moving a bookmark:

```
jj bookmark move main --to @             # forward
jj bookmark move main --to <rev> -B      # backwards or sideways needs --allow-backwards
```

Other bookmark commands: `create`, `list`, `set`, `advance`, `track`, `untrack`, `delete`, `forget`, `rename`. `delete` propagates to the remote on the next push. `forget` is local only.

Do not force a remote you have not inspected. `jj git fetch` first and compare.

## Undo and recovery

```
jj op log                                # every operation, newest first; the undo surface
jj undo                                  # reverse the last operation
jj op restore <op-id>                    # return the whole repo to an earlier state
```

Recovering from a divergent or stale history, in this order:

1. `jj op log`. Nothing is lost by looking.
2. `jj --no-pager log -r 'heads(all())'` to map every tip. `(divergent)` means one change ID now has several versions. It is not corruption.
3. `jj workspace update-stale` if jj reports a stale working copy.
4. `jj file list -r <head>` on each divergent head to see what each holds.
5. Redo any missing work, serially, on the head you keep.
6. `jj abandon <rev> <rev>` the leftover fragments.
7. `jj undo` is the last resort.

Conflicts in jj are recorded data, not a failed state. A restore never drops a side. To resolve, read both versions with `jj file show -r <rev> <path>`, write the correct content without markers, and confirm the conflict clears in `jj st`.

## Revsets you will use

- `@`, `@-`, `root()`, `trunk()`, `mine()`, `bookmarks()`.
- `A..B` is what is reachable from B and not from A, for example `main@origin..@`. That fails if no remote exists yet.
- `heads(all())` lists every tip.

Confirm anything else with `jj help -k revsets`.

## `jj rebase`

It moves changes and can rewrite shared history. Some repos forbid it through a hook. Confirm before use, and never rebase changes that others already have.

## Before you finish

- Run `jj st` before and after every write operation.
- Do not commit or push unless asked.
- Give every change a real description before pushing.
- Report the change ID and the bookmark you touched.
- Put no secrets, names or emails in commit messages.

## Examples

Real output. Match the symptom, then apply the fix.

Git looks broken in a colocated repo. Bad: fight it with git.

```
$ git checkout main
error: Your local changes to the following files would be overwritten by checkout:
	AGENTS.md
Please commit your changes or stash them before switching branches.
Aborting

$ git stash -m 'copy' && git checkout main
error: Entry 'AGENTS.md' not uptodate. Cannot merge.
Cannot save the current worktree state
```

Good: `ls -d .jj`, then `jj --no-pager st` and `jj --no-pager log -n 5`. The "changes" are the contents of `@`.

Pager hang. Bad: `jj log` in a non-interactive shell prints `(END)` and never returns. Good: `jj --no-pager log`.

Editor hang. Bad: `jj describe` opens an editor. Good: `jj describe -m "message"`.

Parallel mutations. Bad: three `jj restore` calls fired at once.

```
Internal error: Failed to check out commit ...
Caused by: Concurrent checkout
```

The result is divergent working-copy heads and a stale working copy:

```
Error: The working copy is stale (not updated since operation ...)
Hint: Run `jj workspace update-stale` to update it.
```

Good: run mutations one at a time. Recover with `jj op log`, `jj --no-pager log -r 'heads(all())'`, `jj workspace update-stale`, then `jj abandon` the leftover fragments.

Two revisions, one path. Bad: restoring the same file from two commits.

```
Warning: There are unresolved conflicts at these paths:
<path> 2-sided conflict including 1 deletion
```

Good: decide which revision wins first, read both with `jj file show -r <rev> <path>`, write the correct content without markers.

Bookmark against live state. Bad: "main is clean and deployable", when `main` pointed at an older tree with none of the current work. Good: compare `jj file list -r main` with `jj file list -r @`, and move the label with `jj bookmark move main --to @`.

Remote that does not exist yet. `jj log -r 'main@origin..@'` in a repo with no remote prints `Error: Revision \`main@origin\` doesn't exist`. That is not a broken repo. Add the remote first.

Trusting a label. Bad: a commit described as one small change that holds 103 unrelated files. Good: `jj show --stat <rev>` before deciding to keep or abandon it.

## Keeping this skill current

Update `version`, `verified-against` and any changed command together. Re-run each command against a scratch repo (`jj git init` in a temp directory) before recording it. Add new gotchas only from real incidents, with the exact error text.
