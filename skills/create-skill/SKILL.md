---
name: create-skill
description: "Write, check and publish an agent skill (a folder with a SKILL.md). Use when turning a repeated workflow into a skill, extending or reviewing a skill, deciding whether a skill is safe to make public, or publishing skills to GitHub and the skills.sh directory. Covers frontmatter, privacy and secret checks, third-party content, QA and the publish steps."
version: 1.0.0
verified-against: "The skills command line, October 2026. It changes quickly: run `skills --help` before relying on a flag."
---

# Create a skill

A skill is a folder with a `SKILL.md`. The agent reads the frontmatter of every installed skill and loads the body only when the description matches the job. Anything you put in a skill runs with the agent's permissions, and anything in a public skill is public the moment it is pushed.

Work through the steps in order. Stop at any failed check.

## 1. Decide it should be a skill

- A **skill** holds judgment and process: how to review, what to ask, what has been rejected before.
- A **script** holds steps that never change. If every step is a fixed command, write the script (and a short task to run it), then let the skill say when to run it.
- A **rule or hook** holds something that must always happen. A skill can be ignored; a hook cannot.
- Look for an existing skill first. Extend it before adding an overlapping one. A skill that builds on others links to them.

## 2. Decide who may see it

Private if it is built around one person's or business's own decisions, brand, voice, clients, prices, internal repositories, commands that exist in one private repository, or how they work. Public only if a stranger could use it as it stands.

If a skill mixes both, split it. Put the general method in the public skill. Put the specifics in a private skill that links to it. Do not publish "with the private parts removed" as an afterthought: write the public version from the general method.

A public skill does not depend on an outside provider, paid service or private command unless that provider is its subject. A skill about one vendor's API may need that vendor. A sales skill may not need one particular data service.

## 3. Build it from real work

Write from captured sessions, commands you ran and exact error text, not from memory of how a tool should behave. When the work teaches a lesson, add it to the owning skill in the same session.

- Add `version` and `verified-against` to the frontmatter for any tool that changes fast, and tell the agent to check the installed version.
- Say what was verified and what was not. A command you did not run is marked as unverified.
- Record what a reviewer rejected, with the bad line and the good line. Rules with examples beat rules without.
- Use fictional examples: names like "Jane at Example Ltd", addresses on `example.com`, `example.org` or `.test`. Never real-shaped data.
- Write it in your own words. Do not paste text from a source into the skill, and do not add "sourced from" or credit lines. `verified-against` names the tool and its version, not where you read about it.
- Delete outdated text outright. Do not leave it as "superseded" or as a dated note. A stale line is read as current by the next agent.

## 4. Layout and frontmatter

```
skill-name/
  SKILL.md          required
  references/       long material the skill points to, opened only when needed
  scripts/          deterministic helpers the skill tells the agent to run
```

- The folder name is the skill name: lowercase letters, digits and hyphens. The `name` in the frontmatter equals the folder name.
- `description` says what the skill does and when to use it, with the words a user would say. If it contains a colon followed by a space, wrap the whole value in double quotes, or the YAML breaks and the skill is skipped.
- Keep `SKILL.md` under 200 lines where you can and under 500 always. Move detail into `references/` and point to it in one line.
- Put human documentation in the repository README, not in the skill folder.
- Every file the skill names exists. No `TODO`, placeholder text or empty sections.
- Write for the agent: short imperative steps, the exact commands, what to do when a step fails.

## 5. Security and privacy checks

Run these on every file in the folder, including `references/` and `scripts/`.

- **Personal data:** names of real people, email addresses, phone numbers, street addresses, home-directory paths, client or customer names.
- **Internal detail:** private repository or folder names, tasks or commands that only exist in one private repository, a secret manager and its secret names, incidents, account problems, the author's own routines, unpublished prices or plans.
- **Secrets:** keys, tokens, passwords, connection strings, anything shaped like one (`sk-`, `ghp_`, `AKIA`, `-----BEGIN`). Rotate a secret that was ever committed; removing it from history is not enough.
- **Scripts:** read every line. A skill script must not download and run remote code, install packages the user did not ask for, or send files anywhere.
- **Instructions:** a skill must not tell the agent to trust text it fetched, to skip confirmation before a destructive step, or to hide what it did.
- **Network code:** if the skill teaches code that fetches a URL it did not get from its own fixed configuration, point to the SSRF guidance in `ssrf-safe-fetch`.
- **Text you did not write:** do not paste it in. Learn from it and write your own version in your own words. If you do need someone else's text, check its license first. See `secure-skill-pull` for vetting skills you did not write.

Use a different reader for the privacy pass than the one who wrote the skill. A second reader finds what the author no longer sees. `skill-publish-review` runs that pass, in bulk if needed. Back it with a scan: run your repository's secret and leak scanner over the whole repository before every push, not only the changed skill.

## 6. QA checks

1. **Frontmatter:** the YAML parses, name equals folder, description present and quoted where needed. A short script can check this for every skill in a folder; run it, do not eyeball it.
2. **References:** every `references/` and `scripts/` path the skill names is on disk.
3. **Triggers:** write three requests that should load the skill and three that should not. Run them in a fresh agent session and record what loaded.
4. **Clean-context run:** give a fresh agent only the skill and a real task. Where it guesses, the skill is missing something.
5. **Commands:** run every command in the skill once. Fix or mark any that fail.
6. **Overlap:** search the other skills for the same job. Merge or link.
7. **Install test:** install from the local path into a throwaway project and confirm the files and behavior. `skills add <path> --list` shows which skills the CLI finds (check `skills --help`).

Record a verdict for each skill: ready, needs fixes (with the list), private, incomplete, or third-party needing a license check. Do not mark a skill ready on the author's say-so alone.

## 7. Publish

1. Put the ready skills in a public GitHub repository, one folder each. Add a README that names each skill, the job it does and how to install it, and a license file.
2. Run the privacy and secret scan on the whole repository. Fix every hit or decide, with a reason, that it is a false alarm.
3. Push through a pull request. Protect the default branch from force pushes and deletion.
4. There is no submission form for skills.sh. A skill appears on its leaderboard when people install it with the CLI, so install it yourself once: `npx skills add owner/repo` (add `--skill name` for one skill from a repository). Ranking comes from anonymous install counts.
5. The CLI sends the skill name, its files and a timestamp. Install private or unreviewed skills with `DISABLE_TELEMETRY=1`.
6. Optional: an install badge in the README (`https://skills.sh/b/owner/repo`), and a tagged release so users can pin a version.
7. A pack bundles public and private skills into one install link. Packs are unlisted, not access-controlled: anyone with the link can install them, so never put secrets in one.

## 8. Keep it true

- Update the skill in the same session as the work that changed what is true.
- Bump `version` when behavior changes. Re-check `verified-against` when the tool updates.
- When a reviewer rejects something the skill allowed, add the rejected line and the fix.
- Re-run the checks before every release. Skills drift.
