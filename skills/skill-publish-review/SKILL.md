---
name: skill-publish-review
description: "Review agent skills before they go into a public repository: find leaked personal or internal detail, broken frontmatter, unfinished work and text that was copied from somewhere else. Use when about to publish or share skills, when auditing a folder of skills in bulk, or when a skill's author says it is ready. Runs independent reviewers in parallel and merges their verdicts."
version: 1.0.0
---

# Review skills before they go public

The author is the worst reviewer of their own skill. They no longer see the private path in line 40 or the name in the example. Review by people or agents who did not write it, in more than one independent pass, and treat every verdict as a claim until you have opened the line it cites.

For writing a skill in the first place, use `create-skill`. This skill is the review that comes before publishing.

## The passes

1. **Facts.** A script counts, for every skill: whether the frontmatter parses, whether `name` equals the folder, whether the description is present, TODO and placeholder text, email addresses, home-directory paths, secret-shaped strings, mentions of private tools or paths, and files that `SKILL.md` names but that are not on disk. Parse the frontmatter with a real YAML parser. A description that contains a colon followed by a space and is not quoted is invalid YAML, a regex will not notice, and a loader may skip the skill without a word.
2. **Verdicts.** Reviewers read each skill in full and give one verdict: ready, fix (with the exact lines), private, incomplete, or hold (looks like someone else's work). Use `references/leak-review-brief.md` for the instructions.
3. **Adversarial leak hunt.** A second set of reviewers, who are not shown the first set's verdicts, assume the first set missed something and look for reasons each skill must not be published. Same brief, with the adversarial framing it already contains. Disagreements between the passes are the most useful output.
4. **Provenance.** One reviewer looks only for evidence of copied text, using `references/provenance-review-brief.md`. It reports evidence and confidence. It does not decide what to do about it.

## Running the reviewers

- Reviewers are read-only. They cannot edit, run or install anything.
- Give each reviewer about twenty skills, the facts rows for them and a manifest of absolute file paths. A reader that only has a read tool cannot list a folder, so any file not in the manifest is never read. Say in the brief that large reference folders are sampled, and make the reviewer say what it did not read.
- Put the brief in a file. Give each reviewer a turn limit that is generous for the number of files, and require the report to start with DONE or INCOMPLETE. A reviewer that runs out of turns without a report has failed; one that returns nothing has failed. Re-run it with a smaller group.
- Reviewers never write the sensitive value into a report. They give the file, the line and the category, so the reports can be stored and shared.
- Do not ask reviewers to suggest credit lines, "sourced from" notes or style rewrites. They report problems and evidence only.

## Merging

- The stricter verdict wins: private beats hold, hold beats incomplete, incomplete beats fix, fix beats ready.
- Open the cited line for every blocker and every "private" or "hold" verdict yourself. A reviewer that read nothing can sound sure. A cited line that does not say what the report says discards that finding.
- For a hold, the decision belongs to the person who owns the skill. Give them the evidence (the file and line, and what it does and does not prove). A license file inside a skill folder that names another copyright holder, a lock file that pins the skill to another project by hash, or a name that differs from the folder is evidence. The same text in two places is evidence of duplication, not of origin.
- Record the merged result in one table: path, verdict, one line of why. Keep the table with the project so the next review starts from it.

## Closing out

1. Fix every "fix" item, or move the skill out of the publish set.
2. Re-run the facts script. Every row is clean.
3. Run the repository's secret and leak scanner over the whole repository, not only the skills.
4. Check that links between skills resolve inside the published set. A public skill that points at a private one leaks its name and breaks for every reader.
5. Mark a skill ready only when a reviewer other than its author has passed it and the scan is clean.

## Things that go wrong

- **Frontmatter that does not parse.** Common in descriptions that mention a command or contain "Use when: ...". Quote the whole value.
- **A skill that only works with private tooling**, such as a command that exists in one private repository. Make it generic or keep it private.
- **A script that fetches a URL the user supplies** with no guard. Point it at `ssrf-safe-fetch` or add the checks.
- **Unsafe instructions** that tell the agent to clone and copy remote code, install global tools without being asked, or skip a confirmation.
- **Dangling links** to skills that are private, renamed or missing.
- **A README that disagrees with the folder**, such as a skill count that does not match the table.
