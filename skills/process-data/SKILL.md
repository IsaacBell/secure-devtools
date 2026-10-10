---
name: process-data
description: "Use when searching, filtering or summarizing a large or awkward file or history: a wide CSV, a big log, JSON, a git history, a long tool output. Covers narrowing before reading (bisecting columns, rows, dates and commits), choosing the cheapest tool that is installed, and keeping output small enough to read."
version: 1.0.0
verified-against: "git 2.51, jq, sqlite3, awk, gzip, ripgrep and uv on macOS; check the installed versions"
---

# Process data

**BLUF:** Read the least you can. Find where the answer is, then read only that. Every step below narrows the data before anyone reads it.

Tools change. Check what is installed before choosing one (`command -v duckdb xsv qsv mlr jq sqlite3 uv`), and check the version before relying on a flag.

## 1. Look at the shape first

- `wc -l` for rows and `wc -c` for bytes. Open a compressed file with `gzip -dc file | head`, never by unpacking it.
- For a table, count columns in the header before printing a row. One 400-column row is most of a screen.
- Never print a whole file you have not sized. Print `head -c 600` of a line, or a row's non-empty fields only.

## 2. Bisect

Halve the search space instead of reading. Pick the axis that fits the question.

- **Columns.** Stream the file once and count non-empty cells per column. Most wide exports are empty in most columns. Keep the few that carry data.
- **Time.** Count events per day or month first, then look closely only at the days around the event you care about. In a log with thousands of rows, one burst day often explains the question.
- **Rarity.** Count each action or kind. Print the rare ones (three or fewer) in full, and only totals for the common ones.
- **History.** To find when something entered a repository: `git log -S'<string>' --reverse -- <path>` names the first commit that added it. `git grep -l '<string>' <ref>` searches a commit or branch without checking it out. `git cat-file -s <ref>:<path>` gives a file's size at any commit, which exposes a config file that quietly grew from 500 bytes to 38,000. `git bisect` finds the commit where a test started failing.
- **Mismatch.** Compare two copies (`diff`, `git diff --stat`) and read only the difference.

## 3. Pick the cheapest tool that is installed

| Job | Options, cheapest first |
| --- | --- |
| Count, group, top N | `sort \| uniq -c \| sort -rn`, `awk`, a short script |
| Pick columns from simple CSV | `cut`, `awk -F,` (breaks on quoted commas) |
| Real CSV (quotes, embedded commas, very wide) | a script with a CSV parser in any language; `sqlite3` with `.import`; `duckdb`, `xsv` or `qsv` where installed |
| JSON | `jq` |
| Search text or code | `rg`, then `grep` |
| Anything repeated | write the script once, take its inputs as arguments, keep it next to the output |

A short Python script run with `uv run --no-project python -I script.py args` handled a 3,500-row, 400-column CSV using only the standard library. It is one option, not the rule. `-I` stops Python importing from the current folder, which matters when the data came from outside.

On the machine this was checked on, `jq`, `sqlite3`, `awk`, `gzip`, `rg` and `uv` were installed, and `duckdb`, `xsv`, `qsv` and `mlr` were not. Do not assume; check.

## 4. Keep output small

- Write long output to a file and read the summary. A tool result over a size limit can be saved and cut, and the part you needed can be the part that is lost. Run once, save, then read the file.
- Print counts and dates, not rows. Mask or leave out personal data (addresses, IPs, tokens) unless the question needs it.
- Do not rerun a long command only to filter its output differently. Save the first output and filter the file.

## 5. Trust, but test the detector

- A pattern that finds nothing proves nothing until it finds the known bad. Run it on a sample that should match and on one that should not.
- Start with the narrowest pattern. A broad pattern that matches normal code buries the real hit. Tighten it, and widen it only if it misses.
- Name what you could not see: a truncated read, an empty column, an export without IPs. An absent field is not an absent event.

## 6. Mistakes that cost time

- A shell glob with no match can abort the whole command (zsh). Check with `ls` first or quote the pattern.
- Relative paths break when the working directory differs between calls. Say where you are, or use absolute paths.
- Quoting a number from a tool result without opening the file it came from. Read the line.
