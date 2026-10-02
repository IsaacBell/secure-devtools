# Roadmap

This is a plan, not a promise. Items can change, slip or be dropped. There are no dates: a release ships when it is ready. Anything that is neither listed here nor filed as an issue is not scheduled.

Current release: **2.0.1**.

## How releases work

- Every fix that merges ships as the next patch release: 2.0.2, then 2.0.3, and so on.
- Issues labeled `release-blocker` gate the next minor release. 2.1.0 ships once every issue with that label is closed.

## 2.1.0 candidates

A minor release that widens what the scanner reads and adds an opt-in feature.

- **Scan gitignored files by default**, with flags to skip gitignored files and to skip hidden files.
- **Full dependency scans** behind a flag (`node_modules` and similar). Scanning dependencies is slower, so it is not the default.
- **`hooks install`**, an optional sub-command that sets up a shell hook which logs the commands run in a terminal. It is opt-in: nothing touches your shell unless you run the command. Logs go to the current folder by default, with an option to choose another destination.
