# secure-devtools

Plain-shell tools that check the code you are about to run, and the machine you run it on, for signs of a supply-chain or dev-environment attack. They run locally, need no account or API key, and have zero npm runtime dependencies.

```sh
pnpx am-i-hacked .     # or: npx am-i-hacked .
```

[![CI](https://github.com/IsaacBell/secure-devtools/actions/workflows/ci.yml/badge.svg)](https://github.com/IsaacBell/secure-devtools/actions/workflows/ci.yml)
[![npm am-i-hacked](https://img.shields.io/npm/v/am-i-hacked?label=am-i-hacked)](https://www.npmjs.com/package/am-i-hacked)
[![npm am-i-being-recorded](https://img.shields.io/npm/v/am-i-being-recorded?label=am-i-being-recorded)](https://www.npmjs.com/package/am-i-being-recorded)
[![npm secure-semgrep](https://img.shields.io/npm/v/secure-semgrep?label=secure-semgrep)](https://www.npmjs.com/package/secure-semgrep)

**Status:** actively maintained, macOS and Linux. Current releases: `am-i-hacked` 2.0.1, `am-i-being-recorded` 1.0.0, `secure-semgrep` 1.0.1. The next `am-i-hacked` release adds a dark-corner system scan, a Python virtualenv integrity check and `--max-findings`; each package's changelog has the detail. Website: <https://isaacbell.github.io/secure-devtools/>.

## Tools

| Tool | What it checks | Run |
| --- | --- | --- |
| [`am-i-hacked`](apps/am-i-hacked/README.md) | A project folder, before you open, install or run it, for malicious-code indicators: editor tasks that run on folder open, payloads disguised as asset files, obfuscation, capture code paired with an exfiltration endpoint, `.env` files in the git index, risky `package.json` scripts, official Yarn releases by SHA256, and Python virtualenv integrity. With `--system`, this machine: login items and their code signatures, crontab, shell startup files, AI-tool config, running processes, and the caches and bin folders where tooling installs code outside any project. | `pnpx am-i-hacked` |
| [`am-i-being-recorded`](apps/am-i-being-recorded/README.md) | Which browser extension is behind a screen-recording indicator, and what else on the machine can capture you. | `pnpx am-i-being-recorded` |
| [`secure-semgrep`](apps/secure-semgrep/README.md) | Bundled Semgrep rules you own — AI-agent, bash and SSRF patterns — plus maintained registry loadouts (Python, JS, TS, React, Node, Rust), fetched from the Semgrep registry at scan time. Needs `semgrep` on PATH. | `pnpx secure-semgrep ./src` |

### Agent skills

Install all seven for your user account, or pick one:

```sh
npx skills add IsaacBell/secure-devtools -g
npx skills add IsaacBell/secure-devtools --skill ssrf-safe-fetch
```

Drop `-g` to install into the current project, and add `--list` to see the skills without installing. `pnpx skills add` works the same way. The `skills` command reports anonymous install counts to skills.sh; set `DISABLE_TELEMETRY=1` to turn that off.

The skills, in [`skills/`](skills/): [quarantine-review](skills/quarantine-review/SKILL.md) (inspect an untrusted repository without running any of it), [secure-skill-pull](skills/secure-skill-pull/SKILL.md) (vet a skill or plugin from a URL without running its installer), [create-skill](skills/create-skill/SKILL.md) (write, check and publish an agent skill), [skill-publish-review](skills/skill-publish-review/SKILL.md) (review skills before they go into a public repository), [ssrf-safe-fetch](skills/ssrf-safe-fetch/SKILL.md) (validate the URL and the resolved address before a server fetches it), [login-item-triage](skills/login-item-triage/SKILL.md) (the manual method behind am-i-hacked's login-item signature checks) and [jujutsu](skills/jujutsu/SKILL.md).

## Why this one?

- One command from a cold machine: `pnpx am-i-hacked .` needs no signup, account, API key or install step.
- Exit `1` on HIGH or MEDIUM findings, so it works as a pre-commit hook, a `package.json` script or a CI step. The [am-i-hacked README](apps/am-i-hacked/README.md#install-and-run) has the workflow snippet.
- It reads the repository for indicators advisory scanners cannot report: a `.vscode/tasks.json` that runs on folder open, a payload saved as a font file, a launchd or systemd item that starts at login, a capture tool paired with an exfiltration endpoint. `npm audit`, OSV-Scanner and Snyk match your dependencies against published advisories, so an unreported attack, or one committed into the tree, stays invisible to them. Run both.

## What it does not do

The scanners look for warning signs; they are not antivirus and do not look up known viruses. A clean result means no warning signs were found, not that the code or the machine is safe. Some checks also flag ordinary code, such as `eval`; when a line is fine, mark it reviewed with a short reason (`am-i-hacked-ignore: <reason>`) and it still appears as reviewed on every run.

## Develop

[mise](https://mise.jdx.dev) installs the pinned toolchain (`node`, `pnpm`, `shellcheck`, `shfmt`, `ripgrep`, `jq`, `semgrep`) from [`mise.toml`](mise.toml).

```sh
mise install     # the toolchain
mise run setup   # dev dependencies and git hooks
mise run check   # shellcheck, shfmt check and the bats tests: what CI runs
```

`mise run` lists every task. The git hooks run the same checks before each commit. CI in [`.github/workflows/`](.github/workflows/) runs the checks and tests, this repository's own security gate (`mise run gate`), a gitleaks secret scan, Semgrep, dependency review and a CodeAnt AI scan. Releases: [docs/RELEASING.md](docs/RELEASING.md). Static analysis runs as `mise run semgrep` (review mode) or `mise run semgrep-strict` (gate); [secure-semgrep's README](apps/secure-semgrep/README.md) documents the loadouts and CI snippets.

## Contributing, security and support

- Maintainer: [Isaac Bell](https://isaacbell.io) ([@IsaacBell](https://github.com/IsaacBell)).
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). Issues and pull requests are welcome.
- Security problems: [report them privately](https://github.com/IsaacBell/secure-devtools/security/advisories/new); [SECURITY.md](SECURITY.md) has the details. Please do not open a public issue. Published fixes are listed under [security advisories](https://github.com/IsaacBell/secure-devtools/security/advisories).
- Sponsor the work: [ko-fi](https://ko-fi.com/ibell). `npm fund` points to the same page.

## License

MIT. See [LICENSE](LICENSE). Third-party notices are in [NOTICE.md](NOTICE.md).
