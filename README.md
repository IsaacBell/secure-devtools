# secure-devtools

Plain-shell security tools that check the code you are about to run, and the machine you run it on, for signs of a supply-chain or dev-environment attack. They run locally and in CI, need no account, and have zero npm runtime dependencies.

```sh
pnpx am-i-hacked .     # or: npx am-i-hacked .
```

[![CI](https://github.com/IsaacBell/secure-devtools/actions/workflows/ci.yml/badge.svg)](https://github.com/IsaacBell/secure-devtools/actions/workflows/ci.yml)
[![npm am-i-hacked](https://img.shields.io/npm/v/am-i-hacked?label=am-i-hacked)](https://www.npmjs.com/package/am-i-hacked)
[![npm am-i-being-recorded](https://img.shields.io/npm/v/am-i-being-recorded?label=am-i-being-recorded)](https://www.npmjs.com/package/am-i-being-recorded)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Status:** actively maintained. `am-i-hacked` 2.0.1 and `am-i-being-recorded` 1.0.0 are the current releases. macOS and Linux.

## Tools

| Tool | What it checks | How to run |
| --- | --- | --- |
| [`am-i-hacked`](apps/am-i-hacked/README.md) | A project folder, for malicious-code indicators: editor tasks that run on folder open, payloads disguised as asset files, obfuscation, capture code paired with an exfiltration endpoint, `.env` files in the git index, risky `package.json` scripts. With `--system`, this machine: login and startup items and their code signatures, crontab, shell startup files, AI-tool config, running processes. | `pnpx am-i-hacked` |
| [`am-i-being-recorded`](apps/am-i-being-recorded/README.md) | Which browser extension is behind a screen-recording indicator, and what else on the machine can capture you. | `pnpx am-i-being-recorded` |
| [`secure-semgrep`](apps/secure-semgrep/README.md) | Semgrep rules and loadout packs for AI-agent, bash and web code. Needs `semgrep`. | From this repository |

Agent skills in [`skills/`](skills/): [quarantine-review](skills/quarantine-review/SKILL.md) (inspect an untrusted repository without running any of it), [third-party-skill-intake](skills/third-party-skill-intake/SKILL.md) (vet a skill or plugin from a URL without running its installer), [login-item-triage](skills/login-item-triage/SKILL.md) and [jujutsu](skills/jujutsu/SKILL.md).

## Why this one?

- **Instant.** One command, no signup, no account, no API key: `pnpx am-i-hacked .`
- **CI by copy-paste.** Exit code `1` on findings; the [package README](apps/am-i-hacked/README.md#-usage) has the workflow snippet.
- **Catches what advisory scanners cannot.** `npm audit`, OSV-Scanner and similar tools match your dependencies against published advisories. They cannot see an attack nobody has reported yet, or one that lives in the repository itself: a `.vscode/tasks.json` that runs when you open the folder, a script saved as a font file, a stealer that starts itself at login. `am-i-hacked` reads the files for those indicators before you open, install or run anything. Use both.

## What it does not do

It looks for warning signs. It is not antivirus, and it does not look up known viruses. A clean result means it found no warning signs. It does not prove the code or the machine is safe.

Some checks also flag normal code, such as `eval`. When you have checked a line and it is fine, mark it with a short reason. That line still shows up as reviewed on every run, so nothing gets hidden.

## Develop

[mise](https://mise.jdx.dev) installs the pinned toolchain (`node`, `pnpm`, `shellcheck`, `shfmt`, `ripgrep`, `jq`, `semgrep`) from [`mise.toml`](mise.toml).

```sh
mise install     # the toolchain
mise run setup   # dev dependencies and git hooks
mise run check   # shellcheck, shfmt check and the bats tests: what CI runs
```

`mise run` lists every task. The git hooks run the same checks before each commit. CI in [`.github/workflows/`](.github/workflows/) runs the checks and tests, this repository's own security gate (`mise run gate`), a gitleaks secret scan, Semgrep, dependency review, and CodeAnt AI scan. Releases: [docs/RELEASING.md](docs/RELEASING.md). Changes: each package's `CHANGELOG.md`.

## Semgrep

[`secure-semgrep`](apps/secure-semgrep/README.md) is the repository's static-analysis pack: bundled, owned rules for AI agents and bash, plus Semgrep loadout packs you can point at any codebase. It lives in [`apps/secure-semgrep`](apps/secure-semgrep/README.md) and publishes to npm as `secure-semgrep`, mirroring how `am-i-hacked` is published.

Run it over this repository (review mode records findings without breaking the build):

```bash
$ mise run semgrep
```

To turn findings into a hard gate, run `mise run semgrep-strict`. In any other repository, use it the same way as a post-`npm install` script — see the [package README](apps/secure-semgrep/README.md) for loadouts (`react`, `ts`, `node`, `py`, `rust`) and CI snippets.

## Contributing, security and support

- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). Issues and pull requests are welcome.
- Security problems: [report them privately](https://github.com/IsaacBell/secure-devtools/security/advisories/new); [SECURITY.md](SECURITY.md) has the details. Please do not open a public issue. Published fixes are listed under [security advisories](https://github.com/IsaacBell/secure-devtools/security/advisories).
- Sponsor the work: [ko-fi](https://ko-fi.com/ibell). `npm fund` points to the same page.

## License

MIT. See [LICENSE](LICENSE).
