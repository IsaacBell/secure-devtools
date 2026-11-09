# What the security checks establish

Review checks for the current PR head, not an earlier green run. A successful
workflow job is evidence that its commands completed; it is not proof that the
repository or its dependencies are safe.

| Check | Coverage and prerequisites |
| --- | --- |
| CI | ShellCheck, shfmt and Bats via `pnpm check`; requires the mise toolchain and frozen pnpm dependencies. Pending Bats cases are skips, not passes. |
| Security gate | Reads PR files using the pinned released scanner from the base branch. Workflow fixes must reach the base branch before a fresh `pull_request_target` event uses them. Release 2.1.0 needs invocation through its physical `bin/scanner.sh`, as in PR #28. |
| Semgrep | Bundled rules plus `p/default` and `p/security-audit`, with SARIF upload for eligible events. Findings are reported for review; the scan does not use `--error` to gate on findings. Operational scan failures must fail the job. Even local-rule validation downloads `p/semgrep-rule-lints` from `semgrep.dev`. |
| CodeAnt | Requires the repository Actions secret `CODEANT_API_TOKEN`. The configured scanners are SAST and SCA, with a 300-second scan timeout and a 10-minute job timeout. Fork PR events do not receive this secret and cannot complete this authenticated check. Do not expose it through `pull_request_target` to work around that restriction. |
| Gitleaks, dependency review, CodeQL and GitGuardian | Separate checks; inspect each result and scan coverage on the current head. |

## CodeAnt trust and result verification

The pinned CodeAnt action downloads a script from
`https://api.codeant.ai/analysis/ci/scan/script/get`, decodes it and executes it.
Pinning the action SHA does not pin this downloaded script. Review that script
and the service's completion/result handling before treating CodeAnt as a
security gate. A green job alone does not establish that a scan completed, that
findings block merges, or that installed `node_modules` contents were examined.
Do not add scan exclusions to make checks green.

Check the run's logs and scan report for the exact commit, enabled scanners,
completed status, findings and exit behavior. Never print the token when
diagnosing authentication. The explicit token preflight reports an unavailable
secret before downloading or running the scan script.

## Pages

The website is static HTML under `docs/`. Check local links and anchors, serve
the directory for a smoke check, and verify the GitHub Pages deployment after
merge. Publishing the site does not publish an npm release. Keep unreleased
dependency-scanning behavior clearly separate from version 2.1.0's exclusions.
