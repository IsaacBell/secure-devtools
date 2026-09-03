# Security Policy

Security is the point of this project, so please report vulnerabilities promptly and
discreetly.

## Supported versions

Only the latest published release receives security fixes. Releases are cut from `main`
and published to npm as needed.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private advisory mechanism:

<https://github.com/IsaacBell/secure-devtools/security/advisories/new>

Include, if possible:

- the affected tool/package and version
- a description of the issue and its impact
- steps to reproduce, or a minimal proof of concept

You will receive an acknowledgement within a few days and we will coordinate a fix and
disclosure timeline with you.

## Scope

- `apps/am-i-compromised/bin/scanner.sh` and its test suite
- CI workflows and dependency manifests

The scanner is a heuristic pre-flight check. It can miss malware and can report false
positives; a clean scan is not proof that a repository or its dependencies are safe.
