# Security Policy

## Supported Versions

Security fixes are handled for the latest released version of GoMap.

| Version | Supported |
|---|---|
| latest | Yes |
| older releases | Best effort |

## Reporting a Vulnerability

Please do not open a public issue for security-sensitive reports.

Report privately through GitHub Security Advisories when available:

- `https://github.com/NexusFireMan/gomap/security/advisories/new`

If advisories are not available, contact the maintainer through the repository owner profile and include enough detail to reproduce the issue safely.

## What To Include

- Affected version or commit.
- Clear reproduction steps.
- Expected and actual behavior.
- Impact assessment.
- Whether the issue requires a specific OS, privilege level, network condition, or target service.

## Scope

In scope:

- Vulnerabilities in GoMap itself.
- Unsafe update, install, or packaging behavior.
- Crashes or denial-of-service conditions caused by untrusted input.
- Output handling bugs that could expose local secrets.

Out of scope:

- Reports about third-party targets scanned without authorization.
- Vulnerabilities in services discovered by GoMap.
- Requests to add exploit code or offensive automation against real systems.
- Social engineering or physical attacks.

## Responsible Use

GoMap must only be used on systems and networks you own or are authorized to test.
