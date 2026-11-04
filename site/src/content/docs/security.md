---
title: Security and responsible use
description: Scope authorization, sensitive scan data, identity limitations and private vulnerability reporting.
---

## Authorization first

Use GoMap only on systems and networks you own or are explicitly authorized to
assess. Agree scope, source addresses, rates and test windows with the system
owner. A controlled-rate profile is not a guarantee of avoiding alerts.

Examples use loopback or private lab addresses. They are not permission to scan
an address that happens to be reachable from your network.

## Protect evidence and credentials

Treat scan outputs as potentially sensitive infrastructure data. Optional raw
hex evidence can contain secrets despite conservative suppression rules; generic
redaction cannot guarantee safety for arbitrary protocols. Keep reports and
credential configuration files private and out of commits, CI artifacts and
public issue attachments.

Do not run the CLI with elevated permissions unless the selected, authorized
workflow actually needs them. Test source-address changes and raw sockets in a
disposable, disconnected environment first.

## Interpret findings conservatively

Service disclosures, TLS names and protocol dialects are observations, not
proof of identity, OS or vulnerabilities. Silent ports remain uncertain.
Review [detection and evidence](/gomap/docs/detection/) and the documented
protocol subsets before drawing conclusions.

## Report privately

Do not open a public issue containing security-sensitive reproduction details.
Use [GitHub private vulnerability reporting](https://github.com/NexusFireMan/gomap/security/advisories/new)
when available, or the maintainer's contact route described in the
[security policy](https://github.com/NexusFireMan/gomap/blob/main/SECURITY.md).

Include the affected version/commit, a minimal safe reproduction, expected and
actual behavior, impact and relevant OS, permissions and network conditions.
Security fixes target the latest released version; older versions are best effort.
