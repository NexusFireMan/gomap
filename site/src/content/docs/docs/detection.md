---
title: Detection and evidence
description: Interpret protocol observations, service hints, confidence and uncertain TCP states conservatively.
---

## Start with observed states

CONNECT scans confirm an open port with a successful TCP connection and a
closed port with an observed refusal. Timeouts can reflect filtering, loss or
insufficient waiting; they do not confirm closure. Other routing and local
failures remain distinct. Review the coverage summary, not just the open table.

## Choose the depth

| Mode | Purpose |
| --- | --- |
| `-s` | Bounded service detection on discovered ports |
| `-Dv` | Deeper version/evidence collection |
| `-De` | Additional bounded protocol probes; may take longer |
| `--recover-timeouts` | Opt-in CONNECT verification for sparse timeout candidates |

No mode guarantees a recognizable service on every open port. Unknown services
remain explicit rather than receiving an invented product or version.

Recovery shares eight extra attempts and three seconds of accumulated recovery
time across the run, skips hosts with more than 32 timeout candidates, and does
not fingerprint recovered ports. It is not available with UDP, SYN or `-g`.
See the [runtime contract](https://github.com/NexusFireMan/gomap/blob/main/docs/SELECTIVE_RECOVERY.md).

## Confidence is not identity

- A protocol negotiation confirms only the validated protocol fields.
- A banner or HTTP header is a server declaration, not an authenticated identity.
- A port hint is tentative and stays low confidence.
- Certificate collection does not verify trust; observed names are unverified.
- Product versions do not prove vulnerabilities or an operating system release.

For the bounded scope and protocol-specific limitations, read the
[confidence inventory](https://github.com/NexusFireMan/gomap/blob/main/docs/SERVICE_DETECTION_TESTS.md).

## Rate and source controls

`--rate` controls per-host pacing; `--global-rate` bounds connection/probe starts
across hosts and phases. Host-specific timeout/retry overrides are available via
`--host-config` for supported engines. Controlled-rate operation is not a promise
that monitoring systems will not observe a scan.

`--random-ip` randomizes HTTP headers only when real source selection is not
configured; it does not spoof the real TCP source IP. Review the
[source-selection documentation](https://github.com/NexusFireMan/gomap#real-source-ip-selection)
before using managed interface addresses.
