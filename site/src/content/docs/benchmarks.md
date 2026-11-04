---
title: Lab benchmarks
description: Read measured GoMap performance together with settings, scope and incomplete coverage.
---

## Speed needs a denominator

Scope throughput is not confirmed-state throughput. A fast scan with many silent
ports can leave most of the requested range inconclusive. Compare identical
settings and report the uncertainty alongside elapsed time.

## Recorded release regression

The October 22, 2026 two-Metasploitable regression used CONNECT scanning, service
detection, zero retries and fixed timeouts. Its full profile requested TCP ports
1-65535 per host, with 128 workers, a 150 ms dial timeout and per-host/global
limits of 500/1000 starts per second.

| Fixture role | Open | Refused / closed | Inconclusive |
| --- | ---: | ---: | ---: |
| Windows | 39 | 65496 | 0 |
| Linux | 9 | 2 | 65524 |

The combined full scan took **296.773 s**. This is a controlled historical lab
measurement, not a default-speed promise, current live inventory or direct
comparison with another scanner. Baseline, accounting and format-preservation
checks passed; Linux's silence still prevented complete discovery.

## Keep the imperfect runs

Earlier runs include unavailable VMs, an interrupted full profile and changing
Windows listener counts. They remain visible in the validation record. A later
passing regression does not erase those failures or explain their cause.

- [All release-regression profiles and failed attempts](https://github.com/NexusFireMan/gomap/blob/main/docs/RELEASE_READINESS.md)
- [Repeated full-range Windows/Linux/VPN matrix](https://github.com/NexusFireMan/gomap/blob/main/docs/CONNECT_BENCHMARK.md)
- [Selective timeout-recovery costs and limits](https://github.com/NexusFireMan/gomap/blob/main/docs/SELECTIVE_RECOVERY.md)

General full-range stability across constrained VM and VPN networks remains
open. Do not interpret these bounded checks as a zero-defect or complete-network
coverage certification.
