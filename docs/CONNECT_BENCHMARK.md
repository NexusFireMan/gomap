# Full-Range CONNECT Benchmark

## Scope And Procedure

Validation date: October 22, 2026. Production source:
`e8ae56d9e61475fad095b468ce7e9cdcf46fa1d7`, built once with Go 1.26.9 on
Linux amd64 before measurements. This is unreleased development code; the CLI
still reports version 2.5.0, not a new release. The source revision is recorded
separately because the binary's default commit metadata is `n/a`.

Targets were the authorized Windows and Linux Metasploitable3 VirtualBox
fixtures and one authorized HTB target over a routed VPN. Preliminary TCP checks
found expected open ports on each host. Previous benchmark results concern
different targets, listener states and tuning; they are not comparable speed
claims.

Each host is scanned sequentially across TCP 1-65535, twice with 128 workers
and twice with 256 workers, in that order. The fixed dial timeout is 200 ms
on the LAN and 1000 ms over VPN. Retries and adaptive timeouts are disabled;
the global limit is 1000 connection attempts/s, with no additional per-host
limit. That is an upper bound, not a promised achieved rate. Service detection
is disabled to isolate CONNECT discovery. No SYN/UDP probes, source-address
changes, firewall changes or external scanner are part of this matrix.

Representative single-run commands, using explicitly authorized targets:

```bash
GOTOOLCHAIN=go1.26.9 go build -o /private/benchmark/gomap .
/private/benchmark/gomap -p - --workers 128 --timeout 200 --retries 0 \
  --adaptive-timeout=false --global-rate 1000 --format json \
  --out /private/benchmark/windows-w128-r1.json 10.0.11.6
/private/benchmark/gomap -p - --workers 128 --timeout 1000 --retries 0 \
  --adaptive-timeout=false --global-rate 1000 --format json \
  --out /private/benchmark/vpn-w128-r1.json "$AUTHORIZED_VPN_IP"
```

Repeat separately for the Linux fixture and both worker counts, using distinct
output paths. Use an existing private directory; keep raw reports and target
identities outside public commits. Do not run overlapping scans, compilations
or tests during measurement. Other workstation/VM activity is not controlled,
so these are lab observations rather than CPU-isolated benchmarks.

Each result must account for all 65535 requested ports, contain no duplicate
open entries and retain the fixture anchors: Windows FTP/HTTP/RPC/SMB, Linux
FTP/SSH/HTTP/SMB, and the VPN target's initially observed SSH/HTTP listeners.
Open sets are compared by port identity against the first run, including
across worker profiles. Missing anchors, changed sets, failed or interrupted
runs must remain visible, not be excluded to improve the summary.

`closed` requires an observed connection refusal. Timeout-inferred filtered
ports remain inconclusive; matching silence across runs is not proof that a
port is closed. Confirmed throughput counts open plus refused ports only.
Durations below use the report's scan duration, excluding binary compilation
and final JSON rendering/cleanup. They are not end-to-end CLI wall times.

## Results

All twelve full-range runs finished between 09:28:17 and 10:06:23 UTC. They
accounted for 786420 requested host-port outcomes, retained all required open
ports and passed JSON metadata/accounting checks. This is not a strict
open-set stability pass for Windows or proof of complete network coverage.

| Role | Workers | Run | Open | Refused | Timeout-Inferred | Other Unresolved | Duration (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Windows | 128 | 1 | 37 | 65498 | 0 | 0 | 142.966 |
| Windows | 128 | 2 | 39 | 65474 | 22 | 0 | 184.327 |
| Windows | 256 | 1 | 39 | 65496 | 0 | 0 | 197.817 |
| Windows | 256 | 2 | 39 | 65494 | 2 | 0 | 189.002 |
| Linux | 128 | 1 | 9 | 2 | 65524 | 0 | 177.320 |
| Linux | 128 | 2 | 9 | 2 | 65524 | 0 | 192.357 |
| Linux | 256 | 1 | 9 | 2 | 65524 | 0 | 209.634 |
| Linux | 256 | 2 | 9 | 2 | 65524 | 0 | 198.421 |
| VPN | 128 | 1 | 2 | 65532 | 1 | 0 | 201.857 |
| VPN | 128 | 2 | 2 | 65532 | 1 | 0 | 199.087 |
| VPN | 256 | 1 | 2 | 65532 | 1 | 0 | 194.231 |
| VPN | 256 | 2 | 2 | 65532 | 1 | 0 | 195.779 |

Each row sums to 65535; timeouts are not added to the refusal count. The same
Linux and VPN open-port identities appeared in all their runs. Windows gained
TCP/3820 and TCP/3920 after its first run and retained both thereafter; no port
from its initial open set disappeared. The first Windows run is included,
not retrospectively discarded as warm-up. Its variation needs investigation
before declaring general full-range stability.

### Repeated-Profile Timing

These are two observations per setting, not a statistically representative
sample or a guarantee. Means and spreads are calculated within each identical
profile, not across hosts or timeout budgets.

| Role | Workers | Min (s) | Max (s) | Mean (s) | Spread (s) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Windows | 128 | 142.966 | 184.327 | 163.647 | 41.361 |
| Windows | 256 | 189.002 | 197.817 | 193.410 | 8.815 |
| Linux | 128 | 177.320 | 192.357 | 184.839 | 15.037 |
| Linux | 256 | 198.421 | 209.634 | 204.028 | 11.213 |
| VPN | 128 | 199.087 | 201.857 | 200.472 | 2.770 |
| VPN | 256 | 194.231 | 195.779 | 195.005 | 1.548 |

More workers did not consistently improve timings under this controlled
profile. This does not justify a universal worker recommendation or changing
the production defaults. These limits and the lack of service probes make
the results unsuitable for direct comparison with older default-speed or
service-detection benchmarks.

## Follow-Up Checks And Limits

After the matrix, a separate Windows check queried its 24 previously timed-out
ports plus 3820/3920, with 1500 ms, four workers, per-host/global limits of
10 attempts/s and one retry. It found 24 refusals and both additional ports
open, with no unresolved ports. A separate socket client also found 3820/3920
open. These later, differently tuned observations do not replace the original
timeouts or establish whether timing, load, loss or listener changes caused
the differences. Per-port OS listener snapshots remain useful follow-up work.

Read-only inspection of the Linux INPUT rules confirmed specific permitted
ports followed by an unconditional `DROP`. That explains why large numbers of
silent outcomes are compatible with this fixture's configuration. Linux's
repeatable nine open ports do not establish the state behind those drops.

The VPN timeout was TCP/3000 in all four full scans. A later GoMap check with
1500 ms and one retry still received no response on that port, while observing
SSH/HTTP ports open and TCP/443 refused. An independent socket client agreed
using a 2000 ms timeout. This corroborates silence, not a specific firewall
rule or an underlying closed state. No authenticated inspection of the VPN
target was performed.

These follow-up checks are excluded from the matrix timings. No configuration
was changed to improve results. Benchmark-variance tracking is validated for
these three cases; broader full-range stability, transient-loss recovery,
privileged SYN/netlink validation and other VPN/platform conditions remain
separate roadmap work. No production scanning behavior changed.
