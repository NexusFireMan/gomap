# Selective CONNECT Recovery Evaluation

## Status

This is a test-only experiment, not a new CLI option or automatic recovery in
production. `Scan`, existing retries, streaming, rate limits and defaults are
unchanged. It evaluates whether a bounded second pass merits later integration,
rather than quietly increasing traffic or relabeling silence as closed.

The prototype lives in `pkg/scanner/selective_recovery_test.go`. A virtual clock
and fake dials cover transient failures, confirmed open/refused outcomes, late
connect completion, persistent silence, clipped final timeouts, paced starts,
attempt exhaustion, invalid diagnostics and scheduler oversleep. Original
open results, metadata and diagnostics must remain unchanged. Confirmations
are returned separately; no untested production output/stream merge is implied.

## Policy Under Evaluation

- Consider only unrecovered timeout issues, sorted by port; exclude existing
  open ports, non-timeout errors, invalid ports and duplicate/inconsistent data.
- Skip the entire recovery when more than 32 timeout candidates remain. This
  is an absolute scope guard, not proof that a firewall caused the silence.
- Allow at most eight extra connection attempts, one per selected port, serially.
- Admit attempts in a three-second scheduling window, at no more than ten
  starts/s. Cap each dial at 1500 ms or the remaining window, whichever is less.
- Promote only successful TCP connections or observed refusals. Another timeout,
  reset, unreachable result or other failure does not confirm closure.

The window prevents new work after expiry and bounds allocated dial time;
OS scheduling and connection cleanup can add milliseconds to observed wall
time. It is not a hard real-time guarantee. Virtual-clock tests assert exact
admission/budget behavior, not fragile real-clock duration thresholds.

The prototype has its own experimental pacing and does **not** integrate the
production shared attempt limiter, source selection, cancellation or protocol
probes. It must not be wired directly into the CLI as-is.

## Reproduce

Deterministic checks need no network or VM:

```bash
GOTOOLCHAIN=go1.26.9 go test -race ./pkg/scanner \
  -run '^TestSelectiveRecovery(Budgets|Exclusions|DoesNotDial)' -count=20
```

Both live tests are explicitly opt-in and require an authorized literal IP:

```bash
GOMAP_RUN_RECOVERY_LAB_TESTS=1 GOMAP_RECOVERY_HOST=10.0.11.6 \
  GOTOOLCHAIN=go1.26.9 go test ./pkg/scanner \
  -run '^TestSelectiveRecoveryCurrentLab$' -count=1 -timeout=30s -v
```

The current test scans a fixed 15-port scope with four workers, a 200 ms fixed
timeout, zero retries and per-host/global limits of ten starts/s. It then
evaluates recovery separately. An unavailable host fails instead of skipping.
It does not run a full-range scan or collect service banners.

To replay a private historical GoMap JSON report, supply its path and the
same explicitly authorized IP with `GOMAP_RECOVERY_INPUT`, selecting
`^TestSelectiveRecoveryHistoricalLab$`. The report must contain exactly that
host and its original timestamp. Keep reports outside the repository. This
compares earlier uncertainty with later observations, not simultaneous A/B
results or a refreshed full-host inventory. Reports and source evidence are
never overwritten by the experiment.

## October 22, 2026 Results

Production source was `7c77263b24e055375ba5e6bbd3c53baf2173c0f8` with test-only
additions, using Go 1.26.9 on Linux amd64. Live fixtures were the authorized
Windows/Linux VMs and VPN target from the [full-range benchmark](CONNECT_BENCHMARK.md).
These small samples are not CPU-isolated performance claims.

### Current 15-Port Scope

| Role | Baseline Open / Refused / Unresolved | Baseline (ms) | Extra Attempts | New Open / Refused Evidence | Recovery (ms) | Remaining Uncertainty |
| --- | --- | ---: | ---: | --- | ---: | ---: |
| Windows | 8 / 7 / 0 | 1623 | 0 | 0 / 0 | 0 | 0 |
| Linux | 7 / 2 / 6 | 1654 | 2 | 0 / 0 | 3007 | 6 |
| VPN | 2 / 12 / 1 | 1764 | 1 | 0 / 0 | 1502 | 1 |

No natural transient timeout was recovered in these current small scopes.
Persistent silence costs extra time without extra evidence; a second pass
should not be enabled indiscriminately. Millisecond figures above measure
the scan/evaluation, not process startup or package compilation.

### Historical Cohorts, Later Probes

Private reports were generated at 09:33:45 UTC (Windows), 09:43:09 UTC (Linux)
and 09:56:34 UTC (VPN), on October 22, 2026. Recovery probes occurred later
the same day; listener/network conditions may have changed.

| Role | Historical Timeouts | Extra Attempts | New Open / Refused Evidence | Recovery (ms) | Remaining Historical Uncertainty | Stop |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| Windows | 22 | 8 | 0 / 8 | 736 | 14 | Attempt budget |
| Linux | 65524 | 0 | 0 / 0 | 0 | 65524 | Broad silence guard |
| VPN | 1 | 1 | 0 / 0 | 1515 | 1 | Candidates exhausted |

Historical report loading/parsing is excluded from recovery timings. These
observations support a small, opt-in recovery budget for sparse uncertainty,
not a default change or a claim that the original timeouts were erroneous.
Open recovery is covered by deterministic fixtures, not demonstrated naturally
in these live samples. Linux's guard avoided re-probing thousands of drops.

## Before Production Integration

Require cancellation-aware sharing of the global/per-host attempt budgets,
explicit CLI compatibility rules, preservation of both original and later
evidence, correct final coverage and exactly-once streaming for recovered opens.
Keep existing source-address and cleanup contracts. Protocol probes need a
separate bounded budget, not an implicit extension of this CONNECT window.
Then repeat controlled current-condition validation with naturally occurring
transients before choosing defaults. This evaluation closes the experiment,
not production integration or the general full-range stability roadmap item.
