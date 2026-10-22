# Selective CONNECT Timeout Recovery

## Status

`--recover-timeouts` enables a bounded, opt-in CONNECT verification phase after
each host's primary scan. It defaults to false and rejects UDP, SYN and `-g`.
Existing retries and default scans are unchanged. Earlier evaluation results
below are retained as historical records, not runtime performance guarantees.

```bash
gomap -s --recover-timeouts -p - 10.0.11.6
gomap --recover-timeouts --stream --format jsonl -p 22,80,443 10.0.11.9
```

## Runtime Contract

- The entire run shares **eight extra attempts and three seconds of accumulated
  recovery time**, not a fresh allowance per host. Normal scanning time between
  hosts does not replenish or consume that allowance. Earlier eligible hosts
  and lower-numbered timeout ports consume it first.
- Only unrecovered timeout issues are eligible. More than 32 timeouts on a host
  skips recovery there without consuming network allowance. Existing open ports,
  refusals, local errors and other non-timeout failures are not re-probed.
- Extra connections run serially, at no more than ten starts/s or the stricter
  `--rate`. They share `--global-rate` with existing work; waiting for permits
  consumes recovery time and is canceled at the recovery deadline.
- Each dial uses the selected source-address binding and the smaller of 1500 ms
  or remaining recovery time. This separate cap is not increased by `--timeout`
  or host overrides. No retry loop or service probes run in this phase.
- An additional open port is streamed once when applicable and retained in the
  sorted final results. Its name is only a low-confidence port hint (or unknown);
  `-s` labels it `TCP service (recovered; not fingerprinted)`. Run targeted service
  detection separately when required. Initial ports keep their original metadata.
- Only successful connections/refusals confirm open/closed. A later failure stays
  uncertain; unreachable/local errors are distinguished from timeout inference.

The three-second window bounds admission, permit waits and allocated dial time,
not OS scheduling, blocked output consumers or report rendering in real time.
No new connection is admitted after deadline expiry. Connections and timers are
closed/canceled; existing source-pool ownership and cleanup remain unchanged.

JSON adds `metrics.options.recover_timeouts` when enabled and per-host
`connect_diagnostics.timeout_recovery`. The latter records initial counters,
extra attempts, confirmed outcomes, elapsed time, stop reason and each attempted
port's original `before` issue plus its later observation. Final coverage uses
the latest observations without double counting. Previously unresolved refusals
leave the final issue list but retain their history in recovery observations;
recovered-open issues are marked recovered. Requested-port counts do not grow.
Without the flag these optional fields are omitted. CSV/JSONL result schemas
are unchanged; text and machine-output stderr include a recovery summary.

Stop reasons include `completed` (all candidates attempted, not necessarily
resolved), `no_timeouts`, `broad_silence`, `attempt_budget`, `time_budget`,
`canceled` and defensive `invalid_diagnostics`/`controlled_profile` guards.

## Original Test-Only Prototype

The original prototype lives in `pkg/scanner/selective_recovery_test.go`. A virtual clock
and fake dials cover transient failures, confirmed open/refused outcomes, late
connect completion, persistent silence, clipped final timeouts, paced starts,
attempt exhaustion, invalid diagnostics and scheduler oversleep. Original
open results, metadata and diagnostics must remain unchanged. Confirmations
are returned separately; no untested production output/stream merge is implied.

## Historical Prototype Policy

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

That historical prototype has its own experimental pacing and does **not** integrate the
production shared attempt limiter, source selection, cancellation or protocol
probes. It must not be wired directly into the CLI as-is.

## Reproduce

Deterministic checks need no network or VM:

```bash
GOTOOLCHAIN=go1.26.10 go test -race ./pkg/scanner \
  -run '^TestSelectiveRecovery(Budgets|Exclusions|DoesNotDial)' -count=20
GOTOOLCHAIN=go1.26.10 go test -race ./pkg/scanner ./pkg/app ./cmd/gomap \
  -run 'Test(TimeoutRecovery|AttemptLimiterContext|CLIRecover|Recovery)' -count=3
```

Both live tests are explicitly opt-in and require an authorized literal IP:

```bash
GOMAP_RUN_RECOVERY_LAB_TESTS=1 GOMAP_RECOVERY_HOST=10.0.11.6 \
  GOTOOLCHAIN=go1.26.10 go test ./pkg/scanner \
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

Select `^TestTimeoutRecoveryHistoricalNativeLab$` with the same environment to
exercise the production engine, shared pacing and JSON provenance on those
historical candidates. Inputs must precede recovery; already-verified reports
are rejected. This remains a later observation, not a refreshed full scan.

## October 22, 2026 Results

These tables describe the original test-only evaluation before CLI integration.

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

## Runtime Validation And Remaining Scope

Production regressions cover evidence-preserving counter updates, open/refused/
timeout/unreachable outcomes, exactly-once callbacks, JSON provenance, shared
multi-host attempts/time, cancellation under a locked global limiter, stricter
per-host pacing, source-bound loopback connections and closure. CLI/application
tests cover defaults, compatibility, option metadata and JSONL row preservation.
The old `Wait` behavior remains unchanged; only recovery uses the cancelable
permit method. Default-format goldens remain unchanged.

### CLI Checks, October 22, 2026

Actual CLI runs used the development binary with `--recover-timeouts`, four
workers, a 200 ms fixed primary timeout, zero primary retries and per-host/global
limits of ten starts/s. Recovery kept its own documented caps.

| Scope | Primary Open / Refused / Inconclusive | Extra Attempts | Recovery (ms) | Stop |
| --- | --- | ---: | ---: | --- |
| Windows, restored VM, 15-port run | 8 / 7 / 0 | 0 | 0 | no_timeouts |
| Linux, first host of a two-host 15-port run | 7 / 2 / 6 | 2 | 3000 | time_budget |
| VPN, second host of that same run | 2 / 12 / 1 | 0 | 0 | time_budget |
| VPN alone, 22/80/443/3000, one primary worker | 2 / 1 / 1 | 1 | 1505 | completed |

Neither persistent-silence case produced new open/refused evidence. The two-host
run verified that the allowance is not renewed for later hosts. JSON contained
the original 200 ms issues and the later capped timeout observations; final
coverage reconciled and preserved all observed opens. A separate native-engine
historical replay skipped Linux's 65524 timeouts with zero attempts and retried
the VPN's single timeout once, still inconclusive (1500 ms).

A preliminary three-host CLI attempt found Windows unavailable (ARP resolution
failed, zero open ports and 15 inconclusive outcomes). It is not a successful
Windows fixture validation. Its recovery exhausted the shared window rather
than granting fresh budgets to later hosts. After the VM was restored, the
15-port CLI run above confirmed eight opens and seven refusals, with complete
scope accounting and no additional recovery traffic. Native-engine replay of
the original Windows report then confirmed eight later refusals in eight
attempts (709 ms), stopped at `attempt_budget`, and retained 14 unresolved
historical candidates. JSON provenance and final counter accounting passed.
This later replay is not a simultaneous comparison or a refreshed full scan.
Native positive-connect recovery remains covered by loopback tests and
open/refused merges by injected transports, not natural open recovery here.

Natural transient/open recovery, additional VPN/platform conditions and broad
full-range stability remain separate validation work. No automatic default
change or recovered-port protocol probing is implied by this feature.
