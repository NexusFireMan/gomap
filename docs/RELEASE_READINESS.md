# Release Readiness

This checklist separates implementation review, reproducible regression testing
and publishing. It does not certify every protocol variant or promise complete
network coverage. No release version/tag is assigned by running these tests.

## Gates

- Review current specialized confidence paths against the [confidence inventory](SERVICE_DETECTION_TESTS.md#identification-confidence-review).
- Run `make ci` with the Go version pinned in `go.mod`; retain lint, test, race and coverage results.
- Start the authorized Windows/Linux Metasploitable3 fixtures, wait for services to settle, and run the two-VM regression below. Investigate missing baseline services; do not skip a failed host or relabel silence as closed.
- Review JSON coverage and stderr warnings alongside elapsed time. Explain unresolved outcomes and differences between runs before promotion.
- Review `CHANGELOG.md` Unreleased entries, compatibility notes and remaining limitations. Leave historical released sections unchanged.
- Promote only through a reviewed `dev` to `main` merge-commit PR, then explicitly select a semantic version and publish its tag as described in [release workflow](RELEASE_WORKFLOW.md). Do not publish from the validation branch.

## Two-VM Regression

The opt-in test defaults to the authorized lab fixtures `10.0.11.6` (Windows)
and `10.0.11.9` (Linux). Override them only with explicitly authorized targets.
It does not log in, install anything, change NICs/firewalls or invoke another
scanner. Unlike older smoke tests, unreachable VMs fail rather than skip.

```bash
git rev-parse HEAD
git status --short
go version
GOMAP_RUN_RELEASE_LAB_TESTS=1 GOMAP_LAB_REVISION=$(git rev-parse HEAD) \
  GOMAP_LAB_WINDOWS_IP=10.0.11.6 GOMAP_LAB_LINUX_IP=10.0.11.9 \
  go test ./pkg/app -run '^TestReleaseLabRegression$' -count=1 -timeout=15m -v
```

Use `GOTOOLCHAIN=go1.26.9` when the host's default toolchain differs from the
repository pin. The timeout bounds the test process; it is not the per-port
timeout. Allow the previous scan to finish before starting another.

| Profile | Scope Per Host | Workers | Dial Timeout | Rate Per Host / Global |
| --- | --- | ---: | ---: | ---: |
| quick-1 / quick-2 | Current curated default TCP set | 32 | 750 ms | 500 / 1000 |
| deep | Explicit 20-port service set in the test, with deep detection | 32 | 750 ms | 500 / 1000 |
| full | TCP 1-65535 | 128 | 150 ms | 500 / 1000 |

All profiles use CONNECT, service detection, explicit targets without host
discovery, zero retries and fixed dial timeouts (adaptive tuning disabled).
Service probes retain their existing bounded protocol timeouts. The full
profile's shorter dial timeout controls the cost of silent ports on this local
network; it is not suitable as an unvalidated VPN/remote default. These are
controlled regression profiles, not default-speed claims or a comparison with
another scanner.

The regression checks known fixture anchors (FTP/HTTP/SMB on both, Windows RPC
and Linux SSH), host/port deduplication, explicit service/confidence/evidence,
requested/open/closed/unresolved accounting, metrics and label conservatism.
It validates JSON, then renders the same observations through JSONL and CSV
and compares state/service/version/confidence/evidence without timestamps.
These format comparisons deliberately do not rescan changing targets. Separate
CLI/output regressions run in normal CI. Raw responses stay in temporary files;
only reviewed, aggregate results belong in public documentation.

## CONNECT Repeatability Matrix

Use this narrower opt-in matrix to isolate discovery from service-probe time.
It runs the curated TCP set three times at each of 32 and 128 workers on both
authorized VMs, sequentially. Each scan uses a fixed 150 ms timeout, zero
retries, and per-host/global limits of 500 connection attempts per second.
This short timeout is a local-lab profile, not a VPN recommendation.

```bash
GOMAP_RUN_CONNECT_VARIANCE_TESTS=1 GOMAP_LAB_REVISION=$(git rev-parse HEAD) \
  GOTOOLCHAIN=go1.26.9 go test ./pkg/scanner \
  -run '^TestConnectVarianceLab$' -count=1 -timeout=4m -v
```

Set `GOMAP_LAB_WINDOWS_IP` and `GOMAP_LAB_LINUX_IP` to override the same two
authorized defaults. `GOMAP_LAB_PORTS=-` explicitly opts into TCP 1-65535;
increase the process timeout (for example `-timeout=60m`) for that silent-port-heavy matrix. The default
command does not execute a full-range live benchmark. Keep these runs separate
from other scans and record competing CPU/network workloads.

The test reports scope/confirmed-state throughput and minimum, maximum, mean
and spread for identical settings. It fails on missing baseline services,
duplicate results, inconsistent accounting or any changed open-port set,
including changes between worker profiles. Such failures require investigation:
dynamic listeners, VM restarts and filtering are not automatically scanner bugs.
Filtered/unknown ports remain inconclusive even when every repetition agrees.
Do not select only passing/fast runs or treat the fixed fixture anchor list as
an exhaustive inventory. Keep private logs outside the repository.

Normal CI separately runs `TestConnectRepeatabilityUnderMixedFailures` without
network access: 1024 and 65535 unique ports (plus duplicate inputs), 1/32/128
workers and zero/one retry. Synthetic timeouts, refusals, successful retries and
yielded completion order must preserve exact open sets, streamed results,
connection closure and diagnostic accounting. This validates bookkeeping, not
kernel packet delivery or live-network completeness.

### Curated Matrix Record

On October 21, 2026, the default matrix passed all twelve scans on production
revision `3e7b8051d3ab5f74a9825108154a56134f753c21` with test-only additions.
Windows retained the same 20 open ports and 976 refusals in every run; Linux
retained the same seven open ports, two refusals and 987 timeout-inferred ports.
The test compared port identities, not just these counts. No service detection,
firewall/NIC changes or external scanner was involved in this matrix.

| Host Role | Workers | Samples | Min / Max / Mean | Spread |
| --- | ---: | ---: | --- | ---: |
| Windows | 32 | 3 | 3.060 / 3.383 / 3.255 s | 0.322 s |
| Windows | 128 | 3 | 3.355 / 3.441 / 3.387 s | 0.085 s |
| Linux | 32 | 3 | 4.905 / 5.162 / 4.991 s | 0.256 s |
| Linux | 128 | 3 | 3.391 / 3.956 / 3.681 s | 0.564 s |

Durations/spreads are truncated from individual high-resolution measurements;
rounded endpoint subtraction can differ by 1 ms. Local lint compilation
overlapped part of the run, so this is a repeatability observation, not a
CPU-isolated benchmark. More workers did not consistently improve Windows
timings. These results justify neither changing defaults nor closing the
full-range/VPN stability task. The live matrix covered 996 ports per host,
not 65535; the full-range matrix in this change used simulated connections.

## Reporting Template

The [October 22 full-range CONNECT matrix](CONNECT_BENCHMARK.md) extends these
records with twelve discovery-only scans across local Windows/Linux and an
authorized VPN target. It uses different rates/timeouts from the earlier
release regression. Its retained Windows open-set change and inconclusive
outcomes must not be summarized as a universal stability pass.

Record the code revision (and dirty source diff, when applicable), toolchain,
OS/network/VM setup, date, exact profile settings and whether either VM restarted.
For each profile and host, report:

```text
profile | requested | open | refused/closed | unresolved | inferred filtered | duration
```

Include baseline-anchor and format-check outcomes. Report quick-run minimum,
maximum and variation only for identical settings. Do not compare the deep and
full profiles as equal workloads. Keep incomplete/aborted/failed runs visible;
do not select only the fastest or fullest run. A passing metadata regression
with unresolved ports is not proof of complete discovery. Filtered is an
inference from silence; it overlaps unresolved rather than adding extra ports.

## Validation Record

Final regression: **October 21, 2026**, starting at `13:33:21 UTC`, on Linux
with Go 1.26.9 and the two authorized VirtualBox Metasploitable3 VMs. Tested
production revision: `ef1d6c0097a4bb03cab595a9c0e8e2b623487ae4`. Subsequent
changes in this review add documentation and a deterministic deadline-failure
test, not production behavior. This is unreleased code, not a new v2.5.0 build.

| Profile | Host Role | Requested | Open | Refused/Closed | Unresolved / Inferred Filtered | Scan Duration, Both Hosts |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| quick-1 | Windows | 996 | 22 | 974 | 0 | 28.754 s |
| quick-1 | Linux | 996 | 7 | 2 | 987 | 28.754 s |
| quick-2 | Windows | 996 | 22 | 974 | 0 | 27.526 s |
| quick-2 | Linux | 996 | 7 | 2 | 987 | 27.526 s |
| deep | Windows | 20 | 16 | 4 | 0 | 1.975 s |
| deep | Linux | 20 | 7 | 1 | 12 | 1.975 s |
| full | Windows | 65535 | 39 | 65488 | 8 | 332.694 s |
| full | Linux | 65535 | 9 | 2 | 65524 | 332.694 s |

All four final profiles passed their baseline anchors, deduplication, coverage
accounting, conservative-label and JSON/JSONL/CSV preservation checks. The full
run observed **48 open ports**. Durations are JSON `duration_ms`, shared across
both sequential hosts, not per-host times. The identical quick profiles range
from 27.526 to 28.754 s (mean 28.140 s, spread 1.228 s). The full test process
took 391.73 s including all profiles and report checks. Host-side CI, fuzzing
and cross-compilation also ran during parts of validation; timings are not a
CPU-isolated benchmark or comparable to previous unrestricted-rate samples.

Earlier preliminary runs included a missing-Linux-anchor failure followed by
recovery; that run is **not approved**. Its subsequent full profile observed
39/9 open ports, zero Windows unresolved and 65524 Linux unresolved, in
304.336 s. A prior full-range attempt using the unadjusted 750 ms / 32-worker
profile was deliberately stopped to bound silent-port cost, not counted as a
successful validation. The final green run does not erase those observations
or explain their cause. No VM firewall/NIC settings were changed to obtain it.

Local final checks passed lint, unit tests, race tests and the 40% coverage
floor, with **71.8%** total coverage. Specialized regression tests passed 20
race-detector repetitions; binary-parser and bounded-stream fuzz campaigns
passed (10722 and 13681 executions respectively). Windows amd64 and macOS
arm64 cross-builds passed; these are build checks, not runtime platform tests.

**Sign-off scope:** the current confidence review, two-VM regression and
changelog/known-limit review are complete. Network completeness remains
inconclusive, especially for Linux. This record supports a reviewed promotion
decision, not automatic publication, zero-defect claims or closing the separate
full-range stability/SYN/netlink roadmap tasks.

## v2.6.0 Candidate Validation

The candidate adds backwards-compatible opt-in features and therefore uses a
minor version, not a patch. Production revision
`4f0d3530dda8db1cec9b19d8d1bc4f2b9709bff1` passed `make ci` with Go 1.26.9:
lint, unit/race tests and 72.5% total coverage against the enforced 60% floor.
The unrelated local ignore-file change is excluded from the candidate.

The final two-VM regression started on October 22, 2026 at 13:42:14 UTC.
Both quick profiles passed their baseline, accounting and output checks:

| Profile | Host Role | Open | Refused/Closed | Unresolved | Duration, Both Hosts |
| --- | --- | ---: | ---: | ---: | ---: |
| quick-1 | Windows | 20 | 976 | 0 | 26.062 s |
| quick-1 | Linux | 7 | 2 | 987 | 26.062 s |
| quick-2 | Windows | 20 | 976 | 0 | 27.138 s |
| quick-2 | Linux | 7 | 2 | 987 | 27.138 s |

The subsequent deep profile failed: both hosts returned zero opens and 20
timeouts, missing every required baseline anchor. Independent checks then
found failed/incomplete ARP resolution for both VMs, no ping responses and no
direct Linux SSH connection. This does not establish the cause of the outage.
The full profile was interrupted to avoid scanning unavailable fixtures; the
84.375 s test process is **not a successful full regression**.

**Promotion gate: blocked pending restored fixtures and a complete passing
regression on the candidate code.** Do not publish a tag from this record.
Full-range network stability and disconnected end-to-end SYN/native netlink
rollback remain explicit limitations, not completed work. Additional identity
fingerprints and lab examples are deferred improvements, not release claims.

## Known Limitations

- TCP silence, packet loss, filtering, VM load/restarts and dynamic listeners can change counts. Full-range stability across constrained VirtualBox/VPN networks remains a roadmap task, not a solved consequence of these tests.
- Generic protocol evidence is not a product/OS assertion. Version/evidence strings and confidence may change conservatively while structured per-result schemas and CSV headers remain stable.
- TLS and RDP certificate collection does not verify trust. Hostnames are observed names, not authenticated identities. AJP/JRMP/RPC/SMB versions describe protocols; IIS does not identify a Windows release.
- Current SNMP auth/privacy algorithms, NetBIOS/Memcached reassembly and kernel-delegated IPv4/IPv6 fragment handling are bounded documented subsets, not universal support.
- End-to-end SYN and native netlink rollback still require their separate disconnected privileged lab validation. This CONNECT regression changes no source addresses and cannot close those tasks.
- Private scan data, arbitrary captured payloads and credentials must not enter commits or release assets. Checksums detect mismatched artifacts but are not themselves independent publisher authentication; APT signing has its separate trust model.

These limitations belong in release notes. A blocked gate should remain explicit
instead of being converted into a release-ready claim.
