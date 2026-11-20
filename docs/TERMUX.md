# Termux Development Profile

## Status

`--mobile` is an opt-in development feature, not part of the published v2.6.0
binary. It works independently of platform/root detection so desktop fixtures
can exercise the same budget. There is no APK, new Android package repository,
automatic mobile selection or certified physical-device support in this change.
GoMap remains native Go; no external scanner or privilege escalation is used.

## Build In Termux

Use Termux's own Go package meeting `go.mod`, not a Linux Go distribution or the
project's Debian APT packages. Termux has Android-specific library, path and
execution constraints: see the [official environment documentation](https://github.com/termux/termux-packages/wiki/Termux-execution-environment).

```bash
pkg update
pkg install git golang
git clone https://github.com/NexusFireMan/gomap.git
cd gomap
git switch dev
go build -o ./gomap .
./gomap --version
./gomap --mobile -s -p 22,80,443 10.0.11.6
```

Choose only an authorized target. Keep the executable, reports and credential
files inside private Termux storage, not shared `/sdcard` storage. Benchmark the
built binary rather than including compilation in scan timing. If the packaged
Go is too old, resolve that through supported Termux packages; do not assume Go's
automatic toolchain downloader supplies an Android-compatible distribution.
Self-update/removal/installer workflows and Android release assets still need
separate review; use the local source-built binary for this initial trial.

## Budget And Output

| Setting | Mobile default | Explicit override |
| --- | --- | --- |
| Scan workers | 32 | Positive `--workers`; zero keeps automatic defaults |
| Global attempt starts | 100/s, shared across hosts/phases | `--global-rate`; explicit zero means unlimited |
| Initial dial timeout | 750 ms | `--timeout` and supported per-IP host overrides |
| CIDR discovery workers | At most 8 | Existing discovery scope preserved |
| Controlled profile | Existing stricter limits/longer waits retained | Existing flag semantics |
| Text | Per-port blocks, short scan banner | Omit `--mobile` for the standard table |

These are initial resource budgets, not hardware-calibrated optimal settings.
Lower concurrency/rates can increase duration. No target, port, response or
detection mode is discarded to make a scan look faster. Timeouts, refusals and
unknown failures retain their original meanings.

Text uses the terminal's soft wrapping, including its own Unicode width handling;
it neither guesses display-cell widths nor truncates banners/evidence. Requested
latency/confidence/evidence fields remain available. Coverage summaries and help/
maintenance output retain their existing presentation and can still wrap.
Streaming text uses per-result blocks with host context. JSONL/CSV rows are
unchanged; JSON metrics optionally include `mobile: true` and resolved limits.

The UDP result queue now holds at most the active worker count, rather than one
slot per requested port. Completed results are drained while probes run, then
sorted as before. Final observations/diagnostics still require memory proportional
to scope: this is not a constant-memory scan or a streaming-only data model.

## Permissions And Network Limits

The initial test focus is ordinary CONNECT and connected UDP sockets without
root. Native SYN is currently gated to Linux by GoMap; raw sockets, NIC address
management and Android privilege/SELinux behavior are not certified here. The
mobile profile does not grant permissions, alter interfaces, automatically use
sudo or promise support for root-only operations.

Validate DNS names separately from literal IPs: a cross-compiled binary's resolver
behavior may differ from a Termux-native build. UDP silence remains uncertain;
Android/kernel ICMP reporting must be observed, not inferred from Linux tests.
Record Wi-Fi/VPN routing and captive-network conditions without disclosing secrets.

Android may suspend/restrict background activity under power management. This
feature does not acquire wake locks or change battery policies. Check the
[Android power-management guidance](https://developer.android.com/topic/performance/power/power-details)
and report interrupted/incomplete runs honestly.

## Deterministic Checks And Queue Microbenchmark

```bash
go test ./...
go test -race ./cmd/gomap ./pkg/app ./pkg/output ./pkg/scanner \
  -run 'Test(CLIMobile|Mobile|UDPBoundedQueue)' -count=3
go test ./pkg/scanner -run '^$' -bench '^BenchmarkUDPResultQueueCapacity$' -benchmem -benchtime=1x
```

The queue-only microbenchmark on Linux/amd64 with Go 1.26.10 measured allocations
of 8,304 bytes for 32 slots, 49,264 bytes for 200 and 15,204,464 bytes for 65,535.
Those are allocations for queue storage only, not Android memory, total scan
allocations, peak RSS or battery measurements. The deterministic full-range fake
probe test preserves all 65,535 observations across worker counts and uncertainty
states without opening network connections.

## Physical-Device Acceptance Still Required

November 20, 2026 validation on Linux/amd64 with Go 1.26.10 passed lint, the full
unit/race suite and coverage checks (72.7% total, 60% floor). The CLI was also
checked against a local HTTP fixture in compact text, JSON, streaming JSONL and
CSV modes, including an explicit unlimited global rate. An Android/arm64 build
with `CGO_ENABLED=0` compiled successfully; it was not executed on Android and
does not establish DNS, permissions, battery or device interoperability.

Record model, Android/Termux/Go versions, CPU ABI, installation method, root state
and the exact GoMap commit. Compare standard/mobile on the same small authorized
scope, then a bounded larger one, with the same detection depth and network:

- Compare actual port/state sets, full evidence and inconclusive coverage, not
  just open-port counts or elapsed time.
- Exercise CONNECT, connected UDP, DNS names, JSON/JSONL/CSV and compact streaming.
- Test Ctrl+C, connectivity changes, screen-off/background behavior and file paths.
- Record timings, RSS/FD observations and repeated thermal/battery conditions with
  a documented measurement method; no root requirement for the basic trial.
- Keep reports/credentials private. Treat APK design, privileged features and
  Android packaging/updating as separate work until validated.
