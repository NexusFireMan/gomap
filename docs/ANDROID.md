# Android APK Foundation

## Status And Architecture

This is an experimental native-library foundation, not an installable APK or an
Android runtime certification. The CLI and Termux profile remain separate.

The intended application uses Kotlin/Jetpack Compose, an owning ViewModel and a
single background consumer. `gomobile bind` generates a JNI/AAR bridge to the
existing Go code. Do not launch the CLI as a subprocess, embed a localhost server
or duplicate protocol detection in Kotlin.

Implemented layers:

- `pkg/scanner/connect_context.go`: cancellation-aware connection-only runner,
  reusing GoMap's single-port CONNECT primitive, dialer, service map, attempt
  limiter and error classification. No changes to the CLI execution path.
- `mobile/`: a small binding-compatible session API using strings and errors,
  bounded JSON event delivery, cancellation and a final coverage summary.
- `android/bindings/`: a separate module pinning `gomobile`/`gobind`; build-tool
  dependencies do not enter the root CLI module. Its dependency graph can select
  newer transitive libraries, so test both module contexts.

## Prototype Contract

`StartConnect(host, ports)` validates and starts one session. Accept only one
literal unicast IPv4/IPv6 address without a zone, an explicit port specification
of at most 8192 characters/256 comma-separated entries and at most 4096 unique
ports. Oversized/invalid scopes fail before any scan starts; nothing is silently
truncated. These are prototype API limits, not changes to CLI scope.

Defaults are 32 workers, 100 starts/s and a 750 ms fixed connection timeout.
There are no retries, DNS resolution, CIDR discovery, banner/version probes,
UDP, SYN, raw sockets, source rotation, interface changes, files or stdout.
The Go-only runner also exposes bounded resource options for tests/embedding.

Session methods map to Java as follows:

| Go | Java | Contract |
| --- | --- | --- |
| `StartConnect` | `Mobile.startConnect` | Validation errors become exceptions |
| `NextEvent` | `Session.nextEvent` | Blocking; one background consumer; empty string means queue closed |
| `Cancel` | `Session.cancel` | Idempotent, concurrent-safe, nonblocking |
| `AwaitSummary` | `Session.awaitSummary` | Blocking join; drain events or cancel first |

Never call blocking methods on the Android main thread. `AwaitSummary` deliberately
avoids the name `Wait`, which would collide with Java's final `Object.wait()`.
Do not construct `Session` directly from generated Java: use `startConnect`.

Each `nextEvent` result is JSON with `schema_version: 1`, `type: "result"`, `host`
and `result`. It includes all observed states, not just open ports. A mapped
service name is a low-confidence port hint, not a confirmed protocol or version.
`closed` requires refusal; timeout-based `filtered` remains inferred/uncertain.

After the queue closes, `awaitSummary` returns JSON with `type: "summary"`, the
same schema/host and `summary`: requested, completed, open, closed, filtered,
unknown, unreported, cancelled and duration_ms. Completed counts delivered
observations, including queued ones. Unfinished/undelivered work is unreported,
never closed. Cancellation has `error: "cancelled"`; other internal failures
use `scan_failed`. Consumers must not treat a partial run as complete coverage.

The session queue holds 32 events; the engine also bounds in-flight observations
by workers. If the UI stops draining, producers apply backpressure. Cancellation
interrupts pending dials, pacing and blocked delivery and joins workers. It does
not discard previously queued observations. `cancel()` is not a blocking join;
use `awaitSummary()` off the main thread before replacing/discarding a session.

## Planned APK Lifecycle And Permissions

Allow only one active UI-owned session. Cancel and join the old session before
starting another, and associate UI events with their owning session to reject
stale updates. Use an application-owned run token or Kotlin referential identity (`===`), not
generated Go proxy value equality (`==`), to distinguish sessions.
A ViewModel should retain state across configuration changes. The initial
foreground-only app should cancel on leaving the foreground and
on owner disposal. Do not claim completion after process death or resume a run
automatically. No foreground service, wake lock or background scanning yet.

Declare `INTERNET`; do not request root, location, broad storage, VPN service or
interface-management privileges for ordinary CONNECT. Review the chosen target
SDK and implement the required permission flow before starting: Android 17/API
37 local-network restrictions require `ACCESS_LOCAL_NETWORK` for apps targeting
37+, while earlier-target behavior differs. See [Android network permissions](https://developer.android.com/develop/connectivity/network-ops/connecting)
and [local-network protection](https://developer.android.com/privacy-and-security/local-network-permission).

Keep session/report data private, disable sensitive logging/backups by default,
and export only on user request through Android's document picker. The prototype
bridge does not persist anything. Require an explicit authorized target and
Start action; never scan on launch, network changes or permission grants.

## Reproducible Build Preparation

Use Go matching the repository and JDK 21. Inside `android/bindings`, pinned tools
can generate Java signatures without an Android SDK:

```bash
cd android/bindings
go mod verify
go test github.com/NexusFireMan/gomap/v2/mobile github.com/NexusFireMan/gomap/v2/pkg/scanner
go tool gobind -lang=java -javapkg=com.nexusfireman.gomap \
  -outdir=../generated github.com/NexusFireMan/gomap/v2/mobile
```

Generated files are disposable and ignored. To compile an actual AAR, first
install/review an Android SDK and compatible NDK, accept their licenses explicitly,
and configure `ANDROID_HOME`/`ANDROID_NDK_HOME`. Then, from the same directory:

```bash
mkdir -p ../build
go tool gomobile bind -target=android/arm64 -androidapi=26 \
  -javapkg=com.nexusfireman.gomap -o ../build/gomap.aar \
  github.com/NexusFireMan/gomap/v2/mobile
```

This AAR command is preparation, not a validated artifact claim. An AAR still
needs a Gradle Android app, manifest, Compose UI and lifecycle implementation to
produce an APK. Pin/review SDK, NDK, AGP, Kotlin and Compose versions when adding
that app; do not download arbitrary tool versions in a release pipeline. Keep
debug builds and signing keys out of Git. Do not reuse CLI release tags or
publish an Android release until runtime validation passes.

## Validation And Remaining Gates

Host validation and CI cover fake mixed outcomes, duplicates, validation failures,
concurrent cancellation, pacing cancellation, worker/connection cleanup, consumer
failure, a saturated session queue and one loopback CONNECT. All unit/race tests
run without external targets. CI also generates the pinned Java bindings and
compiles their signatures on JDK 21, using a minimal `android.content.Context`
compile fixture for Go's Seq support. That fixture is not an Android runtime and
must never be shipped. Android/arm64 package compilation, Java generation and
host-only signature checks do not establish JNI runtime/device support.

Still required: build the AAR with real SDK/NDK, assemble the minimal APK, add
Java/Kotlin compilation/instrumentation CI, and test arm64 hardware (plus emulator
ABI if supported). Validate permission denial/grant, stop/navigation/rotation,
screen-off, Wi-Fi/VPN changes, private storage/export, RSS/FD stability and port
states against the same authorized lab scope as the CLI. APK implementation,
signing/distribution and service detection remain separate follow-up work.
