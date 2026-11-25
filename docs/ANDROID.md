# Native Android Development APK

## Status And Architecture

This is an experimental, installable **debug APK**, not a published Android
release or an Android runtime certification. The CLI and Termux profile remain
separate; the APK supports TCP CONNECT, optional native service/banner detection
and bounded CIDR host discovery without root.

The app uses Kotlin/Jetpack Compose, an owning ViewModel and a single background
consumer. `gomobile bind` generates a JNI/AAR bridge to existing Go code. There
is no CLI subprocess, embedded localhost server or duplicated protocol engine.

- `pkg/scanner/connect_context.go`: cancellable runner reusing GoMap's CONNECT
  primitive, native service parsers, context-bound TCP/TLS sockets and limiter.
- `mobile/`: binding-compatible session API with bounded JSON events, cancellation
  and a final coverage summary. No change to the CLI execution path.
- `android/bindings/`: separately pinned `gomobile`/`gobind`; build-tool dependencies
  stay outside the root CLI module. Test both module contexts.
- `android/app/`: native UI, strict event/coverage decoding, single-session
  controller, explicit document export and JVM/UI/instrumentation fixtures.

## Compatibility Baseline

The minimum is **Android 12 (API 31)**. The APK uses compile SDK 37.0 and target
SDK 37; these do not replace its minimum supported OS. The AAR uses
`-androidapi=31`, minimum SDK 31 and no maximum SDK. Only **arm64-v8a and x86_64**
are packaged; 32-bit devices are not supported by this artifact.

| OS | API | Runtime acceptance |
| --- | --- | --- |
| Android 12 / 12L | 31 / 32 | Pending |
| Android 13 | 33 | Pending |
| Android 14 | 34 | Pending |
| Android 15 | 35 | Pending, including 16 KB page-size behavior |
| Android 16 | 36 | Pending |
| Android 17 | 37 | 0.1/0.2-dev user-reported success on Pixel 8 Pro/GrapheneOS; new profiles/autofill/full-range resource validation pending |

This is an intended range, not certification from a successful build. The SDK
package is **`platforms;android-37.0`**, not `platforms;android-37`. The earlier
failed package lookup did not establish SDK unavailability. The development APK
now compiles against the correct platform without lowering the target.

## Scan And Session Contract

`StartConnect(host, ports)` accepts one literal unicast IPv4/IPv6 address without
a zone and an explicit port specification: at most 8192 characters, 256
comma-separated entries and 4096 unique ports. Invalid/oversized scopes fail
before scanning; nothing is silently truncated. These are APK prototype limits,
not changes to CLI scope.

The original `StartConnect` defaults remain 32 workers, 100 starts/s and a 750 ms
connection timeout, without service negotiation. It retains schema 1 compatibility.

The app now calls `StartSurvey(target, ports, services, discoverOnly)`:

- Accept one literal IP or CIDR, at most 256 addresses (IPv4 /24 or smaller,
  IPv6 /120 or smaller), and at most 65535 requested host-port pairs. IPv4 network
  and broadcast addresses are omitted except on /31 and /32. Reject larger
  scopes before any connections; do not silently truncate.
- Port profile dropdown: **Custom** keeps the existing manual input and remains
  the default; **Common (1000)** uses `@common1000`; **All (65535)** uses
  `1-65535`. The common profile preserves the CLI's current 996 curated entries
  and adds TCP 1883, 5672, 6379 and 11211. It is not the range 1-1000 or a claim
  to reproduce Nmap's ranking. CLI defaults/list membership remain unchanged.
- All ports fit on one IP; a common-port CIDR can use, for example, an IPv4 /26.
  A /24 times 1000 ports exceeds the mobile pair budget and is rejected before
  any probes. Discovery-only /24 remains supported. Changing a profile resets
  authorization and never scans automatically; switching back restores manual input.
- Port scan defaults to optional services enabled; the switch allows connection-
  only scans. Native parsers/probes reuse GoMap, with a four-second service budget
  after each CONNECT, cancellation-aware TCP/TLS and retained open-state evidence even if
  fingerprinting runs out of time. No exhaustive/deep CLI-mode parity is implied.
- Multi-host CIDR port scans first discover responding endpoints using TCP ports
  443,80,22,445,3389, a 400 ms timeout and at most 16 host jobs. A successful
  connection **or refusal** counts as a TCP response, not OS identification.
- Host discovery mode performs only that reachability pass; its port input is
  ignored and there are no service probes. It is useful for `10.0.11.0/24`.
- Silence is `no_response`, never confirmed offline. Unknown failures stay
  separate. Networks that drop the discovery probes can hide reachable hosts;
  scan an explicit IP (or /32 IPv4 / /128 IPv6 scope) to bypass pre-discovery.
- Port scans share up to 32 workers between at most four hosts (32 for one,
  16 each for two, 10 each for three, eight each for four), with a 750 ms
  connection timeout. Discovery, primary connections and additional service
  sockets share **one 100 starts/s budget**, not a separate budget per host.
- Keep undiscovered/unscanned host-port pairs **unreported**, not closed or
  timeout-filtered. Host coverage and port coverage are separate ledgers.
- Retain at most 65535 observations; an explicit safety failure stops scans
  exceeding 10000 open observations, preserving partial coverage and an exported
  error rather than silently omitting rows. Large lists use an ordered endpoint
  index and coalesced UI snapshots. JSON document export encodes directly to a
  buffered output stream instead of building one giant report string.

Full-range scans can take minutes at the unchanged 100-starts/s budget and must
remain in the foreground. Queue bounds, synthetic 65535-row delivery/export tests
and count reconciliation are not physical-device memory/battery certification.

There are no retries, DNS, UDP, SYN, raw sockets, source rotation or interface
changes in the APK. Port-map names remain hints, not confirmed versions.

| Go | Java | Contract |
| --- | --- | --- |
| `StartConnect` | `Mobile.startConnect` | Validation errors become exceptions |
| `StartSurvey` | `Mobile.startSurvey` | Bounded IP/CIDR, service and discovery-only options |
| `NextEvent` | `Session.nextEvent` | Blocking; one consumer; empty string closes the queue |
| `Cancel` | `Session.cancel` | Idempotent, concurrent-safe, nonblocking |
| `AwaitSummary` | `Session.awaitSummary` | Blocking join; drain events or cancel first |

Never block the Android main thread. `AwaitSummary` avoids Java's final
`Object.wait()` name. Construct sessions through `startConnect`, not the
generated Java constructor.

Survey events use JSON `schema_version: 2`, `type: "result"`, `host` and `result`.
Discovery adds `type: "host"` with `host_result.address`, `state` and `evidence`;
states are `responding`, `no_response` and `unknown`. Every port row retains its
host identity; the same port on different hosts is never deduplicated together.
They include all observed states, not only open ports. `closed` requires a
refusal; timeout-based `filtered` remains inferred/uncertain.

After the queue closes, `awaitSummary` returns `type: "summary"` with requested,
completed, open, closed, filtered, unknown, unreported, cancelled and duration_ms.
Completed counts delivered observations, including queued ones. Undelivered work
is unreported, never closed. Cancellation has `error: "cancelled"`; other internal
failures use `scan_failed`. Survey summaries also carry discovery requested,
completed, responding, no_response, unknown and unreported counts. The Kotlin
decoder reconciles both ledgers with actual delivered observations. JSON export
retains per-row host identity, discovery evidence, and the frozen mode/options.

The session queue holds 32 events; in-flight observations are also worker-bounded.
Backpressure prevents unbounded production. Cancellation interrupts dials, pacing
and blocked delivery, joins workers, and preserves already queued observations.
`cancel()` is not a blocking join; use `awaitSummary()` off the main thread before
replacing a session.

## Lifecycle, Permissions And Storage

The controller allows one UI-owned session and joins it before allowing another.
Kotlin referential identity (`===`), not generated Go proxy equality, distinguishes
runs. A ViewModel retains results across configuration changes. Leaving the
foreground or disposing the owner cancels the run. There is no automatic resume,
foreground service, wake lock or background scan. Process death loses RAM results.

The manifest declares `INTERNET`, `ACCESS_NETWORK_STATE` and `ACCESS_LOCAL_NETWORK`, not root, location,
broad storage, a VPN service or interface-management privileges. On API 37+,
Start requests local-network permission when missing. A grant never starts a scan:
the user must press Start again. Denial leaves scanning stopped. This flow still
needs device validation. See [Android network permissions](https://developer.android.com/develop/connectivity/network-ops/connecting)
and [local-network protection](https://developer.android.com/privacy-and-security/local-network-permission).

Scan data stays in memory; backups are disabled and the app does not log scan
payloads or persist history. Export uses Android's document picker only on an
explicit action, with a frozen target/port/result snapshot. The selected document
provider determines where the exported file lives, including possible cloud
storage. Editing target/ports resets authorization. Nothing scans on launch,
network changes or permission grants.

On startup the app reads the active network's local link addresses off the main
thread, preferring a usable IPv4 address, then unscoped global/ULA IPv6. It fills
the target only once while untouched. It does not fetch a public IP, read SSIDs
or MAC addresses, infer a CIDR or start discovery. No active/allowed network
leaves manual input available. A default VPN may supply its local VPN address;
the field remains editable. Late results never overwrite typing, cleared input
or a target retained across rotation. The implementation uses Android's
[active network and link properties](https://developer.android.com/reference/android/net/ConnectivityManager#getLinkProperties(android.net.Network))
and [local link addresses](https://developer.android.com/reference/android/net/LinkProperties#getLinkAddresses()).

The first screen provides IP/CIDR input, port-scan/host-discovery modes, a
services/banners switch, authorization, Start/Stop, ports/hosts views, all/open
and all/responding filters, separate coverage, Clear and JSON export.
English/Spanish resources are included. Service evidence is control-character
sanitized and capped in the bridge; arbitrary protocol content is not guaranteed
secret-free. No service-detection parity with the CLI is implied.

## Build And Install

Use the repository Go toolchain, JDK 21 and these pinned development tools.
Build scripts default `GOTOOLCHAIN` to `go1.26.10` unless explicitly overridden:

| Component | Version |
| --- | --- |
| SDK platform / Build Tools | `android-37.0` / `36.0.0` |
| NDK | `30.0.16248370` |
| Android Gradle Plugin / Gradle | `9.4.0` / `9.6.0` |
| Built-in Kotlin / compiler plugins | `2.2.10` |
| Compose BOM | `2025.10.01` |

The wrapper pins the Gradle distribution SHA-256. Its standard bootstrap JAR is
tracked; app binaries, generated bindings, local SDK paths and signing keys are
ignored. SDK/NDK licenses require explicit review/acceptance. The build does not
automatically accept licenses or download missing SDKs.

From the repository root, with SDK components installed:

```bash
export ANDROID_HOME="$HOME/Android/Sdk"
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
bash android/build-apk.sh
# Connect an authorized device and approve USB debugging before installing:
"$ANDROID_HOME/platform-tools/adb" install -r android/app/build/outputs/apk/debug/app-debug.apk
```

Override environment paths for other installations. The script builds the AAR,
runs JVM tests/lint, assembles debug and instrumentation APKs, then checks the
debug signature, minimum/target SDK, 16 KB ZIP alignment and native ELF alignment.
The app ID is `com.nexusfireman.gomap.dev`, version `0.3.0-dev`; its local debug
key is not suitable for distribution. A differently signed existing install may
require removal before reinstalling, losing its local state.

Run the compiled loopback smoke on a connected device/emulator with:

```bash
export PATH="$JAVA_HOME/bin:$PATH"
./android/gradlew -p android :app:connectedDebugAndroidTest --no-daemon
```

This test uses a local listener, not external targets. Review permission state
before running on API 37+. Compiling instrumentation is not executing it.

### Bridge-Only Tooling

Generate Java signatures without an Android SDK:

```bash
cd android/bindings
go mod verify
go test github.com/NexusFireMan/gomap/v2/mobile github.com/NexusFireMan/gomap/v2/pkg/scanner
go tool gobind -lang=java -javapkg=com.nexusfireman.gomap \
  -outdir=../generated github.com/NexusFireMan/gomap/v2/mobile
```

From the root, `bash android/build-aar.sh` builds the pinned gobind into an
ignored tools directory, packages both 64-bit ABIs with API 31/trimpath, checks
the AAR and collects selected Go/runtime dependency licenses into build assets.
This is not a complete public-distribution license audit.

`android/bindings/cmd/checkaar` validates ZIP/XML/ELF structure, the AAR minimum/no
maximum SDK, Java class entries, ABIs/machines and at least 16 KB ELF LOAD
alignment. Its `--native-apk` mode checks every packaged native library, including
AndroidX dependencies. Static checks do not establish JNI loading, symbol
availability or device behavior; the APK script checks ZIP alignment separately.

## Validation And Remaining Gates

Go unit/race fixtures cover mixed outcomes, duplicates, invalid scope, concurrent
cancellation, pacing, worker/connection cleanup, consumer failure, a saturated
queue and loopback CONNECT without external targets. Root CI also generates
bindings and compiles Java signatures with a minimal Context fixture; that
fixture is not an Android runtime and must never be shipped.

Local validation on November 24, 2026 built the debug and instrumentation APKs
with SDK 37.0/NDK 30. Twelve JVM tests passed: protocol/coverage reconciliation,
consent, cancellation during startup/blocked reads, cleanup, frozen export scope
and malformed/duplicate events. Two tests render Compose with a fake backend
on Robolectric API 31, including 360 dp and 200% text fixtures. Reviewed screenshots
are generated under `android/app/build/reports/ui/`; these are not JNI execution.

The subsequent CIDR/service extension passes 20 JVM tests and adds deterministic mixed discovery states,
same-port/different-host identity, shared pacing, cancellation, native SSH/FTP/
HTTP fixtures and blocked-read/TLS cleanup tests. Host UI fixtures also cover
the host list, service/version/evidence view, equal-height large-font mode controls
and a fixed toolbar Stop action while browsing streamed ports. No external hosts are required.

Profile/autofill regressions additionally cover exact curated membership,
65535 unique delivered observations, explicit open-result safety failure,
frozen profile export, ordered full-range UI storage, streaming JSON, address
selection and protection against delayed autofill overwriting edits. These use
synthetic results and address fixtures, not external targets.

The user reports that the initial 0.1-dev APK works on a **Pixel 8 Pro running
GrapheneOS/Android 17**, including cancellation, rotation, background transition
and JSON export. This is user-reported manual validation of that build, not an
instrumentation run. The user subsequently reported successful operation of
0.2-dev with the CIDR/service additions. New profiles/autofill/full-range behavior
still requires physical validation; broader runtime gates remain open.

The separate Android workflow runs JVM tests/lint and builds/checks both debug
APKs; it does not execute instrumentation. Android lint has no errors; pinned
dependency/tool update advisories remain for review before release. Debug
APK/AAR artifacts are ignored and are not published releases.

Still required: execute the OS acceptance matrix, permission denial/grant,
stop/navigation/rotation, screen-off, Wi-Fi/VPN changes, export and RSS/FD
stability against authorized lab scopes. Complete the runtime dependency/license
inventory, dependency update review and release signing/distribution before a
public Android release. Validate CIDR discovery and service detection on physical
devices; other CLI engines remain follow-up work.
