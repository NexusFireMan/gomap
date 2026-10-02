# Core Reliability Audit

## Scope

Reviewed the CLI, target/port planning, TCP/UDP/SYN engines, protocol detection, source-address lifecycle, report rendering, updater, dependencies and tracked contributor/release documentation. Changes target `dev` through a PR; no release or new scan mode is included.

The scan engine remains native Go: `pkg/scanner`, `pkg/app` and `pkg/output` do not invoke external programs. Maintenance commands under `cmd/gomap` still use Git, Go, package diagnostics and sudo where applicable. This distinction is intentional, not a runtime Nmap dependency.

## Corrected Findings

| Area | Finding and correction |
| --- | --- |
| Build security | CI/release used Go 1.24.9 while local checks used Go 1.26.7. Analysis with the old toolchain reported 19 reachable standard-library advisories. The minimum and Docker builder are updated to Go 1.26.8, which CI/release select through `go.mod`. |
| HTTP resources | Response accumulation had no byte cap and request writes lacked a deadline. Collection now shares a bounded deadline and a 64 KiB limit. |
| TCP framing | Single reads could discard split MySQL, DNS, RPC, AJP and SMB messages. Exact-length reads now enforce allocation limits; RPC fragments are reassembled with byte/count limits. |
| Protocol integrity | MySQL lengths/sequences and RPC verifier lengths are validated. AJP accepts the container's CPONG header, not the request header. |
| SMB evidence | The old request was malformed and dialect offsets were incorrect. Native negotiation now offers SMB 2.0.2/2.1/3.0/3.0.2, validates replies, and avoids OS assertions from unmatched raw strings. |
| SYN correctness | Responses were not correlated with peer IP or ACK and TCP bytes could be misread as another IP header. Correlation and TCP header validation now use the actual Go socket contract. |
| Discovery | One goroutine per host and completion-order output caused unnecessary resource growth and unstable host selection. A bounded pool preserves input order. |
| Duplicate work | Repeated targets/ports caused redundant scans and reports. Deduplication preserves the first occurrence; mixed port lists/ranges are parsed consistently. |
| Terminal output | Remote evidence could contain terminal controls and line breaks. Text rendering neutralizes these without mutating structured results; colored columns align by visible width. |
| HTTP parsing | Header casing and body text could produce incorrect server values. Header matching is case-insensitive and ends at the header/body boundary. |
| Local updates | Predictable `.new` files could follow an existing symlink. Unprivileged replacement now uses an exclusively created temporary file and cleans it on failure. |
| CLI | Duration conversion could overflow, and a positive alias could mask negative `--top`. Both are rejected. |
| Parser overhead | SSH regular expressions were recompiled on every call. They are now immutable package-level expressions. |

## Verification

Tests use byte fixtures, simulated packet connections, fake interface backends and loopback servers. No external scan target or real NIC modification is needed.

```bash
make ci
go test ./pkg/scanner -run '^$' -fuzz '^FuzzBinaryParsers$' -fuzztime=20s -parallel=2
go test ./pkg/scanner -run '^$' -bench '^BenchmarkParseSSH$' -benchmem -benchtime=300ms -count=3
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
```

Initial checks on Go 1.26.7 passed lint, unit tests and the race detector, with coverage increasing from 38.6% to 45.2%. A 20-second binary-parser fuzz run completed 663,164 executions without a crash. Cross-builds for Windows/amd64 and macOS/arm64 and Linux/386 unit tests also passed. Dependency scanning with Go 1.26.7 found no reachable vulnerable symbols, but rerunning with the configured Go 1.24.9 toolchain reported 19 standard-library advisories. One additional advisory existed in an unused dependency module. These are bounded checks, not proof of absence of defects; toolchain versions must accompany security results.

Final `make ci` verification on Go 1.26.8 passed lint, unit tests, race tests and coverage (45.2%). `govulncheck` v1.7.0 reported no reachable vulnerabilities and none in imported packages; one advisory remained in an unused dependency module. This is a point-in-time dependency check, not a guarantee about future advisories.

Windows/amd64 and macOS/arm64 cross-builds and Linux/386 unit tests also passed with Go 1.26.8. The Docker image built successfully; its `-h` and `-v` commands ran with `--network none`. This validates build/startup, not raw-socket privileges or a published GHCR image.

On the local Linux/amd64 Intel i5-14400F, the SSH microbenchmark changed from 127 allocations and approximately 11.5 KiB per operation to 12 allocations and approximately 407 bytes. Three local runs measured roughly 90-122 microseconds before and 6-10 microseconds after. Timing varies with load; this is not an end-to-end scan benchmark and does not replace the historical HTB measurements.

## Remaining Validation And Limits

- Exercise raw SYN discovery and temporary-address cleanup in isolated Linux network namespaces, including signals and setup failures, before a release. Fake-backend tests do not establish real-kernel behavior.
- Source pools must contain operator-owned, routed addresses. Existing addresses are preserved; process crashes, SIGKILL, overlapping pools and external NIC changes remain operational limitations. No MAC-rotation work is included.
- Other text/RDP/LDAP/TDS probes still need broader fragmentation and malformed-response coverage. UDP identification remains partly port-oriented; response receipt alone does not establish a product version.
- SMB 3.1.1 contexts and a complete NetBIOS session handshake are not implemented by this correction. Reported dialects are negotiated choices, not an inventory of every supported dialect.
- `--rate` is a per-host port scheduler, not an aggregate cap for discovery, retries and enrichment. Service detection may use several bounded probes; no strict whole-scan deadline is promised.
- Privileged updater fallback, installation/removal and published APT/GHCR artifacts need separate installation-lab checks. They were not executed against the workstation during this audit.
- Old ignored local notes under `docs/` may describe superseded external-tool integrations. They are not tracked documentation and were not published or rewritten.

## Protocol References

- [Go release downloads and versions](https://go.dev/dl/)
- [Apache AJP packet and CPONG formats](https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html)
- [MySQL packet framing](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_packets.html)
- [Microsoft SMB2 NEGOTIATE request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5)

The SYN parsing change was also checked against the local Go standard library's `net.IPConn.readFrom`, which removes the IPv4 header before returning the TCP segment.
