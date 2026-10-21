# Roadmap

GoMap's roadmap focuses on improving reliability, test coverage, documentation, and release hygiene for authorized reconnaissance workflows.

## Quality and Coverage

- [x] Extend deterministic CLI/parser regression coverage for defaults, validation errors, option normalization, aliases, argument preservation and duration boundaries.
- [x] Add output format regression tests, including write failures.
- [x] Add deterministic service detection unit tests for banners, protocol fixtures, and malformed packets.
- [x] Establish deterministic stream-framing regressions for DNS/TCP, MySQL, ONC RPC, SMB, AJP, DCE/RPC and JRMP: split reads, final EOF bytes, truncation, size/count limits and next-frame boundaries.
- [x] Add passive/connected greeting and FTP/mail conversation regressions, including TLS, numeric multiline replies, capture limits and fixed per-read deadlines.
- [x] Add strict RDP confirmation/negotiation tests, malformed/unoffered selections, failure replies and a loopback TLS certificate upgrade.
- [x] Add HTTP/TLS collection and parser regressions for fragmented headers, incomplete/ambiguous headers, body/header separation, chunked titles and redirect non-following.
- [x] Review bounded LDAP/LDAPS anonymous BindResponse and TDS 7.x PRELOGIN readers with deterministic split/truncation/negative fixtures, response structure/correlation checks, fixed deadlines, loopback exchanges and fuzz tests; broader LDAP operations and TDS sessions remain outside this review.
- [x] Frame the current RESP2 INFO, IRC registration and generic write-first probe transactions with byte/line/depth/count limits, deterministic negative fixtures and fixed deadlines; withhold incomplete version disclosures while retaining complete earlier evidence. RESP3 negotiation and general-purpose client sessions remain outside this scope.
- Require new service probes to extend the [regression matrix](docs/SERVICE_DETECTION_TESTS.md); a completed baseline does not certify every protocol variant.
- [x] Raise the enforced total statement coverage floor past 25% to 40%, consistently in local checks and CI.
- [ ] Raise the enforced total statement coverage floor to 60% with sufficient headroom and meaningful tests.
- Integrated v2.5.0 validation reached 59.3% total coverage. Parser regressions do not imply complete installer/updater or CLI entry-point coverage; those remain follow-up work.
- Development validation including the RDP/TDS confidence review reaches 71.7% total statement coverage; the enforced floor is 40%, not 60%.

## Detection and Scan Reliability

- [x] Report per-host/global coverage and scope versus confirmed-state throughput, with JSON run context and combined phase timings.
- [x] Validate Linux IPv4 UDP positive responses, silence and correlated kernel ICMP port-unreachable using an opt-in, loopback-only network namespace; broader platform/network conditions remain separate validation.
- [x] Add opt-in bounded hex evidence for unparsed TCP/UDP responses, conservative sensitive-content suppression and private Unix output files; redaction is not guaranteed for arbitrary protocols.
- [x] Add strict per-IP CONNECT/UDP timeout/retry/adaptive overrides and initial per-host settings in JSON metrics; native SYN overrides remain unsupported.
- [x] Keep unvalidated UDP port hints low confidence and prevent arbitrary payload bytes from becoming product versions.
- [x] Add bounded NTP/SSDP response-shape checks and deterministic negative/fuzz fixtures without new probes.
- [x] Validate a bounded SNMPv1 response subset with standard ASN.1 decoding, negative fixtures, and metadata disclosure tests.
- [x] Validate bounded SNMPv2c response fields, Counter64 and exception values without exposing communities or bindings.
- [x] Validate a conservative SNMPv3 plaintext USM noAuthNoPriv Response/Report subset; label it unauthenticated and reject unsupported security modes.
- [x] Review unsupported SNMP BER forms/security models; support bounded non-minimal definite lengths and document/test explicit fallbacks without credential disclosure.
- [x] Validate bounded DNS response structure with a Go-native parser, strict framing, and malformed/compressed-record fixtures.
- [x] Validate a conservative mDNS response subset, including cache-flush classes and questionless answers, without exposing record values.
- [x] Validate a conservative LLMNR response subset with its own flag semantics and deterministic negative/fuzz tests.
- [x] Validate a bounded subset of UDP/137 NetBIOS NB/NBSTAT response structure, including compressed names and record framing, without disclosing node names or MAC addresses.
- [x] Recognize a bounded NetBIOS redirect subset with coherent NS/A records, without following redirects or disclosing targets; keep unsupported forms low confidence.
- [x] Validate negative UDP/137 name-query replies with strict NULL-record framing, known error codes, legacy counter-layout fixtures and input/disclosure protections.
- [x] Match DNS/SNMP replies against actual sent probe fields and review unsupported NetBIOS variants; document why existing generic/zero-timestamp probes cannot establish correlation. See [UDP validation scope](docs/UDP_VALIDATION.md).
- [x] Add opt-in, bounded UDP/161 SNMPv2c GET and SNMPv3 engine-discovery fallbacks with per-query identifiers, response correlation and deterministic simulated exchanges.
- [x] Implement opt-in per-IP SNMPv3 authNoPriv/authPriv sessions with SHA-256/SHA-512, optional AES-128, private credential files, bounded exchanges, correlation and time-window checks; validate positive/negative cases with loopback synthetic agents.
- [x] Validate the supported authenticated/encrypted SNMP subset against a disconnected Net-SNMP agent with correct/incorrect credentials; record reproducible lab commands and redacted results.
- [x] Add an opt-in framed Memcached UDP stats query with per-request correlation and conservative version disclosure.
- [x] Implement bounded Memcached application-fragment reassembly with fixed expiry, out-of-order delivery, duplicate/conflict handling, memory/read caps and deterministic tests.
- [x] Validate default/deep behavior and multi-datagram reassembly against an isolated real Memcached agent; record a reproducible lab recipe.
- [x] Add an opt-in unicast NetBIOS NBSTAT query with random transaction IDs, strict response correlation, deterministic negative/fuzz tests and a redacted Windows lab check.
- [x] Consolidate authenticated SNMP, protocol-specific discovery and Memcached reassembly into one integration branch with explicit supported/unsupported scopes and combined validation.
- [x] Add a bounded UDP/138 datagram query, correlated control/error replies and RFC-style two-fragment NetBIOS reassembly, including ordering, duplicates, tuple/length consistency, expiry and disclosure tests.
- [x] Validate IPv4/IPv6 fragment delivery through GoMap's production UDP socket path in a disposable loopback-only namespace, including ordering, loss, mixed IDs and invalid UDP checksums.
- Authenticated SNMP and application reassembly support documented bounded subsets, not every cipher or protocol variant. IPv4/IPv6 packet reassembly is delegated to the OS socket stack, not a second user-space IP engine; NetBIOS datagram interoperability is fixture-tested, not certified against every server implementation. See [fragment handling](docs/UDP_FRAGMENTS.md).
- [x] Keep identification evidence coherent when deduplicating observations; retain stronger confidence and avoid mixing TLS handshakes.
- [x] Validate signal cleanup and error reporting in Linux subprocesses with fake address backends.
- [x] Validate raw-socket deadlines and closure in an isolated loopback-only Linux namespace without sending probes.
- [ ] Validate end-to-end SYN response handling and native netlink address rollback in a disposable, disconnected lab; lifecycle fixtures do not cover these kernel-level workflows.
- [x] Add a global attempt budget covering discovery, retries, and additional service connections without replacing per-host pacing.
- [x] Extend isolated SYN response fixtures and cleanup failure tests without privileged sockets or NIC changes.
- [x] Add negative fixtures for malformed SIP/RTSP, RFB, and Memcached signatures and forged body headers.
- [ ] Extend confidence review across all protocol-specific detection paths; distinguish protocol evidence from product/version disclosure.
- [x] Review TCP CHAOS `version.bind` and the HTTP response to `OPTIONS /wsman`: validate complete/correlated DNS fields, retain server-declared text without assuming BIND, and distinguish HTTP disclosures from confirmed WinRM. Other specialized paths remain under the confidence-review item above.
- [x] Review RDP and TDS PRELOGIN confidence: distinguish X.224-only hints, RDP selections/rejections and actual TLS completion; label certificate CNs unverified and TDS sender-version/encryption fields server-declared, without inferring Microsoft products or Windows. Broader protocol-specific confidence review remains open.
- [x] Preserve explicit UDP states in text, JSON, JSONL, and CSV; count only confirmed open ports.
- [x] Support `--version` and options before or after the CLI target.
- [x] Separate CONNECT timeout port counters from actual timeout budgets; distinguish inferred-filtered timeouts, confirmed refusals and unknown failures without concealing incomplete coverage.
- [x] Add opt-in completion-order text/JSONL streaming for CONNECT results with deterministic delivery, deduplication and writer-error regressions.

- [ ] Stabilize full-range CONNECT results across constrained VirtualBox and VPN lab networks.
- [ ] Expand native fingerprints for SMB server identity, NetBIOS workgroup data, and IRC product/version banners.
- [x] Keep unidentified open TCP ports explicit when service detection is enabled, without inventing service or version data.
- [ ] Track benchmark variance across repeated runs, worker counts, and filtered-port conditions.

## Documentation and Release Workflow

- [ ] Add more lab-based examples for authorized environments.
- [x] Keep README language focused on controlled-rate scanning, structured output, and automation-friendly workflows.
- [ ] Document a repeatable local-lab benchmark procedure and reporting template.

Completed:

- Document APT/GHCR release workflow.
- Add initial CLI, output format, and service detection regression tests.
