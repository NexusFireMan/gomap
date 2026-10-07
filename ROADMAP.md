# Roadmap

GoMap's roadmap focuses on improving reliability, test coverage, documentation, and release hygiene for authorized reconnaissance workflows.

## Quality and Coverage

- [ ] Improve CLI/parser test coverage.
- [x] Add output format regression tests, including write failures.
- [x] Add deterministic service detection unit tests for banners, protocol fixtures, and malformed packets.
- [ ] Extend service detection tests to fragmented responses and malformed packets as new probes are added.
- Raise minimum coverage progressively from 10% to 25%, 40%, and 60%.

## Detection and Scan Reliability

- [x] Keep identification evidence coherent when deduplicating observations; retain stronger confidence and avoid mixing TLS handshakes.
- [ ] Review UDP protocol claims against payload structure rather than inferring validated responses from destination ports alone.
- [x] Validate signal cleanup and error reporting in Linux subprocesses with fake address backends.
- [x] Validate raw-socket deadlines and closure in an isolated loopback-only Linux namespace without sending probes.
- [ ] Validate end-to-end SYN response handling and native netlink address rollback in a disposable, disconnected lab; lifecycle fixtures do not cover these kernel-level workflows.
- [x] Add a global attempt budget covering discovery, retries, and additional service connections without replacing per-host pacing.
- [x] Extend isolated SYN response fixtures and cleanup failure tests without privileged sockets or NIC changes.
- [ ] Validate raw SYN sockets and cleanup on interruption in a disposable, isolated Linux environment; simulated tests do not establish kernel-level behavior.
- [x] Add negative fixtures for malformed SIP/RTSP, RFB, and Memcached signatures and forged body headers.
- [ ] Extend confidence review across all protocol-specific detection paths; distinguish protocol evidence from product/version disclosure.
- [x] Preserve explicit UDP states in text, JSON, JSONL, and CSV; count only confirmed open ports.
- [x] Support `--version` and options before or after the CLI target.
- [ ] Separate confirmed protocol, probable product, and disclosed version confidence; add positive and negative captured-response fixtures.
- [ ] Add reproducible isolated Linux tests for SYN, cancellation, and temporary source-address cleanup.

- [ ] Stabilize full-range CONNECT results across constrained VirtualBox and VPN lab networks.
- [ ] Expand native fingerprints for SMB server identity, NetBIOS workgroup data, and IRC product/version banners.
- [ ] Keep unidentified open ports explicit in text and structured output without inventing service or version data.
- [ ] Track benchmark variance across repeated runs, worker counts, and filtered-port conditions.

## Documentation and Release Workflow

- [ ] Add more lab-based examples for authorized environments.
- [x] Keep README language focused on controlled-rate scanning, structured output, and automation-friendly workflows.
- [ ] Document a repeatable local-lab benchmark procedure and reporting template.

Completed:

- Document APT/GHCR release workflow.
- Add initial CLI, output format, and service detection regression tests.
