# Roadmap

GoMap's roadmap focuses on improving reliability, test coverage, documentation, and release hygiene for authorized reconnaissance workflows.

## Quality and Coverage

- [ ] Improve CLI/parser test coverage.
- [x] Add output format regression tests, including write failures.
- [x] Add deterministic service detection unit tests for banners, protocol fixtures, and malformed packets.
- [ ] Extend service detection tests to fragmented responses and malformed packets as new probes are added.
- Raise minimum coverage progressively from 10% to 25%, 40%, and 60%.

## Detection and Scan Reliability

- [x] Keep unvalidated UDP port hints low confidence and prevent arbitrary payload bytes from becoming product versions.
- [x] Add bounded NTP/SSDP response-shape checks and deterministic negative/fuzz fixtures without new probes.
- [x] Validate a bounded SNMPv1 response subset with standard ASN.1 decoding, negative fixtures, and metadata disclosure tests.
- [ ] Review unsupported SNMP BER forms, SNMPv2/v3, and query correlation without exposing credentials or response values.
- [ ] Validate structured DNS, NetBIOS, mDNS, and LLMNR replies before raising UDP identification confidence; distinguish header shape from query correlation.
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
