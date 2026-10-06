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
- [x] Validate bounded SNMPv2c response fields, Counter64 and exception values without exposing communities or bindings.
- [x] Validate a conservative SNMPv3 plaintext USM noAuthNoPriv Response/Report subset; label it unauthenticated and reject unsupported security modes.
- [x] Review unsupported SNMP BER forms/security models; support bounded non-minimal definite lengths and document/test explicit fallbacks without credential disclosure.
- [x] Validate bounded DNS response structure with a Go-native parser, strict framing, and malformed/compressed-record fixtures.
- [x] Validate a conservative mDNS response subset, including cache-flush classes and questionless answers, without exposing record values.
- [x] Validate a conservative LLMNR response subset with its own flag semantics and deterministic negative/fuzz tests.
- [x] Validate a bounded subset of UDP/137 NetBIOS NB/NBSTAT response structure, including compressed names and record framing, without disclosing node names or MAC addresses.
- [x] Match DNS/SNMP replies against actual sent probe fields and review unsupported NetBIOS variants; document why existing generic/zero-timestamp probes cannot establish correlation. See [UDP validation scope](docs/UDP_VALIDATION.md).
- Authenticated/encrypted SNMP and protocol-specific queries/reassembly remain outside the implemented UDP scope; completed validation/review tasks do not imply support for every variant.
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
