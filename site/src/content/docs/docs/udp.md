---
title: UDP and SNMP
description: Bounded native UDP queries, authenticated SNMP sessions and protocol-specific fragment handling.
---

UDP requires careful interpretation of silence. A positive correlated response,
a supported port-unreachable indication and no response are different outcomes.
Use explicit states rather than assuming every reported row is confirmed open.

## Bounded queries

The deeper UDP modes include optional correlated SNMP, NetBIOS and Memcached
queries. Identifiers and framing are checked against the sent requests;
arbitrary response bytes are not promoted into product versions.

```bash
gomap -u -Dv -p 137,138,161 10.0.11.6
```

This private-IP command is illustrative. Choose only protocols and targets
included in your authorization.

## Authenticated SNMP

Private per-IP `--snmp-config` files support the documented SNMPv3 authNoPriv
and authPriv subset, including SHA-256/SHA-512 and optional AES-128. Treat these
files as credentials: restrict access and never commit them, their secrets or
private agent state.

See [SNMP sessions](https://github.com/NexusFireMan/gomap/blob/main/docs/SNMP_SESSIONS.md)
for the exact configuration, supported combinations and limitations.

## Fragment handling

Memcached and NetBIOS application fragments have bounded protocol-specific
assembly, expiry and consistency checks. IPv4/IPv6 packet reassembly is delegated
to the OS socket stack, not a second raw-IP engine inside normal UDP scans.

These are documented subsets, not support for every security mode, cipher or
datagram variant. Isolated Linux tests and fixtures do not establish universal
interoperability or behavior on every network and OS.

- [UDP validation scope](https://github.com/NexusFireMan/gomap/blob/main/docs/UDP_VALIDATION.md)
- [Fragment handling and isolated tests](https://github.com/NexusFireMan/gomap/blob/main/docs/UDP_FRAGMENTS.md)
