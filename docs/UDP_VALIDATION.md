# UDP Response Validation

This document records the supported parsing/correlation scope and the review
of unsupported variants. A received datagram establishes responsiveness, not
authenticated identity or complete discovery. Default structural checks add no
queries, multicast listeners, credentials or external scanner dependencies.
The optional framed UDP/11211 path below performs its own bounded exchange.

## Query Matching

The scan passes the actual sent probe to the response classifier. A structurally
valid reply with mismatched fields remains a responsive port, but its service
version is cleared and identification confidence is low. Matching fields retain
medium confidence; current identifiers are fixed and do not prevent replay.

| Current Probe | Checked Fields | Limits |
| --- | --- | --- |
| DNS | Transaction ID, opcode, echoed question name/type/class | Case-insensitive name comparison; no authentication |
| SNMPv1 | Version, community, request ID, binding OIDs/count/order | Community never appears in output; tooBig may omit bindings |
| NTP | No reliable correlation available | Existing client packet has a zero transmit timestamp |
| SSDP | No unique transaction identifier available | Header shape only; LOCATION is never fetched |
| NetBIOS/mDNS/LLMNR | No valid query to correlate | Existing generic one-byte probe remains unchanged |

The pure SNMP matcher also handles matching v2c query/response fixtures, but the
scanner currently sends only its existing v1 query. A v2c/v3 reply cannot be
presented as matching that v1 query. A schema-valid reply observed without query
context remains structural evidence only.

## Memcached Query And Reassembly

`-u -Dv`/`-De` on UDP/11211 sends one framed stats request with a fresh 16-bit
identifier. A connected socket restricts the peer; matching headers contribute
to a session-local assembly. This is correlation, not authentication. Default
and controlled-profile scans keep their existing behavior.

The implementation bounds datagrams to 2048 bytes, assemblies to 16 fragments
and 16 KiB, and processing to 32 reads. One fixed deadline covers the response,
capped at five seconds; fragments and duplicates never renew it. Sequence slots
may arrive out of order; identical duplicates do not consume additional payload
memory. Conflicting duplicates, inconsistent totals, invalid reserved fields and
oversize/expired messages abort identification. Unknown request IDs contribute
no payload. The state exists only for one query and is discarded afterward.

Complete stats framing is required. Returned values are excluded from metadata;
only a bounded, validated version field may identify the product version.
Evidence includes actual fragment/byte counts. Missing or malformed fragments
do not erase an observed responsive port or invent a product identification.
No SET, flush, cache-key enumeration or item retrieval is implemented.

On October 16, 2026, an isolated Memcached 1.6.45 container returned two fragments
and 2238 payload bytes. The opt-in CLI test verified the reassembled version and
confirmed that the default path remained unconfirmed. See CONTRIBUTING.md for
reproduction; record the image digest when comparing later runs. This validates
Memcached application fragments, not generic IP or NetBIOS datagram reassembly.
The wire format follows the [upstream protocol](https://github.com/memcached/memcached/blob/master/doc/protocol.txt).

## Variant Review

| Variant | Policy | Reason |
| --- | --- | --- |
| SNMP definite BER with non-minimal lengths | Supported with bounded normalization | Framing normalized; standard ASN.1 decoding still validates values |
| SNMP indefinite lengths / constructed simple values | Rejected | Prohibited by the SNMP BER restrictions |
| BER high-tag-number forms, length fields over four octets, nesting over 16 levels | Low-confidence fallback | Outside the bounded implemented subset |
| SNMPv1/v2c Response-PDU | Structural validation; query fields checked when a compatible query exists | Not authenticated identity |
| SNMPv3 plaintext USM noAuthNoPriv Response/Report, zero flags | Structural validation only, explicitly unauthenticated | No matching v3 request is sent |
| SNMPv3 authNoPriv/authPriv, ciphertext, other security models | Low-confidence fallback | No credentials, cryptographic verification or decryption is implemented |
| Traps, informs, other SNMP PDUs | Low-confidence fallback | Not replies to the existing query |
| NetBIOS NB/NBSTAT positive replies | Bounded structural validation | No valid NetBIOS query is currently sent |
| NetBIOS negative name-query replies, codes 1/2/3/5 | Bounded structural validation, medium confidence | Encoded name and empty NULL record required; no query correlation or server identity |
| NetBIOS redirects with encoded NS target and matching A owner | Bounded structural validation, medium confidence | Exact decoded-name match, RFC flags/counts and IN class; never followed, targets not disclosed, no query correlation |
| Other NetBIOS errors/redirect forms, WACK, registration/release replies | Low-confidence fallback | Outside the implemented name-query/status/redirect response subset |
| UDP/138 datagrams, fragmented NetBIOS messages | Low-confidence fallback | No datagram decoder or reassembly is implemented |

Existing single-datagram validators use the 2048-byte bound. A fallback never
promotes raw response values, usernames, engine identifiers, communities,
hostnames, workgroups or MAC addresses into identification metadata. Redirects
are not followed. Completing this review does **not** mean every variant is
implemented; authenticated SNMP and other protocol-specific queries/reassembly
require separately scoped changes.

## Deterministic Validation

Unit fixtures cover matching and mismatched IDs, questions, communities and
OIDs; BER normalization and depth/length limits; unsupported security models;
NetBIOS response variants; disabled detection; and disclosure prevention.
Negative NBNS fixtures cover both the zero-answer-counter layout shown with a
NULL record in RFC 1002 section 4.2.14 and a count-one layout. Validation uses
a private counter-normalized copy only for the zero-counter form and rejects
header-only errors, incorrect flags/classes/TTL, unsupported codes, truncated
records and trailing data. Input bytes are unchanged. Errors describe the
name-service reply, not a closed port, vendor version or authenticated host.
Dedicated fuzz targets exercise query matching and BER framing. Tests use no
live targets or private captures. Run `make ci` before merging.

## References

- [SNMP BER restrictions, RFC 3417 section 8](https://www.rfc-editor.org/rfc/rfc3417.html#section-8)
- [SNMPv3 message format, RFC 3412](https://www.rfc-editor.org/rfc/rfc3412.html)
- [SNMP USM, RFC 3414](https://www.rfc-editor.org/rfc/rfc3414.html)
- [NetBIOS packet formats, RFC 1002](https://www.rfc-editor.org/rfc/rfc1002.html)
- [NTP timestamp fields, RFC 5905](https://www.rfc-editor.org/rfc/rfc5905.html)
