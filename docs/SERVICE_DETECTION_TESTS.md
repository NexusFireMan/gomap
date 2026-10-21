# Service Detection Regression Matrix

This is a maintained baseline, not a claim that every protocol variant has been
implemented or certified. Default tests use synthetic bytes, standard readers
and owned loopback endpoints; no public targets, VM credentials or external
scanners are required. IP/application UDP fragments are covered separately in
[UDP fragment handling](UDP_FRAGMENTS.md).

## Covered Paths

| Path | Regression Coverage |
| --- | --- |
| DNS/TCP and MySQL | Every byte split, one-byte/partial reads, final bytes alongside EOF, truncation/timeouts, frame-size limits and unconsumed next-frame data |
| ONC RPC record marking | Multi-fragment reconstruction, 64-fragment/4096-byte limits, zero-size continuations, cumulative overflow and malformed/truncated records |
| SMB | Bounded session frames and dialect negotiation over loopback; malformed session headers, failed status, partial frames and next-frame boundaries |
| AJP | CPING/CPONG only; fragmented replies, wrong magic/length/type, final EOF and rejection of invalid headers before body reads |
| DCE/RPC | Split/padded bind acknowledgments, accepted/rejected contexts, secondary-address suppression, truncation/deadline errors and next-frame preservation |
| JRMP | Split stream negotiation and PingAck, endpoint-length limits, incomplete/error replies, final EOF and exact bounded request bytes; no remote calls/deserialization |
| Text greetings | Passive/connected SSH, FTP, SMTP, POP3 and IMAP fixtures; first-line and numeric multiline assembly, fixed caller deadline, 4096-byte cap and final partial-byte retention |
| FTP and mail conversations | Existing command sequences over chunked loopback connections, SMTP/POP3/IMAP TLS paths, complete numeric multiline replies and stopping on incomplete greetings |
| RDP | Complete 11/19-byte TPKT/X.224 confirmations, offered selections, failure responses, strict lengths/types and an actual loopback TLS upgrade/certificate CN |
| HTTP/TLS | Small stream writes, metadata retention, malformed status lines, complete/unambiguous headers, body/header separation, framed/chunked titles and redirect non-following |

The stream fixtures deliberately split writes/reads without sleeps. TCP is free
to coalesce writes; deterministic one-byte/every-split readers separately prove
chunk-boundary invariance. TLS test keys are generated in memory, and assertions
do not depend on certificate timestamps or cipher choices.

## Corrections Driven By Tests

The new tests first reproduced a passive greeting reduced to its first byte,
malformed/unframed RDP negotiation acceptance, and product inference from
truncated/contradictory HTTP headers or HTML titles placed in headers.

Greeting collection now completes one line or a matching numeric multiline
reply without renewing the caller's deadline per fragment. Complete replies
return immediately; partial replies may use the remainder of the existing
timeout and remain available as evidence. This is not full RESP, IRC, POP3
capability-list or IMAP transaction reassembly. The generic FTP-lines path has
a strict 4096-byte capture bound.

RDP confirms only the class-0 server confirmation and the supported selections
offered by the existing probe (standard RDP, TLS, CredSSP). A failure code is
not a successful selection or an OS/version fingerprint. The previous test
fixture that combined selected-protocol values has been corrected to one
selected protocol.

HTTP status-line recognition remains available as a generic hint when headers
are incomplete. Product disclosure requires successfully parsed headers with
at most one Server field. Body truncation does not invalidate a complete Server
header, but cannot manufacture a title hint. Titles are content, not confirmed
server implementation evidence. Parsing uses Go's HTTP reader, not a new
hand-written HTTP grammar. Existing probe definitions and configured deadlines
are unchanged; rejecting weak versions may invoke existing fallback paths.

## Run Locally

```bash
make ci
go test -race ./pkg/scanner -run 'Test(FramedReaders|RPCRecord|AJPReply|TextGreeting|RDPStream|SMBAndAJPStream|HTTPAndTLS|FragmentedMail|OversizedGreeting)' -count=10
go test ./pkg/scanner -run '^$' -fuzz '^FuzzBoundedStreamFraming$' -fuzztime=15s -parallel=2
go test ./pkg/scanner -run '^$' -fuzz '^FuzzHandshakeFragmentation$' -fuzztime=15s -parallel=2
go test ./pkg/scanner -run '^$' -fuzz '^FuzzHTTPHeaderBoundaries$' -fuzztime=15s -parallel=2
```

The fuzz targets compare complete/fragmented reader outcomes, input ownership,
allocation bounds and header-validity invariants. Re-run them after extending
protocol parsing; update this matrix with new negative cases and limits.

## Remaining Review

- LDAP and TDS still need equivalent bounded framing/correlation review.
- RESP/IRC/generic write-first probes need protocol-specific transaction
  termination, not a generic greeting reader substituted for binary/bulk data.
- Retaining partial text bytes does not establish a complete product/version;
  truncated-text confidence policies need their own protocol-specific review.
- These tests do not certify all server implementations, hostile timing/loss,
  or all TLS/protocol variants. Live lab validation remains opt-in.

## References

- [RDP server confirmation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/13757f8f-66db-4273-9d2c-385c33b1e483)
- [RDP negotiation failures](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/1b3920e7-0116-4345-bc45-f2c4ad012761)
- [Go HTTP response reader](https://pkg.go.dev/net/http#ReadResponse)
