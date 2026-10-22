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
| RDP | Complete 11/19-byte TPKT/X.224 confirmations, offered selections, failure responses, strict lengths/types, low-confidence X.224-only hints, no Microsoft/Windows attribution, checked I/O failures and an actual loopback TLS upgrade with unverified CN and one original deadline |
| HTTP/TLS | Small stream writes, metadata retention, malformed status lines, complete/unambiguous headers, body/header separation, framed/chunked titles and redirect non-following |
| LDAP/LDAPS | Complete definite-BER frames, non-minimal length forms up to four length octets, matching request IDs, BindResponse results/optional fields, malformed primitives, request echoes, size/count limits and a loopback TLS exchange |
| TDS 7.x PRELOGIN | Complete server reply packets, bounded multi-packet assembly, EOM/sequence/SPID checks, option-table framing/ranges, reflected request rejection, invalid values, fixed deadlines and loopback exchanges; validated sender-version/encryption disclosures without vendor/OS or active TLS claims |
| RESP2 INFO | Simple/error/integer/bulk/array framing, nulls, binary bulk bodies, byte/depth/node/element caps, complete version fields, request-before-response and incomplete/ambiguous payload rejection |
| IRC registration | Complete classic IRC lines, initial NOTICE plus later numerics, registration/error termination, matching version/evidence lines, line/count caps and incomplete trailing-line suppression |
| Generic write-first | Numeric multiline, SMTP EHLO, POP3 dot termination, tagged IMAP CAPABILITY, HTTP length/chunk/close framing and RTSP/SIP headers/bodies; fixed deadlines, short-write failures and buffered next-message preservation |
| Runtime confidence | Truncated SSH/mail/FTP and HTTP-like disclosures, malformed RESP/control bytes, complete earlier disclosures and opt-in raw evidence without manufacturing a version |
| TCP DNS version disclosure | Exact frame boundary; successful, non-truncated response; fixed ID and question/answer name/type/class correlation; one TXT value; malformed, ambiguous and control-containing replies rejected; no automatic BIND attribution |
| Candidate WSMan HTTP | Existing OPTIONS request over chunked loopback; every-split header assembly; complete headers, ambiguous Server suppression and body isolation; no authentication-token disclosure or WinRM confirmation from generic HTTP |

## Identification Confidence Review

This inventory covers current production routes through `grabBanner`,
`tryProtocolFingerprint`, UDP classification and opt-in UDP sessions. Confidence
applies to the stated observation, not automatically to a product, OS or owner.
High confidence never means that all variants or malformed inputs are certified.

| Route | Supported Observation And Confidence | Not Established |
| --- | --- | --- |
| MySQL initial packet | Complete bounded packet and declared version field; generic ERR rejection medium, absent/invalid greeting low | Full SQL session, authenticated vendor/build; control-containing version text rejected |
| SMB native | High for validated offered SMB2/3 dialect, matching zero message/session IDs and bounded security buffer | Highest supported dialect, Windows/Samba identity, authentication or signing enforcement |
| SMB text / TCP139 | Text mentions medium; unanswered NetBIOS session/port hint low | Native SMB negotiation or server OS |
| ONC RPC / NFS / mountd / lock manager / status / ACL | High for correlated accepted NULL program/version reply with no procedure-result body | Daemon build, exports, OS or working non-NULL operations |
| DCE/RPC | High for validated bind acknowledgment; accepted/rejected interface context retained | Windows identity; rejected context does not establish interface support |
| JRMP / AJP | High for acknowledged transport ping / CPONG | JVM, Tomcat or application version; no remote calls/deserialization |
| LDAP/LDAPS | Medium for correlated bounded anonymous BindResponse | Directory vendor/version or authenticated session |
| DNS version.bind / WSMan candidate / RDP / TDS | Scope and confidence described in the dedicated regressions below | Automatic BIND/WinRM/Microsoft/Windows attribution |
| TLS-only | High for transport; application port guess low | Certificate trust, host ownership or application identity |
| HTTP and text banners | Complete disclosed fields may be high; generic descriptions/titles medium; incomplete disclosure low | Independent product/OS verification; IIS versions no longer imply Windows releases |
| UDP shape/correlated discovery | Medium for bounded supported shapes and, when available, matching probe fields; unknown payload/port hint low | Server identity, replay resistance or actual closed state from silence |
| Authenticated SNMPv3 | High for the supported cryptographically validated response, identifiers/engine/time window and optional AES-128 | Product version or support for every SNMP algorithm/variant |
| Memcached UDP / NetBIOS datagrams | Medium for bounded correlated query/reassembly; incomplete/unmatched reply low | Cache contents, server identity or universal datagram interoperability |

MySQL rejection, text SMB, native SMB correlation/security ranges, RPC NULL
trailing results and IIS/Windows inference have dedicated negative fixtures in
`specialized_confidence_test.go`. Existing framing, transport, UDP and secure
session tests cover the other rows. Native SMB1 replies cannot satisfy this
SMB2-only request, though legacy pure text parsers remain available for fixtures.
SMB protocol details follow [Microsoft's negotiation example](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c9efe8ca-ff34-44d0-bfbe-58a9b9db50d4);
NULL procedure scope follows [RFC 5531](https://www.rfc-editor.org/rfc/rfc5531.html).

## Disclosure And Framing Regressions

The DNS/WSMan confidence review covers these two paths, not every specialized
fingerprint. `version.bind` is server-configurable text, and HTTPAPI/Negotiate do
not uniquely identify WinRM. The inventory above distinguishes the other current
paths; new probes must add their own review. The WSMan candidate probe sends the same OPTIONS request and
uses one existing deadline with a 4096-byte header cap and at most 34 lines;
collection stops at the header terminator without waiting for a body or close.
Complete Server headers remain usable even when the later body is incomplete. DNS reuses the
existing conservative DNS frame validator and `dnsmessage` decoder. Multiple
answers or TXT chunks are deliberately unsupported for this disclosure path.

```bash
go test -race ./pkg/scanner -run 'Test(DNSDisclosure|WSMan)' -count=20
go test ./pkg/scanner -run '^$' -fuzz '^FuzzProtocolDisclosures$' -fuzztime=15s -parallel=2
```

The RDP/TDS confidence review preserves existing requests, parser limits and
service aliases. RDP selection/failure responses carry medium confidence;
X.224-only confirmations carry low confidence. A failed TLS upgrade does not
erase earlier RDP protocol evidence, but cannot produce a certificate hostname.
The existing certificate probe does not validate trust or authenticate the host.
RDP TLS shares the negotiation's original deadline rather than renewing it.
TDS displays only the first four validated VERSION bytes (major/minor/build),
not a marketing release, TDS wire version or inferred Windows platform. Zero
sender versions are withheld; ENCRYPTION values are declared options, not a
completed TLS session. No TDS TLS/login/query traffic is added. Other optional
fields and padding are not copied into evidence. These are bounded subsets,
not a review of all RDP/TDS sessions or a substitute for other paths' fixtures.

```bash
go test -race ./pkg/scanner -run 'Test(RDP|TDS)' -count=20
go test ./pkg/scanner -run '^$' -fuzz '^FuzzNegotiationDisclosures$' -fuzztime=15s -parallel=2
```

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
timeout and remain available as evidence. Greeting-only reads are distinct from
the protocol-specific write-first transaction readers below. The generic
FTP-lines path has a strict 4096-byte capture bound.

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

LDAP no longer identifies a reply from text or a tag at a fixed offset. The
reader collects at most 4096 bytes under one existing probe deadline. It checks
the sent message ID (currently 1), result fields, UTF-8 string encodings and
bounded optional referral/SASL/control structure. Referrals are not followed;
diagnostics, names, credentials and control values are not exposed. An error
result can confirm the protocol without implying a successful bind. Length
normalization is local to each element; Go's ASN.1 parser validates primitives.

TDS accepts the initial PRELOGIN server-response shape, not a reflected request
or an arbitrary packet of the same type. Limits are 4096 assembled payload
bytes and 32 packets with one fixed probe deadline. Checked ranges cannot
overlap each other or the option table. The existing request is unchanged; no
login, TLS negotiation or SQL statement follows. Option payloads are not
promoted to product-version or server-identity claims.

Existing INFO and IRC registration requests now precede response reads; their
payloads, number of probes and configured timeouts are unchanged. RESP2 values
use a 64 KiB wire-byte cap, eight nested levels, 64 array entries and 128 total
nodes. Complete INFO bulk bodies, including versions after the first line, are
parsed without treating embedded data as a separate greeting. Raw unframed
Redis text is not sufficient runtime product evidence. Default reports expose
only the selected version, not the full INFO body.

IRC collection stops at MYINFO/ISUPPORT, a registration error or ERROR, with
512 bytes per classic line, 32 lines and 4096 total bytes. It sends no PONG,
VERSION, WHO, authentication or other follow-up command. A blocked registration
can still time out; only already complete disclosures may then be used.

Generic write-first collection recognizes the response framing used by existing
probes: numeric multiline replies, EHLO replies, POP3 CAPA's terminal dot, IMAP's
matching a001 completion, and HTTP-like headers/bodies. Generic text has a
4096-byte/32-line cap; HTTP GET/HEAD uses 64 KiB, with 64 chunks and 32 trailers.
Known terminal replies return without waiting for connection closure. Next
messages remain in the supplied buffered reader; probe connections are single
use and closed afterward. Close-delimited HTTP bodies still require EOF or the
existing deadline. No redirect is followed.

Runtime observation checks are separate from pure fixture parsers. A missing
line/multiline/frame terminator prevents promotion of that disclosure's version,
even if a regex could recognize its prefix. Raw partial bytes remain available
to the existing evidence/capture paths, but their presence is not a confirmed
version. Complete earlier lines/headers remain independently useful. Unsupported
binary/control-containing text is not sanitized into a stronger text identity.
These rules do not certify every grammar or authenticate disclosures.

## Run Locally

```bash
make ci
go test -race ./pkg/scanner -run 'Test(FramedReaders|RPCRecord|AJPReply|TextGreeting|RDPStream|SMBAndAJPStream|HTTPAndTLS|FragmentedMail|OversizedGreeting)' -count=10
go test ./pkg/scanner -run '^$' -fuzz '^FuzzBoundedStreamFraming$' -fuzztime=15s -parallel=2
go test ./pkg/scanner -run '^$' -fuzz '^FuzzHandshakeFragmentation$' -fuzztime=15s -parallel=2
go test ./pkg/scanner -run '^$' -fuzz '^FuzzHTTPHeaderBoundaries$' -fuzztime=15s -parallel=2
go test -race ./pkg/scanner -run 'Test(LDAP|TDS)' -count=10
go test ./pkg/scanner -run '^$' -fuzz '^FuzzLDAPBindFraming$' -fuzztime=15s -parallel=2
go test ./pkg/scanner -run '^$' -fuzz '^FuzzTDSPreloginFraming$' -fuzztime=15s -parallel=2
go test -race ./pkg/scanner -run 'Test(TextTransactions|RESP|Transaction|CloseDelimited|WriteFirstText|GenericProbeKeeps|ObservedBanner|RedisBulk|IRCAndRESP)' -count=20
go test ./pkg/scanner -run '^$' -fuzz '^FuzzTextTransactionFragmentation$' -fuzztime=15s -parallel=2
go test ./pkg/scanner -run '^$' -fuzz '^FuzzObservedBannerConfidence$' -fuzztime=15s -parallel=2
```

The fuzz targets compare complete/fragmented reader outcomes, input ownership,
allocation bounds and header-validity invariants. Re-run them after extending
protocol parsing; update this matrix with new negative cases and limits.

## Remaining Review

- LDAP review covers the existing anonymous bind, not StartTLS, searches,
  authenticated/SASL sessions or all extension schemas. Counts of controls and
  referral entries are capped at 32. Unknown extra fields, indefinite lengths,
  high-tag-number forms and lengths using more than four octets are rejected.
  Static message-ID matching is not replay protection or server authentication.
- TDS review covers initial option-table PRELOGIN replies with known options
  0-7, VERSION first and VERSION/ENCRYPTION present. It does not cover login/error
  token streams, TDS 8 TLS-first sessions, legacy 4.2 or unknown future options.
  Packet numbering and fixed-connection context are structural checks, not a
  cryptographic response identifier or authentication.
- RESP framing covers RESP2 used by INFO, not HELLO/RESP3, streaming aggregates,
  subscriptions or authenticated sessions. A generic RESP value alone does not
  identify a Redis product/version.
- IRC framing covers the existing registration exchange, not a full client,
  IRCv3 capability/tag negotiation or all server-specific numeric sequences.
- Generic readers cover the listed probe transactions, not arbitrary binary
  protocols, general IMAP literals, every HTTP extension or pipelined sessions.
- These tests do not certify all server implementations, hostile timing/loss,
  or all TLS/protocol variants. Live lab validation remains opt-in.

## References

- [RDP server confirmation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/13757f8f-66db-4273-9d2c-385c33b1e483)
- [RDP negotiation failures](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/1b3920e7-0116-4345-bc45-f2c4ad012761)
- [Go HTTP response reader](https://pkg.go.dev/net/http#ReadResponse)
- [LDAP protocol and encoding](https://www.rfc-editor.org/rfc/rfc4511.html)
- [TDS PRELOGIN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/60f56408-0188-4cd5-8b90-25c6f2423868)
- [TDS packet sequencing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/3420734b-287b-4cde-a0dd-538c770a89a1)
- [RESP wire format](https://redis.io/docs/latest/develop/reference/protocol-spec/)
- [IRC client protocol](https://www.rfc-editor.org/rfc/rfc2812.html)
