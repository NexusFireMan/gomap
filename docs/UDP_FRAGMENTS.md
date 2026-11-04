# UDP Fragment Handling

## Two Different Layers

An IP fragment is not an application fragment. GoMap receives UDP through
connected Go sockets: the operating system reconstructs IPv4/IPv6 packets
before returning a UDP payload. Application fragmentation, such as Memcached
or NetBIOS Datagram Service, requires separate state in GoMap.

Normal scans do not open a raw IP receiver, replace the kernel IP stack, add
privilege requirements or invoke another scanner. The existing per-protocol
size limits still apply after kernel reassembly. Packet capture, offline PCAP
processing, jumbograms and a user-space raw-IP engine are not added.

## NetBIOS UDP/138

`-u -Dv` (also implied by `-De`) on port 138 sends one read-only, unicast
Datagram Query Request for an unscoped wildcard name. It encodes the connected
socket's actual IPv4 address/port and a cryptographically generated 16-bit ID.
There is no source spoofing, broadcast, registration, name release, forwarding,
SMB operation, retry or follow-up to a positive query response. This query is
for an NBDD relay; ordinary hosts may ignore it. Silence is `open|filtered`,
not evidence that the service is closed or absent. IPv6 is not an NBT endpoint
format; the query path reports it as unavailable without sending a query.
Default, detection-disabled and controlled-profile scans are unchanged.

The connected socket restricts the peer. Received header source address/port
must also agree with that endpoint. Positive/negative query responses must
match the sent ID and full encoded destination name, have valid flags/name
framing and contain no trailing bytes. Error codes 0x82-0x84 require a matching
ID and exact error framing; these are application errors, not closed ports.

Data datagrams (direct unique/group or broadcast types) have their own IDs;
they are not responses to the query. The assembler pins type, node type, ID,
source address/port and total length. Its result is structural evidence only,
explicitly labelled `request not correlated; not authenticated`. It never
infers a Windows/Samba release or treats a syntactically valid header as
authenticated identity.

The supported layout follows RFC 1002's single-datagram or two-packet split:
names occur in the first packet; the second contains the remaining data.
Fragments may arrive in either order. Identical duplicates do not add state;
conflicting duplicates, tuple/length changes, incompatible offsets, malformed
names, empty/truncated messages or expiry abort identification. For the
two-part layout, the second offset may encode consumed length or the remaining
length described in the RFC's transmission pseudocode; the complete lengths
must agree before concatenation. No speculative gap filling is performed.

Bounds are 2048 bytes per received datagram, 4096 reassembled body bytes,
two fragment slots and 32 reads. A single configured deadline is capped at
two seconds, never extended by duplicates. State is local to one connection
and discarded on return. Names use uncompressed NetBIOS first-level encoding
and bounded DNS-style scope labels; compressed names and other fragment layouts
remain unconfirmed. Names, MACs, IDs and reconstructed payloads never enter
identification metadata. Evidence reports only protocol labels and counts.
Incomplete/malformed responses retain observed responsiveness at low confidence.

## Validation

Normal tests cover encoding, malformed names/headers, ordering, duplicate
ownership/conflicts, tuple/length changes, expiry, read limits, final-read data,
control correlation and metadata disclosure. Loopback exchanges exercise
complete, incomplete, malformed, silent and negative-query cases end to end.
Fuzzing checks assembly/input-ownership/memory invariants. These fixtures are
not interoperability certification against every NetBIOS server.

`TestIsolatedUDPIPFragments` requires an opt-in, disconnected Linux namespace
with loopback as its only interface. Its fixture sends actual raw IPv4/IPv6
fragments to an owned local UDP socket. It exercises the production socket
reader and DNS classifier, verifying intact ordered/reversed reconstruction
and matched query fields; missing fragments, mixed IDs and invalid UDP
checksums must not produce an application response. Only the test injector
needs raw-socket privileges inside that namespace. See CONTRIBUTING.md for
reproduction. Other OS kernels, firewall/loss conditions, extension-header
combinations and overlap policies are not certified by these tests.

On October 16, 2026, `make ci` passed with 62.7% total coverage, the NetBIOS
fixtures passed three repeated runs, and the assembly fuzz target completed
100,064 executions without failure. The IPv4/IPv6 namespace matrix passed
three runs with the race detector (36 cases). A Windows amd64 cross-build
also succeeded, and `govulncheck` reported no known vulnerabilities.
Two authorized Windows/Linux lab VMs stayed silent on the datagram query;
both correctly remained `open|filtered`. That smoke check does not establish
live NetBIOS datagram interoperability. No VM/NIC configuration was changed.

## References

- [NetBIOS Datagram Service format and reception, RFC 1002](https://www.rfc-editor.org/rfc/rfc1002.html#section-4.4)
- [IPv4 fragmentation/reassembly, RFC 791](https://www.rfc-editor.org/rfc/rfc791.html#section-3.2)
- [IPv6 Fragment Header, RFC 8200](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5)
