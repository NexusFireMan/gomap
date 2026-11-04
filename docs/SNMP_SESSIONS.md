# Authenticated SNMPv3 Sessions

`--snmp-config` enables a narrow, read-only SNMPv3 client on UDP/161. It uses
[GoSNMP v1.45.0](https://github.com/gosnmp/gosnmp/tree/v1.45.0), linked into the
GoMap binary, for USM authentication, key localization and privacy. No external
scanner or SNMP command is invoked. This dependency avoids a custom cryptographic
implementation; GoMap adds its own framing, scope, correlation and attempt checks.

## Credential File

Keep this file outside the repository, with owner-only permissions on Unix
(`0400` or `0600`). Windows requires a private ACL configured by the operator.
The following values are placeholders, not usable lab credentials:

```json
{
  "10.0.11.9": {
    "username": "READ_ONLY_USER",
    "auth_protocol": "sha256",
    "auth_password": "REPLACE_WITH_PRIVATE_AUTH_PASSPHRASE",
    "privacy_protocol": "aes128",
    "privacy_password": "REPLACE_WITH_PRIVATE_PRIVACY_PASSPHRASE"
  }
}
```

Keys must be literal, unzoned IP addresses in the expanded scan target scope.
IPv4-mapped aliases normalize to the same IP; duplicates are rejected. Entries
apply only to their exact destination; credentials are not tried against other
hosts. Unknown/duplicate fields, nulls, trailing input, empty objects and files
over 64 KiB are rejected. Each entry requires a 1-32-byte user, `sha256` or
`sha512`, and an 8-256-byte authentication passphrase. Privacy must explicitly
be `none` with no privacy passphrase, or `aes128` with an 8-256-byte passphrase.
MD5, SHA-1, DES and vendor cipher variants are not supported by this interface.

Symlinks and non-regular credential files are rejected. The file is validated
before output creation or discovery; an output path referring to the same inode
is rejected, including hardlinks. Do not place secrets in argv, Git, issues,
chat, public captures or CI artifacts. Values, usernames, engine identifiers and
low-level library errors are not copied into reports. In-process secret memory
and the library's key cache are not guaranteed to be erased before process exit.
SNMP USM user/engine metadata is visible on the wire even with encrypted PDUs.

## Session Bounds And Validation

Only explicit UDP scans can use this option. It enables service detection and
rejects controlled-profile/source-identity combinations. At most two datagrams
are sent on one connected UDP socket: initial engine discovery, then a GET for
`sysDescr.0`. Each write acquires the shared attempt limiter. Configured port
retries do not repeat credentials; automatic engine/time resynchronization,
walks and SET operations are not allowed. Each phase accepts at most one
datagram, capped at 2048 bytes. Socket deadlines and an overall context bound
the session (two configured timeouts, capped at 30 seconds per phase, plus two
configured global pacing intervals). Per-phase deadlines start after pacing;
contention on the shared limiter can also delay completion.

The initial unauthenticated engine report establishes session-local parameters,
not trusted identity. Authenticated responses must match the message/request
identifiers, configured user, pinned engine, engine-boots value and a 150-second
time window around the discovered clock. The requested security level cannot
be downgraded. GoSNMP verifies the digest and decrypts the payload; GoMap then
requires a successful GetResponse for the requested OID/context. The returned
value is not promoted to a product/version claim. An unverified received
datagram remains responsive, low-confidence evidence; timeout/refusal states
remain explicit when no datagram was received.

Successful confirmation is labeled `SNMPv3 (authenticated)` or
`SNMPv3 (authenticated, AES-128)`. This proves possession of the configured USM
key for this exchange, not a unique hardware identity or vendor/product version.
No authenticated engine state is persisted between scans.

## Tests And Remaining Scope

Loopback synthetic agents exercise SHA-256/SHA-512 with/without AES-128, changed
digests, wrong passwords/identifiers/OIDs, old/future engine clocks, changed
engines/boots and downgrade attempts. Pure fixtures exercise identifier encoding,
attempt limits, canceled contexts, bounded framing and secret-file validation.
Fuzz targets cover the credential decoder and frame parser. Tests do not contact
public targets or modify NICs.

## Independent-Agent Lab Validation

On October 16, 2026, the CLI passed against Net-SNMP 5.9.4
(`5.9.4+dfsg-2+deb13u1`) in a disposable Debian container with `--network none`,
read-only root filesystem, private temporary configuration and no published
ports. SHA-256/SHA-512 with both `none` and `aes128` privacy confirmed the four
valid profiles; four corresponding incorrect-passphrase cases stayed
unconfirmed. Reports did not disclose usernames, passphrases or returned values.
The container and temporary secret files were removed after the test.

Reproduce on a Linux host with Docker:

```bash
docker build -t gomap-snmp-agent:local scripts/lab/snmp
GOMAP_RUN_SNMP_AGENT_TESTS=1 GOMAP_SNMP_AGENT_IMAGE=gomap-snmp-agent:local \
  go test ./pkg/app -run '^TestSNMPAgentInterop$' -count=3 -v
```

Image building downloads Debian packages; the agent and scanned CLI then run
without an external network. Image/package revisions should be recorded when
comparing later runs. The validated local image ID was
`sha256:4d98f8bbb1d6230b6698463368c0207ae7dc964579f57985844ba4b35821e034`.
This confirms this agent/profile matrix, not universal interoperability.

## Unsupported Variants

Other USM algorithms/security models, non-default contexts, encrypted traps,
automatic resynchronization, application-level fragment reassembly and general
SNMP enumeration remain outside this deliberately bounded implementation.

References: [USM, RFC 3414](https://www.rfc-editor.org/rfc/rfc3414.html),
[SHA-2, RFC 7860](https://www.rfc-editor.org/rfc/rfc7860.html),
[AES privacy, RFC 3826](https://www.rfc-editor.org/rfc/rfc3826.html).
