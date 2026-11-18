<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# PROXY protocol — HAProxy, "The PROXY protocol", versions 1 and 2

Details of the rows of the [RFC compliance summary](../rfc-compliance.md) for this document. Each section gives the requirement, how Kuicksilver meets it (with the files), the tests that pin it, its history, notes on peers and the open items. Status: ✅ met · 🔶 feature subset or accepted deviation · ⬜ planned · ❌ not planned; "since" is the release from which the current behaviour holds (history below and in [CHANGELOG.md](../../../CHANGELOG.md)).

The text is HAProxy's `doc/proxy-protocol.txt` ("The PROXY protocol, Versions 1 & 2", the 2020 revision), not an RFC;
its MUST and SHOULD statements are treated as an RFC's. No copy of it is in the repository or in the peer clones, and
the quotes below are from memory of that text: the section numbers in particular may be off by one. Kuicksilver is a
receiver only (the Ktor server engine's TCP connectors); it never sends the header. Decisions:
[ADR-0020](../../adr/0020-proxy-protocol.md).

Scope list (receiver): v1 grammar and length (§2.1); v2 signature, version, command, family, length, address blocks
(§2.2); TLVs and their checks: ALPN, AUTHORITY, CRC32C, NOOP, UNIQUE_ID, SSL with sub-TLVs, NETNS, reserved ranges
(§2.2.1–§2.2.8); detection of the version (§2.3); access filtering and "no guessing" (the receiver rules of §2 and the
security considerations). Out of scope: the
sender side; UDP (QUIC/HTTP/3), where the protocol has no defined place before a QUIC packet (the spec's DGRAM
transport describes the original flow, not a header on a datagram).

## <a id="header-v1"></a>Version 1: the human-readable header

Status: ✅ since 0.3.0 (experimental) · [summary](../rfc-compliance.md#http)

**Requirement.**

- The line is `PROXY`, a single space, `TCP4`, `TCP6` or `UNKNOWN`, then for TCP4/TCP6 a single space and the source
  address, destination address, source port and destination port separated by single spaces, ended by CRLF; "the
  receiver must ... a 108-byte buffer is always enough", the line is at most 107 bytes with its CRLF, and "If the
  receiver doesn't find the CRLF sequence within the first 107 characters, it must declare the line invalid".
- Addresses: TCP4 in dotted-decimal, TCP6 in the RFC 4291 text form; ports decimal 0..65535.
- `UNKNOWN`: "the receiver must ignore anything presented before the CRLF is found" and use the real connection's
  addresses.
- "The receiver may be tolerant to partial headers or may simply drop the connection when receiving a partial header.
  Recommendation is to be tolerant".
- Any byte sequence that does not exactly match "must be discarded and cause the receiver to abort the connection".

**How it is met.** `kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/ProxyProtocolCodec.kt`:
`frame` looks at each byte once as it arrives (the `PROXY ` prefix, the first LF only after a CR, no CRLF
within 107 bytes refused at the 107th byte); `decode` checks the whole line again: `UNKNOWN` followed by CRLF or a space
(anything after it ignored), else `TCP4 `/`TCP6 ` and exactly four fields. IPv4: four decimal numbers 0..255 without
leading zeros (glibc's `inet_pton`, which nghttpx relies on, refuses them too, from memory); IPv6: RFC 4291 text without
brackets or a zone ID, a dotted IPv4 tail allowed (an IPv4-mapped address); ports without leading zeros, as nghttpx's
`parse_proxy_line_port` (`refs/peers/nghttp2/src/shrpx_client_handler.cc:1228-1253`). Addresses are reported in
canonical text (RFC 5952; `ipLiteralOf`). `readProxyHeader` takes a header split over any number of reads and never
reads past its CRLF. A malformed line closes the connection with a reset.

**Tests.** `ProxyProtocolCodecTest.v1Tcp4`, `.v1Tcp6IsReportedInCanonicalText`, `.v1UnknownIgnoresWhatFollows`,
`.v1LongestLineIsTaken`, `.negative_v1WithoutCrlfWithin107BytesIsRefused`, `.negative_v1LineEndsOtherThanCrlfAreRefused`,
`.negative_v1MalformedFieldsAreRefused`, `.negative_readerRefusesAV1LineWithoutCrlfWithoutWaitingForMore`,
`.readerTakesAHeaderSplitIntoSingleBytesAndLeavesWhatFollows`, `ServerProxyProtocolTest.v1OriginIsTheClientAndLocalStaysTheProxy`,
`.negative_malformedHeadersAreClosed`; fuzzing: `ProxyHeaderFuzzTest.proxyHeader`.

**Notes on peers.** nghttpx (`shrpx_client_handler.cc:1288-1483`) looks for LF or NUL within the first 107 bytes of
what it peeked, refuses a NUL there and a line whose LF is not after CR, accepts `PROXY UNKNOWN` with anything after it
(its test `TestH2H1ProxyProtocolV1JustUnknown`, `integration-tests/nghttpx_http2_test.go:1549`), parses addresses with
`inet_pton` and ports without leading zeros; it takes the header only when it is whole in one read (it peeks the socket
first, `shrpx_client_handler.cc:196-224`). Kuicksilver accepts a header split over reads, the spec's recommendation, and
a NUL after `UNKNOWN`, which the spec says to ignore.

## <a id="header-v2"></a>Version 2: the binary header

Status: ✅ since 0.3.0 (experimental) · [summary](../rfc-compliance.md#http)

**Requirement.**

- The 12-byte signature `\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A`; the 13th byte's high nibble is the version,
  "\x2 : this is version 2 of the protocol. Only this value is valid" and "Receivers must only accept this value for this
  field"; its low nibble the command, LOCAL (0) or PROXY (1): "Other values are unassigned and MUST NOT be emitted by
  senders. Receivers MUST drop connections presenting unexpected values here".
- The 14th byte: family (UNSPEC, INET, INET6, UNIX) and transport (UNSPEC, STREAM, DGRAM); "Other values are unspecified
  and must not be emitted in version 2 of this protocol and must be rejected as invalid by receivers".
- The 15th and 16th bytes: the length of what follows, in network order; the address block is 12 (INET), 36 (INET6) or
  216 (UNIX) bytes, and the length must be at least that.
- LOCAL: "the receiver must accept this connection as valid and must use the real connection endpoints and discard the
  protocol block including the family which is ignored". UNSPEC: the receiver must ignore the address information.
- Detection (§2.3): a receiver may take both versions on one port, telling them apart by the first bytes.

**How it is met.** `ProxyProtocolCodec.frame` checks the signature byte by byte, then the version and command (only 0x20
and 0x21), the family byte (only 0x00, 0x11, 0x12, 0x21, 0x22, 0x31, 0x32), and from the 16 fixed bytes the total length
against `maxHeaderSize` (`ProxyProtocolConfig.Builder.maxHeaderSize`, 4096 by default, 232..65551) before the body is
read, so a 65,535-byte length costs nothing; `readProxyHeader` then reads exactly that many bytes. `decode` refuses a
block shorter than its family's addresses (also for LOCAL, as nghttpx does), returns LOCAL and PROXY/UNSPEC headers
without addresses (the connection's own apply), and reads INET, INET6 and UNIX addresses (a UNIX path up to its first
NUL, an abstract one as `@name`). A DGRAM transport is accepted as the spec defines it; the addresses are reported as
for STREAM. The first byte tells the versions apart (`P` or CR); any other first byte closes the connection.

**Tests.** `ProxyProtocolCodecTest.v2ProxyInet`, `.v2ProxyInet6AndDgram`, `.v2ProxyUnixPaths`,
`.v2LocalAndUnspecKeepTheRealAddresses`, `.negative_v2BadVersionCommandOrFamilyIsRefused`,
`.negative_v2AddressBlockShorterThanItsFamilyIsRefused`, `.negative_v2HugeLengthIsRefusedFromTheFixedPartAlone`,
`.negative_readerRefusesAHugeV2LengthWithoutWaitingForTheBody`, `.readerLeavesBytesThatCameInTheSameWrite`,
`ServerProxyProtocolTest.v2HeaderSentApartFromItsRequest`, `.localCommandKeepsTheConnectionsOwnAddresses`.

**Notes on peers.** nghttpx (`shrpx_client_handler.cc:1485-1600`) checks the version nibble, refuses commands other than
LOCAL and PROXY and family bytes other than the seven defined, refuses blocks shorter than the family's addresses
whatever the command, ignores UNSPEC and UNIX addresses, and needs the whole header in its first read (it refuses a
"prematurely truncated header block", line 1524). It does not parse TLVs. Netty's `HAProxyMessageDecoder` (not in the
local Gradle caches or the peer clones; from memory) bounds v2 headers by a configurable maximum as well.

## <a id="tlvs"></a>Version 2 TLVs and the CRC32c

Status: ✅ since 0.3.0 (experimental) · [summary](../rfc-compliance.md#http)

**Requirement.**

- After the addresses, type-length-value fields: a type byte, a 16-bit length, the value; they fill the rest of the
  block.
- `PP2_TYPE_CRC32C` (0x03): "When the checksum is supported by the receiver, the receiver MUST: Store the received
  CRC32c checksum value aside. Replace the 32 bits of the checksum field in the received PROXY header with all '0's and
  calculate a CRC32c checksum value of the whole PROXY header. Verify that the calculated CRC32c checksum is the same as
  the received CRC32c checksum. If it is not, the receiver MUST treat the TCP connection providing the header as
  invalid."
- `PP2_TYPE_NOOP` (0x04): to be ignored. `PP2_TYPE_UNIQUE_ID` (0x05): an opaque byte sequence "of up to 128 bytes".
  `PP2_TYPE_SSL` (0x20): `client` (1 byte), `verify` (4 bytes), then sub-TLVs (`PP2_SUBTYPE_SSL_VERSION` 0x21, `_CN`
  0x22, `_CIPHER` 0x23, `_SIG_ALG` 0x24, `_KEY_ALG` 0x25). `PP2_TYPE_ALPN` (0x01), `PP2_TYPE_AUTHORITY` (0x02, UTF-8),
  `PP2_TYPE_NETNS` (0x30). Types 0xE0..0xEF custom, 0xF0..0xF7 experimental, 0xF8..0xFF future: unknown types are
  skipped.

**How it is met.** `ProxyProtocolCodec.tlvs` parses the TLVs of a PROXY header with an INET, INET6 or UNIX family: a
TLV whose header is cut or whose length passes the block's end closes the connection; a CRC32C TLV must be 4 bytes and
appear once (a second one would leave undefined which field was zeroed), and is checked as quoted (CRC32c, the
Castagnoli polynomial, RFC 3720 appendix B.4 vectors; the value in network order, from memory of HAProxy's
`make_proxy_line_v2`); a unique ID over 128 bytes, and an SSL TLV shorter than its 5 fixed bytes or whose sub-TLVs do
not fill it exactly, close the connection; NOOP is dropped; every other TLV, known or not, is kept for the application
(`ProxyHeader.tlvs`, `alpn`, `authority`, `uniqueId`, `netns`, `ssl`). The TLVs of LOCAL and PROXY/UNSPEC headers are
not read: the spec discards those blocks (HAProxy, from memory, reads TLVs only after INET and INET6 addresses), so a
checksum there is not verified either.

**Tests.** `ProxyProtocolCodecTest.v2Tlvs`, `.crc32cVector`, `.v2CrcThatMatchesIsTaken`, `.negative_v2CrcMismatchIsRefused`,
`.negative_v2CrcTlvOfAnotherLengthOrTwiceIsRefused`, `.negative_v2TlvOverrunningTheHeaderIsRefused`,
`ServerProxyProtocolTest.tlsConnectorReadsTheHeaderBeforeTheClientHello` (a header with a CRC32c).

## <a id="receiver"></a>The receiver: access filtering, no guessing, the header first

Status: ✅ since 0.3.0 (experimental) · [summary](../rfc-compliance.md#http)

**Requirement.**

- "The receiver MUST be configured to only receive the protocol described in this specification and MUST not try to
  guess whether the protocol header is present or not. This means that the protocol explicitly prevents port sharing
  between public and private access. Otherwise it would open a major security breach by allowing untrusted parties to
  spoof their connection addresses. The receiver SHOULD ensure proper access filtering so that only trusted proxies are
  allowed to use this protocol."
- The header comes first on the connection, before anything the client sends (before TLS on a TLS port); "the sender
  must always ensure that the header is sent at once".

**How it is met.** `ProxyProtocolConfig` per connector (`proxyProtocol { }` on `plainConnector { }` and
`tlsConnector(identity) { }`; `kuicksilver.proxyProtocol.*` for `EngineMain`'s deployment port), off by default. At least
one trusted source is required; a TCP peer outside `trustedSources` is closed at accept, before a byte is read
(`TcpListener.kt`), rather than served as if the protocol were off: that would share the port between public and private
access, which the spec rules out, and a proxy left out of the list by mistake would see its connections served with its
header read as HTTP. On a PROXY connector every connection must start with a valid header (no guessing): a request
without one is closed unanswered. The header is read before the TLS handshake from the socket's own read channel, which
the TLS session then reads on from (`Socket.tlsServer(config, input)`), so a ClientHello sent in the header's segment is
kept; on a plain connector the same channel goes to HTTP/1.1. The wait is bounded by `headerTimeout` (5 s by default)
and what is left of `requestHeaderTimeoutSeconds` from accept, whichever ends first. The client the header names becomes
`call.request.origin` (remote and local addresses and ports) on HTTP/1.1 and HTTP/2 calls, `call.request.local` keeps the
TCP connection, and `call.request.proxyHeader` gives the header itself.

**Tests.** `ServerProxyProtocolTest.negative_headerFromAnUntrustedSourceIsRefused`, `.negative_connectionWithoutAHeaderIsClosed`,
`.negative_headerNotCompleteWithinTheTimeoutIsCut`, `.pipelinedRequestsAfterTheHeaderAreServed`,
`.tlsConnectorReadsTheHeaderBeforeTheClientHello`, `.http2CallsReportTheClient`, `.repeatOffendersAreTheClientsBehindTheProxy`,
`ProxyProtocolConfigTest.addressesAndBlocksMatch`, `.ipv4MappedPeersMatchIpv4Blocks`, `.negative_ipv6BlocksDoNotTakeMappedIpv4Peers`,
`.negative_unknownPeerIsNotTrusted`, `.negative_invalidConfigurationsAreRefused`, `TlsServerAfterPrefixTest.clientHelloInThePrefixSegmentIsKept`,
`EngineMainTest.proxyProtocolKeysOnTheDeploymentPort`, `.negative_proxyProtocolKeysWithSslPortRefused`.

**Notes on peers.** nghttpx turns the protocol on per frontend (`--accept-proxy-protocol`, `doc/nghttpx.1.rst`) with no
list of trusted sources: every peer of such a frontend must send a header (`shrpx_client_handler.cc:477-481`). Others
(from memory, not in the local clones): nginx `listen ... proxy_protocol` likewise, with `set_real_ip_from` choosing
whom to believe; Go's `pires/go-proxyproto` has a per-peer policy (use, ignore, reject, require). Kuicksilver combines
both: the header is required, and only from the listed peers.

**Out of scope.** HTTP/3 on a TLS connector's UDP port takes no header (the protocol defines none for QUIC); its
requests report their UDP peer, and `call.request.proxyHeader` is null. `Alt-Svc` still advertises HTTP/3 on the
connector's port as configured (`altSvc`): behind an L4 proxy that does not forward UDP, set `altSvc = false`.
