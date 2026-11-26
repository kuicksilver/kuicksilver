<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# PROXY protocol — HAProxy, "The PROXY protocol", versions 1 and 2

Details of the rows of the [RFC compliance summary](../rfc-compliance.md) for this document. Each section gives the requirement, how Kuicksilver meets it (with the files), the tests that pin it, its history, notes on peers and the open items. Status: ✅ met · 🔶 feature subset or accepted deviation · ⬜ planned · ❌ not planned; "since" is the release from which the current behaviour holds (history below and in [CHANGELOG.md](../../../CHANGELOG.md)).

The text is HAProxy's `doc/proxy-protocol.txt`, "The PROXY protocol, Versions 1 & 2", revision 2020/03/05, not an RFC;
its MUST and SHOULD statements are treated as an RFC's. Every quote below was checked against that revision; the section
numbers are its own. Kuicksilver is a receiver only (the Ktor server engine's TCP connectors); it never sends the header.
Decisions: [ADR-0022](../../adr/0022-proxy-protocol.md).

Scope list (receiver): the receiver rules of section 2 (a complete and valid header before processing, the timeout, no
guessing, access filtering); the version 1 line (§2.1); the version 2 signature, version, command, family, transport,
length and address blocks, and telling the versions apart (§2.2); the TLVs and their checks (§2.2.1–§2.2.8: ALPN,
AUTHORITY, CRC32C, NOOP, UNIQUE_ID, SSL with sub-TLVs, NETNS, reserved ranges); the security considerations (§5). Out of
scope: the sender side; UDP (QUIC, HTTP/3), where the protocol has no defined place before a QUIC packet (the DGRAM
transport of §2.2 describes the original flow, not a header on a datagram).

## <a id="header-v1"></a>Version 1: the human-readable header

Status: ✅ since 0.3.0 (experimental) · [summary](../rfc-compliance.md#http)

**Requirement (§2.1).**

- One line: `PROXY`, "exactly one space", `TCP4`, `TCP6` or `UNKNOWN`; for TCP4 and TCP6 the source and destination
  addresses and ports, each after "exactly one space", then "the CRLF sequence". For "UNKNOWN", "the rest of the line
  before the CRLF may be omitted by the sender, and the receiver must ignore anything presented before the CRLF is found."
- Addresses: "IPv4 addresses must be indicated as a series of exactly 4 integers in the range [0..255] inclusive written
  in decimal representation separated by exactly one dot between each other. Heading zeroes are not permitted in front of
  numbers in order to avoid any possible confusion with octal numbers. IPv6 addresses must be indicated as series of sets
  of 4 hexadecimal digits (upper or lower case) delimited by colons between each other, with the acceptance of one double
  colon sequence to replace the largest acceptable range of consecutive zeroes. The total number of decoded bits must
  exactly be 128." Ports: "a decimal integer in the range [0..65535] inclusive. Heading zeroes are not permitted in front
  of numbers in order to avoid any possible confusion with octal numbers."
- Length: "The maximum line lengths the receiver must support including the CRLF are : [...] worst case [...] 107 chars".
  "So a 108-byte buffer is always enough to store all the line and a trailing zero for string processing."
- "The receiver must wait for the CRLF sequence before starting to decode the addresses in order to ensure they are
  complete and properly parsed. If the CRLF sequence is not found in the first 107 characters, the receiver should
  declare the line invalid. [...] The receiver must not tolerate a single CR or LF character to end the line when a
  complete CRLF sequence is expected."
- "Any sequence which does not exactly match the protocol must be discarded and cause the receiver to abort the
  connection."
- "If the announced transport protocol is "UNKNOWN", then the receiver [...] SHOULD accept the connection and use the
  real connection's parameters as if there were no PROXY protocol header on the wire."
- Section 2: "The receiver may be tolerant to partial headers or may simply drop the connection when receiving a partial
  header. Recommendation is to be tolerant".

**How it is met.** `kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/ProxyProtocolCodec.kt`:
`frame` looks at each byte once as it arrives (the `PROXY ` prefix, the first LF only after a CR, no CRLF within 107
bytes refused at the 107th byte); `decode` checks the whole line again: `UNKNOWN` followed by CRLF or a space (anything
after it ignored, a NUL or a lone CR included), else `TCP4 `/`TCP6 ` and exactly four fields. IPv4: four decimal numbers
0..255 without leading zeros. IPv6: hexadecimal groups separated by colons, at most one `::`, 128 bits; groups of 1 to 4
digits are taken (what `inet_ntop` writes, which senders use), and a dotted IPv4 tail, brackets and a zone ID are refused
(they are no hexadecimal groups, and a dotted tail would let IPv4's leading zeros in). Ports without leading zeros, as
nghttpx's `parse_proxy_line_port` (`refs/peers/nghttp2/src/shrpx_client_handler.cc:1228-1253`). Addresses are reported
in canonical text (RFC 5952; `ipLiteralOf`). `readProxyHeader` takes a header split over any number of reads (the
recommended tolerance) and never reads past its CRLF. A malformed line closes the connection with a reset.

**Tests.** `ProxyProtocolCodecTest.v1Tcp4`, `.v1Tcp6IsReportedInCanonicalText`, `.v1UnknownIgnoresWhatFollows`,
`.v1LongestLineIsTaken`, `.negative_v1WithoutCrlfWithin107BytesIsRefused`, `.negative_v1LineEndsOtherThanCrlfAreRefused`,
`.negative_v1MalformedFieldsAreRefused`, `.negative_readerRefusesAV1LineWithoutCrlfWithoutWaitingForMore`,
`.readerTakesAHeaderSplitIntoSingleBytesAndLeavesWhatFollows`, `ServerProxyProtocolTest.v1OriginIsTheClientAndLocalStaysTheProxy`,
`.negative_malformedHeadersAreClosed`; fuzzing: `ProxyHeaderFuzzTest.proxyHeader`.

**Notes on peers.** nghttpx (`shrpx_client_handler.cc:1288-1483`) looks for LF or NUL within the first 107 bytes of
what it peeked, refuses a NUL there and a line whose LF is not after CR, accepts `PROXY UNKNOWN` with anything after it
(its test `TestH2H1ProxyProtocolV1JustUnknown`, `integration-tests/nghttpx_http2_test.go:1549`), parses addresses with
`inet_pton` and ports without leading zeros; it takes the header only when it is whole in one read (it peeks the socket
first, `shrpx_client_handler.cc:196-224`), which §2.1 allows ("A receiver may reject an incomplete line which does not
contain the CRLF sequence in the first atomic read operation"). Kuicksilver accepts a header split over reads, the
recommendation of section 2, and a NUL after `UNKNOWN`, which §2.1 says to ignore.

## <a id="header-v2"></a>Version 2: the binary header

Status: ✅ since 0.3.0 (experimental) · [summary](../rfc-compliance.md#http)

**Requirement (§2.2).**

- The 12-byte signature `\x0D \x0A \x0D \x0A \x00 \x0D \x0A \x51 \x55 \x49 \x54 \x0A`. The 13th byte's high nibble is
  the version: "As of this specification, it must always be sent as \x2 and the receiver must only accept this value."
  Its low nibble is the command, LOCAL (0) or PROXY (1): "other values are unassigned and must not be emitted by senders.
  Receivers must drop connections presenting unexpected values here."
- LOCAL: "The receiver must accept this connection as valid and must use the real connection endpoints and discard the
  protocol block including the family which is ignored."
- The 14th byte: family (AF_UNSPEC, AF_INET, AF_INET6, AF_UNIX) and transport (UNSPEC, STREAM, DGRAM); for each nibble
  "other values are unspecified and must not be emitted in version 2 of this protocol and must be rejected as invalid by
  receivers." AF_UNSPEC and UNSPEC: "The receiver is free to accept the connection anyway and use the real endpoint
  addresses or to reject it. The receiver should ignore address information." "In practice, the following protocol bytes
  are expected": `\x00`, `\x11`, `\x12`, `\x21`, `\x22`, `\x31`, `\x32`, with address blocks of 12, 36 and 216 bytes.
- The 15th and 16th bytes: "Thus the length of the protocol header in bytes is always exactly 16 + this value."
  "Receivers MUST always consider this field to skip the appropriate number of bytes and must not assume zero is
  presented for LOCAL connections."
- "The receiver must not start to parse an address before the whole address block is received. The receiver must also
  reject incoming connections containing partial protocol headers."
- "A receiver may be configured to support both version 1 and version 2 of the protocol. Identifying the protocol version
  is easy : [...] otherwise the protocol is not covered by this specification and the connection must be dropped."

**How it is met.** `ProxyProtocolCodec.frame` checks the signature byte by byte, then the version and command (only 0x20
and 0x21), then the family byte: a family nibble above 3 or a transport nibble above 2 is refused whatever the command;
a LOCAL header takes any other byte, a PROXY header only the seven bytes listed (for the other valid pairs, such as
AF_INET with UNSPEC, the receiver "is free to [...] reject it"). From the 16 fixed bytes the total length is checked
against `maxHeaderSize` (`ProxyProtocolConfig.Builder.maxHeaderSize`, 4096 by default, 232..65551) before the body is
read, so a 65,535-byte length costs nothing; `readProxyHeader` then reads exactly 16 + length bytes. `decode` discards a
LOCAL block unread whatever its length and family (zero, shorter or longer than any address block), and returns a PROXY
header with AF_UNSPEC (only `\x00` reaches it) without addresses: the connection's own apply. For PROXY with AF_INET,
AF_INET6 or AF_UNIX a block shorter than the family's addresses holds a partial address and is refused. Addresses are
read for INET, INET6 and UNIX (a UNIX path up to its first NUL, an abstract one as `@name`). A DGRAM transport is
accepted; its addresses are reported as for STREAM. The first byte tells the versions apart (`P` or CR); any other first
byte drops the connection.

**Tests.** `ProxyProtocolCodecTest.v2ProxyInet`, `.v2ProxyInet6AndDgram`, `.v2ProxyUnixPaths`,
`.v2LocalAndUnspecKeepTheRealAddresses`, `.v2LocalIsAcceptedWhateverItsFamilyAndLength`,
`.negative_v2LocalWithAnInvalidNibbleIsRefused`, `.negative_v2ProxyWithAnUnlistedCombinationIsRefused`,
`.negative_v2BadVersionCommandOrFamilyIsRefused`, `.negative_v2AddressBlockShorterThanItsFamilyIsRefused`,
`.negative_v2HugeLengthIsRefusedFromTheFixedPartAlone`, `.negative_readerRefusesAHugeV2LengthWithoutWaitingForTheBody`,
`.readerLeavesBytesThatCameInTheSameWrite`, `ServerProxyProtocolTest.v2HeaderSentApartFromItsRequest`,
`.localCommandKeepsTheConnectionsOwnAddresses`.

**Notes on peers.** nghttpx (`shrpx_client_handler.cc:1485-1600`) checks the version nibble, refuses commands other than
LOCAL and PROXY and family bytes other than the seven listed, refuses blocks shorter than the family's addresses before
it looks at the command (so it drops a LOCAL health check with `\x11` and length 0, which the LOCAL rule above says to
accept), ignores UNSPEC and UNIX addresses, and needs the whole header in its first read (it refuses a "prematurely
truncated header block", line 1524). It does not parse TLVs.

## <a id="tlvs"></a>Version 2 TLVs and the CRC32c

Status: ✅ since 0.3.0 (experimental) · [summary](../rfc-compliance.md#http)

**Requirement.**

- §2.2: "If the length specified in the PROXY protocol header indicates that additional bytes are part of the header
  beyond the address information, a receiver may choose to skip over and ignore those bytes, or attempt to interpret
  those bytes." They are TLVs: a type byte, a 16-bit length, the value. "A receiver may choose to skip over and ignore the
  TLVs it is not interested in or it does not understand."
- §2.2.3, `PP2_TYPE_CRC32C`: "If the checksum is provided as part of the PROXY header and the checksum functionality is
  supported by the receiver, the receiver MUST: - store the received CRC32c checksum value aside. - replace the 32 bits of
  the checksum field in the received PROXY header with all '0's and calculate a CRC32c checksum value of the whole PROXY
  header. - verify that the calculated CRC32c checksum is the same as the received CRC32c checksum. If it is not, the
  receiver MUST treat the TCP connection providing the header as invalid. The default procedure for handling an invalid
  TCP connection is to abort it." The checksum is "as described in RFC4960, Appendix B".
- §2.2.4 `PP2_TYPE_NOOP`: "The TLV of this type should be ignored when parsed." §2.2.5 `PP2_TYPE_UNIQUE_ID`: "an opaque
  byte sequence of up to 128 bytes". §2.2.6 `PP2_TYPE_SSL`: `client` (1 byte), `verify` (4 bytes), then sub-TLVs; "The
  total length of the pp2_tlv_ssl TLV will reflect this." §2.2.1 ALPN, §2.2.2 AUTHORITY ("an UTF8-encoded string"),
  §2.2.7 NETNS; §2.2.8 reserves 0xE0..0xEF, 0xF0..0xF7 and 0xF8..0xFF.

**How it is met.** `ProxyProtocolCodec.tlvs` parses the TLVs of a PROXY header with an INET, INET6 or UNIX family (it
interprets them, as the first quote allows). A TLV whose header is cut by the end of the block, or whose length passes
it, is a partial TLV: the header is refused under §2.2's "The receiver must also reject incoming connections containing
partial protocol headers." A CRC32C TLV must be 4 bytes ("a 32-bit number") and appear once (a second one would leave
undefined which field was zeroed), and is checked as quoted: CRC32c of RFC 4960 appendix B (the Castagnoli polynomial;
the test vectors are those of RFC 3720 appendix B.4), the value in network byte order; a mismatch aborts the
connection. A unique ID over 128 bytes, and an SSL TLV shorter than its 5 fixed bytes or whose sub-TLVs do not fill it
exactly, close the connection; NOOP is dropped; every other TLV, known or not, is kept for the application
(`ProxyHeader.tlvs`, `alpn`, `authority`, `uniqueId`, `netns`, `ssl`). The TLVs of a LOCAL header, a CRC32C among them,
are not read: §2.2 says to "discard the protocol block including the family which is ignored". Nor are those after a
PROXY header with AF_UNSPEC, whose bytes the receiver "may choose to skip over and ignore".

**Tests.** `ProxyProtocolCodecTest.v2Tlvs`, `.crc32cVector`, `.v2CrcThatMatchesIsTaken`, `.negative_v2CrcMismatchIsRefused`,
`.negative_v2CrcTlvOfAnotherLengthOrTwiceIsRefused`, `.negative_v2TlvOverrunningTheHeaderIsRefused`,
`ServerProxyProtocolTest.tlsConnectorReadsTheHeaderBeforeTheClientHello` (a header with a CRC32c).

## <a id="receiver"></a>The receiver: access filtering, no guessing, the header first

Status: ✅ since 0.3.0 (experimental) · [summary](../rfc-compliance.md#http)

**Requirement.**

- Section 2: "The receiver MUST NOT start processing the connection before it receives a complete and valid PROXY
  protocol header." "The receiver may apply a short timeout and decide to abort the connection if the protocol header is
  not seen within a few seconds (at least 3 seconds to cover a TCP retransmit)."
- Section 2: "The receiver MUST be configured to only receive the protocol described in this specification and MUST not
  try to guess whether the protocol header is present or not. This means that the protocol explicitly prevents port
  sharing between public and private access. Otherwise it would open a major security breach by allowing untrusted
  parties to spoof their connection addresses. The receiver SHOULD ensure proper access filtering so that only trusted
  proxies are allowed to use this protocol."
- Section 2: "The sender must always ensure that the header is sent at once".
- Section 5: "Implementers should be very careful about not trying to automatically detect whether they have to decode
  the header or not, but rather they must only rely on a configuration parameter. [...] However, accepting the header only
  from a number of known sources should be safe."

**How it is met.** `ProxyProtocolConfig` per connector (`proxyProtocol { }` on `plainConnector { }` and
`tlsConnector { }`; `kuicksilver.connector.proxyProtocol.*` for `EngineMain`'s deployment port), off by default: a
configuration parameter, never detection. At least one trusted source is required; a TCP peer outside the trusted sources (`trust(...)`)
is closed at accept, before a byte is read (`TcpListener.kt`), rather than served as if the protocol were off: that would
share the port between public and private access, which section 2 rules out, and a proxy left out of the list by mistake
would see its connections served with its header read as HTTP. A deployment that relies on a firewall alone can list
`0.0.0.0/0` and `::/0`: every peer must then send a header. On a PROXY connector every connection must start with a
valid header (no guessing), and nothing of the connection is processed before it: a request without one is closed
unanswered. The header is read before the TLS handshake from the socket's own read channel, which the TLS session then
reads on from (`Socket.tlsServer(config, input)`), so a ClientHello sent in the header's segment is kept; on a plain
connector the same channel goes to HTTP/1.1. The wait is `headerTimeout` (5 s by default; the builder refuses less than
3 s), cut to what is left of `requestHeaderTimeout` from accept (`ProxyProtocolConfig.headerWait`); the engine
refuses to start a PROXY connector with `requestHeaderTimeout` below 3 s, so at accept the wait is at least 3 s. The client the header names becomes `call.request.origin` (remote and local addresses
and ports) on HTTP/1.1 and HTTP/2 calls, `call.request.local` keeps the TCP connection, and `call.request.proxyHeader`
gives the header itself. On a PROXY connector the HTTP/2 repeat-offender penalty is never the TCP peer's: a flood strikes
the client the header names, or nobody when it names none, and the accept-time check of the peer is skipped.

**Tests.** `ServerProxyProtocolTest.negative_headerFromAnUntrustedSourceIsRefused`, `.negative_connectionWithoutAHeaderIsClosed`,
`.negative_headerNotCompleteWithinTheTimeoutIsCut`, `.pipelinedRequestsAfterTheHeaderAreServed`,
`.tlsConnectorReadsTheHeaderBeforeTheClientHello`, `.http2CallsReportTheClient`, `.repeatOffendersAreTheClientsBehindTheProxy`,
`.negative_aPenaltyOnTheProxysAddressDoesNotRefuseItsClients`, `.negative_aFloodBehindAHeaderWithoutAClientStrikesNobody`,
`.negative_proxyProtocolWithARequestHeadDeadlineBelowThreeSecondsDoesNotStart`,
`ServerH2FloodTest.negative_floodsBehindAnUnknownProxyHeaderDoNotRefuseTheProxy`,
`ProxyProtocolConfigTest.addressesAndBlocksMatch`, `.ipv4MappedPeersMatchIpv4Blocks`, `.negative_ipv6BlocksDoNotTakeMappedIpv4Peers`,
`.negative_unknownPeerIsNotTrusted`, `.negative_invalidConfigurationsAreRefused`, `.headerWaitIsTheTimeoutCutToTheRequestHeadDeadline`,
`TlsServerAfterPrefixTest.clientHelloInThePrefixSegmentIsKept`, `EngineMainTest.proxyProtocolKeysOnTheDeploymentPort`,
`.negative_proxyProtocolKeysWithSslPortRefused`, `.negative_proxyProtocolKeysWithAShortRequestHeadDeadlineRefused`.

**Notes on peers.** nghttpx turns the protocol on per frontend (`--accept-proxy-protocol`, `doc/nghttpx.1.rst`) with no
list of trusted sources: every peer of such a frontend must send a header (`shrpx_client_handler.cc:477-481`).
Kuicksilver requires the header too, and takes it only from the listed peers, which section 5 calls safe.

**Out of scope.** HTTP/3 on a TLS connector's UDP port takes no header (the protocol defines none for QUIC); its
requests report their UDP peer, and `call.request.proxyHeader` is null. `Alt-Svc` still advertises HTTP/3 on the
connector's port as configured (`http3 { altSvc }`): set `http3 { altSvc = false }` unless the proxy forwards UDP on the same port number.
