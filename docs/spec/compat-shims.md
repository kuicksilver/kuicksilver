<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Kuicksilver — compatibility shims

Date: 2026-11-13; as of 0.3.0 (unreleased). Status: living document, updated with each change it describes.

Every place where Kuicksilver departs from, or goes beyond, the standard it implements only so that a specific peer that
lags behind or breaks the standard still works with it. The [RFC compliance summary](rfc-compliance.md) and its details
describe what the standards ask; [interop.md](interop.md) has the runs that found most of these peers. Each shim lists
what it does, the peers that need it, the standard text it relates to, where it lives, whether it is on by default, the
tests that pin it, the risk it carries and when it can go.

Not listed (the last section names those that came close): defaults taken from other implementations ("as quic-go
does"), robustness the RFCs require (a MUST or SHOULD to accept something), greasing, and the correct handling of peer
behaviour that is legal but unusual. A borderline entry says why it is listed.

| # | Shim | Peers | On by default | Kind |
|---|---|---|---|---|
| 1 | [WebTransport draft-02 and draft-14 codepoints](#1-webtransport-draft-02-and-draft-14) | Chrome, Firefox (draft-02); Safari (draft-14) | no (`webTransport`) | older drafts next to draft-16 |
| 2 | [The draft-02 response field `sec-webtransport-http3-draft`](#2-the-draft-02-response-field) | Chrome | no (`webTransport`) | a field no draft defines |
| 3 | [Draft-02 session when a newer draft lacks `reset_stream_at`](#3-draft-02-session-when-a-newer-draft-lacks-reset_stream_at) | Safari (expected), any client announcing draft-02 and a newer draft | no (`webTransport`) | our reading of draft-16 §7.1 (borderline) |
| 4 | [Pre-IANA `reset_stream_at` codepoint](#4-pre-iana-reset_stream_at-codepoint) | none verified (quic-go sends both) | no (`resetStreamAt`, on with WebTransport) | a second, unregistered codepoint |
| 5 | [msquic's provisional Initial SCID](#5-msquics-provisional-initial-scid) | msquic | yes (client) | departs from RFC 9000 §7.2 MUSTs |
| 6 | [A resent STREAM range never carries the FIN](#6-a-resent-stream-range-never-carries-the-fin) | quiche | yes | sender choice inside RFC 9000 (borderline) |
| 7 | [HTTP/1.1 status line without the SP before an absent reason](#7-http11-status-line-without-the-sp-before-an-absent-reason) | servers that break RFC 9112 §4 | yes (client) | lenient parsing the RFC allows (borderline) |
| 8 | [SOCKS5 username/password reply with VER 5](#8-socks5-usernamepassword-reply-with-ver-5) | some SOCKS5 proxies | yes (client) | accepts a value RFC 1929 does not define |
| T1 | [Interop client: request and FIN in one STREAM frame](#t1-interop-client-request-and-fin-in-one-stream-frame) | quiche's hq server | test only | not shipped in the library |

## 1. WebTransport draft-02 and draft-14

**What it does.** The wire format is draft-ietf-webtrans-http3-16, but a server with WebTransport also announces
`SETTINGS_ENABLE_WEBTRANSPORT=1` (0x2b603742, draft-02 to -06) and `SETTINGS_WT_MAX_SESSIONS=1` (0x14e9cd29, draft-13 and
-14) next to `SETTINGS_WT_ENABLED=1`; a client announces draft-16 and draft-02. Either side recognises the older settings
in the peer's SETTINGS, takes the `:protocol` token `webtransport` (draft-02 to -14) as well as `webtransport-h3`, and a
client talking to a server without draft-16 sends `:protocol webtransport` with `sec-webtransport-http3-draft02: 1`. A
draft-02 session has no `reset_stream_at` (its draft predates RESET_STREAM_AT), so its streams are reset with RESET_STREAM.
`SETTINGS_ENABLE_WEBTRANSPORT` other than 0 or 1 is `H3_SETTINGS_ERROR`, as draft-02 §3.1 requires.

**Peers.** Chrome 155 and Firefox 158 speak draft-02 ([interop.md](interop.md#interop-webtransport-browsers-2026-10-22-and-2026-10-23),
`ChromeWebTransportTest`, `tools/interop/wt-firefox-manual.sh`); Safari 26.4 speaks draft-14 (second-hand, not run here).

**Standard text.** draft-16 §7.1, "The highest version supported by both endpoints is selected", and §3.1, "For draft
versions of WebTransport only, clients MUST also send SETTINGS_WT_ENABLED with the draft-specific codepoint" (quoted as in
[the draft's details](rfc/draft-ietf-webtrans-http3.md#s3-1-settings)): the version mechanism lets an endpoint speak older
drafts, but no draft defines a server that speaks draft-02 and draft-16 at once; the codepoints are those of the older
drafts.

**Where.** `kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/webtransport/WtVersion.kt:12` (the versions,
`offeredIn` at :38, `WtSettings.ours` at :133, `WtTokens.LEGACY` at :147),
`kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/frame/SettingsCodec.kt:22` and :25 (the codepoints),
`kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/runtime/H3Session.control.kt:236` (the 0-or-1 check),
`kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/webtransport/WtSessionImpl.kt:447` (the client's draft-02
request field).

**On by default.** No: only with `Http3Settings.webTransport` (false by default) or the Ktor server's `webTransport`
(false by default), and on the client per `HttpClient.webTransport` call.

**Tests.** `webtransport.WebTransportSettingsTest.serverAdvertisesAllWtCodepoints`, `.clientAdvertisesWtEnabled`,
`.wtSettingsNotSentByDefault`, `.peerVersionIsTheHighestBothAnnounce`, `.negative_clientNeverPicksADraftItDidNotOffer`,
`.negative_draft02SettingAboveOneIsSettingsError`, `webtransport.WebTransportSessionTest.establishLegacyTokenAccepted`,
`.clientUsesLegacyTokenForDraft02Server`, `.draft02ClientWithoutResetStreamAtIsAccepted`;
`ChromeWebTransportTest.chromeDraft02` (opt-in, `-Pkuicksilver.browserTests=true`).

**Risk.** Low. A draft-02 session resets streams with RESET_STREAM, so a reset stream's header can be lost and the peer
may not tie the reset to the session (robustness, not security). None of the drafts has WebTransport flow control here
for any version: one session per connection, a second CONNECT is refused with `H3_REQUEST_REJECTED`.

**Removal.** draft-02 when Chrome and Firefox ship draft-15 or later (`SETTINGS_WT_ENABLED`, `webtransport-h3`) by
default; draft-14 when Safari does. The final RFC will retire all three draft codepoints.

## 2. The draft-02 response field

**What it does.** A server that accepts a CONNECT carrying `sec-webtransport-http3-draft02` adds
`sec-webtransport-http3-draft: draft02` to its 2xx.

**Peers.** Chrome's draft-02 client refuses a 2xx without it.

**Standard text.** None: draft-16 has no such field. RFC 9110 §5.1 lets a recipient ignore an unknown field, so the field
costs other clients nothing.

**Where.** `kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/runtime/ServerRequestStream.kt:482`; the name and
value at `kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/webtransport/WtVersion.kt:153`.

**On by default.** No, as shim 1; then always for a request with the draft-02 field.

**Tests.** `webtransport.WebTransportSessionTest.establishLegacyTokenAccepted` (checks the field);
`ChromeWebTransportTest.chromeDraft02`, `.chromeWithDraft07EnabledFallsBackToDraft02`.

**Risk.** None known: a fixed value, sent only to a client that asked in draft-02 form.

**Removal.** With draft-02 (shim 1).

## 3. Draft-02 session when a newer draft lacks `reset_stream_at`

Borderline: within the draft's version selection, but a reading the draft does not state, made for one browser.

**What it does.** draft-14 and draft-16 need `reset_stream_at` on both sides. A client that announces draft-16 or
draft-14 without the transport parameter but also draft-02 gets a draft-02 session when its CONNECT is a draft-02 request
(`:protocol webtransport` with `sec-webtransport-http3-draft02: 1`); its draft-16 or draft-14 CONNECT is refused (400 and
`H3_MESSAGE_ERROR`). Our client does the same against such a server: it sends a draft-02 CONNECT.

**Peers.** Safari before 26.4, which by WebKit bugs 303152 and 305006 announces draft-14 without `reset_stream_at` and
may announce draft-02 too (second-hand, not run here); any implementation that announces a newer draft before it has
RESET_STREAM_AT.

**Standard text.** draft-16 §7.1, "The highest version supported by both endpoints is selected", read as the highest
version both can actually run; §3.1, "both the client and the server enable the extension by sending an empty
reset_stream_at transport parameter" (as quoted in the draft's [details](rfc/draft-ietf-webtrans-http3.md#s3-1-settings)).

**Where.** `kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/webtransport/WtVersion.kt:92` (`wtClientVersion`)
and :109 (`wtServerVersion`).

**On by default.** No, as shim 1.

**Tests.** `webtransport.WebTransportSessionTest.withoutResetStreamAtBothSidesFallBackToDraft02`,
`.draft16And02ClientWithoutResetStreamAtIsAcceptedAsDraft02`,
`.negative_draft16ConnectWithoutResetStreamAtIsMalformedEvenWithDraft02Offered`,
`webtransport.WebTransportSettingsTest.draft14And02ServerWithoutResetStreamAtGetsADraft02Connect`.

**Risk.** Low: the session runs draft-02 in every respect (shim 1's risk); a newer-draft session is never run without the
transport parameter its §3.1 requires.

**Removal.** With draft-02 (shim 1), or earlier once every client that announces a newer draft sends `reset_stream_at`.

## 4. Pre-IANA `reset_stream_at` codepoint

**What it does.** With `QuicConfig.resetStreamAt` the transport parameter is sent twice, as 0x1d and as
0x17f7586d2cb571, the codepoint of earlier versions of the draft, and either one received enables RESET_STREAM_AT (a
non-empty value of either is `TRANSPORT_PARAMETER_ERROR`).

**Peers.** None verified. quic-go (2bb41ed) sends and accepts both codepoints, naming the old one draft-07's, so it
works with 0x1d alone; Cloudflare quiche 4ebd213 implements neither codepoint; Chrome was not checked (no Chromium source
here). Earlier notes named Chrome and quiche without evidence.

**Standard text.** draft-ietf-quic-reliable-stream-reset-11 §3: "Support for receiving RESET_STREAM_AT frames is
advertised by sending the reset_stream_at (0x1d) transport parameter (Section 7.4 of [RFC9000]) with an empty value." The
old codepoint is not registered; RFC 9000 §7.4.2, "An endpoint MUST ignore transport parameters that it does not
support", keeps it harmless to peers that do not know it.

**Where.** `kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/wire/TransportParametersCodec.kt:43` (the
codepoint), :132 (sent), :331 (accepted).

**On by default.** No: `QuicConfig.resetStreamAt` is false by default; WebTransport turns it on (server and client).

**Tests.** `wire.TransportParametersTest.resetStreamAtBothCodepoints`.

**Risk.** Low: nine more bytes in the transport parameters, and RESET_STREAM_AT frames (type 0x24) toward a peer that
announced only the old codepoint, which must then read them as that draft's frame.

**Removal.** Once no peer is shown to need it (none is today; removal is not decided). The removal must mind
remembered transport parameters: a client that remembered `reset_stream_at` from a server that sent only the old codepoint would take that server's next 0-RTT
acceptance for a lowered capability and close with PROTOCOL_VIOLATION
(`kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/core/ZeroRtt.kt:267`); quic-go ties its own removal to a new
ticket format for the same reason.

## 5. msquic's provisional Initial SCID

**What it does.** A client takes the Source Connection ID of the server's first Initial and discards later long-header
packets with another one. One exception: an Initial with nothing but ACK, PING and PADDING whose SCID is the DCID the
client sends to is processed (its ACK counts, so the RTT sample is taken and acknowledged data is not resent) without
fixing the SCID and without recording its packet number; the next Initial fixes it.

**Peers.** msquic (17f6e9f): until it has the whole ClientHello its connection sends from the client's own DCID (the
IsInitial source CID, `src/core/connection.c`), and takes its own SCID only when the listener accepts the connection
(`QuicConnGenerateNewSourceCid` in `src/core/listener.c`): one connection, packet numbers continuing, two SCIDs.

**Standard text.** RFC 9000 §7.2: "Once a client has received a valid Initial packet from the server, it MUST discard
any subsequent packet it receives on that connection with a different Source Connection ID." and "A client MUST change
the Destination Connection ID it uses for sending packets in response to only the first received Initial or Retry
packet." The provisional Initial is a valid Initial that does not fix the SCID, so both MUSTs are departed from for it. The
owner keeps it for 0.3.0 as an approved deviation; the §7.2 row of the summary is 🔶 for it
([details](rfc/9000.md#s7-2-the-servers-source-connection-id-is)).

**Where.** `kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/core/PacketReceiver.kt:380` (the decision, with
`onlyAcks` at :491), `kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/core/ConnectionIdManager.kt:204`
(sequence 0 replaced while it is the only one).

**On by default.** Yes, on every client; no switch.

**Tests.** `core.ReceivePathTest.ackOnlyInitialFromTheClientsOwnDcidDoesNotFixTheScid`,
`.negative_ackOnlyInitialFromAnotherScidFixesIt`, `.clientDiscardsLongHeaderWithDifferentScid`,
`core.HandshakeLimitsTest.ackOnlyFirstInitialUnderAmplificationLimitKeepsOneQuickHandshake`.

**Risk.** Low. Initial keys are public, so whoever sees the client's first Initial can forge an ACK-only Initial from its
DCID; the RFC already lets such an attacker forge an Initial that fixes a wrong SCID. A forged provisional Initial can
acknowledge the client's Initial packets, so they are not resent until a real server packet arrives (a stall, up to the
handshake timeout); it fixes nothing and records no packet number.

**Removal.** When msquic sends its first Initial from its own SCID (not the case in 17f6e9f), or answers with nothing
before its listener accepts the connection.

## 6. A resent STREAM range never carries the FIN

Borderline: RFC 9000 lets a sender put the FIN in a frame of its own; this is listed because the choice is made only for
one peer's receiver.

**What it does.** A lost range of stream data is resent without the FIN: a FIN still in flight needs no copy, a lost one
goes as an empty STREAM frame with the FIN.

**Peers.** quiche: its receiver took the final size from a frame whose bytes it had already read, dropped the frame as a
duplicate and never woke the application for the FIN (`kuicksilver->quiche:handshakeloss` lost one request in 50, run
20261015-170940; [RFC 9002 details](rfc/9002.md)). quiche 4ebd213 keeps the first FIN of such a frame
(`RecvBuf::write`, "Discard consumed data unless it carries the first FIN", test `duplicate_data_first_fin`).

**Standard text.** RFC 9000 §2.2: "Data that has already been received can be discarded."; §4.5: "The final size is the
sum of the Offset and Length fields of a STREAM frame with a FIN flag" — the FIN of a duplicate frame still gives the
final size.

**Where.** `kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/stream/SendStream.kt:182`.

**On by default.** Yes; no switch.

**Tests.** `stream.SendStreamTest.retransmittedDataDoesNotCarryAFinThatIsStillInFlight`,
`.lostDataAndLostFinGoAsDataThenAnEmptyFin`.

**Risk.** None for security; a lost FIN costs one small frame more.

**Removal.** When the interop runner's quiche image has the fix above and `kuicksilver->quiche:handshakeloss` stays green
without the shim over several runs.

## 7. HTTP/1.1 status line without the SP before an absent reason

Borderline: RFC 9112 §4 lets a recipient parse leniently, but the case accepted is one where the server broke a MUST.

**What it does.** The client takes `HTTP/1.1 204` as well as `HTTP/1.1 204 ` (the grammar's form); everything else of the
status line is parsed strictly.

**Peers.** Servers that leave out the space; OkHttp 5.3.2 (`StatusLine.parse`) and, by the source comment, Go accept it.

**Standard text.** RFC 9112 §4: `status-line = HTTP-version SP status-code SP [ reason-phrase ]`, "A server MUST send the
space that separates the status-code from the reason-phrase even when the reason-phrase is absent", and "recipients MAY
instead parse on whitespace-delimited word boundaries and, aside from the line terminator, treat any form of whitespace
as the SP separator while ignoring preceding or trailing whitespace".

**Where.** `kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/h1/ResponseHead.kt:125`
(`statusLineOf`).

**On by default.** Yes (the Ktor client engine over HTTP/1.1); no switch.

**Tests.** `h1.H1ResponseHeadTest.statusLineWithoutReasonPhraseIsAccepted`.

**Risk.** Low: a missing trailing space cannot shift the status code or the framing (the line must still be exactly
`HTTP/1.x SP 3DIGIT`); response splitting needs a second recipient that reads the line differently.

**Removal.** None planned: the leniency is what the RFC allows and what other clients do.

## 8. SOCKS5 username/password reply with VER 5

**What it does.** The reply to the username/password subnegotiation is accepted with VER 1, as RFC 1929 defines, or 5
(the SOCKS version); any other VER fails the connection with `ProxyException`. STATUS is checked as usual.

**Peers.** SOCKS5 proxies that answer the subnegotiation with the SOCKS version (not named in the source); curl
tolerates them too.

**Standard text.** RFC 1929 §2: "The VER field contains the current version of the subnegotiation, which is X'01'.", and
the reply is `VER STATUS` with a 1-octet VER; the RFC gives no rule for another value.

**Where.** `kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/h1/Socks5.kt:78`.

**On by default.** Yes, with a SOCKS5 proxy and credentials; no switch.

**Tests.** `h1.Socks5Test.authReplyVersion5Tolerated` (VER 5 accepted, VER 4 refused).

**Risk.** Low: the VER byte carries no authentication; a proxy that rejects the credentials still fails the connection
by STATUS.

**Removal.** None planned; the proxies are not tracked.

## Test-only

### T1. Interop client: request and FIN in one STREAM frame

**What it does.** The QUIC Interop Runner client writes each `hq-interop` request into the stream's buffer and closes it
in one step, so the request and its FIN share one STREAM frame. The library's `flushAndClose` hands buffered data to the
core with the FIN for every application (`api.StreamBridgeTest.flushAndCloseSendsDataAndFinInOnePacket`); that is
ordinary coalescing and not a shim.

**Peers.** quiche's hq server left 0-RTT requests whose FIN arrived in a frame of its own unanswered
(`quiche->kuicksilver:zerortt`, [interop.md](interop.md#interop-matrix-020-quic-interop-runner-740c05a-2026-10-13)).

**Standard text.** RFC 9000 §19.8: a STREAM frame's FIN "marks the end of the stream"; nothing requires it to travel with
the data.

**Where.** `kuicksilver-interop/src/commonMain/kotlin/io/kuicksilver/interop/HqInteropClient.kt:113` (`request`).

**On by default.** Interop images only; not in any published artifact.

**Tests.** The runner's `zerortt` case against quiche (`tools/interop/required.json`).

**Risk.** None: test code.

**Removal.** When quiche's hq server answers a request whose FIN comes alone.

## Removed

- **`Proxy-Connection: Keep-Alive` on CONNECT** (0.3.0). The CONNECT that opens a tunnel through an HTTP proxy carried the
  field for HTTP/1.0 proxies, as OkHttp 5.3.2 does (`RealRoutePlanner`, "For HTTP/1.0 proxies like Squid"), against RFC
  9112 appendix C.2.2: "clients are encouraged not to send the Proxy-Connection header field in any requests". No peer
  was recorded that needed it, and a CONNECT tunnel does not depend on keep-alive; the CONNECT now carries none —
  `ClientProxyTest.negative_connectCarriesNoProxyConnection`.

## Considered and not listed

- **Discarding later long-header packets with another SCID** (msquic answers a repeated Initial from a second connection
  instance): the RFC 9000 §7.2 MUST itself.
- **HTTP/2: a stream that depends on itself is a stream error** (RFC 7540 §5.3.1): RFC 9113 §5.3.2 retains "some of the
  mandatory handling ... to ensure that implementations of this document remain interoperable", and the check is
  stricter, not lenient.
- **TLS 1.2** (`TlsVersions.Tls12And13`, for peers without 1.3 such as old Android and JDK stacks): off by default, and RFC
  9325 §3.1.1 says "Implementations MUST support TLS 1.2"; Extended Master Secret is required, so legacy peers are refused
  as RFC 7627 §5.2 allows. No cipher suite, version or renegotiation is relaxed for old stacks.
- **X25519 in the server's first key-share preference** (ngtcp2 and others offer X25519 shares only): a default within RFC
  9846's group selection, saving a HelloRetryRequest.
- **The ALPN of a ticket received on a resumed connection** (`ksl_ssl.c`, OpenSSL 3.5 copies the resumed session's ALPN;
  fixed in OpenSSL 4.1): a fix of our own TLS library's behaviour so that we follow RFC 8446 §4.2.10, not a peer.
- **The client's remembered RTT per server** (quic-go drops a silent half-open connection after 5 s): RFC 9002 §6.2.2,
  "MAY use the previous connection's final smoothed RTT".
- **Following a client's NAT rebind during the handshake** (interop rebind cases, quiche): RFC 9000 §9 lets a server
  "proceed with path validation and allow the peer to migrate".
- **Probing the other packet number spaces on a PTO** (quic-go `handshakeloss` stalls): RFC 9002 §6.2.4 SHOULD.
- **No glitch token for repeated MAX_STREAMS or DATA_BLOCKED** (quic-go, quiche): legal peer behaviour handled correctly.
- **One lost range queued once** (quiche fails the handshake on bytes repeated in one packet): sending each byte once
  per packet is plain efficiency.
- **WebTransport: reading what arrived before CONNECTION_CLOSE** (Firefox's `WT_CLOSE_SESSION`) and **waiting for the
  peer's FIN before STOP_SENDING on close** (Chrome): correct handling of legal behaviour and a timing choice within the
  draft's close procedure.
- **HTTP/1.1 parsing the RFCs allow or require**: obs-fold in a response replaced with SP (RFC 9112 §5.2 MUST for a user
  agent), a bare LF as a line end in the head (§2.2 MAY), the request-line whitespace of §3 (MAY), a 301 for an invalid
  origin-form target (§3.2), a higher minor version processed as HTTP/1.1 (RFC 9110 §6.2 SHOULD), an invalid status
  code read as a 5xx (RFC 9110 §15 SHOULD). Where Ktor's own parser is more lenient (Unicode spaces, control characters,
  chunk-size lines), both engines are stricter; nothing lenient is added for any client.
- **SOCKS5 empty password**: refused (RFC 1929 §2, PASSWD has 1 to 255 octets), stricter than curl and Go.
- **Greasing** (`Http3Settings.grease`, `grease_quic_bit`): excluded by definition.
- **Android API levels** (`java.nio.file`, `DnsResolver.rawQuery`): platform APIs, not a peer's protocol.
- **The interop runner's trust** (`InteropTrust`, `KSL_INTEROP_EXPECTED_NAME`): the runner's self-signed test
  certificates, test code.
- **Values borrowed from other implementations** (0-RTT buffering as quic-go, keep-alive periods, token store sizes,
  limits after nghttp2 and Go): defaults, not departures.
