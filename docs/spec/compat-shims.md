<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Kuicksilver — compatibility shims

Date: 2026-11-24; as of 0.3.0 (unreleased). Status: living document, updated with each change it describes.

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
| 1 | [WebTransport draft-02 and draft-14 codepoints](#1-webtransport-draft-02-and-draft-14) | Chrome, Firefox (draft-02); Safari (draft-14) | no (`webTransport`) | older drafts next to draft-17 |
| 2 | [The draft-02 response field `sec-webtransport-http3-draft`](#2-the-draft-02-response-field) | Chrome | no (`webTransport`) | a field no draft defines |
| 4 | [Pre-IANA `reset_stream_at` codepoint](#4-pre-iana-reset_stream_at-codepoint) | Google QUICHE (knows only this one); quic-go and picoquic send both | no (`resetStreamAt`, on with WebTransport) | a second, unregistered codepoint |
| 9 | [HTTP/2: a stream that depends on itself is a stream error](#9-http2-a-stream-that-depends-on-itself-is-a-stream-error) | h2spec 2.6.0 (RFC 7540 checks); nghttp2 and Go keep the same error | yes (client and server) | retained RFC 7540 error, stricter than RFC 9113 (borderline) |
| T1 | [Interop client: request and FIN in one STREAM frame](#t1-interop-client-request-and-fin-in-one-stream-frame) | quiche's hq server | test only | not shipped in the library |

## 1. WebTransport draft-02 and draft-14

**What it does.** The wire format is draft-ietf-webtrans-http3-17, but a server with WebTransport also announces
`SETTINGS_ENABLE_WEBTRANSPORT=1` (0x2b603742, draft-02 to -06) and `SETTINGS_WT_MAX_SESSIONS=1` (0x14e9cd29, draft-13 and
-14) next to `SETTINGS_WT_ENABLED=1` of draft-17 (0x20b8933b) and draft-16 (0x2c7cf000); a client announces draft-17,
draft-16 and draft-02. Either side recognises the older settings in the peer's SETTINGS; a server takes the `:protocol` token
`webtransport` for a session of draft-02 or draft-14 (and `webtransport-h3` only for draft-16 and draft-17), and a client
talking to a server without draft-16 or draft-17 sends `:protocol webtransport` with `sec-webtransport-http3-draft02: 1`. A draft-02 session has no
`reset_stream_at` (its draft predates RESET_STREAM_AT), so its streams are reset with RESET_STREAM.
`SETTINGS_ENABLE_WEBTRANSPORT` other than 0 or 1 is `H3_SETTINGS_ERROR`, as draft-02 §3.1 requires. Draft-16 is not part
of this shim: it is an earlier draft of the same document, which webtransport-go and picoquic speak, announced under
draft-17 §7.1's own rule.

**Peers.** Chrome 155 and Firefox 158 speak draft-02 ([interop.md](interop.md#interop-webtransport-browsers-2026-10-22-and-2026-10-23),
`ChromeWebTransportTest`, `tools/interop/wt-firefox-manual.sh`); Safari, which shipped WebTransport in 26.4 (March 2026),
speaks draft-14 (Safari 27.2, 2026-11-25: `SETTINGS_WT_MAX_SESSIONS` and `:protocol webtransport`, no draft-02 setting;
[interop.md](interop.md#interop-webtransport-browsers-2026-10-22-and-2026-10-23)). Independently: webtransport-go (2a2b547, 2026-11-09) announces
draft-02's setting "for backwards compatibility with older clients" and `SETTINGS_WT_MAX_SESSIONS` because "Safari
requires SETTINGS_WT_MAX_SESSIONS >= 1 (draft-ietf-webtrans-http3-14)" (`server.go`); picoquic h3zero (f506de8,
2026-11-19) parses all three, "Chrome sends SETTINGS_ENABLE_WEBTRANSPORT (0x2b603742) instead of WT_MAX_SESSIONS"
(`picohttp/h3zero_common.c`). No public source found on 2026-11-24 says a browser ships draft-15 or later.

**Standard text.** draft-17 §7.1: "Draft versions that introduce incompatible changes define distinct SETTINGS_WT_ENABLED
codepoints. Both the client and the server MUST send SETTINGS_WT_ENABLED with the codepoint corresponding to their
supported draft version. An endpoint that supports multiple draft versions sends SETTINGS_WT_ENABLED once for each
distinct codepoint. The highest version supported by both endpoints is selected." §3.1: "For draft versions of
WebTransport only, clients MUST also send SETTINGS_WT_ENABLED for each draft version they support" (see also [the
draft's details](rfc/draft-ietf-webtrans-http3.md#s3-1-settings)). Both older drafts predate `SETTINGS_WT_ENABLED`
(draft-02 signals support with `SETTINGS_ENABLE_WEBTRANSPORT`, draft-14 with `SETTINGS_WT_MAX_SESSIONS`), so announcing
them goes beyond what draft-17 describes, though in the spirit of its §7.1; the codepoints are those of the older drafts.

**Justification (kept, hardening audit 2026-11-21, S1).** draft-ietf-webtrans-http3 §7.1 has endpoints announce every
draft they support; Chrome and Firefox (draft-02) and Safari 26.4+ (draft-14) are the only WebTransport clients in the
field; the whole feature is opt-in (`webTransport`), and draft-02 and draft-14 sessions run their own draft's rules in
full. Draft-17 (November 2026) keeps that model (§7.1 above) and changes nothing for these two drafts. Without the shim
no browser can open a session: a page's `new WebTransport()` rejects, with no fallback. Security impact: none either way.

**Where.** `kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/webtransport/WtVersion.kt:15` (the versions,
`offeredIn` at :63, `WtSettings.ours` at :198, `WtTokens.LEGACY` at :228),
`kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/frame/SettingsCodec.kt:30` and :33 (the codepoints),
`kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/runtime/H3Session.control.kt:427` (the 0-or-1 check),
`kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/webtransport/WtSessionImpl.kt:878` (the client's draft-02
request field).

**On by default.** No: only with `Http3Settings.webTransport` (false by default) or the Ktor server's `webTransport`
(false by default), and on the client per `HttpClient.webTransport` call.

**Tests.** `webtransport.WtDraftVersionsTest.eachDraftClientIsServedInItsDraft`, `.eachDraftServerGetsACONNECTOfItsDraft`,
`webtransport.WebTransportSessionTest.draft02SessionWithoutResetStreamAtResetsWithResetStream`,
`webtransport.WebTransportSettingsTest.serverAdvertisesAllWtCodepoints`, `.clientAdvertisesWtEnabled`,
`.wtSettingsNotSentByDefault`, `.peerVersionIsTheHighestBothAnnounce`, `.negative_clientNeverPicksADraftItDidNotOffer`,
`.negative_draft02SettingAboveOneIsSettingsError`, `webtransport.WebTransportSessionTest.establishLegacyTokenAccepted`,
`.clientUsesLegacyTokenForDraft02Server`, `.draft02ClientWithoutResetStreamAtIsAccepted`;
`ChromeWebTransportTest.chromeDraft02` (opt-in, `-Pkuicksilver.browserTests=true`).

**Risk.** Low. A draft-02 session resets streams with RESET_STREAM, so a reset stream's header can be lost and the peer
may not tie the reset to the session (robustness, not security). draft-02 has no WebTransport flow control: a draft-02
session keeps its connection to itself, and another CONNECT on it is refused with `H3_REQUEST_REJECTED`. draft-14,
draft-16 and draft-17 sessions have it when both sides declare it.

**draft-14 flow control (interop risk, conformant).** draft-14 §5.1 counts "Sending SETTINGS_WT_MAX_SESSIONS with a value
greater than "1"" as declaring flow control, and its `SETTINGS_WT_INITIAL_*` default to 0 (§5.5). A draft-14 client
(Safari) that sends `SETTINGS_WT_MAX_SESSIONS` above 1 and no initial limits therefore gets a session where our side may
open no stream and send no stream data until the client sends WT_MAX_STREAMS and WT_MAX_DATA; one that never does
leaves our sends waiting (we send WT_STREAMS_BLOCKED and WT_DATA_BLOCKED once per limit). We cannot avoid this and
conform. Escape hatch: with all three `Http3Settings.webTransportInitialMax*` at 0 we never declare flow control, and a
connection carries one session, as before pooling. Safari 27.2 does not meet it: it sends `SETTINGS_WT_MAX_SESSIONS=1`
with `SETTINGS_WT_INITIAL_MAX_DATA=8388608` and 100 streams each way, which declare flow control with credit (run of
2026-11-25).

**Removal.** draft-02 when Chrome and Firefox ship draft-15 or later (`SETTINGS_WT_ENABLED`, `webtransport-h3`) by
default; draft-14 when Safari does. Only the two older codepoints, 0x2b603742 and 0x14e9cd29, go with this shim;
0x20b8933b (draft-17's IANA section) and 0x2c7cf000 (draft-16's) are `SETTINGS_WT_ENABLED` of the document itself.

## 2. The draft-02 response field

**What it does.** A server that accepts a CONNECT as a draft-02 session, whose client sent
`sec-webtransport-http3-draft02: 1`, adds `sec-webtransport-http3-draft: draft02` to its 2xx. A session of draft-14,
draft-16 or draft-17 never gets it, whatever the request carried (hardening audit S2: the field was added for the request
field with any value, so a draft-16 session whose `webtransport-h3` CONNECT carried the field was answered with a draft-02
marker; the audit's `== "1"` alone would still have marked that one, so the session's version is checked too). So a
CONNECT carrying the draft-02 request field on a connection whose selected draft is newer gets no response field: in
`webtransport-h3` form it runs that draft without the marker, and in draft-02 form (`webtransport`) it is malformed, as
its token is not the selected draft's ([considered and not listed](#considered-and-not-listed)).

**Peers.** Chrome's draft-02 client refuses a 2xx without it (our `ChromeWebTransportTest`; neither webtransport-go nor
picoquic sends it, and their Chrome interop was not checked).

**Standard text.** None: no draft defines the field. RFC 9110 §5.1 lets a recipient ignore an unknown field, so the field
costs other clients nothing.

**Justification (kept, hardening audit 2026-11-21, S2).** It goes with shim 1: without it Chrome refuses the session.

**Where.** `kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/runtime/ServerRequestStream.kt:801`; the name and
value at `kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/webtransport/WtVersion.kt:234`.

**On by default.** No, as shim 1; then always for a draft-02 session whose client sent the request field's value `1`.

**Tests.** `webtransport.WebTransportSessionTest.establishLegacyTokenAccepted` (checks the field),
`.negative_draft02ResponseFieldOnlyForADraft02Session`, `webtransport.WtDraftVersionsTest.eachDraftClientIsServedInItsDraft`;
`ChromeWebTransportTest.chromeDraft02`, `.chromeWithDraft07EnabledFallsBackToDraft02`.

**Risk.** None known: a fixed value, sent only to a client that asked in draft-02 form and runs draft-02.

**Removal.** With draft-02 (shim 1).

## 4. Pre-IANA `reset_stream_at` codepoint

**What it does.** With `QuicConfig.resetStreamAt` the transport parameter is sent twice, as 0x1d and as
0x17f7586d2cb571, the codepoint of earlier versions of the draft, and either one received enables RESET_STREAM_AT (a
non-empty value of either is `TRANSPORT_PARAMETER_ERROR`).

**Peers.** Google QUICHE, Chromium's QUIC, knows only the old codepoint (hardening audit 2026-11-21, S4, from QUICHE's
GitHub head 35cbd037 of 2026-11-05: `quiche/quic/core/crypto/transport_parameters.cc:104`, `kReliableStreamReset =
0x17F7586D2CB571`, sent at :1112-1119 and parsed at :1521-1527; frame 0x24 in `quic_types.h:367`; off by default,
`quic_config.cc:1062`, and turned on by the embedder; Chrome's own setting was not checked). With 0x1d alone a
QUICHE-based peer never enables RESET_STREAM_AT, and WebTransport draft-14 and later to it fails §3.1. quic-go (df125bc)
sends and accepts both codepoints (`internal/wire/transport_parameters.go:50`, :54, :211, :457-461); picoquic (f506de8)
too, "Advertise both codepoints until peers that only know draft-07 are gone" (`picoquic/transport.c:483-488`, :946-954).
Cloudflare quiche 4ebd213 implements neither codepoint; ngtcp2 does not implement RESET_STREAM_AT.

**Standard text.** draft-ietf-quic-reliable-stream-reset-11 §3: "Support for receiving RESET_STREAM_AT frames is
advertised by sending the reset_stream_at (0x1d) transport parameter (Section 7.4 of [RFC9000]) with an empty value." The
old codepoint is not registered; RFC 9000 §7.4.2, "An endpoint MUST ignore transport parameters that it does not
support", keeps it harmless to peers that do not know it. Draft-11 (September 2026, the latest on 2026-11-24, cited by
WebTransport draft-17) keeps 0x1d and frame type 0x24.

**Justification (kept, hardening audit 2026-11-21, S4).** Google QUICHE (Chromium) knows only 0x17f7586d2cb571; quic-go
and picoquic announce and accept both; RFC 9000 §7.4.2 makes the extra codepoint inert for everyone else.

**Where.** `kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/wire/TransportParametersCodec.kt:44` (the
codepoint), :133 (sent), :332 (accepted).

**On by default.** No: `QuicConfig.resetStreamAt` is false by default; WebTransport turns it on (server and client).

**Tests.** `wire.TransportParametersTest.resetStreamAtBothCodepoints`.

**Risk.** Low: nine more bytes in the transport parameters, and RESET_STREAM_AT frames (type 0x24) toward a peer that
announced only the old codepoint, which must then read them as that draft's frame.

**Removal.** When Google QUICHE accepts 0x1d (and quic-go and picoquic, which keep both for the same reason, drop the old
one). The removal must mind remembered transport parameters: a client that remembered `reset_stream_at` from a server
that sent only the old codepoint would take that server's next 0-RTT acceptance for a lowered capability and close with
PROTOCOL_VIOLATION (`kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/core/ZeroRtt.kt:273`); quic-go ties its
own removal to a new ticket format for the same reason.

## 9. HTTP/2: a stream that depends on itself is a stream error

Borderline: stricter, not lenient. A retained RFC 7540 error, as the reference stacks keep it, rather than a shim for a
test tool; listed because RFC 9113 dropped the rule.

**What it does.** A HEADERS frame whose priority fields make the stream depend on itself, or a PRIORITY frame that does,
is a stream error of type PROTOCOL_ERROR; every other RFC 7540 priority signal is parsed and ignored. Each of the three
checks (HEADERS opening a stream, HEADERS on an open stream, PRIORITY) runs only while the peer has not sent
SETTINGS_NO_RFC7540_PRIORITIES = 1 (after it, RFC 9218 §2.1: "MUST ignore HTTP/2 priority signals").

**Peers.** h2spec 2.6.0, whose http2/5.3.1 cases ("Sends HEADERS frame that depends on itself", "Sends PRIORITY frame
that depend on itself") expect the RFC 7540 error
([interop.md](interop.md#h2spec-the-http2-server-h2spec-260-2026-11-06): 146 of 146 cases must pass). No real peer sends a
self-dependency. The reference stacks still reject one: Go with a stream PROTOCOL_ERROR on HEADERS and PRIORITY
(`x/net/http2/server.go`, quoting RFC 7540), nghttp2 with a connection error on request HEADERS
(`lib/nghttp2_session.c`); a stream error sits between the two.

**Justification (kept, QUIC and HTTP/2 hardening 2026-11-24).** RFC 9113 §5.3.2 keeps RFC 7540 priority handling for
interoperability; nghttp2 and Go still treat a self-dependency as an error; it can only affect a peer that already broke
RFC 7540.

**Standard text.** RFC 7540 §5.3.1 made it an error. RFC 9113 §5.3.2: "This update to HTTP/2 deprecates the priority
signaling defined in RFC 7540 [RFC7540]. The bulk of the text related to priority signals is not included in this
document. The description of frame fields and some of the mandatory handling is retained to ensure that implementations
of this document remain interoperable with implementations that use the priority signaling described in RFC 7540." RFC
9113 has no self-dependency rule (§6.3 keeps only the stream 0 and frame length errors).

**Where.** `kuicksilver-http2/src/commonMain/kotlin/io/kuicksilver/http2/core/H2ConnectionCore.frames.kt:158` (HEADERS
opening a stream), :203 (HEADERS on an open stream), :289 (PRIORITY).

**On by default.** Yes; no switch.

**Tests.** `core.StreamStateTest.negative_selfDependencyIsStreamError`; h2spec (`tools/interop/h2spec.sh`).

**Risk.** None for security: only the offending stream is reset. An RFC 9113 peer that sent such a signal (RFC 7540
forbade it, so none should) would lose that stream.

**Removal.** When h2spec drops its RFC 7540 §5.3.1 cases and the reference stacks drop the error, or if a peer is found
that sends such signals.

## Test-only

### T1. Interop client: request and FIN in one STREAM frame

Not a deviation: ordinary coalescing in test code, listed for the peer whose behaviour it works around.

**What it does.** The QUIC Interop Runner client writes each `hq-interop` request into the stream's buffer and closes it
in one step, so the request and its FIN share one STREAM frame. The library's `flushAndClose` hands buffered data to the
core with the FIN for every application (`api.StreamBridgeTest.flushAndCloseSendsDataAndFinInOnePacket`); that is
ordinary coalescing and not a shim.

**Peers.** quiche's hq server left 0-RTT requests whose FIN arrived in a frame of its own unanswered
(`quiche->kuicksilver:zerortt`, [interop.md](interop.md#interop-matrix-020-quic-interop-runner-740c05a-2026-10-13)).

**Standard text.** RFC 9000 §19.8: a STREAM frame's FIN "marks the end of the stream"; nothing requires it to travel with
the data.

**Where.** `kuicksilver-interop/src/commonMain/kotlin/io/kuicksilver/interop/HqInteropClient.kt:123` (`request`).

**On by default.** Interop images only; not in any published artifact.

**Tests.** The runner's `zerortt` case against quiche (`tools/interop/required.json`).

**Risk.** None: test code.

**Removal.** When quiche's hq server answers a request whose FIN comes alone.

## Removed

- **Draft-02 session when a newer draft lacks `reset_stream_at`** (shim 3, 0.3.0; its number is kept free). A client that
  announced a newer WebTransport draft without the `reset_stream_at` transport parameter but also draft-02 got a draft-02
  session when its CONNECT was a draft-02 request, and our client sent such a CONNECT to such a server; a draft-02 request
  ran draft-02 even when a higher common version could run. That read draft-17 §7.1's "The highest version supported by
  both endpoints is selected" as the highest both can run, and let the request's form pick the version, where §7.1
  selects from the client's SETTINGS and §3.1 makes every session malformed when the transport parameters are missing.
  It was kept for Safari (second-hand); hardening audit 2026-11-21 (S3) removed it on one Safari run that shows Safari
  sends `reset_stream_at`. Safari 27.2 (macOS 26.7.2, 2026-11-25) sends it: the server's qlog records it among Safari's
  transport parameters (`transport:parameters_set`, owner remote, with `max_datagram_frame_size` 65535), and Safari ran
  every step of the page in a draft-14 session on a build without the fallback
  ([interop](interop.md#interop-webtransport-browsers-2026-10-22-and-2026-10-23), the Safari row). Now the highest
  common version runs or nothing does —
  `webtransport.WebTransportSessionTest.negative_withoutResetStreamAtBothSidesNoSessionIsOpened`,
  `.negative_draft16And02ClientWithoutResetStreamAtIsMalformedInDraft02FormToo`,
  `.negative_draft02FormConnectOnANewerDraftIsMalformed`.
- **msquic's provisional Initial SCID** (shim 5, 0.3.0; its number, like those of shims 6 and 7, now under "Considered and not listed", is kept free so the anchors of the others stay). The
  client processed an Initial with nothing but ACK, PING and PADDING whose SCID was the DCID it sends to without letting
  it fix the server's SCID, so that an msquic server, which sends from the client's DCID until its listener accepts the
  connection and then switches to a new SCID that it also names in `initial_source_connection_id`, could finish the
  handshake. That departed from both MUSTs of RFC 9000 §7.2 ("MUST discard any subsequent packet it receives on that
  connection with a different Source Connection ID"; "MUST change the Destination Connection ID [...] in response to
  only the first received Initial or Retry packet") and, in effect, from §7.3. The client is now strict, as quic-go,
  ngtcp2, quinn and picoquic are: such a handshake fails (msquic#3762, #4905) and the Ktor client goes over TCP
  ([details](rfc/9000.md#s7-2-the-servers-source-connection-id-is), [interop](interop.md)) —
  `core.ReceivePathTest.negative_msquicProvisionalScidFailsTheHandshakeAtOnceAndSilently`.
- **SOCKS5 username/password reply with VER 5** (shim 8, 0.3.0; its number is kept free). The reply to the RFC 1929
  subnegotiation was accepted with VER 5 (the SOCKS version) as well as X'01', as curl does (it ignores the byte); no
  proxy that needs it was ever named. RFC 1929 §2: "The VER field contains the current version of the subnegotiation,
  which is X'01'"; Go's x/net/internal/socks refuses any other value too. Any VER but 1 now fails the connection with
  `ProxyException` before the CONNECT is sent — `h1.Socks5Test.negative_authReplyVersionMustBe1`. Should a real proxy
  need it, it would come back as an opt-in.
- **`Proxy-Connection: Keep-Alive` on CONNECT** (0.3.0). The CONNECT that opens a tunnel through an HTTP proxy carried the
  field for HTTP/1.0 proxies, as OkHttp 5.3.2 does (`RealRoutePlanner`, "For HTTP/1.0 proxies like Squid"), against RFC
  9112 appendix C.2.2: "clients are encouraged not to send the Proxy-Connection header field in any requests". No peer
  was recorded that needed it, and a CONNECT tunnel does not depend on keep-alive; the CONNECT now carries none —
  `ClientProxyTest.negative_connectCarriesNoProxyConnection`.

## Considered and not listed

- **Either WebTransport `:protocol` token for any draft** (webtransport-go accepts both, `isWebTransportProtocol` in
  `protocol.go`; picoquic too, "we need to be lenient and treat both versions as equivalent", `h3zero_common.c`): not
  kept. Each draft names its token (draft-16 and draft-17 §3.2, "the :protocol pseudo-header field MUST be set to
  webtransport-h3"; draft-02 and draft-14, `webtransport`), and every known client sends its own draft's: Chrome and
  Firefox draft-02 with `webtransport`, Safari draft-14 with `webtransport`, webtransport-go, picoquic and Kuicksilver
  draft-16 or draft-17 with `webtransport-h3`. A CONNECT whose token is not the selected draft's is malformed (400,
  `H3_MESSAGE_ERROR`) — `webtransport.WtDraftVersionsTest.negative_tokenOfAnotherDraftIsMalformed`.
- **Discarding later long-header packets with another SCID** (an msquic server's ServerHello after its provisional SCID
  among them): the RFC 9000 §7.2 MUST itself.
- **TLS 1.2** (`TlsVersions.Tls12And13`, for peers without 1.3 such as old Android and JDK stacks): off by default, and RFC
  9325 §3.1.1 says "Implementations MUST support TLS 1.2"; Extended Master Secret is required, so legacy peers are refused
  as RFC 7627 §5.2 allows. No cipher suite, version or renegotiation is relaxed for old stacks.
- **X25519 in the server's first key-share preference** (ngtcp2 and others offer X25519 shares only): a default within RFC
  9846's group selection, saving a HelloRetryRequest.
- **The ALPN of a ticket received on a resumed connection** (`ksl_ssl.c`, OpenSSL 3.5 copies the resumed session's ALPN;
  fixed in OpenSSL 4.1): a fix of our own TLS library's behaviour so that we follow RFC 8446 §4.2.10, not a peer.
- **The client's remembered RTT per server** (quic-go drops a silent half-open connection after 5 s): RFC 9002 §6.2.2,
  "MAY use the previous connection's final smoothed RTT".
- **Following a client's NAT rebind during the handshake** (interop rebind cases with quiche and picoquic): RFC 9000 §9
  lets a server "proceed with path validation and allow the peer to migrate".
- **Probing the other packet number spaces on a PTO** (quic-go `handshakeloss` stalls): RFC 9002 §6.2.4 SHOULD.
- **A resent STREAM range never carries the FIN** (was shim 6; quiche): a lost range of stream data is resent without
  the FIN, a FIN still in flight needs no copy and a lost one goes as an empty STREAM frame with the FIN
  (`kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/stream/SendStream.kt`, `nextRange`;
  `stream.SendStreamTest.retransmittedDataDoesNotCarryAFinThatIsStillInFlight`, `.lostDataAndLostFinGoAsDataThenAnEmptyFin`).
  RFC 9000 §2.2 and §19.8 leave the FIN's placement to the sender, so this is a sender choice, not a deviation; quic-go,
  ngtcp2 and picoquic resend the original frame, FIN included, which conforms as well. It was made for quiche's receiver,
  which took the final size from a frame whose bytes it had already read, dropped the frame as a duplicate and never woke
  the application for the FIN (`kuicksilver->quiche:handshakeloss` lost one request in 50, run 20261015-170940); quiche
  4ebd213 (2026-10-27) keeps that FIN (`RecvBuf::write`, test `duplicate_data_first_fin`). The cost is one small frame
  per lost FIN. The special case may go once the interop runner's quiche image has that change and
  `kuicksilver->quiche:handshakeloss` and `:transferloss` (required in `tools/interop/required.json`) stay green without it
  over several runs.
- **No glitch token for repeated MAX_STREAMS or DATA_BLOCKED** (quic-go, quiche): legal peer behaviour handled correctly.
- **One lost range queued once** (quiche fails the handshake on bytes repeated in one packet): sending each byte once
  per packet is plain efficiency.
- **WebTransport: reading what arrived before CONNECTION_CLOSE** (Firefox's `WT_CLOSE_SESSION`) and **waiting for the
  peer's FIN before STOP_SENDING on close** (Chrome): correct handling of legal behaviour and a timing choice within the
  draft's close procedure.
- **HTTP/1.1 parsing the RFCs allow or require**, by side:
  - obs-fold: the client replaces it with SP in a response head and a trailer section (RFC 9112 §5.2: a user agent MUST);
    the server rejects it with 400 in a request head and a trailer section (§5.2 lets it reject or replace);
  - a bare LF as a line end (§2.2 MAY): the client takes it in a response head and a trailer section, kept on purpose: the
    client is the final recipient, so no second parser behind it can read the line otherwise, and Go and curl do the
    same; the server refuses it (400) unless the application sets `h1AllowBareLf`, since a server sits behind proxies
    (§11.2), as llhttp; the chunk-size line takes CRLF alone on both sides;
  - the request-line whitespace §3 lets a recipient accept (HTAB, VT, FF, a bare CR as SP, whitespace around the line): not
    accepted since 0.3.0, the server takes exactly one SP, as Go and llhttp;
  - the status line without the SP before an absent reason phrase (`HTTP/1.1 204`, was shim 7): the client accepts it. A
    server MUST send that SP, but §4 says "recipients MAY instead parse on whitespace-delimited word boundaries and,
    aside from the line terminator, treat any form of whitespace as the SP separator while ignoring preceding or
    trailing whitespace", and word-boundary parsing takes exactly this line; Go, curl ("the browsers do not so let's not
    insist") and OkHttp accept it, llhttp does not. The rest of the status line is strict (`HTTP/1.x SP 3DIGIT`), so the
    leniency cannot shift the status code or the framing
    (`h1.H1ResponseHeadTest.statusLineWithoutReasonPhraseIsAccepted`; a numbered shim until 0.3.0);
  - Content-Length as a list of equal values or repeated equal lines: both sides take it as one length (§6.3 item 5 and
    RFC 9110 §8.6 allow it; Go takes repeats only, curl both, llhttp neither); unequal values fail;
  - Transfer-Encoding with Content-Length: the client frames by the coding and does not reuse the connection (§6.3 item 3,
    "ought to be handled as an error"), as Go and curl; the server answers 400 and closes (§6.1);
  - Transfer-Encoding in an HTTP/1.0 message: the client reads the body until the close and does not reuse the connection,
    the server answers 400 (§6.1 MUST treat the framing as faulty);
  - the server's 301 for an invalid origin-form target (§3.2), a higher minor version processed as HTTP/1.1 (RFC 9110 §6.2
    SHOULD, both sides), and the client's invalid status code read as a 5xx (RFC 9110 §15 SHOULD).
  Where Ktor's own parser is more lenient (Unicode spaces, control characters, field names, chunk-size lines), both engines
  are stricter; nothing lenient is added for any client.
- **HTTP/2: a client's GOAWAY is not checked for parity** (Go's `ClientConn.Shutdown`, `x/net/http2/transport.go`
  `sendGoAway`, sends its own next, odd, stream identifier): peer tolerance, not a deviation. RFC 9113 §6.8 defines the
  last stream identifier as one the receiver initiated but gives the receiver no rule for another value, and §5.4.1 only
  permits an error. The server still refuses a GOAWAY that raises the identifier ("MUST NOT increase"), and the client
  refuses a server's GOAWAY that names an even stream, as nghttp2 does; a server's value names pushes, which we never make,
  and refusing Go's would reset the requests its shutdown waits for ([details](rfc/9113.md#s6-8-goaway)).
- **SOCKS5 empty password**: refused (RFC 1929 §2, PASSWD has 1 to 255 octets), stricter than curl and Go.
- **Greasing** (`Http3Settings.grease`, `grease_quic_bit`): excluded by definition.
- **Android API levels** (`java.nio.file`, `DnsResolver.rawQuery`): platform APIs, not a peer's protocol.
- **The interop runner's trust** (`InteropTrust`, `KSL_INTEROP_EXPECTED_NAME`): the runner's self-signed test
  certificates, test code.
- **Values borrowed from other implementations** (0-RTT buffering as quic-go, keep-alive periods, token store sizes,
  limits after nghttp2 and Go): defaults, not departures.
