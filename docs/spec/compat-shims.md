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
| 3 | [Draft-02 session when a newer draft lacks `reset_stream_at`](#3-draft-02-session-when-a-newer-draft-lacks-reset_stream_at) | none verified (Safari was expected; removal waits for one Safari run) | no (`webTransport`) | beyond draft-17 §7.1 |
| 4 | [Pre-IANA `reset_stream_at` codepoint](#4-pre-iana-reset_stream_at-codepoint) | Google QUICHE (Chromium's QUIC) | no (`resetStreamAt`, on with WebTransport) | a second, unregistered codepoint |
| 6 | [A resent STREAM range never carries the FIN](#6-a-resent-stream-range-never-carries-the-fin) | quiche | yes | sender choice inside RFC 9000 (borderline) |
| 7 | [HTTP/1.1 status line without the SP before an absent reason](#7-http11-status-line-without-the-sp-before-an-absent-reason) | servers that break RFC 9112 §4 | yes (client) | lenient parsing the RFC allows (borderline) |
| 8 | [SOCKS5 username/password reply with VER 5](#8-socks5-usernamepassword-reply-with-ver-5) | some SOCKS5 proxies | yes (client) | accepts a value RFC 1929 does not define |
| 9 | [HTTP/2: a stream that depends on itself is a stream error](#9-http2-a-stream-that-depends-on-itself-is-a-stream-error) | h2spec 2.6.0 (RFC 7540 checks) | yes (client and server) | stricter than RFC 9113 (borderline) |
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
speaks draft-14 (second-hand, not run or verified here). Independently: webtransport-go (2a2b547, 2026-11-09) announces
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
`offeredIn` at :55, `WtSettings.ours` at :203, `WtTokens.LEGACY` at :233),
`kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/frame/SettingsCodec.kt:30` and :33 (the codepoints),
`kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/runtime/H3Session.control.kt:407` (the 0-or-1 check),
`kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/webtransport/WtSessionImpl.kt:787` (the client's draft-02
request field).

**On by default.** No: only with `Http3Settings.webTransport` (false by default) or the Ktor server's `webTransport`
(false by default), and on the client per `HttpClient.webTransport` call.

**Tests.** `webtransport.WtDraftVersionsTest.eachDraftClientIsServedInItsDraft`, `.eachDraftServerGetsACONNECTOfItsDraft`,
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
connection carries one session, as before pooling. Not observed with a real Safari yet: a release-checklist item.

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
its token is not the selected draft's ([considered and not listed](#considered-and-not-listed)); only while shim 3 lasts
does a draft-02 request from a client that also announces draft-02 run draft-02, and get the field.

**Peers.** Chrome's draft-02 client refuses a 2xx without it (our `ChromeWebTransportTest`; neither webtransport-go nor
picoquic sends it, and their Chrome interop was not checked).

**Standard text.** None: no draft defines the field. RFC 9110 §5.1 lets a recipient ignore an unknown field, so the field
costs other clients nothing.

**Justification (kept, hardening audit 2026-11-21, S2).** It goes with shim 1: without it Chrome refuses the session.

**Where.** `kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/runtime/ServerRequestStream.kt:795`; the name and
value at `kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/webtransport/WtVersion.kt:239`.

**On by default.** No, as shim 1; then always for a draft-02 session whose client sent the request field's value `1`.

**Tests.** `webtransport.WebTransportSessionTest.establishLegacyTokenAccepted` (checks the field),
`.negative_draft02ResponseFieldOnlyForADraft02Session`, `webtransport.WtDraftVersionsTest.eachDraftClientIsServedInItsDraft`;
`ChromeWebTransportTest.chromeDraft02`, `.chromeWithDraft07EnabledFallsBackToDraft02`.

**Risk.** None known: a fixed value, sent only to a client that asked in draft-02 form and runs draft-02.

**Removal.** With draft-02 (shim 1).

## 3. Draft-02 session when a newer draft lacks `reset_stream_at`

Borderline: beyond the draft's version selection, made for one browser. The hardening audit (2026-11-21, S3) decided to
remove it once one Safari 26.4 or later run confirms that Safari sends `reset_stream_at`; the removal is prepared and
waits for that run (open item below).

**What it does.** draft-14, draft-16 and draft-17 need `reset_stream_at` on both sides. Two behaviours are bundled:
(a) a client that announces a newer draft without the transport parameter but also draft-02 gets a draft-02 session when
its CONNECT is a draft-02 request (`:protocol webtransport` with `sec-webtransport-http3-draft02: 1`); its newer-draft
CONNECT is refused (400 and `H3_MESSAGE_ERROR`). Our client does the same against such a server: it sends a draft-02
CONNECT. (b) A server runs draft-02 for any draft-02 request from a client that announces draft-02, even when a higher
common version could run.

**Peers.** None verified. Safari was the expected one (second-hand), but WebKit bug 303152 (RESET_STREAM_AT sent and
received, fixed 2025-12-02) and bug 305006 (2026-01-07) landed before Safari 26.4, the first release with WebTransport,
so a shipping Safari most likely sends `reset_stream_at`. webtransport-go refuses to run without it
(`EnableStreamResetPartialDelivery`, `server.go`, `client_conn.go`); picoquic has no such fallback.

**Standard text.** draft-17 §7.1 now spells out the server's selection: "If the client sends the codepoint in Section
9.2, the server selects the version described in this document. Otherwise, if the client sends codepoints for draft
versions that the server supports, the server selects the highest of those versions"; §3.1: "If the server receives ...
transport parameters that do not have correct values for every required transport parameter, the server MUST treat all
established and newly incoming WebTransport sessions as malformed". Both (a), which reads "the highest version
supported by both endpoints" as the highest both can run, and (b), which lets the request's form pick the version, go
beyond that text: draft-17 makes the shim a clearer departure than draft-16 did, and changes nothing in the audit's
decision to remove it.

**Where.** `kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/webtransport/WtVersion.kt:120` (`wtClientVersion`)
and :137 (`wtServerVersion`).

**On by default.** No, as shim 1.

**Tests.** `webtransport.WebTransportSessionTest.withoutResetStreamAtBothSidesFallBackToDraft02`,
`.draft16And02ClientWithoutResetStreamAtIsAcceptedAsDraft02`,
`.negative_draft16ConnectWithoutResetStreamAtIsMalformedEvenWithDraft02Offered`,
`webtransport.WebTransportSettingsTest.draft14And02ServerWithoutResetStreamAtGetsADraft02Connect`.

**Risk.** Low: the session runs draft-02 in every respect (shim 1's risk); a newer-draft session is never run without the
transport parameter its §3.1 requires.

**Removal.** Decided (audit S3): pick the highest common version; if the transport cannot carry it, the session is
malformed. It waits for one Safari 26.4+ run ([interop.md](interop.md#interop-webtransport-browsers-2026-10-22-and-2026-10-23),
the Safari row) that shows its SETTINGS and transport parameters: Safari sends `reset_stream_at` (0x1d or
0x17f7586d2cb571) → remove; it does not → keep, and name Safari here as the verified peer.

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

**Where.** `kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/wire/TransportParametersCodec.kt:43` (the
codepoint), :132 (sent), :331 (accepted).

**On by default.** No: `QuicConfig.resetStreamAt` is false by default; WebTransport turns it on (server and client).

**Tests.** `wire.TransportParametersTest.resetStreamAtBothCodepoints`.

**Risk.** Low: nine more bytes in the transport parameters, and RESET_STREAM_AT frames (type 0x24) toward a peer that
announced only the old codepoint, which must then read them as that draft's frame.

**Removal.** When Google QUICHE accepts 0x1d (and quic-go and picoquic, which keep both for the same reason, drop the old
one). The removal must mind remembered transport parameters: a client that remembered `reset_stream_at` from a server
that sent only the old codepoint would take that server's next 0-RTT acceptance for a lowered capability and close with
PROTOCOL_VIOLATION (`kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/core/ZeroRtt.kt:273`); quic-go ties its
own removal to a new ticket format for the same reason.

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

**Where.** `kuicksilver-quic/src/commonMain/kotlin/io/kuicksilver/quic/stream/SendStream.kt:203-206`.

**On by default.** Yes; no switch.

**Tests.** `stream.SendStreamTest.retransmittedDataDoesNotCarryAFinThatIsStillInFlight`,
`.lostDataAndLostFinGoAsDataThenAnEmptyFin`.

**Risk.** None for security; a lost FIN costs one small frame more.

**Removal.** quiche has the fix: `RecvBuf::write` in `quiche/src/stream/recv_buf.rs` (4ebd213, 2026-10-27) keeps the
first FIN of a frame whose bytes were already read ("Discard consumed data unless it carries the first FIN"), pinned by
its test `duplicate_data_first_fin`. The shim can go once the interop runner's quiche image includes that change and
`kuicksilver->quiche:handshakeloss` (the case that lost a request; required in `tools/interop/required.json`) stays
green without the shim over several runs, as does `kuicksilver->quiche:transferloss`, which resends stream data too.

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

## 9. HTTP/2: a stream that depends on itself is a stream error

Borderline: stricter, not lenient, and kept for a test tool built on the older RFC rather than for a peer; listed
because it goes beyond RFC 9113 only to keep that check passing.

**What it does.** A HEADERS frame whose priority fields make the stream depend on itself, or a PRIORITY frame that does,
is a stream error of type PROTOCOL_ERROR; every other RFC 7540 priority signal is parsed and ignored. Each of the three
checks (HEADERS opening a stream, HEADERS on an open stream, PRIORITY) runs only while the peer has not sent
SETTINGS_NO_RFC7540_PRIORITIES = 1 (after it, RFC 9218 §2.1: "MUST ignore HTTP/2 priority signals").

**Peers.** h2spec 2.6.0, whose http2/5.3.1 cases ("Sends HEADERS frame that depends on itself", "Sends PRIORITY frame
that depend on itself") expect the RFC 7540 error
([interop.md](interop.md#h2spec-the-http2-server-h2spec-260-2026-11-06): 146 of 146 cases must pass).

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

**Removal.** When h2spec drops its RFC 7540 §5.3.1 cases, or if a peer is found that sends such signals.

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

**Where.** `kuicksilver-interop/src/commonMain/kotlin/io/kuicksilver/interop/HqInteropClient.kt:123` (`request`).

**On by default.** Interop images only; not in any published artifact.

**Tests.** The runner's `zerortt` case against quiche (`tools/interop/required.json`).

**Risk.** None: test code.

**Removal.** When quiche's hq server answers a request whose FIN comes alone.

## Removed

- **msquic's provisional Initial SCID** (shim 5, 0.3.0; its number is kept free so the anchors of the others stay). The
  client processed an Initial with nothing but ACK, PING and PADDING whose SCID was the DCID it sends to without letting
  it fix the server's SCID, so that an msquic server, which sends from the client's DCID until its listener accepts the
  connection and then switches to a new SCID that it also names in `initial_source_connection_id`, could finish the
  handshake. That departed from both MUSTs of RFC 9000 §7.2 ("MUST discard any subsequent packet it receives on that
  connection with a different Source Connection ID"; "MUST change the Destination Connection ID [...] in response to
  only the first received Initial or Retry packet") and, in effect, from §7.3. The client is now strict, as quic-go,
  ngtcp2, quinn and picoquic are: such a handshake fails (msquic#3762, #4905) and the Ktor client goes over TCP
  ([details](rfc/9000.md#s7-2-the-servers-source-connection-id-is), [interop](interop.md)) —
  `core.ReceivePathTest.negative_msquicProvisionalScidFailsTheHandshakeAtOnceAndSilently`.
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
