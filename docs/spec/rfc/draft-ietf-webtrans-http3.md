<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# draft-ietf-webtrans-http3 — WebTransport over HTTP/3 (draft-ietf-webtrans-http3-16)

Details of the rows of the [RFC compliance summary](../rfc-compliance.md) for this document. Each section gives the requirement, how Kuicksilver meets it (with the files), the tests that pin it, its history, notes on peers and the open items. Status: ✅ met · 🔶 feature subset or accepted deviation · ⬜ planned · ❌ not planned; "since" is the release from which the current behaviour holds (history below and in [CHANGELOG.md](../../../CHANGELOG.md)).

## <a id="webtransport"></a>WebTransport

Status: ✅ since 0.3.0 · [summary](../rfc-compliance.md#http)

Original row: draft-ietf-webtrans-http3.

**Requirement.** WebTransport.

**Recorded status.** ✅ 0.3.0 (experimental)

**How it is met.**

- per-section rows below

**Scope.** Experimental (the draft can still change). WebTransport flow control (§5) and several sessions per
connection (pooling) with fair turns between them (§8), on both sides ([flow-control row](#s5-flow-control)); without
flow control, which a peer may leave off, one session per connection (§5.1, §5.2; sessions row). No keying-material
exporter API: §4.8 applies only "If the application requests an exporter for a given WebTransport session".

**Peer interop notes.**

- draft-16 on the wire, the codepoints of draft-02 and draft-14 accepted for browsers ([compatibility shims](../compat-shims.md#1-webtransport-draft-02-and-draft-14), shims 1 to 3)
- Safari speaks draft-14 (second-hand), which needs `reset_stream_at` on both sides; WebKit bugs 303152 and 305006 suggest Safari 26.4 and later sends it (not verified here: the Safari check in [interop.md](../interop.md) is not run yet); a Safari that announces draft-02 too but not `reset_stream_at` gets a draft-02 session when its CONNECT is a draft-02 request, while its draft-14 CONNECT, or one from a Safari that announces draft-14 alone, is refused

**Open items.** None.

## <a id="s3-1-settings"></a>§3.1, §7.1 — SETTINGS

Status: ✅ since 0.3.0 · [summary](../rfc-compliance.md#http)

Original row: draft-ietf-webtrans-http3-16 §3.1, §7.1 (SETTINGS).

**Requirement.** With `Http3Settings.webTransport` (needs `enableConnectProtocol` and `h3Datagram`; `Http3Endpoint.bind` refuses it without QUIC datagrams and turns `QuicConfig.resetStreamAt` on) a server sends `SETTINGS_WT_ENABLED=1` (0x2c7cf000), `SETTINGS_WT_MAX_SESSIONS` (0x14e9cd29, draft-14: `webTransportMaxSessions` with flow control, else 1) and `SETTINGS_ENABLE_WEBTRANSPORT=1` (0x2b603742, draft-02), a client the first and the last.

**Recorded status.** ✅ 0.3.0

Quoted (§3.1): "WebTransport over HTTP/3 relies on the RESET_STREAM_AT frame defined in [RESET-STREAM-AT]. To indicate support, both the client and the server enable the extension by sending an empty reset_stream_at transport parameter"; "A client MUST NOT establish WebTransport sessions if the server's SETTINGS do not have correct values for every required setting or if the server's transport parameters do not have correct values for every required transport parameter"; "the server MUST treat all established and newly incoming WebTransport sessions as malformed".

**How it is met.**

- the transport parameters of §3.1: `max_datagram_frame_size` above 0 (`webTransport` is refused without it) and an empty `reset_stream_at`, which `Http3Endpoint` (`connect`, `connectEarly`, `bind`) and the Ktor engines turn on with `webTransport`
- the version is the highest both sides announce (§7.1 "The highest version supported by both endpoints is selected"; our client announces draft-16 and draft-02, so it never picks a draft it did not offer, and against a draft-14-only server it has none in common and throws `Http3Exception.Settings`)
- a session is opened (client) or accepted (server) only when the peer sent every required setting and transport parameter of that version: draft-16 and draft-14 need the peer's `max_datagram_frame_size` above 0 and `reset_stream_at` on both sides (`QuicConnection.resetStreamAtEnabled`); draft-02 (Chrome, Firefox) predates RESET_STREAM_AT and needs no `reset_stream_at` (draft-02 §3.1 asks for `SETTINGS_ENABLE_WEBTRANSPORT` only)
- a peer that announces a newer draft without its §3.1 transport parameters but also draft-02 gets a draft-02 session when its CONNECT is a draft-02 request (`:protocol webtransport` with `sec-webtransport-http3-draft02: 1`; our client sends one then); this fallback is our reading of §7.1 ("the highest version supported by both endpoints" taken as the highest version both can actually run), not text of the draft; the server judges the request, not the SETTINGS alone: a draft-16 or draft-14 CONNECT from that peer would be a session that broke §3.1 and could not reset as §4.4 requires, so it is malformed, as is any CONNECT from a peer that announces only the newer draft: the client throws `Http3Exception.Settings` before any CONNECT, and the server treats the request as malformed (sessions row)
- `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI` (0x2b64), `_BIDI` (0x2b65) and `SETTINGS_WT_INITIAL_MAX_DATA` (0x2b61) from `Http3Settings.webTransportInitialMaxStreamsUni` / `Bidi` / `MaxData`, sent when not 0, which turns flow control on with a peer that declares it too ([flow-control row](#s5-flow-control))
- the peer's codepoints become `Http3PeerSettings.webTransport` and the highest draft it speaks, and leave `unknown`
- `SETTINGS_WT_ENABLED` other than 0 or 1 → `H3_SETTINGS_ERROR`; with `webTransport`, `SETTINGS_ENABLE_WEBTRANSPORT` (draft-02) other than 0 or 1 too (draft-02 §3.1 "an endpoint that receives a value other than "0" or "1" MUST close the connection with the H3_SETTINGS_ERROR error code")
- the 0-RTT ticket context covers the setting

**Tests that pin it.**

- `webtransport.WebTransportSettingsTest.*` (including `negative_wtEnabledAboveOneIsSettingsError`, `negative_draft02SettingAboveOneIsSettingsError`, `negative_webTransportWithoutQuicDatagramsRefused`, `endpointTurnsResetStreamAtOnForWebTransport`), `webtransport.WebTransportSessionTest.negative_wtWithoutServerResetStreamAtFails`, `.negative_acceptWithoutClientResetStreamAtIsMalformed`, `.draft02ClientWithoutResetStreamAtIsAccepted`, `.withoutResetStreamAtBothSidesFallBackToDraft02`, `.draft16And02ClientWithoutResetStreamAtIsAcceptedAsDraft02`, `.negative_draft16ConnectWithoutResetStreamAtIsMalformedEvenWithDraft02Offered`, `webtransport.WebTransportSettingsTest.peerVersionIsTheHighestBothAnnounce`, `.negative_clientNeverPicksADraftItDidNotOffer`, `.draft14And02ServerWithoutResetStreamAtGetsADraft02Connect`, `api.StreamBridgeTest.resetStreamAtEnabledWhenBothSidesAdvertiseIt` (QUIC)

**Open items.** None.

## <a id="s3-2-sessions"></a>§3.2, §3.3, §3.4, §5.1, §5.2, §7.1 — sessions

Status: ✅ since 0.3.0 · [summary](../rfc-compliance.md#http)

Original row: draft-ietf-webtrans-http3-16 §3.2, §3.3, §5.1, §5.2, §7.1 (sessions); §3.4 added in 0.3.0.

**Requirement.** Client `Http3Connection.webTransport`: waits for the server's SETTINGS (10 s), then for the answer to the CONNECT (10 s; an unanswered CONNECT is reset with `H3_REQUEST_CANCELLED` and `WebTransportException.Timeout` thrown), needs its WebTransport codepoint, Extended CONNECT, `H3_DATAGRAM` and the transport parameters of the SETTINGS row (`Http3Exception.Settings` otherwise).

Quoted (§3.4): "it is RECOMMENDED that clients and servers apply the scheduling guidance in both Section 9 of [RFC9218] and Section 10 of [RFC9218] for all data that they send in the enclosing WebTransport session, including Capsules, WebTransport streams and datagrams".

**Recorded status.** ✅ 0.3.0

**How it is met.**

- `:protocol webtransport-h3` to a draft-15+ server, else `webtransport` with `sec-webtransport-http3-draft02: 1`
- `WT-Available-Protocols` as a Structured Field List, a `WT-Protocol` naming another protocol resets the CONNECT with `WT_ALPN_ERROR` and throws `WebTransportException.Alpn`, one that is no valid Structured Field String is ignored (no protocol selected); parameters are ignored but parsed as RFC 8941 parameters (keys `( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" )`, values bare items), and a malformed one makes the whole field ignored (mutation review 2026-11-15: any run up to `;`, `,` or whitespace passed as a value, and keys took Unicode letters and digits; the parsers of `Capsule-Protocol`, `priority` and these fields now share one set of Structured Field helpers — `webtransport.WtProtocolsGapTest.negative_malformedParametersInvalidateTheField`, `.negative_malformedAvailableProtocolsAreIgnoredAsAWhole`)
- a non-2xx → `ConnectRejected`, redirects not followed
- a caller cancelled before it has the session ends the CONNECT in one of two §6-conformant ways: before the session is set up, RESET_STREAM and STOP_SENDING with `H3_REQUEST_CANCELLED`; once it has started and its end is watched (cancelled as `webTransport` returns), a graceful close as `close(0, "")`: WT_CLOSE_SESSION with code 0 and no reason, then FIN; a setup that fails there for a reason of its own resets the CONNECT with `H3_INTERNAL_ERROR` — `webtransport.WebTransportSessionTest.negative_aCallerCancelledAsTheConnectIsAnsweredResetsTheStream`, `.negative_aCallerCancelledAsItsSessionIsHandedOverCountsItOffOnce`, `.negative_aSessionThatFailsToStartResetsItsConnectStream`, `.negative_aCallerCancelledAsItsSessionIsCountedLeavesTheCountAtZero`
- several sessions on one connection when flow control is on for it, up to our own `webTransportMaxSessions` (`WebTransportException.ConnectionFull` beyond, before anything is sent); without flow control one (§5.1 "If flow control is not enabled, clients MUST NOT attempt to establish more than one simultaneous WebTransport session"), ConnectionFull too
- Server: both tokens are `isWebTransport`
- `acceptWebTransport` waits for the client's SETTINGS (10 s) and requires its WebTransport setting of a draft we speak (§3.1 "For draft versions of WebTransport only, clients MUST also send SETTINGS_WT_ENABLED with the draft-specific codepoint"; draft-14 `SETTINGS_WT_MAX_SESSIONS` above 0, draft-02 `SETTINGS_ENABLE_WEBTRANSPORT=1`, which Chrome and Firefox send), its `H3_DATAGRAM` and the transport parameters of the SETTINGS row, else the request is malformed (§3.1, RFC 9114 §4.1.2): answered with 400 and stopped with `H3_MESSAGE_ERROR`; no session is established before the client's SETTINGS, so none is established with wrong ones; it answers 200 with `WT-Protocol` (one of the offered) and, for a draft-02 client, `sec-webtransport-http3-draft: draft02`
- another WebTransport CONNECT while sessions are open is admitted only when flow control is on for it and for every open session (the client's SETTINGS are awaited first, §7.1) and fewer than `webTransportMaxSessions` are open; otherwise it is reset with `H3_REQUEST_REJECTED` before the application (§5.1 "A server that receives more than one session on an underlying transport connection when flow control is not enabled MUST reset the excessive CONNECT streams with a H3_REQUEST_REJECTED status"; draft-14 §5.2 likewise); a draft-02 session neither shares a connection nor joins one; the connection stays
- a session ends with its CONNECT stream, and its late streams are rejected
- §3.4: the session's streams are sent at the RFC 9218 priority (urgency, incremental) of its CONNECT stream: opened with it, and an accepted stream gets it before the application writes; a server moves them with the client's PRIORITY_UPDATE for the CONNECT stream (a priority the server's response set stays, as for every request); capsules travel on the CONNECT stream itself; datagrams go with the CONNECT stream's urgency too (every HTTP datagram goes with its request stream's): a datagram never preempts stream data of strictly more urgent streams (the HTTP/3 control and QPACK streams included), while stream data of the same or a lower urgency waits behind it (unreliable, latency-sensitive), O(1) per packet; the urgency is strict both ways, so more urgent bulk streams hold the datagrams back and a datagram flood starves streams of the same or a lower urgency; the send queue keeps one FIFO per urgency, so a datagram never waits behind a less urgent one (of this session or another request on the connection) and order is kept within an urgency (`QuicConnection.sendDatagram(data, policy, priority)`; RFC 9297 §2 leaves the prioritization of HTTP datagrams open) — `runtime.DatagramSendQueueTest.negative_urgentDatagramDoesNotWaitBehindALessUrgentOne`
- §5.2 "Servers SHOULD limit the rate of incoming WebTransport sessions on HTTP/3 connections to prevent excessive consumption of resources": at most `webTransportMaxSessions` (4) at once, and a rate per connection, a burst of 32 CONNECTs then 8 a second; beyond either a CONNECT is reset with `H3_REQUEST_REJECTED` (one above the rate also spends a glitch token, so a peer that keeps trying meets `H3_EXCESSIVE_LOAD`), and the endpoint's connection admission bounds the connections
- §3.2 "Clients cannot initiate WebTransport sessions in 0-RTT packets": our client never sends a CONNECT in 0-RTT; one that arrives in 0-RTT anyway is held until the handshake completes, answered 425 under `Reject425`, or dropped when the connection is lost or the 0-RTT rejected, each leaving no session slot behind

**Tests that pin it.**

- `webtransport.WebTransportServerSessionsTest.*` (several sessions on one connection: `twoSessionsShareTheConnectionAndKeepTheirStreams`, `oneSessionEndingLeavesTheOthers`, `negative_sessionBeyondTheLimitIsRefused`, `negative_connectsRacingForTheLastSlotAdmitOne`, `negative_secondSessionWithoutTheClientsFlowControlIsRefused`, `negative_secondSessionWithoutTheServersFlowControlIsRefused`, `negative_draft02SessionDoesNotShare`, `negative_draft02SessionDoesNotJoin`, `draft14ClientSessionsShareTheConnection`, `goAwayDrainsEverySessionAndDrainOnlyItsOwn`, `connectionLossEndsEverySession`, `negative_sessionsOpenedAndEndedInALoopMeetTheRate`), `runtime.EarlyDataTest.negative_webTransportConnectIn0RttWaitsForTheHandshake`, `.negative_webTransportConnectAnswered425LeavesNoSlot`, `.negative_webTransportConnectHeldWhenTheConnectionIsLostIsDropped`, `.negative_webTransportConnectInRejected0RttLeavesNothing`, `webtransport.WebTransportFlowControlTest.negative_clientBeyondItsOwnLimitIsRefused`, `.negative_serverAtItsLimitRefusesUnprocessed`, `webtransport.WebTransportSessionTest.*` (including `negative_secondSessionRejected`, `negative_wtProtocolOutsideOfferIsAlpnError`, `negative_wtWithoutServerSupportFails`, `negative_acceptWithoutClientSettingsFails`, `negative_acceptWithoutClientDatagramsIs400`, `negative_acceptWithoutClientWtSettingIsMalformed`, `negative_acceptWithoutClientResetStreamAtIsMalformed`, `negative_unansweredConnectTimesOut`, `malformedWtProtocolIsIgnored`), `webtransport.WebTransportStreamsTest.wtStreamsAreSentAtTheConnectPriority`, `.wtStreamsFollowAPriorityUpdateOfTheConnect`, `core.DatagramCoreTest.negative_datagramDoesNotPreemptMoreUrgentStreamData`, `.datagramGoesAheadOfStreamDataOfTheSameOrLowerUrgency`, `.datagramWithoutUrgencyGoesFirst` (QUIC), `GuideSamplesTest.webTransportSamples`

**Open items.** None.

## <a id="s4-2-streams"></a>§4.2, §4.3, §4.6 — streams

Status: ✅ since 0.3.0 · [summary](../rfc-compliance.md#http)

Original row: draft-ietf-webtrans-http3-16 §4.2, §4.3, §4.6 (streams).

**Requirement.** With `Http3Settings.webTransport`: a uni stream of type `0x54` and a bidirectional stream that starts with the `WT_STREAM` signal `0x41` (read before the stream is taken for a request, so the Session ID is never parsed as a frame length) are routed to their session by the Session ID.

Quoted: "SHOULD buffer streams and datagrams until they can be associated with an established session".

**Recorded status.** ✅ 0.3.0

**How it is met.**

- a Session ID that is not a client-initiated bidirectional stream, or (server) one beyond the bidirectional stream limit we granted, → `H3_ID_ERROR` (review: the latter was buffered for 5 s)
- the signal anywhere else (after HEADERS, on the control stream after SETTINGS) → `H3_FRAME_ERROR` (as the control stream's first frame → `H3_MISSING_SETTINGS`, RFC 9114 §6.2.1; see the SETTINGS row)
- a client accepts a server-initiated bidirectional stream only with the signal (`H3_STREAM_CREATION_ERROR` otherwise, as without WebTransport)
- streams that arrive before their session wait (16 per connection, 5 s each), the excess and late ones are rejected with `WT_BUFFERED_STREAM_REJECTED`
- datagrams that arrive before their session's CONNECT HEADERS wait on the server and reach the session once it is accepted (review: they were dropped): §4.6 "SHOULD buffer streams and datagrams until they can be associated with an established session", at most 16 per connection, the excess dropped, each "temporarily (on the order of a round trip)" as RFC 9297 §2.1 requires of a stream not yet created: one PTO (RFC 9002 §6.2.1 with the default max_ack_delay of 25 ms) plus one smoothed RTT, at least 50 ms and at most 5 s (review: 5 s each); a datagram for a stream that exists but whose HEADERS are still arriving waits up to 5 s, as an early WebTransport stream does (§4.6 "SHOULD buffer"; `webtransport.WtStreamRoutingTest.aDatagramForAStreamWhoseHeadersAreOnTheWayWaitsLonger`); every kept datagram goes when its own hold ends (`aShortHoldBehindALongOneEndsOnTime`), and only while the stream may still become a session (not once its HEADERS were read; a request other than CONNECT is aborted with `H3_DATAGRAM_ERROR`, RFC 9297 §2)

**Tests that pin it.**

- `webtransport.WtStreamRoutingTest.*` (including `datagramBeforeConnectHeadersIsDelivered`, `datagramKeptPastItsHoldIsDropped`, `datagramWithinItsHoldIsKept`, `pendingHoldFollowsTheRtt`, `datagramsForAnOpenGetLeaveTheSlotsToASession`, `sessionIdBeyondStreamLimitIsIdError`, `negative_pendingDatagramsBounded`, `negative_bufferedStreamsCapped`, `negative_wtSignalMidRequestIsFrameError`, `negative_wtSessionIdNotClientBidiIsIdError`)

**Open items.** None.

## <a id="s4-4-session"></a>§4.4, §4.5, §4.7, §6 — session

Status: ✅ since 0.3.0 · [summary](../rfc-compliance.md#http)

Original row: draft-ietf-webtrans-http3-16 §4.4, §4.5, §4.7, §6 (session).

**Requirement.** `WebTransportSession`: streams opened with their header and flushed at once, the peer's handed out by `acceptBidi`/`acceptUni`.

**Recorded status.** ✅ 0.3.0

**How it is met.**

- application codes 0..2^32-1 mapped into `0x52e4a40fa8db..0x52e5ac983162` skipping GREASE, a peer code outside it reads as `StreamReset(null)`/`StreamStopped(null)`
- datagrams by the session's quarter stream ID, `TooLarge` reports the payload limit
- the Capsule Protocol on the CONNECT stream (`WT_CLOSE_SESSION` terminal, ≤ 4 + 1024 bytes; `WT_DRAIN_SESSION` empty; the flow-control capsules read with flow control on, [flow-control row](#s5-flow-control), and skipped without it; other types skipped)
- the session's streams are reset and stopped with `WT_SESSION_GONE`
- a cancelled `close()` still ends the session completely (the CONNECT is ended in the connection's scope)
- an ended session is no longer referenced by its connection: a peer that opens and closes sessions on one connection
  grows nothing (`WebTransportRetentionTest.aClosedSessionIsNotHeldByItsConnection`, JVM)
- an application that cancels a stream's `output` resets it, one that cancels its `input` stops it, both with code 0
- `drainRequested` on the peer's drain or a GOAWAY, and on this side's own `drain()` (0.3.0: the sending side's application winds down too; the Ktor client's `closeHttp3Connections()` drains every session, also one whose CONNECT completes after it) — `WebTransportCloseTest.ownDrainSetsBothFlags`, `ClientKillSwitchTest.closeHttp3ConnectionsDrainsWebTransportSessions`, `.webTransportSessionTrackedAfterCloseIsDrained`
- §4.4 "WebTransport implementations MUST use the RESET_STREAM_AT frame [RESET-STREAM-AT] with a Reliable Size set to at least the size of the WebTransport header when resetting a WebTransport data stream": every reset of our sending side of a WebTransport stream (by the application, its cancelled `output`, the session's end, a stream rejected while buffered or one opened as the session closed) is a RESET_STREAM_AT, with the header we wrote as the reliable size (cut by the transport to what was written) or 0 on a stream the peer opened, whose header travels the other way (reliable-stream-reset-11 §4: "a RESET_STREAM_AT frame with this value is logically equivalent to a RESET_STREAM frame"); a session of draft-14 or later exists only with `reset_stream_at` on both sides (SETTINGS row), so the frame always goes; only a draft-02 session (browsers, whose draft predates the frame) may lack it, and the transport then sends the RESET_STREAM of draft-02 (`wtResetUsesResetStreamAtWhenNegotiated`, `withoutResetStreamAtBothSidesFallBackToDraft02`)

**Tests that pin it.**

- `webtransport.WtErrorCodesTest.*`, `webtransport.WebTransportStreamsTest.*`, `webtransport.WebTransportCloseTest.*` (including `cancelledCloseStillEndsTheSession`, `negative_closeReasonOver1024IsMessageError`, `negative_closeReasonInvalidUtf8IsMessageError`, `negative_dataAfterCloseCapsuleIsMessageError`, `closeFreesTheSlot`), `GuideSamplesTest.webTransportEchoSample`

**Peer interop notes.**

- `close` sends the capsule and FIN (5 s for the peer's credit, then a reset) and waits for the peer's FIN, sending STOP_SENDING `WT_SESSION_GONE` only when it does not come within 5 s (stopping at once made Chrome report a lost connection instead of the close code), the peer's capsule or FIN (code 0) closes the session the same way, a malformed close (reason above 1024 bytes, not UTF-8, data after it) or drain → `H3_MESSAGE_ERROR` on the CONNECT stream

**Open items.** None.

## <a id="s5-flow-control"></a>§5, §8 — flow control and fairness

Status: ✅ since 0.3.0 · [summary](../rfc-compliance.md#http)

**Requirement.** §5.1: "A WebTransport endpoint that allows a WebTransport session to share an underlying transport
connection with other WebTransport sessions MUST enable flow control"; "If both endpoints take at least one of these
actions, flow control is enabled, and the limits described in the entirety of Section 5 apply"; "If flow control is not
enabled, an endpoint MUST ignore receipt of any flow control capsules". §5.6.2: "An endpoint MUST NOT open more streams
than permitted by the current stream limit set by its peer"; "If an endpoint receives an incoming stream for a session
that would exceed the advertised Maximum Streams value, it MUST close the WebTransport session with a
WT_FLOW_CONTROL_ERROR error code"; a WT_MAX_STREAMS "that does not increase the Maximum Streams value previously
received", or above 2^60, closes it too. §5.6.4: "The sum of the lengths of Stream Body data sent on all streams
associated with this session MUST NOT exceed the Maximum Data value advertised by a receiver"; data in excess, or a
WT_MAX_DATA "that does not increase", closes the session. §5.4: reset streams count their final size; "Endpoints MUST
treat receipt of a WT_MAX_STREAM_DATA or a WT_STREAM_DATA_BLOCKED capsule as a session error". §5.6: "An endpoint MUST
NOT wait for a WT_DATA_BLOCKED or WT_STREAMS_BLOCKED capsule before sending a WT_MAX_DATA or WT_MAX_STREAMS capsule";
"Endpoints SHOULD send WT_MAX_DATA and WT_MAX_STREAMS capsules as they consume data or close streams"; §5.6.3, §5.6.5:
a blocked sender "SHOULD send" WT_STREAMS_BLOCKED / WT_DATA_BLOCKED. §3.2 (0-RTT): "If the server accepts 0-RTT, the
server MUST NOT reduce these initial flow control values"; "A client MUST close the connection with H3_SETTINGS_ERROR
if the SETTINGS frame received in the resumed connection reduces any flow control values". §8: "WebTransport endpoints
SHOULD implement a fairness scheme that ensures that each session that shares a transport connection gets a reasonable
share of controlled resources; this applies both to sending data and to opening new streams".

**Recorded status.** ✅ 0.3.0

**How it is met.**

- settings: `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI` (0x2b64), `_BIDI` (0x2b65), `SETTINGS_WT_INITIAL_MAX_DATA` (0x2b61) from
  `Http3Settings.webTransportInitialMaxStreamsUni` / `Bidi` / `MaxData` (24, 24, 3 932 160), sent when non-zero;
  flow control is on for a draft-14 or draft-16 session when both sides declared it (draft-14 also by
  `SETTINGS_WT_MAX_SESSIONS` above 1); draft-02 has none; `Http3Endpoint` refuses settings whose sessions do not fit the
  QUIC limits, and the connection's receive window is kept at the open sessions' combined data limit
- sending: a stream takes one of the peer's stream credits before it is opened; body bytes take session credit before
  they are written; a blocked sender sends WT_STREAMS_BLOCKED / WT_DATA_BLOCKED once per limit; credit taken for bytes
  that never went out comes back by the stream's final size (`QuicStream.sentFinalSize`), and an open that never
  produced a stream the peer sees gives its slot back
- receiving: every peer stream counts from the moment it reaches its session (accepted or not, and streams rejected
  before the session existed are tallied for it); its bytes count by the highest offset the transport received, the
  bytes taken and its final size, without the header (its length on the wire); credit is given back as the application
  takes bytes into its buffer, or as a stream is abandoned, never waiting for a blocked capsule; WT_MAX_STREAMS goes
  out as the peer's streams end
- capsules: a value that is not one varint is H3_MESSAGE_ERROR; violations reset and stop the CONNECT stream with
  WT_FLOW_CONTROL_ERROR (`WebTransportException.FlowControl`); draft-14 closes only on a lower WT_MAX_* ("less than a
  previously received value"); WT_MAX_STREAM_DATA and WT_STREAM_DATA_BLOCKED are a session error for draft-14 and
  draft-16 sessions with or without flow control; without flow control the four flow-control capsules are skipped
- 0-RTT: the server binds its flow-control values and session limit into its tickets; the client keeps them with its
  stored settings and fails a resumed connection that lowers them with H3_SETTINGS_ERROR
- §8 fairness: opening a stream and handing a chunk to the send buffer go through weighted deficit round robin queues
  per connection, by streams for opens and by bytes for data; a session's weight is 8 − the urgency of its CONNECT
  stream (§3.4), read again at every turn, so a more urgent session gets the larger share but none waits more than a
  round (urgency is a preference, not strict: the sessions are separate trust domains, RFC 9218 §10 "it is RECOMMENDED
  that servers avoid such starvation where possible"); each session holds at most its part of the connection's send
  buffer (`maxSendBuffer`, followed per stream with `QuicStream.sendReleased`): a reserve of one part in
  `webTransportMaxSessions` + 1 stays free for a session that joins and the rest is split between the open sessions, so
  one whose peer never reads a stream cannot stall the others, and a session alone gets nearly all of it; datagrams and
  capsules are outside the turns (a session's datagram burst can push other sessions' datagrams out of the connection's
  datagram queue, never stall their streams)
- a draft-14 peer that declares flow control only by `SETTINGS_WT_MAX_SESSIONS` gives no initial credit (its section
  5.5): `WebTransportDiagnostics.creditStall` reports a session left at zero for ten seconds, and the Ktor server logs it
  ([compatibility shims](../compat-shims.md#1-webtransport-draft-02-and-draft-14))

**Tests that pin it.**

- `webtransport.WebTransportFlowControlTest.*` (including every `negative_*` violation: streams and data past the limits,
  unread bytes without FIN, reset and rejected streams, non-increasing and lowering limits, 2^60 + 1, the prohibited
  capsules, a malformed value; the credit cases: writes after the peer's stop, a stop while waiting, cancelled opens,
  exact and idle readers, cancelled reads; the draft-14 rules and stall report; the window floor; the 0-RTT ticket
  binding), `webtransport.WtSessionFlowPropertyTest.*` (randomized agreement, liveness, dishonest sender),
  `webtransport.WtTurnsTest.*` (including `negative_theLeastUrgentSessionProgressesAgainstAFlood`,
  `aChangedUrgencyTakesEffectWhileTheSessionWaits`, `randomizedDynamicSessionsAllProgress`),
  `webtransport.WebTransportServerSessionsTest.negative_aSessionWhosePeerNeverReadsDoesNotStallTheOthers`,
  `.aLoneSessionUsesTheBufferLessTheReserve`, `.negative_aSessionJoiningAFullBufferWritesAtOnce`,
  `api.SendReleasedTest.*` (QUIC), `runtime.EarlyDataTest.negative_webTransportFlowControlLoweredAfter0RttIsSettingsError`,
  `.webTransportFlowControlChangeInvalidatesEarlyData`, `api.FinalSizeTest.*`, `core.StreamFinalSizeTest.*` (QUIC),
  `WebTransportCreditStallTest.*` (Ktor server)

**Open items.** None.

## <a id="ktor-server"></a>Ktor server

Status: ✅ since 0.3.0 · [summary](../rfc-compliance.md#http)

Original row: draft-ietf-webtrans-http3-16 (Ktor server).

**Requirement.** `webTransport = true` turns the settings on.

**Recorded status.** ✅ 0.3.0

**How it is met.**

- `Route.webTransport(path)` matches only a WebTransport Extended CONNECT over HTTP/3 (an HTTP/1.1 request never reaches it, another method gets Ktor's 405; no matching route → Ktor's 404; another route's 2xx → 501), checks `origin` (403; same host or none by default, the opaque `null` and non-http(s) origins refused)
- a request that rules out capsules (`content-type`, …) → 400, picks the first of its protocols the client offers, accepts, and closes the session when the handler returns (0) or throws (`WEB_TRANSPORT_HANDLER_FAILED`)
- without the flag the SETTINGS are not sent and such a CONNECT gets 501 as before
- `webTransport` turns `reset_stream_at` on (SETTINGS row)
- §5.2 "Servers SHOULD limit the rate of incoming WebTransport sessions": `webTransportMaxSessions` at once and a rate per connection (sessions row), and the endpoint's connection limits bound the connections
- a draft-14 client that leaves a session without flow-control credit for ten seconds (`WebTransportDiagnostics.creditStall`) is logged once as a warning

**Tests that pin it.**

- `ServerWebTransportTest.*` (including `negative_foreignOriginIs403`, `negative_opaqueOriginIs403`, `negative_plainRouteCannotFakeASession`), `WebTransportCreditStallTest.*`, `GuideSamplesTest.webTransportSample`

**Open items.** None.

## <a id="ktor-client"></a>Ktor client

Status: ✅ since 0.3.0 · [summary](../rfc-compliance.md#http)

Original row: draft-ietf-webtrans-http3-16 (Ktor client). Until session pooling (0.3.0 development) each session had a QUIC connection of its own outside the pool, an accepted deviation from RFC 9114 §3.3.

**Requirement.** `HttpClient.webTransport(url)`: `https` only (IllegalArgumentException), the Kuicksilver engine and an open client only (IllegalStateException).

**Recorded status.** ✅ 0.3.0

**How it is met.**

- `H1Only` and a proxy for the URL are refused (UnsupportedOperationException; `webTransportIgnoresProxy` connects directly)
- at most `maxWebTransportSessions` (64) at once, one more fails at once
- the resolved addresses are tried in order within `connectTimeout`
- RFC 9114 §3.3 ("Clients SHOULD NOT open more than one HTTP/3 connection to a given IP address and UDP port"): sessions share the engine's pooled HTTP/3 connection of the URL's host and port with each other and with requests; the pooled connection is made WebTransport-capable (WebTransport, Extended CONNECT and `reset_stream_at`), a request-only one is replaced and finishes its requests; a session the connection cannot take (`ConnectionFull`: no flow control, or our limit) or the server refuses unprocessed (`H3_REQUEST_REJECTED`, its limit, §5.2; the connection is then taken as full at its count; a refusal while none of our sessions is on it is the server's rate, not its limit, and is thrown) goes to an extra connection to the same server, which later sessions share too (sessions racing past a full connection share one being set up) and which closes with its last session
- one deadline (`connectTimeout`) for every connection a call sets up or waits for: sessions waiting for an extra connection another one sets up share its failure
- a connection that ends just as a session joins it is passed over (twice at most)
- requests and sessions on one connection are not taken in turns against each other (§3.4 asks RFC 9218's scheduling for the data of a session; the sessions' own turns are among sessions): both are the client application's traffic to one origin, and requests keep their RFC 9218 priorities
- a connection stays in use while a session is open and until its CONNECT stream ended both ways (at most five seconds after the session closed), so a connection closing with its last user never cuts the close short (the server sees the close code)
- `connectTimeout` bounds the setup, a session that cannot be opened releases its connection
- no fallback to HTTP/1.1
- §8 "a WebTransport client SHOULD limit the number of outgoing sessions": `maxWebTransportSessions` (64)

**Tests that pin it.**

- `ClientWebTransportTest.*` (including `twoSessionsOfOneOriginShareOneConnection`, `requestsShareTheSessionsConnection`, `closingTheSessionReturnsTheConnectionToThePool`, `serverLimitReachedOpensASecondConnection`, `negative_racingSessionsShareTheExtraConnections`, `negative_sessionsWaitingForAFailedSetupFailWithinOneTimeout`, `negative_aConnectionClosingAsASessionJoinsIsPassedOver`, `negative_aRefusalWithoutOurSessionsOpensNoFurtherConnection`, `negative_withoutFlowControlEachSessionGetsAConnection`, `connectionLossEndsEverySession`, `negative_proxyRefused`, `negative_sessionCapExceeded`, `negative_afterCloseFails`, `cancellationDuringConnectReleasesTheConnection`, `nextAddressAfterAFailedHandshake`), `GuideSamplesTest.webTransportClientSample`

**Open items.** None.
