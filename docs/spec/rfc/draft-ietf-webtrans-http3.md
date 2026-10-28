<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# draft-ietf-webtrans-http3 — WebTransport over HTTP/3 (draft-ietf-webtrans-http3-16)

Details of the rows of the [RFC compliance summary](../rfc-compliance.md) for this document. Each section gives the requirement, how Kuicksilver meets it (with the files), the tests that pin it, its history, notes on peers and the open items. Status: ✅ met · 🔶 feature subset · ⬜ planned · ❌ not planned; "since" is the release from which the current behaviour holds (history below and in [CHANGELOG.md](../../../CHANGELOG.md)).

## <a id="webtransport"></a>WebTransport

Status: 🔶 since 0.3.0 · [summary](../rfc-compliance.md#http)

Original row: draft-ietf-webtrans-http3.

**Requirement.** WebTransport.

**Recorded status.** 🔶 0.3.0 (experimental, in progress)

**How it is met.**

- per-section rows below

**Peer interop notes.**

- draft-16 on the wire, the codepoints of draft-02 and draft-14 accepted for browsers

**Open items.** See the roadmap ([docs/roadmap.md](../../roadmap.md)).

## <a id="s3-1-settings"></a>§3.1, §7.1 — SETTINGS

Status: 🔶 since 0.3.0 · [summary](../rfc-compliance.md#http)

Original row: draft-ietf-webtrans-http3-16 §3.1, §7.1 (SETTINGS).

**Requirement.** With `Http3Settings.webTransport` (needs `enableConnectProtocol` and `h3Datagram`; `Http3Endpoint.bind` refuses it without QUIC datagrams) a server sends `SETTINGS_WT_ENABLED=1` (0x2c7cf000), `SETTINGS_WT_MAX_SESSIONS=1` (0x14e9cd29, draft-14) and `SETTINGS_ENABLE_WEBTRANSPORT=1` (0x2b603742, draft-02), a client the first and the last.

**Recorded status.** 🔶 0.3.0

**How it is met.**

- no `SETTINGS_WT_INITIAL_*`, so no WebTransport flow control and one session per connection (§5.1)
- the peer's codepoints become `Http3PeerSettings.webTransport` and the highest draft it speaks, and leave `unknown`
- `SETTINGS_WT_ENABLED` other than 0 or 1 → `H3_SETTINGS_ERROR`
- the 0-RTT ticket context covers the setting

**Tests that pin it.**

- `webtransport.WebTransportSettingsTest.*` (including `negative_wtEnabledAboveOneIsSettingsError`, `negative_webTransportWithoutQuicDatagramsRefused`)

**Open items.** See the roadmap ([docs/roadmap.md](../../roadmap.md)).

## <a id="s3-2-sessions"></a>§3.2, §3.3, §5.1, §5.2, §7.1 — sessions

Status: 🔶 since 0.3.0 · [summary](../rfc-compliance.md#http)

Original row: draft-ietf-webtrans-http3-16 §3.2, §3.3, §5.1, §5.2, §7.1 (sessions).

**Requirement.** Client `Http3Connection.webTransport`: waits for the server's SETTINGS (10 s), then for the answer to the CONNECT (10 s; an unanswered CONNECT is reset with `H3_REQUEST_CANCELLED` and `WebTransportException.Timeout` thrown), needs its WebTransport codepoint, Extended CONNECT and `H3_DATAGRAM` (`Http3Exception.Settings` otherwise).

**Recorded status.** 🔶 0.3.0

**How it is met.**

- `:protocol webtransport-h3` to a draft-15+ server, else `webtransport` with `sec-webtransport-http3-draft02: 1`
- `WT-Available-Protocols` as a Structured Field List, a `WT-Protocol` naming another protocol resets the CONNECT with `WT_ALPN_ERROR` and throws `WebTransportException.Alpn`, one that is no valid Structured Field String is ignored (no protocol selected)
- a non-2xx → `ConnectRejected`, redirects not followed
- one session per connection.
- Server: both tokens are `isWebTransport`
- `acceptWebTransport` waits for the client's SETTINGS (10 s) and requires its `H3_DATAGRAM`, else the request is malformed (§3.1) and answered with 400, answers 200 with `WT-Protocol` (one of the offered) and, for a draft-02 client, `sec-webtransport-http3-draft: draft02`
- a second WebTransport CONNECT while one is open is reset with `H3_REQUEST_REJECTED` before the application (no flow control, one session)
- a session ends with its CONNECT stream, and its late streams are rejected

**Tests that pin it.**

- `webtransport.WebTransportSessionTest.*` (including `negative_secondSessionRejected`, `negative_wtProtocolOutsideOfferIsAlpnError`, `negative_wtWithoutServerSupportFails`, `negative_acceptWithoutClientSettingsFails`, `negative_acceptWithoutClientDatagramsIs400`, `negative_unansweredConnectTimesOut`, `malformedWtProtocolIsIgnored`), `GuideSamplesTest.webTransportSamples`

**Open items.** See the roadmap ([docs/roadmap.md](../../roadmap.md)).

## <a id="s4-2-streams"></a>§4.2, §4.3, §4.6 — streams

Status: 🔶 since 0.3.0 · [summary](../rfc-compliance.md#http)

Original row: draft-ietf-webtrans-http3-16 §4.2, §4.3, §4.6 (streams).

**Requirement.** With `Http3Settings.webTransport`: a uni stream of type `0x54` and a bidirectional stream that starts with the `WT_STREAM` signal `0x41` (read before the stream is taken for a request, so the Session ID is never parsed as a frame length) are routed to their session by the Session ID.

Quoted: "SHOULD buffer streams and datagrams until they can be associated with an established session".

**Recorded status.** 🔶 0.3.0

**How it is met.**

- a Session ID that is not a client-initiated bidirectional stream, or (server) one beyond the bidirectional stream limit we granted, → `H3_ID_ERROR` (review: the latter was buffered for 5 s)
- the signal anywhere else (after HEADERS, on the control stream after SETTINGS) → `H3_FRAME_ERROR` (as the control stream's first frame → `H3_MISSING_SETTINGS`, RFC 9114 §6.2.1; see the SETTINGS row)
- a client accepts a server-initiated bidirectional stream only with the signal (`H3_STREAM_CREATION_ERROR` otherwise, as without WebTransport)
- streams that arrive before their session wait (16 per connection, 5 s each), the excess and late ones are rejected with `WT_BUFFERED_STREAM_REJECTED`

**Tests that pin it.**

- `webtransport.WtStreamRoutingTest.*` (including `datagramBeforeConnectHeadersIsDelivered`, `datagramKeptPastItsHoldIsDropped`, `datagramWithinItsHoldIsKept`, `pendingHoldFollowsTheRtt`, `datagramsForAnOpenGetLeaveTheSlotsToASession`, `sessionIdBeyondStreamLimitIsIdError`, `negative_pendingDatagramsBounded`, `negative_bufferedStreamsCapped`, `negative_wtSignalMidRequestIsFrameError`, `negative_wtSessionIdNotClientBidiIsIdError`)

**Open items.**

- datagrams that arrive before their session's CONNECT HEADERS wait on the server and reach the session once it is accepted (review: they were dropped): §4.6 "SHOULD buffer streams and datagrams until they can be associated with an established session", at most 16 per connection, the excess dropped, each "temporarily (on the order of a round trip)" as RFC 9297 §2.1 requires of a stream not yet created: one PTO (RFC 9002 §6.2.1 with the default max_ack_delay of 25 ms) plus one smoothed RTT, at least 50 ms and at most 5 s (review: 5 s each), and only while the stream may still become a session (not once its HEADERS were read; a request other than CONNECT is aborted with `H3_DATAGRAM_ERROR`, RFC 9297 §2)

## <a id="s4-4-session"></a>§4.4, §4.5, §4.7, §6 — session

Status: 🔶 since 0.3.0 · [summary](../rfc-compliance.md#http)

Original row: draft-ietf-webtrans-http3-16 §4.4, §4.5, §4.7, §6 (session).

**Requirement.** `WebTransportSession`: streams opened with their header and flushed at once, the peer's handed out by `acceptBidi`/`acceptUni`.

**Recorded status.** 🔶 0.3.0

**How it is met.**

- application codes 0..2^32-1 mapped into `0x52e4a40fa8db..0x52e5ac983162` skipping GREASE, a peer code outside it reads as `StreamReset(null)`/`StreamStopped(null)`
- datagrams by the session's quarter stream ID, `TooLarge` reports the payload limit
- the Capsule Protocol on the CONNECT stream (`WT_CLOSE_SESSION` terminal, ≤ 4 + 1024 bytes; `WT_DRAIN_SESSION` empty; other types, flow-control capsules included, skipped: no flow control, §5.1)
- the session's streams are reset and stopped with `WT_SESSION_GONE`
- a cancelled `close()` still ends the session completely (the CONNECT is ended in the connection's scope)
- an application that cancels a stream's `output` resets it, one that cancels its `input` stops it, both with code 0
- `drainRequested` on the peer's drain or a GOAWAY
- a stream we opened is reset with RESET_STREAM_AT keeping its header as the reliable size when both sides set `QuicConfig.resetStreamAt` (the Ktor server sets it with `webTransport`; `wtResetUsesResetStreamAtWhenNegotiated`), else with RESET_STREAM (the header may then be lost and the peer drops the stream)

**Tests that pin it.**

- `webtransport.WtErrorCodesTest.*`, `webtransport.WebTransportStreamsTest.*`, `webtransport.WebTransportCloseTest.*` (including `cancelledCloseStillEndsTheSession`, `negative_closeReasonOver1024IsMessageError`, `negative_closeReasonInvalidUtf8IsMessageError`, `negative_dataAfterCloseCapsuleIsMessageError`, `closeFreesTheSlot`), `GuideSamplesTest.webTransportEchoSample`

**Peer interop notes.**

- `close` sends the capsule and FIN (5 s for the peer's credit, then a reset) and waits for the peer's FIN, sending STOP_SENDING `WT_SESSION_GONE` only when it does not come within 5 s (stopping at once made Chrome report a lost connection instead of the close code), the peer's capsule or FIN (code 0) closes the session the same way, a malformed close (reason above 1024 bytes, not UTF-8, data after it) or drain → `H3_MESSAGE_ERROR` on the CONNECT stream

**Open items.** See the roadmap ([docs/roadmap.md](../../roadmap.md)).

## <a id="ktor-server"></a>Ktor server

Status: 🔶 since 0.3.0 · [summary](../rfc-compliance.md#http)

Original row: draft-ietf-webtrans-http3-16 (Ktor server).

**Requirement.** `webTransport = true` turns the settings on.

**Recorded status.** 🔶 0.3.0

**How it is met.**

- `Route.webTransport(path)` matches only a WebTransport Extended CONNECT over HTTP/3 (an HTTP/1.1 request never reaches it, another method gets Ktor's 405; no matching route → Ktor's 404; another route's 2xx → 501), checks `origin` (403; same host or none by default, the opaque `null` and non-http(s) origins refused)
- a request that rules out capsules (`content-type`, …) → 400, picks the first of its protocols the client offers, accepts, and closes the session when the handler returns (0) or throws (`WEB_TRANSPORT_HANDLER_FAILED`)
- without the flag the SETTINGS are not sent and such a CONNECT gets 501 as before

**Tests that pin it.**

- `ServerWebTransportTest.*` (including `negative_foreignOriginIs403`, `negative_opaqueOriginIs403`, `negative_plainRouteCannotFakeASession`), `GuideSamplesTest.webTransportSample`

**Open items.** See the roadmap ([docs/roadmap.md](../../roadmap.md)).

## <a id="ktor-client"></a>Ktor client

Status: 🔶 since 0.3.0 · [summary](../rfc-compliance.md#http)

Original row: draft-ietf-webtrans-http3-16 (Ktor client).

**Requirement.** `HttpClient.webTransport(url)`: `https` only (IllegalArgumentException), the Kuicksilver engine and an open client only (IllegalStateException).

**Recorded status.** 🔶 0.3.0

**How it is met.**

- `H1Only` and a proxy for the URL are refused (UnsupportedOperationException; `webTransportIgnoresProxy` connects directly)
- at most `maxWebTransportSessions` (64) at once, one more fails at once
- the resolved addresses are tried in order within `connectTimeout`
- one dedicated QUIC connection per session outside the pool, with WebTransport, Extended CONNECT and `reset_stream_at`, closed with H3_NO_ERROR once the session's CONNECT ended both ways (the server sees the close code)
- `connectTimeout` bounds the setup, a session that cannot be opened closes its connection
- no fallback to HTTP/1.1

**Tests that pin it.**

- `ClientWebTransportTest.*` (including `negative_proxyRefused`, `negative_sessionCapExceeded`, `negative_afterCloseFails`, `cancellationDuringConnectReleasesTheConnection`, `nextAddressAfterAFailedHandshake`), `GuideSamplesTest.webTransportClientSample`

**Open items.** See the roadmap ([docs/roadmap.md](../../roadmap.md)).
