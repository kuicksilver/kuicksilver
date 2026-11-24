<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# draft-ietf-quic-qlog — qlog (draft-ietf-quic-qlog-*)

Details of the rows of the [RFC compliance summary](../rfc-compliance.md) for this document. Each section gives the requirement, how Kuicksilver meets it (with the files), the tests that pin it, its history, notes on peers and the open items. Status: ✅ met · 🔶 feature subset or accepted deviation · ⬜ planned · ❌ not planned; "since" is the release from which the current behaviour holds (history below and in [CHANGELOG.md](../../../CHANGELOG.md)).

## <a id="qlog"></a>qlog

Status: ✅ since 0.2.0 · [summary](../rfc-compliance.md#quic)

Original row: draft-ietf-quic-qlog-*.

**Requirement.** Qlog.

**Recorded status.** ✅ 0.2.0 (version 0.3, JSON-SEQ)

**Tests that pin it.**

- `qlog.QlogWriterTest.firstRecordIsHeader`, `qlog.QlogWriterTest.eventsUseRelativeMillis`, `qlog.QlogWriterTest.packetSentFields`, `qlog.QlogWriterTest.lossAndMetricsEvents`, `qlog.QlogWriterTest.stopsAtCapWithoutError`, `qlog.QlogWriterTest.filePerConnectionNamedByOdcid`
- a sent `reset_stream`, `reset_stream_at` or `stop_sending` frame carries `stream_id` and `error_code` (and `final_size`, `reliable_size`) as the schema's ResetStreamFrame and StopSendingFrame do (0.3.0; before, only `frame_type`) — `qlog.QlogWriterTest.resetAndStopSendingNameTheirStream`
- the trace is opened on the first event (an undecrypted Initial creates no file) and closed in `release()`, a failure of the sink's `open`/`write`/`close` disables tracing for that connection without touching it or the endpoint — `qlog.QlogRobustnessTest.*`
- schema draft-ietf-quic-qlog-main-schema/quic-events 0.3 — not validated in qvis yet
- the transport's trace takes the events of the layer above (HTTP/3) from any thread through one queue the endpoint
  loop writes: records whole and never interleaved, at most 4096 queued, nothing written after the trace ended or its
  sink failed (0.3.0) — `qlog.QlogExternalRecordsTest.*`
- the header's `common_fields` name the stacks (`protocol_type`, quic-events-04 section 2: MUST contain "QUIC"; "HTTP3"
  with an ALPN list that offers `h3`) and the `reference_time` of the relative times (main-schema-05 section 3.4.1:
  0, the trace's start); times never go back from one record to the next (section 3.4.1, SHOULD); the transport
  events' enumerations are quic-events-04's: connection states (section 4.6), the `packet_dropped` trigger (section
  5.7), `connection_closed` triggers (section 4.3), no `packet_lost` trigger the loss detector cannot tell (section
  7.5) (0.3.0; before, no `protocol_type` or `reference_time`, and the states, two triggers and free-text close
  triggers were our own) — `qlog.QlogExternalRecordsTest.theHeaderNamesTheProtocolsAndTheReferenceTime`,
  `qlog.QlogExternalRecordsTest.timesNeverGoBackInTheFile`, `qlog.QlogExternalRecordsTest.transportEnumerationsAreTheDrafts`,
  `qlog.QlogExternalRecordsTest.negative_aTraceWithoutHttp3TakesNoHttp3Event`
- every frame of `packet_sent` and `packet_received` with the members quic-events-04 section 8.11 defines (ACK ranges,
  `ack_delay` and ECN counts, STREAM and CRYPTO offsets and lengths, stream limits, connection IDs, path data,
  CONNECTION_CLOSE's `error_space`, `error_code`, `error_code_value`, `reason`, `trigger_frame_type`, ...), RESET_STREAM_AT
  and DATAGRAM through its `$QuicFrame` extension point; packet types of section 8.5 (0-RTT included); no token or
  stateless reset token bytes and no payloads; one `connection_closed`, and the trace open through the closing period
  (0.3.0; before, frames by type alone, 0-RTT packets as 1RTT, and the trace ended at the close) —
  `qlog.QlogFramesTest.everyFrameTypeIsTypedSentAndReceived`, `qlog.QlogFramesTest.aRealExchangeLogsTypedFramesBothWays`,
  `qlog.QlogFramesTest.negative_eachFrameTypeRefusesWhatTheDraftDoesNot`,
  `qlog.QlogFramesTest.negative_tokensAndPayloadsNeverReachTheTrace`,
  `qlog.QlogFramesTest.negative_aPayloadThatDoesNotDecodeLeavesNoFrames`
- every connection state change with `old` and `new` (section 4.6), one `connection_closed` with an owner of section 8.3,
  the trace kept through the closing or draining period and ended when the connection is released, after a close, a
  stateless reset or the endpoint's close; a lost or dropped 0-RTT packet as `0RTT`; a frame that fails to format never
  touches the connection (0.3.0) — `qlog.QlogLifecycleTest.aCloseIsLoggedOnceAndEveryStateUntilTheTraceEnds`,
  `qlog.QlogLifecycleTest.anEndpointCloseEndsTheTraces`, `qlog.QlogLifecycleTest.negative_aFrameThatFailsToFormatLeavesTheConnectionAlone`,
  `qlog.QlogLifecycleTest.aSecondEndWhileClosingLogsNoSecondClose`, `qlog.QlogFramesTest.aPacketSentWhileOneIsReceivedKeepsBothFrameLists`,
  `endpoint.StatelessResetTest.aStatelessResetEndsTheTraceAfterTheDrainingPeriod`,
  `qlog.QlogExternalRecordsTest.transportEnumerationsAreTheDrafts`
- `transport:parameters_set` (quic-events-04 section 5.3) for our transport parameters (`owner` local) and the peer's
  (`owner` remote), "two separate event instances", once the peer's are accepted, on both roles: connection IDs, the
  stateless reset token, limits and timers, the preferred address; `max_datagram_frame_size`, `reset_stream_at` and
  `grease_quic_bit` as the "unspecified fields" the section allows (0.3.0; before, no transport parameters, so a trace
  could not show whether the peer sent `reset_stream_at`) — `qlog.QlogLifecycleTest.bothSidesLogTheirOwnAndThePeersTransportParameters`

## <a id="qlog-h3"></a>qlog HTTP/3 and QPACK events

Status: ✅ since 0.3.0 · [summary](../rfc-compliance.md#quic)

Original row: draft-ietf-quic-qlog-h3-events-04.

**Requirement.** The HTTP/3 and QPACK events of draft-ietf-quic-qlog-h3-events-04, dated like main-schema-05 and
quic-events-04 (13 February 2023), whose section 3 fixes `qlog_version` "0.3" (h3-events-04 itself cites main-schema-04) ([ADR-0021](../../adr/0021-qlog-http3-events.md)): in
the `http` category `parameters_set`, `parameters_restored`, `stream_type_set`, `frame_created` and `frame_parsed`; in
the `qpack` category `state_updated` and `stream_state_updated`. The drafts define the events, not when an
implementation must write one: qlog's MUSTs are about the format, which `runtime.QlogSchema` checks.

**How it is met.** `kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/runtime/H3Qlog.kt` formats the
events; `QlogRecorder` (`kuicksilver-quic`, internal API) queues them into the connection's trace, which the endpoint
loop writes. Every frame we send or read is logged: DATA, HEADERS (request, response and trailer field sections, with
their fields once decoded; one that is too large or does not decode with an empty list), SETTINGS (each setting by its
IANA name, others by number), GOAWAY, MAX_PUSH_ID and CANCEL_PUSH with their identifiers, reserved (GREASE) frames
with their `length` (section 5.2.8), unknown ones and frames whose payload was not read with `frame_type_value`
(section 5.2.9), PRIORITY_UPDATE as a `priority_update` frame through the `$HTTPFrame` extension point (section 5.2;
`stream_id` or `push_id` and `priority_field_value`, the members of the later drafts), and WebTransport's
`WT_STREAM` signal as an unknown frame with a `session_id` of ours. A frame refused by the stream it arrived on is
logged before the error. Unidirectional stream types are logged as sent and as read in `stream_type` (section 4.3:
`control`, `qpack_encode`, `qpack_decode`, `reserved`, `unknown` with `stream_type_value`; WebTransport streams with
`session_id`). SETTINGS give `parameters_set` (`owner` local or remote; settings beyond the three section 4.1 names
as `name => value`),
the server SETTINGS a 0-RTT client remembered `parameters_restored`. QPACK: `state_updated` for our encoder's table
(`owner` local) and the peer's (remote) when capacity, size, known received count or insert count change, and
`stream_state_updated` when a field section blocks on an insert and when it is unblocked (section 6.1 counts
`current_insert_count`). The header's `common_fields` give `protocol_type` `["QUIC","HTTP3"]` when the connection's
ALPN list offers `h3` (otherwise `["QUIC"]`, and the trace takes no HTTP/3 event; section 2 of quic-events-04 and of
h3-events-04), `time_format` "relative" and `reference_time` 0, the trace's start (main-schema-05 sections 3.4.1 and
3.4.7); no record gets an earlier time than the one before it (section 3.4.1, SHOULD). Field values are
`[redacted]` (except `:method`, `:scheme`, `:status`, `:protocol`) unless `QlogSink.logHeaderValues` is set (threat
model 3.26).

**Tests that pin it.**

- a client and a server exchange, both traces checked record by record against the schema, with the events above as
  sent and as read — `runtime.H3QlogTest.aRealExchangeFollowsTheSchemaAtBothEnds`,
  `runtime.H3QlogTest.qpackStateAndBlockedStreamsAreLogged`,
  `runtime.EarlyDataTest.storedSettingsAreLoggedAsRestored`,
  `webtransport.WebTransportSessionTest.webTransportStreamsAreInTheQlogTrace`
- unknown, reserved, oversized and refused frames, a stream ending inside a frame — `runtime.H3QlogTest.unknownFramesAndStreamTypesAreLoggedByNumber`,
  `runtime.H3QlogTest.aHeadersFrameTooLargeIsLoggedWithoutFields`, `runtime.H3QlogTest.anErrorMidStreamLeavesAValidTrace`,
  `runtime.H3QlogTest.aStreamEndingInsideAFrameLeavesAValidTrace`
- redaction and the opt-in — `runtime.H3QlogTest.negative_fieldValuesNeverReachADefaultTrace`,
  `runtime.H3QlogTest.fieldValuesAreLoggedWhenTheSinkOptsIn`
- concurrency, size and failing sinks — `runtime.H3QlogTest.concurrentStreamsNeverInterleaveRecords`,
  `runtime.H3QlogTest.hugeHeadersStayOneValidRecord`, `runtime.H3QlogTest.negative_aThrowingSinkLeavesTheConnectionAlone`,
  `runtime.H3QlogTest.aStalledSinkNeverHoldsTheConnection`, `runtime.H3QlogTest.anUntracedConnectionHasNoRecorder`
- `http:frame_created` is logged once the frame's write call returned; a write that throws logs nothing (a later flush
  failure does not retract it) — `runtime.H3QlogTest.negative_aFrameWhoseWriteFailedIsNotCreated`
- peer bytes never break a record; the schema check refuses corrupt and off-schema records —
  `runtime.H3QlogTest.negative_peerBytesNeverBreakARecord`, `runtime.H3QlogTest.negative_theSchemaCheckRefusesWhatQvisWouldNot`

**Peers.** quic-go writes `http3:frame_created`/`frame_parsed`, `http3:datagram_*` of h3-events-12
(`http3/qlog/event.go:13`, frame members `http3/qlog/frame.go:56-79`, `header_fields`) and logs field values unless the
application wraps its tracer in `RedactHeaders` (`http3/qlog/header_redactor.go:12-29`); a HEADERS frame it cannot
decode is logged with its length and no fields (`http3/qlog.go:11-19`), as here. quiche writes the `http3:` events of
the current drafts (`qlog/src/events/mod.rs:549-574`), settings by their IANA names (`quiche/src/h3/frame.rs:370-410`),
a frame's `length` as its payload length (`quiche/src/h3/mod.rs:1545-1547`), and the fields of a HEADERS frame once
decoded, values included, with no redaction (`mod.rs:3156-3183`). Both write `qlog_version` 0.3 in the header for qvis (quic-go
`qlogwriter/trace.go:115-121`); Go's x/net writes main-schema-04 and quic-events-03 with 0.3 because "qvis only
supports up to 0.3" (`net/quic/qlog/qlog.go:192-196`).

**Deviations** ([ADR-0021](../../adr/0021-qlog-http3-events.md)).

- an application error code above 2^32 - 1 (WebTransport's), which `$ApplicationError / uint32` cannot hold
  (quic-events-04 sections 8.11.4, 8.11.5, 4.3), is written as `application_error_0x<hex>`, our extension of the
  `$ApplicationError` socket (section 8.11.23); in a CONNECTION_CLOSE frame it is left to `error_code_value`.
- a peer's NEW_CONNECTION_ID or RETIRE_CONNECTION_ID `sequence_number` or `retire_prior_to` above 2^32 - 1 (uint32 in
  section 8.11.15, 62 bits in RFC 9000) is written as it came, not clamped.
- not a deviation, but a reading: a CONNECTION_CLOSE frame's CRYPTO_ERROR goes in `error_code_value` alone, since section
  8.11.19 does not list the CryptoError that section 8.11.22 points to.

**Open items.**

- not loaded in qvis: the traces were validated offline against the draft's definitions as `runtime.QlogSchema`
  encodes them (no network here); opening a trace in qvis is a manual check still to do.
- the move to the current drafts (main-schema/quic-events/h3-events -12, `http3:` names) is one change for both layers.
- not written: `http:push_resolved` (no server push), `qpack:dynamic_table_updated`, `qpack:headers_encoded`,
  `qpack:headers_decoded`, `qpack:instruction_created` and `qpack:instruction_parsed` (the QPACK codecs do not expose
  single instructions; the field sections are in `http:frame_*`). HTTP/3 datagrams (RFC 9297) have events only in the
  later drafts (`http3:datagram_created`/`datagram_parsed`); the QUIC DATAGRAM frames that carry them are in the
  transport's events. Capsules travel in DATA frames and are logged as such; no draft defines capsule events.
