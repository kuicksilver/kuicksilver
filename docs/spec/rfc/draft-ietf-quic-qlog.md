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

## <a id="qlog-h3"></a>qlog HTTP/3 and QPACK events

Status: ✅ since 0.3.0 · [summary](../rfc-compliance.md#quic)

Original row: draft-ietf-quic-qlog-h3-events-04.

**Requirement.** The HTTP/3 and QPACK events of draft-ietf-quic-qlog-h3-events-04, the revision of the batch whose
main-schema-05 and quic-events-04 define the trace's qlog 0.3 ([ADR-0021](../../adr/0021-qlog-http3-events.md)): in
the `http` category `parameters_set`, `parameters_restored`, `stream_type_set`, `frame_created` and `frame_parsed`; in
the `qpack` category `state_updated` and `stream_state_updated`. The drafts define the events, not when an
implementation must write one: qlog's MUSTs are about the format, which `runtime.QlogSchema` checks.

**How it is met.** `kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/runtime/H3Qlog.kt` formats the
events; `QlogRecorder` (`kuicksilver-quic`, internal API) queues them into the connection's trace, which the endpoint
loop writes. Every frame we send or read is logged: DATA, HEADERS (request, response and trailer field sections, with
their fields once decoded; one that is too large or does not decode with an empty list), SETTINGS (each setting by its
IANA name, others by number), GOAWAY, MAX_PUSH_ID and CANCEL_PUSH with their identifiers, reserved (GREASE) frames
with their number, and frames the draft has no type for as `unknown` with `raw_frame_type`: PRIORITY_UPDATE (with
`stream_id` or `push_id` and `priority_field_value`, members of the later drafts) and WebTransport's `WT_STREAM`
signal (with `session_id`). A frame refused by the stream it arrived on is logged before the error. Unidirectional
stream types are logged as sent and as read (`control`, `qpack_encode`, `qpack_decode`, `reserved`, `unknown` with
`raw_stream_type`; WebTransport streams with `session_id`). SETTINGS give `parameters_set` (`owner` local or remote),
the server SETTINGS a 0-RTT client remembered `parameters_restored`. QPACK: `state_updated` for our encoder's table
(`owner` local) and the peer's (remote) when capacity, size, known received count or insert count change, and
`stream_state_updated` when a field section blocks on an insert and when it is unblocked. Field values are
`[redacted]` (except `:method`, `:scheme`, `:status`, `:protocol`) unless `QlogSink.logHeaderValues` is set (threat
model 3.25).

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
- the schema check refuses corrupt and off-schema records — `runtime.H3QlogTest.negative_theSchemaCheckRefusesWhatQvisWouldNot`

**Peers.** quic-go writes `http3:frame_created`/`frame_parsed`, `http3:datagram_*` of h3-events-12
(`http3/qlog/event.go:13`, frame members `http3/qlog/frame.go:56-79`, `header_fields`) and logs field values unless the
application wraps its tracer in `RedactHeaders` (`http3/qlog/header_redactor.go:12-29`); a HEADERS frame it cannot
decode is logged with its length and no fields (`http3/qlog.go:11-19`), as here. quiche writes the `http3:` events of
the current drafts (`qlog/src/events/mod.rs:549-574`), settings by their IANA names (`quiche/src/h3/frame.rs:370-410`),
a frame's `length` as its payload length (`quiche/src/h3/mod.rs:1545-1547`), and HEADERS frames it parsed with empty
`headers` (`frame.rs:343-350`). Both write `qlog_version` 0.3 in the header for qvis (quic-go
`qlogwriter/trace.go:115-121`); Go's x/net writes main-schema-04 and quic-events-03 with 0.3 because "qvis only
supports up to 0.3" (`net/quic/qlog/qlog.go:192-196`).

**Open items.**

- not loaded in qvis: the traces were validated offline against the draft's definitions as `runtime.QlogSchema`
  encodes them (no network here); opening a trace in qvis is a manual check still to do.
- the move to the current drafts (main-schema/quic-events/h3-events -12, `http3:` names) is one change for both layers.
- not written: `http:push_resolved` (no server push), `qpack:dynamic_table_updated`, `qpack:headers_encoded`,
  `qpack:headers_decoded`, `qpack:instruction_created` and `qpack:instruction_parsed` (the QPACK codecs do not expose
  single instructions; the field sections are in `http:frame_*`).
