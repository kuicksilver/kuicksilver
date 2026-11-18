<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0021. qlog HTTP/3 events: the qlog 0.3 family, one trace per connection, field values redacted by default

Date: 2026-11-18. Status: accepted (0.3.0 feature-parity item 11).

## Context

Since 0.2.0 the QUIC endpoint writes a qlog trace per connection: qlog version 0.3 as JSON-SEQ, the event names of
draft-ietf-quic-qlog-main-schema-05 and draft-ietf-quic-qlog-quic-events-04 (`transport:`, `recovery:`,
`connectivity:`). HTTP/3 wrote nothing into it, so a trace showed packets and stream frames but not which request,
response or SETTINGS they carried. quic-go and quiche log HTTP/3 frames, stream types and settings into the same trace
as the transport (quic-go `http3/qlog/event.go`, quiche `qlog/src/events/http3.rs`).

Three questions had to be settled: which schema revision, how an HTTP/3 layer that runs on its own threads writes into
a trace the endpoint loop owns, and what a trace may contain, since HTTP fields carry credentials.

## Decision

- **The draft that matches the trace.** The HTTP/3 events follow draft-ietf-quic-qlog-h3-events-04, published on 13
  February 2023 together with main-schema-05 and quic-events-04 (the date on all three). main-schema-05 section 3 says
  "the required "qlog_version" field MUST have a value of "0.3"", the value the transport events were already
  written with; OpenSSL documents main-schema-05 with quic-events-04 as "qlog version 0.3" (`doc/man7/openssl-qlog.pod`).
  The drafts do not name each other as a set: h3-events-04 section 10 and quic-events-04 cite main-schema-04 (and
  h3-events-04 quic-events-03) of 24 October 2022, so the pairing rests on the common date and the version main-schema-05
  fixes. The events are `http:parameters_set`,
  `http:parameters_restored`, `http:stream_type_set`, `http:frame_created`, `http:frame_parsed`,
  `qpack:state_updated` and `qpack:stream_state_updated`. quic-go (`urn:ietf:params:qlog:events:http3-12`) and
  quiche (`http3:` names) write the current drafts, whose names and members differ (`http3:` for `http:`,
  `initiator` for `owner`, `frame_type_bytes` for `frame_type_value`, `header_fields` for `headers`); mixing the two in
  one file would give a trace no tool reads whole. qvis, the viewer these traces are for, reads 0.3 (quic-go and Go's
  x/net write `qlog_version` 0.3 for that reason). The move to the current drafts is one change for both layers, later.
- **Names as the draft's CDDL gives them.** `stream_type_set` has `stream_type` and, for an unknown type,
  `stream_type_value` (h3-events-04 section 4.3); an unknown frame has `frame_type_value` (section 5.2.9); a reserved
  (GREASE) frame has its `length` only (section 5.2.8); `qpack:state_updated` counts `current_insert_count` (section
  6.1); settings beyond the three the draft names go into `parameters_set` as `name => value` (section 4.1, "* text =>
  uint64").
- **What the draft has no type for.** PRIORITY_UPDATE (RFC 9218) is a frame type of its own, `priority_update` with
  `stream_id` or `push_id` and `priority_field_value` (the members of the later drafts), through the `$HTTPFrame`
  extension point, which section 5.2 provides "to support additional HTTP/3 frame types". WebTransport's `WT_STREAM`
  signal and stream type are the draft's `unknown` frame and stream type with their number and a `session_id` member
  of our own (main-schema-05 section 3.4: "tools SHOULD allow for the presence of unknown event fields"). No
  `http:push_resolved`: there is no server push.
  No `qpack:headers_encoded`/`headers_decoded`/`instruction_*`/`dynamic_table_updated`: the field sections are in
  `http:frame_*` already, and the QPACK codecs are sans-IO and do not expose their instructions one by one.
- **One trace, written by the loop.** The HTTP/3 layer formats an event on its own thread and hands it to the
  connection's `QlogRecorder` (internal API), which queues it; the endpoint loop writes the queue before its next
  transport event, and a drain task the first queued event schedules writes it when no transport event follows. A
  `QlogSink` is therefore still called on the loop only, records never interleave, and a slow or failing sink costs what
  it cost before (tracing stops for that connection). The queue holds 4096 events per connection; more are dropped.
  A connection without a sink has no recorder: the HTTP/3 layer checks one nullable field and formats nothing.
- **The header names the stacks.** quic-events-04 and h3-events-04 section 2 require `protocol_type` to contain
  "QUIC" and, once an HTTP/3 or QPACK event is in the trace, "HTTP3"; main-schema-05 section 3.4.7 does not allow a value
  that differs between events in `common_fields`. The header is written at a connection's first event, before HTTP/3
  runs, so it is decided from the connection's ALPN list: when it offers `h3` (RFC 9114 section 3.1) the header says
  `["QUIC","HTTP3"]`, otherwise `["QUIC"]`, and such a trace takes no HTTP/3 event. `reference_time` is 0 with
  `time_format` "relative": times count from the trace's start, which main-schema-05 section 3.4.1 allows ("time since
  connection start in ms"), and no wall clock enters the trace.
- **Times never go back, and transport times stay as they were.** main-schema-05 section 3.4.1: events "SHOULD be
  logged in strictly ascending timestamp order". An HTTP/3 event is stamped on its own thread; a transport event carries
  its loop turn's clock reading, which may be older. The loop writes queued HTTP/3 events just before a transport
  event, or in a drain task, and gives each its own time kept between the last record's time and the time of that
  transport event (or the loop's clock in the drain task): one stamped later than the turn that writes it takes the
  turn's time. Only HTTP/3 events move, by less than a loop turn; transport events keep their times, which
  `tools/interop/closing-challenge.py` maps to packet captures. (A first version raised the transport event's time
  instead, which could move such a mapping.)
- **Typed transport frames.** `packet_sent` and `packet_received` carry every frame with the members quic-events-04
  section 8.11 defines: offsets and lengths of STREAM and CRYPTO frames, ACK ranges with `ack_delay` and ECN counts,
  stream limits, connection IDs, path data, CONNECTION_CLOSE with `error_space`, `error_code` (a TransportError name,
  section 8.11.22), `error_code_value`, `reason` and `trigger_frame_type`, and so on;
  RESET_STREAM_AT and DATAGRAM through the `$QuicFrame` extension point. A sent packet's frames are read back from its
  plaintext payload before it is sealed, so the trace shows what went on the wire; a received packet's frames are
  recorded as the decoder hands them to the connection. An untraced connection does neither. Packet types are those of
  section 8.5, 0-RTT packets included, also for a lost or dropped 0-RTT packet. Each direction has its own recorder.
  Formatting a received frame never fails the connection: a failure drops that packet's frames from the trace, and the
  frame still reaches the connection.
- **Deviations from the draft's types, as decided.** Three values do not fit the types the drafts give them, and the
  trace writes them as follows rather than dropping or bending them:
  - A CRYPTO_ERROR in a CONNECTION_CLOSE frame: section 8.11.19 types `error_code` as `TransportError /
    $ApplicationError / uint32` while section 8.11.22 says to use CryptoError for it, which 8.11.19 does not list. The
    frame leaves `error_code` out and gives the code in `error_code_value` (both optional): no deviation in the frame.
    `connectivity:connection_closed`, whose `connection_code` lists CryptoError (section 4.3), names it there.
  - An application error code above 2^32 - 1 (WebTransport's, draft-ietf-webtrans-http3 section 4.4), which
    `$ApplicationError / uint32` cannot hold, in a RESET_STREAM, STOP_SENDING or RESET_STREAM_AT (where `error_code` is
    required) and in `connection_closed`: written as `application_error_0x<hex>`, our extension of the
    `$ApplicationError` socket (section 8.11.23 asks applications to extend it, the way CryptoError writes its codes).
    No tool knows the name; it is a deviation, chosen over losing the code. In a CONNECTION_CLOSE frame such a code is
    left to `error_code_value`.
  - A NEW_CONNECTION_ID or RETIRE_CONNECTION_ID `sequence_number` or `retire_prior_to` above 2^32 - 1: section 8.11.15
    types them uint32, RFC 9000 allows 62 bits. Ours never get there; a peer's is written as it came, not clamped (a
    clamped value would name another connection ID). A deviation for such a peer only.
- **Secrets in frames.** Never written: a NEW_TOKEN's token (logged by its length: a token lets its holder skip
  address validation; section 8.8 makes its bytes optional), the stateless reset token of a NEW_CONNECTION_ID
  (optional in section 8.11.15; whoever holds it can end the connection), and STREAM, CRYPTO and DATAGRAM payloads.
  Written: connection IDs (section 8.11.15 requires them, and they travel in clear in packet headers) and PATH_CHALLENGE
  data (useful to pair a challenge with its response, worthless once the path is validated). There is no opt-in for the
  tokens, unlike field values: nothing in a trace needs them.
- **The trace covers the closing period.** `connectivity:connection_closed` is written once, when the connection
  starts to close, and the trace stays open until the connection releases its resources (RFC 9000 section 10.2), so
  the packet that carries the close and those that answer it are in it. Every state change is logged with the state
  left (`old`) and the state entered (`new`, section 4.6): `handshake_complete`, `handshake_confirmed`, `closing`,
  `draining`, `closed`. The first state, `handshake_started`, is not: a server connection is made for an Initial
  before it is known to decrypt, and logging then would open a trace for every forged Initial.
- **When an HTTP/3 frame is `created`.** `http:frame_created` (and `http:stream_type_set` for our streams) is logged once
  the frame (or the stream type) was handed to its stream, the write call returned, and never for a write that
  failed: a HEADERS or DATA frame the peer's STOP_SENDING refused, a control frame on a stream that is gone. The same
  for every frame: request and response heads and trailers, DATA, SETTINGS, GOAWAY, PRIORITY_UPDATE, GREASE, WebTransport
  signals.
- **Field values redacted by default (CWE-532).** Every header and trailer field is written with its name; its value is
  `[redacted]` unless the sink sets `QlogSink.logHeaderValues`, except `:method`, `:scheme`, `:status` and
  `:protocol`, tokens the protocol defines. quic-go logs values and offers a redaction wrapper
  (`http3/qlog/header_redactor.go`); here a trace handed to someone else holds no cookie, credential or URL unless
  the operator asked for it.

## Consequences

- A trace holds both layers in the order of their writing; an HTTP/3 event's time may be moved back to the loop turn
  that wrote it.
- The transport events changed with the header: their enumerations are now quic-events-04's (connection states of
  section 4.6, a `packet_dropped` trigger of section 5.7, `connection_closed` triggers of section 4.3; `packet_lost`
  without a trigger, as section 7.5 has none for "time or packet threshold"), their frames are typed, and the last
  record of a trace is no longer always `connection_closed` (the soak test's failure capture looks for it).
- Traces of 0.3.0 are read by the qvis builds that read 0.3, and by tools that read the h3-events-04 names.
- The traces were validated offline against the drafts' definitions as the tests encode them (`runtime.QlogSchema`);
  loading them in qvis is a manual step.

## Alternatives rejected

- **The current drafts (h3-events-12) for HTTP/3 only**: two schema versions in one file.
- **A lock around the writer** so that HTTP/3 threads call the sink: a slow sink would then block the loop from any
  thread, and the sink contract (called on the loop) would change.
- **Values logged by default, with a redaction option** (quic-go's choice): the default trace would then be a secret.
