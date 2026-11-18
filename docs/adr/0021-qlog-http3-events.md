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
- **Times never go back.** main-schema-05 section 3.4.1: events "SHOULD be logged in strictly ascending timestamp
  order". An HTTP/3 event is stamped on its own thread and a transport event with its loop turn's clock reading, which
  may be older; the writer gives no record an earlier time than the one before it (events of one loop turn share a
  time, as they did before).
- **Field values redacted by default (CWE-532).** Every header and trailer field is written with its name; its value is
  `[redacted]` unless the sink sets `QlogSink.logHeaderValues`, except `:method`, `:scheme`, `:status` and
  `:protocol`, tokens the protocol defines. quic-go logs values and offers a redaction wrapper
  (`http3/qlog/header_redactor.go`); here a trace handed to someone else holds no cookie, credential or URL unless
  the operator asked for it.

## Consequences

- A trace holds both layers in the order of their writing. A transport event written after an HTTP/3 event stamped
  later carries that later time: it can move by at most the time a loop turn takes.
- The transport events changed with the header: their enumerations are now quic-events-04's (connection states of
  section 4.6, a `packet_dropped` trigger of section 5.7, `connection_closed` triggers of section 4.3; `packet_lost`
  without a trigger, as section 7.5 has none for "time or packet threshold"). Their frames are still logged by type
  alone, valid through the `$QuicFrame` extension point but without the members section 8.11 defines for each type.
- Traces of 0.3.0 are read by the qvis builds that read 0.3, and by tools that read the h3-events-04 names.
- The traces were validated offline against the drafts' definitions as the tests encode them (`runtime.QlogSchema`);
  loading them in qvis is a manual step.

## Alternatives rejected

- **The current drafts (h3-events-12) for HTTP/3 only**: two schema versions in one file.
- **A lock around the writer** so that HTTP/3 threads call the sink: a slow sink would then block the loop from any
  thread, and the sink contract (called on the loop) would change.
- **Values logged by default, with a redaction option** (quic-go's choice): the default trace would then be a secret.
