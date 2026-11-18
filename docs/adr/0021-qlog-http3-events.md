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

- **The draft that matches the trace.** The HTTP/3 events follow draft-ietf-quic-qlog-h3-events-04, the HTTP/3
  revision of the batch that brought main-schema-05 and quic-events-04, which OpenSSL documents as "qlog version 0.3"
  (`doc/man7/openssl-qlog.pod`) and which the transport events already follow. The events are `http:parameters_set`,
  `http:parameters_restored`, `http:stream_type_set`, `http:frame_created`, `http:frame_parsed`,
  `qpack:state_updated` and `qpack:stream_state_updated`. quic-go (`urn:ietf:params:qlog:events:http3-12`) and
  quiche (`http3:` names) write the current drafts, whose names and members differ (`http3:` for `http:`,
  `initiator` for `owner`, `frame_type_bytes` for `raw_frame_type`, `header_fields` for `headers`); mixing the two in
  one file would give a trace no tool reads whole. qvis, the viewer these traces are for, reads 0.3 (quic-go and Go's
  x/net write `qlog_version` 0.3 for that reason). The move to the current drafts is one change for both layers, later.
- **What the draft has no type for** is its `unknown` frame or stream type with the number (`raw_frame_type`,
  `raw_stream_type`), plus members of its own that tools ignore: PRIORITY_UPDATE (RFC 9218) with `stream_id` or
  `push_id` and `priority_field_value` (the names of the later drafts), WebTransport's `WT_STREAM` signal and stream type
  with `session_id`. GREASE frames are `reserved`, with their number. No `http:push_resolved`: there is no server push.
  No `qpack:headers_encoded`/`headers_decoded`/`instruction_*`/`dynamic_table_updated`: the field sections are in
  `http:frame_*` already, and the QPACK codecs are sans-IO and do not expose their instructions one by one.
- **One trace, written by the loop.** The HTTP/3 layer formats an event on its own thread and hands it to the
  connection's `QlogRecorder` (internal API), which queues it; the endpoint loop writes the queue before its next
  transport event, and a drain task the first queued event schedules writes it when no transport event follows. A
  `QlogSink` is therefore still called on the loop only, records never interleave, and a slow or failing sink costs what
  it cost before (tracing stops for that connection). The queue holds 4096 events per connection; more are dropped.
  A connection without a sink has no recorder: the HTTP/3 layer checks one nullable field and formats nothing.
- **Field values redacted by default (CWE-532).** Every header and trailer field is written with its name; its value is
  `[redacted]` unless the sink sets `QlogSink.logHeaderValues`, except `:method`, `:scheme`, `:status` and
  `:protocol`, tokens the protocol defines. quic-go logs values and offers a redaction wrapper
  (`http3/qlog/header_redactor.go`); here a trace handed to someone else holds no cookie, credential or URL unless
  the operator asked for it.

## Consequences

- A trace holds both layers in time order of their writing; an HTTP/3 event's time is read on its own thread, so an
  event may carry a time a few microseconds after the transport event written after it.
- Traces of 0.3.0 are read by the qvis builds that read 0.3, and by tools that read the h3-events-04 names.
- The traces were validated offline against the drafts' definitions as the tests encode them (`runtime.QlogSchema`);
  loading them in qvis is a manual step.

## Alternatives rejected

- **The current drafts (h3-events-12) for HTTP/3 only**: two schema versions in one file.
- **A lock around the writer** so that HTTP/3 threads call the sink: a slow sink would then block the loop from any
  thread, and the sink contract (called on the loop) would change.
- **Values logged by default, with a redaction option** (quic-go's choice): the default trace would then be a secret.
