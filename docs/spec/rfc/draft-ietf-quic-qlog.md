<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# draft-ietf-quic-qlog — qlog (draft-ietf-quic-qlog-*)

Details of the rows of the [RFC compliance summary](../rfc-compliance.md) for this document. Each section gives the requirement, how Kuicksilver meets it (with the files), the tests that pin it, its history, notes on peers and the open items. Status: ✅ met · 🔶 feature subset · ⬜ planned · ❌ not planned; "since" is the release from which the current behaviour holds (history below and in [CHANGELOG.md](../../../CHANGELOG.md)).

## <a id="qlog"></a>qlog

Status: ✅ since 0.2.0 · [summary](../rfc-compliance.md#quic)

Original row: draft-ietf-quic-qlog-*.

**Requirement.** Qlog.

**Recorded status.** ✅ 0.2.0 (version 0.3, JSON-SEQ)

**Tests that pin it.**

- `qlog.QlogWriterTest.firstRecordIsHeader`, `qlog.QlogWriterTest.eventsUseRelativeMillis`, `qlog.QlogWriterTest.packetSentFields`, `qlog.QlogWriterTest.lossAndMetricsEvents`, `qlog.QlogWriterTest.stopsAtCapWithoutError`, `qlog.QlogWriterTest.filePerConnectionNamedByOdcid`
- the trace is opened on the first event (an undecrypted Initial creates no file) and closed in `release()`, a failure of the sink's `open`/`write`/`close` disables tracing for that connection without touching it or the endpoint — `qlog.QlogRobustnessTest.*`
- schema draft-ietf-quic-qlog-main-schema/quic-events 0.3 — not validated in qvis yet
