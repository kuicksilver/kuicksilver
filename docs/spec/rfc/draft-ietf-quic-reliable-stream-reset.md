<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# draft-ietf-quic-reliable-stream-reset — QUIC Stream Resets with Partial Delivery (draft-ietf-quic-reliable-stream-reset-11, RESET_STREAM_AT)

Details of the rows of the [RFC compliance summary](../rfc-compliance.md) for this document. Each section gives the requirement, how Kuicksilver meets it (with the files), the tests that pin it, its history, notes on peers and the open items. Status: ✅ met · 🔶 feature subset · ⬜ planned · ❌ not planned; "since" is the release from which the current behaviour holds (history below and in [CHANGELOG.md](../../../CHANGELOG.md)).

## <a id="reset-stream-at"></a>RESET_STREAM_AT

Status: 🔶 since 0.3.0 · [summary](../rfc-compliance.md#quic)

Original row: draft-ietf-quic-reliable-stream-reset-11.

**Requirement.** RESET_STREAM_AT.

Quoted: "MUST NOT change the Application Error Code".

**Recorded status.** 🔶 0.3.0 (experimental, off by default)

**How it is met.**

- with both sides' parameter `QuicStream.resetAt(code, reliableSize)` (core: `ConnectionCore.resetStreamAt`) sends RESET_STREAM_AT (0x24): the bytes below the reliable size (cut to what was written) keep being sent and retransmitted, the rest is dropped, and the frame waits until every reliable byte was sent once, so its final size stays within the peer's flow control (section 4)
- the stream retires once they are acknowledged
- acknowledgements of bytes past the reliable size that were sent before the reset release nothing twice
- without the peer's parameter it is RESET_STREAM
- a later RESET_STREAM (our `reset`, or answering STOP_SENDING) carries the same final size and the RESET_STREAM_AT's code (section 5.2 "MUST NOT change the Application Error Code", 0.2.1 — `core.ResetStreamAtTest.laterResetKeepsTheResetStreamAtCode`).
- Receiver: the reliable bytes are delivered, then the reset (a stream input never reads -1 for it)
- bytes read before the frame arrived may go past the reliable size
- the smallest reliable size received counts, once a RESET_STREAM_AT arrived on the stream, a later RESET_STREAM or RESET_STREAM_AT with another code → STREAM_STATE_ERROR (section 5.2; two plain RESET_STREAMs with different codes stay ignored, as RFC 9000 allows), the final size must not change (FINAL_SIZE_ERROR)
- a server's 0-RTT acceptance that drops a remembered `reset_stream_at` → PROTOCOL_VIOLATION, as a lower limit
- the server binds `resetStreamAt` into its tickets' early-data context, so it never accepts 0-RTT with the extension turned off since the ticket (section 3 MUST NOT, 0.2.1 — `core.ZeroRttTest.negative_resetStreamAtIsPartOfTheEarlyDataContext`)
- reliable size above final size → FRAME_ENCODING_ERROR
- the frame without our parameter → FRAME_ENCODING_ERROR (an unknown frame)

**Tests that pin it.**

- `wire.TransportParametersTest.resetStreamAtBothCodepoints`, `core.ResetStreamAtTest.*` (including `resetAtDeliversReliablePrefix` with 10% loss both ways, `resetAtWaitsForFlowControlCredit`, `ackOfBytesPastTheReliableSizeKeepsTheBufferExact`, `negative_resetCodeChangeIsStreamStateError`, `stream.StreamStateTest.secondPlainResetWithAnotherCodeIsIgnored`, `.negative_changedCodeAfterResetStreamAtIsStreamStateError`, `negative_resetStreamAtReliableSizeAboveFinalIsError`, `negative_resetStreamAtWithoutNegotiationIsFrameEncodingError`), `wire.FrameCodecTest.resetStreamAtRoundTrips`, `.negative_resetStreamAtReliableSizeAboveFinalIsError`, `api.StreamBridgeTest.resetAtDeliversThePrefixThenTheReset`

**Peer interop notes.**

- `QuicConfig.resetStreamAt` advertises `reset_stream_at` as 0x1d, and as the pre-IANA 0x17f7586d2cb571 for Chrome and quiche (both are accepted; quic-go and neqo use 0x1d)

**Open items.** See the roadmap ([docs/roadmap.md](../../roadmap.md)).
