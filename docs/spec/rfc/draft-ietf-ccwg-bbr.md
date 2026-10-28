<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# draft-ietf-ccwg-bbr — BBR Congestion Control (draft-ietf-ccwg-bbr-06)

Details of the rows of the [RFC compliance summary](../rfc-compliance.md) for this document. Each section gives the requirement, how Kuicksilver meets it (with the files), the tests that pin it, its history, notes on peers and the open items. Status: ✅ met · 🔶 feature subset · ⬜ planned · ❌ not planned; "since" is the release from which the current behaviour holds (history below and in [CHANGELOG.md](../../../CHANGELOG.md)).

## <a id="bbr-bbrv3"></a>BBR (BBRv3)

Status: ✅ since 0.2.0 · [summary](../rfc-compliance.md#quic)

Original row: draft-ietf-ccwg-bbr-06.

**Requirement.** BBR (BBRv3).

Quoted: "MUST treat any CE marks as congestion"; "MUST conform to the congestion control guidelines specified in Section 3.1 of [RFC8085]".

**Recorded status.** ✅ 0.2.0 (opt-in, experimental)

**How it is met.**

- `Bbr` (`QuicConfig.congestionController`; CUBIC stays the default)
- delivery-rate sampling §4.1 (`recovery/DeliveryRateSampler`, per-packet snapshot on `SentPacket`, app-limited marking when `PacketBuilder.poll` runs out of data with room in the window, samples shorter than min RTT give no rate; an ACK's packets reach the sampler before its loss detection, `LossListener.onDelivered`)
- max_bw over two ProbeBW cycles and extra_acked over 10 rounds (`recovery/WindowedMaxFilter`, Linux win_minmax)
- min_rtt 10 s with ProbeRTT every 5 s (cwnd 0.5 BDP, ≥ 200 ms and one round)
- Startup (gain 2.77, exit on a 3-round plateau below +25 % or, at the end of a loss round, on ≥ 6 lost ranges above 2 %; a CE report counts as one such event and a round with CE skips the 2 % test, 0.2.0 — §3.7 "MUST treat any CE marks as congestion"), Drain (0.5), ProbeBW Down (0.9) / Cruise (IsTimeToCruise on max_bw) / Refill / Up (1.25, cwnd 2.25) with the Reno-coexistence and 2-3 s randomised probe times
- inflight_longterm from probes losing > 2 % (InflightAtLoss, floored at 4 datagrams), bw/inflight_shortterm × 0.7 per lossy round outside probes, headroom 15 %
- ECN-CE as loss (§3.7) after the ACK's packets left the flight, every CE report counted (once per round), CE while probing ends the probe
- §5.5.11 spurious-loss undo: loss detection remembers 64 lost packets per space for the persistent-congestion period and reports a late ACK (`onSpuriousLoss`, RFC 9002 §6.1) or the loss standing (`onLossSettled`)
- an episode whose every lost packet came back restores cwnd, the bounds and Startup or the probe
- the snapshot is taken when the episode begins (as Linux `bbr_ssthresh`), not per round
- §5.4 restart from idle paces at BBR.bw (the pacer bucket caps the first burst at the 1 ms quantum; BBR is paced below 1 ms srtt) and ends a finished ProbeRTT
- send quantum max(min(1 ms, 64 KiB), 2 datagrams)
- RFC 9002 §7.6.2's kMinimumWindow is the response of its NewReno controller (§7: another controller "MUST conform to the congestion control guidelines specified in Section 3.1 of [RFC8085]"), which BBR does not take
- a PTO probe past a full window is not cwnd-limited
- RFC 9000 §9.4: a new peer address gets a fresh controller, a NAT rebinding keeps it
- the model moves once per ACK frame (`LossListener.onAckProcessed`)
- limitations: above ~2 % random loss the flow runs near its floor (by design), at RTT > ~1.5 s ProbeRTT interrupts Startup's plateau test
- experimental

**Tests that pin it.**

- nothing allocates per ACK (`CoreAllocationTest.steadyStateBbrAllocatesZero`)
- `recovery.BbrTest.*` (24, among them `startupEndsOnSustainedCeMarks`, `aLargerDatagramSizeNeverRaisesTheWindow`), `recovery.BbrPropertyTest.*` (3: random streams keep the invariants, 10-100 Gbit/s × 100 µs-2 s without overflow), `fuzz.BbrInvariantFuzzTest.bbrInvariants` (Jazzer), `recovery.LossDetectionTest.*Spurious*`/`*Settle*`/`anAckReportsItsPacketsDeliveredBeforeItsLosses`, `recovery.PacerTest.aLongIdleGapAtTenGbitPerSecondRefillsTheBucket`, `recovery.PacerTest.bbrIsPacedEvenBelow1msSrtt`, `core.PathTest.bbrStartsAFreshModelOnANewAddress`, `core.PathTest.bbrKeepsItsModelAcrossANatRebinding`, `recovery.DeliveryRateSamplerTest.*`, `recovery.WindowedMaxFilterTest.*`, `testing.BbrSimulationTest.*`, `testing.BbrHarshScenarioTest.*`, `testing.BbrHighRateScenarioTest.*`
- numbers in [the QUIC guide](../../guide/quic.md#choosing-a-congestion-controller)

**Peer interop notes.**

- MTU changes move the 4-datagram floor (applied when the window is next set, as ngtcp2) and, before the first ACK, lower the initial window, never raising the window itself (RFC 8899 §3 item 7, 0.2.0)
- recovery saves and restores cwnd, persistent congestion is BBR's RTO (§5.6.4.4 `OnEnterRTO`): cwnd = max(inflight + 1 datagram, BBR.MinPipeCwnd of 4 datagrams), as ngtcp2 `bbr_cc_on_persistent_congestion`, and the RTO recovery that follows ends with the ACK of a packet sent after it, restoring the window from before (`RestoreCwnd`) — `recovery.BbrTest.persistentCongestionLeavesRoomForOneDatagramAboveTheFlight`, `.theWindowBeforePersistentCongestionComesBackWhenItsRecoveryEnds`
- references ngtcp2 `ngtcp2_bbr.c`/`ngtcp2_rtb.c`, Linux `tcp_bbr.c` v3
