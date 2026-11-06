<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# draft-ietf-quic-load-balancers — QUIC-LB: Generating Routable QUIC Connection IDs (draft-ietf-quic-load-balancers)

Details of the rows of the [RFC compliance summary](../rfc-compliance.md) for this document. Each section gives the requirement, how Kuicksilver meets it (with the files), the tests that pin it, its history, notes on peers and the open items. Status: ✅ met · 🔶 feature subset · ⬜ planned · ❌ not planned; "since" is the release from which the current behaviour holds (history below and in [CHANGELOG.md](../../../CHANGELOG.md)).

## <a id="quic-lb"></a>QUIC-LB

Status: ✅ since 0.3.0 (experimental) · [summary](../rfc-compliance.md#quic)

Original row: draft-ietf-quic-load-balancers.

The text is draft-ietf-quic-load-balancers-21 (27 August 2025, expired 28 February 2026; Standards Track, not an RFC).
Kuicksilver is a server here: it encodes its server ID into the connection IDs it issues. The load balancer's side
(sections 4.2, 4.3, 5.5, 6) and the configuration agent's (5.3, 9.4) are not part of it; the codec decodes only to gate
Stateless Resets.

**Requirement (server).**

- 3.1: "The first three bits of any connection ID MUST encode an identifier for the configuration that the connection ID
  uses." "A configuration MUST NOT use the reserved identifier 0b111." "Servers MUST NOT generate new connection IDs using
  an old configuration after receiving a new one from the configuration agent. Servers MUST use that QUIC version's
  methods to update the client with CIDs (e.g., NEW_CONNECTION_ID frames) using the new configuration and retire CIDs
  using the old configuration."
- 3.2: "Servers with no active configuration MUST issue connection IDs with the reserved value of the three most
  significant bits set to 0b111 [...] These connection IDs MUST self-encode their length", "SHOULD provide the client
  exactly one CID over the life of the connection", "SHOULD send the "disable_active_migration" transport parameter",
  "all bytes but the first SHOULD have no larger of a chance of collision as random bytes. The connection ID SHOULD be of
  at least length 8".
- 3.3: the five low bits of the first octet "are reserved to express the length of the following connection ID".
- 5.1, 5.3: a server ID of "at least one octet", "The nonce length MUST be at least 4 octets", "the server ID and nonce
  lengths MUST sum to 19 octets or less".
- 5.4: "If there is no key in the configuration, the server MUST fill the Nonce field with bytes that have no observable
  relationship to the field in previously issued connection IDs." 5.4.1: with 16 octets "the server MUST use a
  single-pass encryption algorithm". 5.4.2: otherwise "the server MUST follow the algorith below"; expand's "'length'
  argument MUST NOT exceed 19 and MUST NOT be less than 5".
- 9: "Servers that are encoding their server ID without a key algorithm SHOULD only use it to generate new CIDs for the
  Server Initial Packet and SHOULD NOT send CIDs in QUIC NEW_CONNECTION_ID frames, except that it sends one new
  Connection ID in the event of config rotation".
- 9.6: "Whether or not it implements the counter method, the server MUST NOT reuse a nonce until it switches to a
  configuration with new keys", "servers SHOULD start with a random nonce value", "A server that has exhausted its nonces MUST either switch to a different configuration, or if
  none exists, use the 4-tuple routing config rotation codepoint."
- RFC 9000 5.1.2: the endpoint that raises Retire Prior To "SHOULD continue to accept the previously issued connection IDs
  until they are retired by the peer".
- 9.7: deployments that mix clear text and encrypted IDs "MUST use different server ID allocations for the clear text and
  the encrypted versions".

**How it is met.**

- `QuicLbConfig` (public, experimental): config rotation codepoint 0..6, server ID of 1..15 bytes, nonce of at least 4,
  both at most 19 bytes, an optional AES key as a `LoadBalancerKey` (the bytes go into `ksl` once through
  `QuicCrypto.newLoadBalancerKey`, which wipes them; Kotlin keeps a handle and a keyed fingerprint, and every endpoint
  that takes the configuration holds its own copy, `ksl_key_lb_dup`, so the caller's close never reaches it), an optional
  `QuicLbNonceReservation`. `QuicEndpointConfig.loadBalancer` needs a server, a `connectionIdLength` equal to
  `1 + server ID + nonce` and at least 8, and a key when a `preferredAddress` is offered. The Ktor engine's
  `quicLoadBalancer` and `updateLoadBalancer` (every listener checked before any changes), `Http3Endpoint.updateLoadBalancer`
  and the sans-IO `EndpointCore.updateLoadBalancer` reach the same code.
- `endpoint/QuicLb.kt`: `QuicLbCodec` writes `configId << 5 | (length - 1)` and the server ID and nonce, in clear or
  encrypted by `QuicLbCipher` (one AES-128-ECB block for 16 bytes, else the four-pass Feistel network with `expand` and
  the nibble split of odd lengths); `decodeServerId` / `matchesServerId` run it backwards. AES runs in `ksl`
  (`ksl_key_ecb16`, the key schedule expanded once and copied per call; ADR-0003).
- Nonces (5.4, 9.6): `QuicLbNonceSpaces` holds, for the life of the process, one counter per key fingerprint and nonce
  length (per nonce length in clear), shared by every endpoint and server ID that uses it. Each value is permuted
  (`QuicLbCipher` over the nonce length) with a key derived in `ksl` from the configuration key (`ksl_key_lb_derive`), or
  in clear with a key of the process, so nonces show no relation to each other and none repeats while the process runs.
  The counter starts at a random point. With a `QuicLbNonceReservation` (every configuration of a nonce space must bring
  the same one, or none) the start and the permutation are fixed (derived from the key, or in clear from the
  reservation's stored `secret()`), and the counter goes on past the mark the last process stored: nonces are used only
  below the stored mark, the next block of 65,536 is stored ahead of need outside any lock, and a crash skips, never
  reuses. Only the space instance the registry keeps ever stores, so the stored mark only moves up; the first block is
  stored when an update builds the configuration, on `Dispatchers.IO`, off the loops (one update at a time; a stale
  reuse is prepared again; a caller cancelled after the commit leaves it in force). A failed store is retried after a
  back-off counted in receive batches of every loop and in requests that find nothing reserved, scaled by the number of
  loops (about one store try a round for the group), and counted apart (`loadBalancerReservationFailures`); while no
  nonce is reserved nothing is drawn, and a request gets an unroutable ID for itself only. The derivation blocks end in
  0x80..0x82, never a Feistel pass number, so none is an `expand` block under the same key. Once 2^(8 x nonce length) values are drawn the endpoint
  issues unroutable IDs, counts it in `loadBalancerNoncesExhausted` and logs it.
- `endpoint/CidRoute.kt`: `QuicLbRoute` makes every ID (server connections under the current configuration; unroutable
  IDs `0b111 << 5 | (length - 1)` with CSPRNG bytes when there is none, the nonces are spent, or for a client connection
  of a loop group). The owning loop is `SipHash(group key, ID) mod loops` for any ID of our length with a matching
  length octet; a nonce whose ID hashes to another loop waits in that loop's pool (1,024 IDs), past that it is issued
  where it was drawn with an owner exception (`OwnerExceptions`: at most 65,536 live IDs, past that the nonce spent unused rather than a live entry dropped,
  each released when its ID leaves or its connection fails to be made; the datagram path checks a per-bucket counter and
  compares bytes in place, without allocating or a global lock). A Retry's SCID takes no exception: its nonce is spent
  unused past a full pool (`loadBalancerNoncesWasted`). Stateless Resets: only while the reset limit would let one out (else
  counted as rate limited), for an ID under the current or previous configuration's codepoint that decrypts, within a
  budget of decryptions per address and in total a second, to this server's ID, and hashes to this loop.
  `QuicLbState` holds the current and previous configurations of an endpoint (shared by a group's loops; a group's cores
  cannot be built without it); keys are made and nonce spaces looked up outside its lock. It frees a configuration's key
  copy and permutation key once it is neither current nor previous and no loop uses it, and refuses a server ID used in
  clear and encrypted (9.7, over every configuration the endpoint used), a codepoint the current or previous
  configuration holds with another key, server ID or nonce length, and another nonce reservation than the space's.
- `QuicEndpoint.updateLoadBalancer`: new IDs use the new configuration at once; every live server connection gets one
  NEW_CONNECTION_ID under it whose Retire Prior To retires every earlier ID (`ConnectionIdManager.requestReissue`), and
  the replacements the client's retirements call for come from it too. A change while the client has not retired what the
  last one asked for waits for those retirements (RFC 9000 5.1.2), one at most. The issuance mode follows the ID actually
  made: a plaintext change sends exactly one ID (fills of a connection that had the full set stop), an unroutable one
  none. `null` switches to unroutable IDs: new connections get one ID and `disable_active_migration`, live ones keep
  their IDs and stop handing out new ones. After a Retry the connection keeps the Retry's SCID as its one server ID
  (sections 3.2 and 9) whenever its first octet still tells what it allows (0b111, or the current or previous codepoint);
  only a codepoint that went away since the Retry, or an unroutable SCID made while no nonce was reserved when one is now,
  gets a fresh ID, the Retry SCID staying an alias. A kept SCID that is not of the current configuration gets the change's
  NEW_CONNECTION_ID at once (section 3.1).
- Plaintext configurations and unroutable IDs: the connection hands out only its handshake ID (`CidIssuance.Single`,
  `ConnectionIdManager.limitToSingle`), no `preferred_address`. A connection whose nonces run out under it keeps the IDs it
  has and issues no unroutable one (3.2).

**Tests.** `QuicLbTest.*` (every Appendix B vector encoded and decoded, the 5.4.2.4 example and its expand and AES
output, round trips of lengths 4..19, `nonceCounterNeverRepeats`, `noncesArePermuted`, `nonceExhaustionReturnsNull`,
`nonceSpaceSharedByKeyAcrossServerIdsAndEndpoints`, `nonceReservationSurvivesARestart`,
`negative_reservationFailureGoesUnroutable`, `reservationStoreBacksOff`, `negative_reservationMustMatchTheNonceSpace`,
`plaintextReservationSurvivesARestart`, `negative_configIdSevenRejected`, `negative_sidPlusNonceOver19Rejected`,
`negative_nonceUnder4Rejected`), `EndpointCoreTest.quicLbIssuedCidsDecodeToServerId`,
`.quicLbOwnerLoopMatchesIssuingLoop`, `.quicLbOwnerOfAnOlderConfigurationsId`, `.quicLbRotationKeepsOldConnectionsRouting`,
`.quicLbBackToBackUpdatesWaitForRetirements`, `.quicLbExhaustionGoesUnroutable`, `.quicLbExhaustionAfterHandshakeStopsIssuing`,
`.quicLbPlaintextHandsOutOneCid`, `.quicLbUnroutableUpdateStopsIssuing`, `.negative_lengthMismatchWithEndpointRejected`,
`.negative_updateLoadBalancerRefused`, `.negative_quicLbGroupCoresWithoutSharedState`,
`.quicLbOldKeyClosedByTheCallerKeepsTheEndpointAlive`, `.quicLbAtMostOnePlaintextIdPerChange`,
`.quicLbRetriedConnectionIssuesByItsOwnId`, `.quicLbSkewedIssuanceWastesNoNonce`,
`StatelessResetTest.negative_quicLbDecryptionsAreRateLimited`, `.negative_quicLbResetsOverTheLimitAreCountedRateLimited`,
`StatelessResetTest.quicLbResetForOwnUnknownCid`, `.negative_quicLbNoResetForOtherServerId`,
`.negative_quicLbNoResetForUnknownConfigId`, `.negative_quicLbNoResetForUnroutableCid`,
`.negative_quicLbNoResetFromNonOwnerLoop`, `LoopGroupTest.quicLbForwardedToOwner`, `GuideSamplesTest.loadBalancerSamples`,
`ServerQuicLoadBalancerTest`, `KslCryptoTest.lbKey*`, C `lb_key_fips197`, `lb_key_concurrent_ecb16` (TSAN),
`negative_lb_key_wrong_kind`.

**Notes on the draft text.**

- B.1, second line, prints `1 350d28b420 3487d970b 20a350d28b4203487d970b`: a nine-digit nonce, and a first octet 0x20
  whose config rotation bits are 1, as the line says, but whose length bits are 0 instead of 10. With the leading zeros
  restored the nonce is `03487d970b` and the CID `2a350d28b42003487d970b`, which the test checks.
- B.2, last line, is labelled cr_bits 3, but its first octet `0x12` is configuration 0 (length 18); the rotation bits are
  not encrypted, so the test uses configuration 0.
- 5.4.2.4, step 10, XORs with `0xb3e4357c` where the AES output printed above starts `0xb334357c`; the final CID of the
  example (`0x0767947d29be054a`) is what the algorithm gives and what the test checks.
- 5.5.2 clears `left_1` after the third decryption pass where `right_1` is meant (the server never decodes this way; the
  codec clears the half it wrote, as in 5.4.2.3).

**Interpretations.**

- RFC 9000 section 5.1.1 asks that a peer have "a sufficient number of available and unused connection IDs"; plaintext
  and unroutable connections follow draft sections 3.2 and 9 instead and hand out one.
- RFC 9000 section 5.1: "Connection IDs MUST NOT contain any information that can be used by an external observer [...]
  to correlate them with other connection IDs for the same connection." Encrypted IDs hide the server ID and the nonce;
  a plaintext configuration shows the server ID in every ID, which is why such a connection gets one ID, and a second
  only on a configuration change (draft section 9). The reset token is HMAC(per-loop key, ID), and no ID repeats while
  the process runs, so "the combination of connection ID and static key MUST NOT be used for another connection"
  (section 10.3.2) holds; the endpoint's ID length is fixed, as that section requires of a stateless token design.
- 9.6 across processes: with a `QuicLbNonceReservation` the endpoint keeps it itself, keyed or in clear; a plaintext
  configuration must have one (`QuicLbConfig` throws IllegalArgumentException otherwise). Without one, an encrypted
  configuration leaves it to the operator, as `QuicLbConfig.key` and the guide state: every process start needs a key no
  earlier process used.
- When the configuration goes away (`updateLoadBalancer(null)`), live connections keep the IDs they have: section 3.1's
  "update the client with CIDs [...] using the new configuration" names a configuration, and the IDs of the last one keep
  routing wherever the load balancer still has it.
- A server answers no Stateless Reset for an unroutable ID: it carries no server ID to check (threat-model 3.4).
- Owner by hash costs one copy between loops for about 1 in 32 new connections (a random 8-byte first Initial DCID whose
  first octet encodes our length is taken for one of ours and forwarded, consistently, to the loop it hashes to).

**Open items.** None.
