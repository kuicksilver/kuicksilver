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
- 9.6: "the server MUST NOT reuse a nonce until it switches to a configuration with new keys", "servers SHOULD start with
  a random nonce value", "A server that has exhausted its nonces MUST either switch to a different configuration, or if
  none exists, use the 4-tuple routing config rotation codepoint."
- 9.7: deployments that mix clear text and encrypted IDs "MUST use different server ID allocations for the clear text and
  the encrypted versions".

**How it is met.**

- `QuicLbConfig` (public, experimental): config rotation codepoint 0..6, server ID of 1..15 bytes, nonce of at least 4,
  both at most 19 bytes, an optional 16-byte key. `QuicEndpointConfig.loadBalancer` needs a server, a
  `connectionIdLength` equal to `1 + server ID + nonce` and at least 8, and a key when a `preferredAddress` is offered.
- `endpoint/QuicLb.kt`: `QuicLbCodec` writes `configId << 5 | (length - 1)` and the server ID and nonce, in clear or
  encrypted by `QuicLbCipher` (one AES-128-ECB block for 16 bytes, else the four-pass Feistel network with `expand` and
  the nibble split of odd lengths); `decodeServerId` / `matchesServerId` run it backwards. The AES key is a `ksl` key
  (`ksl_key_lb`, `ksl_key_ecb16`; ADR-0003) behind `QuicCrypto.newLoadBalancerKey`.
- `QuicLbNonces`: a counter from a random seed, permuted with a random key of the endpoint's own (`ksl_key_random(KSL_EKEY_LB)`),
  so a nonce never repeats while the process runs and none relates to the previous one, also in clear; once the
  2^(8 x nonce length) values are drawn it returns nothing and the endpoint issues unroutable IDs.
- `endpoint/CidRoute.kt`: `QuicLbRoute` makes every ID (server connections under the current configuration; unroutable
  IDs `0b111 << 5 | (length - 1)` with CSPRNG bytes when there is none, the nonces are spent, or for a client connection
  of a loop group), tells the owning loop (`SipHash(group key, ID) mod loops`) and gates Stateless Resets: only for an ID
  under the current or previous configuration's codepoint that decrypts to this server's ID and hashes to this loop.
  `QuicLbState` holds the configurations of an endpoint (shared by a group's loops), keeps the nonce counter of each
  (server ID, nonce length, key) for the endpoint's life, and refuses a configuration that would use a server ID in clear
  that an encrypted one used, or the other way round (9.7).
- `QuicEndpoint.updateLoadBalancer`: new IDs use the new configuration at once; `EndpointCore.reissueForLoadBalancer`
  gives every live server connection one NEW_CONNECTION_ID under it whose Retire Prior To retires every earlier ID
  (`ConnectionIdManager.reissueForNewConfiguration`), and the replacements the client's retirements call for come from
  it too. `null` switches to unroutable IDs: new connections get one ID and `disable_active_migration`, live ones keep
  their IDs and stop handing out new ones.
- Plaintext configurations and unroutable IDs: the connection hands out only its handshake ID (`CidIssuance.Single`,
  `ConnectionIdManager.limitToSingle`), no `preferred_address`; a plaintext connection gets one more ID on a configuration
  change.

**Tests.** `QuicLbTest.*` (every Appendix B vector encoded and decoded, the 5.4.2.4 example and its expand and AES
output, round trips of lengths 4..19, `nonceCounterNeverRepeats`, `noncesArePermuted`, `nonceExhaustionReturnsNull`,
`negative_configIdSevenRejected`, `negative_sidPlusNonceOver19Rejected`, `negative_nonceUnder4Rejected`),
`EndpointCoreTest.quicLbIssuedCidsDecodeToServerId`, `.quicLbOwnerLoopMatchesIssuingLoop`,
`.quicLbRotationKeepsOldConnectionsRouting`, `.quicLbExhaustionGoesUnroutable`, `.quicLbPlaintextHandsOutOneCid`,
`.quicLbUnroutableUpdateStopsIssuing`, `.negative_lengthMismatchWithEndpointRejected`,
`.negative_updateLoadBalancerRefused`, `StatelessResetTest.quicLbResetForOwnUnknownCid`,
`.negative_quicLbNoResetForOtherServerId`, `.negative_quicLbNoResetForUnknownConfigId`,
`.negative_quicLbNoResetForUnroutableCid`, `.negative_quicLbNoResetFromNonOwnerLoop`,
`LoopGroupTest.quicLbForwardedToOwner`, `GuideSamplesTest.loadBalancerSamples`, `KslCryptoTest.lbKey*`, C
`lb_key_fips197`, `negative_lb_key_wrong_kind`.

**Notes on the draft text.**

- B.1, second line, prints `1 350d28b420 3487d970b 20a350d28b4203487d970b`: a nine-digit nonce and a first octet that is
  not cr_bits 1. With the leading zeros restored the nonce is `03487d970b` and the CID `2a350d28b42003487d970b`, which
  the test checks.
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
- When the configuration goes away (`updateLoadBalancer(null)`), live connections keep the IDs they have: section 3.1's
  "update the client with CIDs [...] using the new configuration" names a configuration, and the IDs of the last one keep
  routing wherever the load balancer still has it.
- A server answers no Stateless Reset for an unroutable ID: it carries no server ID to check (threat-model 3.4).

**Open items.**

- Section 9.6, "the server MUST NOT reuse a nonce until it switches to a configuration with new keys", holds for the
  life of the process. A restarted server starts from a new random seed and permutation key, so its nonces collide with
  the previous process's only by chance (about one in 2^(8 x nonce length / 2) after as many draws); keeping the counter
  across restarts would need persistent state. Rotate the key when the server restarts, or use nonces of 8 bytes or more.
- The Ktor server engine and `Http3Endpoint` do not expose `updateLoadBalancer` yet ([roadmap](../../roadmap.md)).
