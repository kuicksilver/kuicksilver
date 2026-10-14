// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(DelicateKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.runBlocking
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** The trust pipeline end to end over in-memory QUIC handshakes: threat-model section 5 "Trust and TLS" plus the malformed and hostile inputs around it. */
class VerificationNegativeTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val ca = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))

    private fun pin(der: ByteArray) = Certificate(der).spkiSha256

    private val acceptAll = TrustConfig.Custom { chain, _, _ -> VerifyResult.Accepted(chain) }

    private class Outcome(
        val done: Boolean,
        val failed: DriveResult.Failed?,
        val serverDone: Boolean,
    )

    private fun run(
        client: TlsConfig,
        serverChain: List<ByteArray> = listOf(TestCerts.server),
        serverKey: ByteArray = TestCerts.serverKey,
        serverBlock: TlsConfig.Builder.() -> Unit = {
        },
    ): Outcome {
        val p = Pump(KslQuicCrypto.newSession(client), KslQuicCrypto.newSession(Fixtures.server(serverChain, serverKey, serverBlock)))
        p.c.setTransportParameters(Fixtures.tp)
        p.s.setTransportParameters(Fixtures.tp)
        try {
            val (rc, _) = p.run { want -> runBlocking { p.c.verifyPeer(want.chain) } }
            return Outcome(p.cs.done, rc as? DriveResult.Failed, p.ss.done)
        } finally {
            p.close()
        }
    }

    private fun expectReject(
        o: Outcome,
        alert: Int,
        reason: (VerifyReason) -> Boolean = { true },
        msg: String,
    ) {
        val f = o.failed
        assertTrue(f != null && !o.done, "$msg: expected failure, done=${o.done}")
        assertEquals(alert, f.alert, "$msg: alert")
        val v = assertIs<TlsException.Verify>(f.exception, msg)
        assertTrue(reason(v.reason), "$msg: reason ${v.reason}")
    }

    private fun expectAccept(
        o: Outcome,
        msg: String,
    ) {
        assertTrue(o.done && o.serverDone && o.failed == null, "$msg: expected success, failed=${o.failed?.exception}")
    }

    @Test fun anchoredCaAccepts() = expectAccept(run(Fixtures.client(ca)), "anchored")

    @Test fun negative_wrongKeySameName() =
        expectReject(
            run(
                Fixtures.client(TrustConfig.Pinned(setOf(pin(TestCerts.server)), base = ca)),
                listOf(TestCerts.serverOtherKey),
                TestCerts.serverOtherKeyKey,
            ),
            42,
            {
                it is VerifyReason.PinMismatch
            },
            "wrong key, same name",
        )

    @Test fun negative_pinAgainstSystemTrust() =
        expectReject(run(Fixtures.client(TrustConfig.Pinned(setOf(pin(TestCerts.proxy)), base = ca))), 42, {
            it is VerifyReason.PinMismatch
        }, "trusted chain but foreign pin")

    @Test fun pinnedLeafAccepts() =
        expectAccept(
            run(Fixtures.client(TrustConfig.Pinned(setOf(pin(TestCerts.server)), base = ca))),
            "pinned leaf",
        )

    @Test fun pinScopeAnyInValidatedChainAcceptsCaPin() =
        expectAccept(
            run(Fixtures.client(TrustConfig.Pinned(setOf(pin(TestCerts.testCa)), scope = PinScope.AnyInValidatedChain, base = ca))),
            "CA pin, any scope",
        )

    @Test fun pinScopeLeafRejectsCaPin() =
        expectReject(run(Fixtures.client(TrustConfig.Pinned(setOf(pin(TestCerts.testCa)), scope = PinScope.Leaf, base = ca))), 42, {
            it is VerifyReason.PinMismatch
        }, "CA pin, leaf scope")

    @Test fun negative_pinNotInValidatedChain() =
        expectReject(
            run(
                Fixtures.client(TrustConfig.Pinned(setOf(pin(TestCerts.otherCa)), scope = PinScope.AnyInValidatedChain, base = ca)),
                listOf(TestCerts.server, TestCerts.otherCa),
            ),
            42,
            {
                it is VerifyReason.PinMismatch
            },
            "pin only in the presented, not the validated chain",
        )

    @Test fun rejectedReasonCarriesChainPins() {
        val f = run(Fixtures.client(TrustConfig.Pinned(setOf(pin(TestCerts.proxy)), base = ca))).failed!!
        val r = (f.exception as TlsException.Verify).reason as VerifyReason.PinMismatch
        assertEquals(listOf(pin(TestCerts.server), pin(TestCerts.testCa)), r.chainPins)
    }

    @Test fun expectedNameAccepts() =
        expectAccept(
            run(
                Fixtures.client(TrustConfig.ExpectedName("proxy.internal", base = ca), name = "other.test"),
                listOf(TestCerts.proxy),
                TestCerts.proxyKey,
            ),
            "ExpectedName proxy",
        )

    @Test fun negative_expectedNameThirdName() =
        expectReject(run(Fixtures.client(TrustConfig.ExpectedName("proxy.internal", base = ca), name = "other.test")), 42, {
            true
        }, "server.test cert vs ExpectedName proxy.internal")

    @Test fun customVerifierAccepts() = expectAccept(run(Fixtures.client(acceptAll)), "custom accept + matching name")

    @Test fun negative_customVerifierMustCheckName() =
        expectReject(run(Fixtures.client(acceptAll, name = "wrong.test")), 42, {
            true
        }, "custom accept but name mismatch -> ksl matcher")

    @Test fun negative_tofuKeyChange() {
        val store =
            object : TofuStore {
                val m = HashMap<String, SpkiSha256>()

                override suspend fun get(name: String) = m[name]

                override suspend fun put(
                    name: String,
                    pin: SpkiSha256,
                ) {
                    m[name] =
                        pin
                }
            }
        expectAccept(run(Fixtures.client(TrustConfig.Tofu(store))), "first use")
        assertEquals(pin(TestCerts.server), store.m["server.test"])
        expectAccept(run(Fixtures.client(TrustConfig.Tofu(store))), "same key again")
        expectReject(run(Fixtures.client(TrustConfig.Tofu(store)), listOf(TestCerts.serverOtherKey), TestCerts.serverOtherKeyKey), 42, {
            it is VerifyReason.PinMismatch
        }, "key change")
    }

    @Test fun negative_cnOnlyCertRejected() =
        expectReject(run(Fixtures.client(ca, name = "cn.test"), listOf(TestCerts.serverCnOnly), TestCerts.serverCnOnlyKey), 42, {
            it is VerifyReason.HostnameMismatch
        }, "CN only")

    @Test fun negative_partialWildcardRejected() =
        expectReject(
            run(
                Fixtures.client(ca, name = "foo.wild.test"),
                listOf(TestCerts.serverPartialWildcard),
                TestCerts.serverPartialWildcardKey,
            ),
            42,
            {
                it is VerifyReason.HostnameMismatch
            },
            "f*.wild.test",
        )

    @Test fun wildcardOneLabel() {
        expectAccept(run(Fixtures.client(ca, name = "a.wild.test")), "*.wild.test vs a.wild.test")
        expectReject(
            run(Fixtures.client(ca, name = "a.b.wild.test")),
            42,
            { it is VerifyReason.HostnameMismatch },
            "*.wild.test vs a.b.wild.test",
        )
    }

    @Test fun negative_ipLiteralAgainstDnsSan() =
        expectReject(run(Fixtures.client(ca, name = "127.0.0.1"), listOf(TestCerts.serverDnsIp), TestCerts.serverDnsIpKey), 42, {
            it is VerifyReason.HostnameMismatch
        }, "IP literal vs dNSName=127.0.0.1")

    @Test fun ipLiteralAgainstIpSanAccepted() {
        expectAccept(run(Fixtures.client(ca, name = "127.0.0.1")), "IPv4 SAN")
        expectAccept(run(Fixtures.client(ca, name = "[::1]")), "IPv6 SAN")
    }

    @Test fun negative_wrongEkuRejected() {
        expectReject(run(Fixtures.client(ca), listOf(TestCerts.serverClientEku), TestCerts.serverClientEkuKey), 43, {
            it is VerifyReason.InvalidPurpose
        }, "clientAuth-only EKU on a server")
        expectReject(run(Fixtures.client(acceptAll), listOf(TestCerts.serverClientEku), TestCerts.serverClientEkuKey), 43, {
            true
        }, "same on the pause path")
    }

    @Test fun absentEkuAccepted() =
        expectAccept(
            run(Fixtures.client(ca), listOf(TestCerts.serverNoEku), TestCerts.serverNoEkuKey),
            "absent EKU = any purpose (RFC 5280)",
        )

    @Test fun expiredIsAlert45() =
        expectReject(run(Fixtures.client(ca), listOf(TestCerts.expired), TestCerts.expiredKey), 45, {
            it is VerifyReason.Expired
        }, "expired")

    @Test fun notYetValidIsAlert45() =
        expectReject(run(Fixtures.client(ca), listOf(TestCerts.notYetValid), TestCerts.notYetValidKey), 45, {
            it is VerifyReason.NotYetValid
        }, "not yet valid")

    @Test fun hostNameNormalization() = expectAccept(run(Fixtures.client(ca, name = "Server.TEST.")), "mixed case + trailing dot")

    @Test fun genericAlertsHideTheReason() {
        val f = run(Fixtures.client(ca, name = "wrong.test") { genericAlerts = true }).failed
        assertTrue(f != null)
        assertEquals(40, f.alert, "handshake_failure instead of bad_certificate")
        val e = run(Fixtures.client(ca) { genericAlerts = true }, listOf(TestCerts.expired), TestCerts.expiredKey).failed
        assertTrue(e != null)
        assertEquals(40, e.alert, "handshake_failure instead of certificate_expired")
    }

    @Test fun negative_quicServerPinnedClientCertRejected() {
        val clientId = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())
        val foreignPin = TrustConfig.Pinned(setOf(pin(TestCerts.proxy)), base = ca)
        val o =
            run(Fixtures.client(ca) { identity = clientId }) {
                clientAuth = ClientAuth.Required
                trust = foreignPin
            }
        assertTrue(!o.serverDone, "server must not complete with a client certificate outside the pin set")
        val ownPin = TrustConfig.Pinned(setOf(pin(TestCerts.client)), base = ca)
        expectAccept(
            run(Fixtures.client(ca) { identity = clientId }) {
                clientAuth = ClientAuth.Required
                trust = ownPin
            },
            "pinned client certificate",
        )
    }

    /** ClientAuth.Optional + Pinned (review T3): a client without a certificate is accepted, a presented one must match a pin. */
    @Test fun quicServerOptionalPinnedAcceptsClientWithoutCertificate() {
        val pinned = TrustConfig.Pinned(setOf(pin(TestCerts.client)), base = ca)
        expectAccept(
            run(Fixtures.client(ca)) {
                clientAuth = ClientAuth.Optional
                trust = pinned
            },
            "anonymous client under Optional + Pinned",
        )
        val unpinned = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())
        val o =
            run(Fixtures.client(ca) { identity = unpinned }) {
                clientAuth = ClientAuth.Optional
                trust = TrustConfig.Pinned(setOf(pin(TestCerts.proxy)), base = ca)
            }
        assertTrue(!o.serverDone, "a presented certificate is still checked")
    }

    /** AnchoredCa trusts each listed certificate as an anchor (TrustConfig.AnchoredCa.roots), an intermediate as well (review T5). */
    @Test fun anchoredAtIntermediateAccepts() {
        val atIntermediate = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.intermediate)))
        expectAccept(
            run(
                Fixtures.client(atIntermediate),
                listOf(TestCerts.serverViaIntermediate, TestCerts.intermediate),
                TestCerts.serverViaIntermediateKey,
            ),
            "chain ending at the anchored intermediate",
        )
        expectAccept(
            run(Fixtures.client(atIntermediate), listOf(TestCerts.serverViaIntermediate), TestCerts.serverViaIntermediateKey),
            "leaf only: the anchor completes the chain",
        )
        expectReject(
            run(Fixtures.client(atIntermediate)),
            48,
            { it is VerifyReason.UnknownIssuer },
            "negative: a chain from the root's other branch is not anchored at the intermediate",
        )
    }

    @Test fun clientCertificateRequiredAnchoredCa() {
        val clientId = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())
        expectAccept(
            run(Fixtures.client(ca) { identity = clientId }) {
                clientAuth = ClientAuth.Required
                trust = ca
            },
            "client cert from the anchored CA",
        )
        val other = TlsIdentity.fromDer(listOf(TestCerts.clientOtherCa), TestCerts.clientOtherCaKey.copyOf())
        val o =
            run(Fixtures.client(ca) { identity = other }) {
                clientAuth = ClientAuth.Required
                trust = ca
            }
        assertTrue(!o.serverDone, "server rejects a client cert from another CA")
        val wrongEku = TlsIdentity.fromDer(listOf(TestCerts.proxy), TestCerts.proxyKey.copyOf())
        val o2 =
            run(Fixtures.client(ca) { identity = wrongEku }) {
                clientAuth = ClientAuth.Required
                trust = ca
            }
        assertTrue(!o2.serverDone, "server rejects a serverAuth-only client cert")
    }
}
