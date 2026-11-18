// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.KeyExchangeGroups
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsVersions
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** `KuicksilverTlsConnector.Builder.keyExchangeGroups` reaches the TLS configurations of TCP and HTTP/3 alike. */
class ServerKeyExchangeGroupsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val groups = KeyExchangeGroups(listOf(KeyExchangeGroups.SECP384R1, KeyExchangeGroups.X25519))

    @Test fun theConnectorsGroupsReachTcpAndQuic() {
        val connector = KuicksilverTlsConnector.Builder(ServerFixtures.identity()).apply { keyExchangeGroups = groups }.build()
        assertEquals(groups, connector.keyExchangeGroups)
        assertEquals(groups, connector.tlsConfig(listOf("http/1.1")).keyExchangeGroups, "TCP")
        assertEquals(groups, connector.tlsConfig(listOf("h3")).keyExchangeGroups, "QUIC")
        assertEquals(groups, connector.withPort(8443).keyExchangeGroups, "a resolved connector keeps them")
        assertEquals(
            KeyExchangeGroups.Default,
            KuicksilverTlsConnector.Builder(ServerFixtures.identity()).build().keyExchangeGroups,
            "the default",
        )
    }

    @Test fun negative_keySharesOrNoTls12CurveFailWhenTheConfigurationIsMade() {
        val shares =
            KuicksilverTlsConnector
                .Builder(ServerFixtures.identity())
                .apply {
                    keyExchangeGroups = KeyExchangeGroups(listOf(KeyExchangeGroups.X25519), setOf(KeyExchangeGroups.X25519))
                }.build()
        assertFailsWith<TlsException.Config> { shares.tlsConfig(listOf("http/1.1")) }
        val hybridOnly =
            KuicksilverTlsConnector
                .Builder(ServerFixtures.identity())
                .apply {
                    versions = TlsVersions.Tls12And13
                    keyExchangeGroups = KeyExchangeGroups(listOf(KeyExchangeGroups.X25519MLKEM768))
                }.build()
        assertFailsWith<TlsException.Config>("TCP with TLS 1.2") { hybridOnly.tlsConfig(listOf("http/1.1")) }
        assertEquals(
            1,
            hybridOnly
                .tlsConfig(listOf("h3"))
                .keyExchangeGroups.groups.size,
            "QUIC is TLS 1.3 only: the hybrid is fine",
        )
    }
}
