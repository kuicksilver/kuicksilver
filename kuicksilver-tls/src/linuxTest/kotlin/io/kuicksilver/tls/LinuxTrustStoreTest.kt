// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.tls

import io.kuicksilver.native.KslLoader
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import platform.posix.getenv
import platform.posix.setenv
import platform.posix.unsetenv
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Linux Native: a TrustConfig.Platform client whose CA store cannot be found fails when its context is built, naming the paths. */
class LinuxTrustStoreTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun platformClient() =
        tlsConfig(TlsRole.Client) {
            serverName = "example.com"
            trust = TrustConfig.Platform
        }

    private fun <T> withEnv(
        file: String?,
        dir: String?,
        block: () -> T,
    ): T {
        val saved = listOf("SSL_CERT_FILE", "SSL_CERT_DIR").associateWith { getenv(it)?.toKString() }

        fun put(
            k: String,
            v: String?,
        ) = if (v == null) unsetenv(k) else setenv(k, v, 1)
        put("SSL_CERT_FILE", file)
        put("SSL_CERT_DIR", dir)
        try {
            return block()
        } finally {
            saved.forEach { (k, v) -> put(k, v) }
        }
    }

    @Test fun negative_missingStoreNamesTheVariablesAndPaths() {
        val e =
            withEnv("/nonexistent/kuicksilver/ca.pem", "/nonexistent/kuicksilver/certs") {
                assertFailsWith<TlsException.Config> { KslContext.create(platformClient(), quic = false).close() }
            }
        val m = e.message.orEmpty()
        assertTrue("SSL_CERT_FILE=/nonexistent/kuicksilver/ca.pem" in m && "SSL_CERT_DIR=/nonexistent/kuicksilver/certs" in m, m)
        assertTrue("TrustConfig.Platform" in m, m)
    }
}
