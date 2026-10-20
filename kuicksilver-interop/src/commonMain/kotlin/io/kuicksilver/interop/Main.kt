// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.interop

import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.qlog.DirectoryQlogSink
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.tls.TlsIdentity
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking

/** The QUIC Interop Runner endpoint: ROLE, TESTCASE, REQUESTS, SSLKEYLOGFILE, QLOGDIR (and our KSL_CC) from the environment; exit 0 / 1 (a failed transfer or a lost connection) / 127 (unsupported). */
internal object Interop {
    val v1: List<VersionProfile> get() = Testcases.v1
    private val keys = listOf("ROLE", "TESTCASE", "REQUESTS", "DOWNLOADS", "CERTS", "WWW", "SSLKEYLOGFILE", "QLOGDIR", "KSL_INTEROP_EXPECTED_NAME", "KSL_CC")
    fun environment(): Map<String, String> = keys.mapNotNull { k -> envVar(k)?.let { k to it } }.toMap()

    fun run(env: Map<String, String>): Int {
        val testcase = env["TESTCASE"] ?: "handshake"
        val role = env["ROLE"] ?: return 127
        if (testcase !in Testcases.supported) { Files.log("unsupported test case $testcase"); return 127 }
        val cc = Testcases.congestionController(env["KSL_CC"]) ?: run { Files.log("unknown KSL_CC ${env["KSL_CC"]}"); return 127 }
        if (env["KSL_CC"] != null) Files.log("congestion controller ${env["KSL_CC"]}")
        KslLoader.ensureLoaded()
        return when (role) {
            "server" -> runBlocking {
                val plan = Testcases.server(testcase, cc)!!; val certs = env["CERTS"] ?: "/certs"
                val identity = TlsIdentity.fromPem(Files.readText("$certs/cert.pem"), Files.readText("$certs/priv.key").toCharArray())
                val www = env["WWW"] ?: "/www"; val qlog = env["QLOGDIR"]?.let { DirectoryQlogSink(it) }
                if (plan.http3) H3InteropServer.start(identity, 443, www, plan.versions, admission = plan.admission, cipherSuites = plan.cipherSuites, handshakeTimeout = plan.handshakeTimeout, qlog = qlog, congestionController = plan.congestionController).use { awaitCancellation() }
                else HqInteropServer.start(identity, 443, www, plan.versions, admission = plan.admission, cipherSuites = plan.cipherSuites, handshakeTimeout = plan.handshakeTimeout, qlog = qlog, congestionController = plan.congestionController, earlyData = plan.earlyData).use { awaitCancellation() }
                @Suppress("UNREACHABLE_CODE") 0
            }
            "client" -> runBlocking {
                val plan = Testcases.client(testcase, cc)!!
                val requests = (env["REQUESTS"] ?: "").split(Regex("\\s+")).filter { it.isNotBlank() }
                // a lost connection (idle timeout, the peer's close, a stateless reset) is a failed cell, exit 1: uncaught it ended the
                // JVM with 1 but Kotlin/Native with 133 (ngtcp2->kuicksilver-native:rebind-addr, 2026-10-20)
                try {
                    val ok = if (plan.http3) H3InteropClient.download(requests, env["DOWNLOADS"] ?: "/downloads", plan, InteropTrust.config(env), env["SSLKEYLOGFILE"], env["QLOGDIR"]?.let { DirectoryQlogSink(it) })
                        else HqInteropClient.download(requests, env["DOWNLOADS"] ?: "/downloads", plan, InteropTrust.config(env), env["SSLKEYLOGFILE"], env["QLOGDIR"]?.let { DirectoryQlogSink(it) })
                    if (ok) 0 else 1
                } catch (e: QuicException.ConnectionLost) { Files.log("connection lost: $e"); 1 }
            }
            else -> 127
        }
    }
}

fun main() { exitWith(Interop.run(Interop.environment())) }
