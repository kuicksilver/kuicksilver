// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.interop

import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.qlog.DirectoryQlogSink
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.tls.TlsIdentity
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking
import kotlin.system.exitProcess

/** The QUIC Interop Runner endpoint: ROLE, TESTCASE, REQUESTS, SSLKEYLOGFILE, QLOGDIR from the environment; exit 0 / 1 / 127 (unsupported). */
internal object Interop {
    val v1: List<VersionProfile> get() = Testcases.v1
    private val keys = listOf("ROLE", "TESTCASE", "REQUESTS", "DOWNLOADS", "CERTS", "WWW", "SSLKEYLOGFILE", "QLOGDIR", "KSL_INTEROP_EXPECTED_NAME")
    fun environment(): Map<String, String> = keys.mapNotNull { k -> envVar(k)?.let { k to it } }.toMap()

    fun run(env: Map<String, String>): Int {
        val testcase = env["TESTCASE"] ?: "handshake"
        val role = env["ROLE"] ?: return 127
        if (testcase !in Testcases.supported) { Files.log("unsupported test case $testcase"); return 127 }
        KslLoader.ensureLoaded()
        return when (role) {
            "server" -> runBlocking {
                val plan = Testcases.server(testcase)!!; val certs = env["CERTS"] ?: "/certs"
                val identity = TlsIdentity.fromPem(Files.readText("$certs/cert.pem"), Files.readText("$certs/priv.key").toCharArray())
                val www = env["WWW"] ?: "/www"; val qlog = env["QLOGDIR"]?.let { DirectoryQlogSink(it) }
                if (plan.http3) H3InteropServer.start(identity, 443, www, plan.versions, admission = plan.admission, cipherSuites = plan.cipherSuites, handshakeTimeout = plan.handshakeTimeout, qlog = qlog).use { awaitCancellation() }
                else HqInteropServer.start(identity, 443, www, plan.versions, admission = plan.admission, cipherSuites = plan.cipherSuites, handshakeTimeout = plan.handshakeTimeout, qlog = qlog).use { awaitCancellation() }
                @Suppress("UNREACHABLE_CODE") 0
            }
            "client" -> runBlocking {
                val plan = Testcases.client(testcase)!!
                val requests = (env["REQUESTS"] ?: "").split(Regex("\\s+")).filter { it.isNotBlank() }
                val ok = if (plan.http3) H3InteropClient.download(requests, env["DOWNLOADS"] ?: "/downloads", plan, InteropTrust.config(env), env["SSLKEYLOGFILE"], env["QLOGDIR"]?.let { DirectoryQlogSink(it) })
                    else HqInteropClient.download(requests, env["DOWNLOADS"] ?: "/downloads", plan, InteropTrust.config(env), env["SSLKEYLOGFILE"], env["QLOGDIR"]?.let { DirectoryQlogSink(it) })
                if (ok) 0 else 1
            }
            else -> 127
        }
    }
}

fun main() { exitProcess(Interop.run(Interop.environment())) }
