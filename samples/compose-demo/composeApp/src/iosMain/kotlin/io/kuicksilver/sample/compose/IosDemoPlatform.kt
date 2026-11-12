// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)

package io.kuicksilver.sample.compose

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.engine.darwin.Darwin
import io.kuicksilver.ktor.client.Http3ConnectionMigration
import io.kuicksilver.ktor.client.followDefaultNetwork
import io.kuicksilver.quic.nwPathUpdates
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.reinterpret
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import platform.CoreFoundation.CFArrayRef
import platform.CoreFoundation.CFDataRef
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFStringRef
import platform.Foundation.CFBridgingRelease
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSData
import platform.Foundation.NSString
import platform.Foundation.NSURLAuthenticationMethodServerTrust
import platform.Foundation.NSURLCredential
import platform.Foundation.NSURLSessionAuthChallengeCancelAuthenticationChallenge
import platform.Foundation.NSURLSessionAuthChallengePerformDefaultHandling
import platform.Foundation.NSURLSessionAuthChallengeUseCredential
import platform.Foundation.create
import platform.Foundation.credentialForTrust
import platform.Foundation.serverTrust
import platform.Security.SecCertificateCreateWithData
import platform.Security.SecPolicyCreateSSL
import platform.Security.SecTrustEvaluateWithError
import platform.Security.SecTrustRef
import platform.Security.SecTrustSetAnchorCertificates
import platform.Security.SecTrustSetAnchorCertificatesOnly
import platform.Security.SecTrustSetPolicies

/**
 * iOS: two TCP references, Ktor's CIO and Darwin (URLSession), in two columns; `NWPathMonitor` for the network and for
 * connection migration.
 */
class IosDemoPlatform : DemoPlatform {
    private val current = MutableStateFlow<String?>(null)

    override val name: String = "iOS"

    // the Mac as the simulator reaches it; on a phone, the Mac's LAN address
    override val defaultHost: String = "127.0.0.1"

    override val referenceNote: String =
        "Two TCP references: CIO (Ktor's own HTTP/1.1, over plain http:// because CIO has no TLS on iOS) and Darwin " +
            "(URLSession over TLS). URLSession may itself pick HTTP/3 when the server announces it with Alt-Svc, and Ktor " +
            "reports HTTP/1.1 for it either way: start the server with --no-alt-svc to keep Darwin on TCP."

    override fun migration(): Http3ConnectionMigration = Http3ConnectionMigration.followDefaultNetwork()

    override fun networkId(): String? = current.value

    override fun networks(): Flow<String> =
        nwPathUpdates()
            .onEach { current.value = it?.let { k -> "${k.interfaceType}#${k.interfaceIndex}" } }
            .map { k -> k?.let { "${it.interfaceType} (${it.interfaceName})" } ?: "no network" }

    override fun referenceLanes(server: DemoServer): List<Lane> =
        listOf(
            Lane("CIO (TCP)", "HTTP/1.1, plain http:// (no TLS in CIO on iOS)", HttpClient(CIO), server.http(""), isKuicksilver = false),
            Lane("Darwin (URLSession)", "TLS; may use HTTP/3 itself when Alt-Svc offers it", darwinClient(), server.https(""), isKuicksilver = false),
        )
}

/** Ktor's Darwin engine trusting the demo CA only and checking the certificate for [DEMO_SERVER_NAME], as the Kuicksilver lane does. */
fun darwinClient(): HttpClient =
    HttpClient(Darwin) {
        engine {
            handleChallenge { _, _, challenge, completion ->
                val space = challenge.protectionSpace
                val trust = space.serverTrust
                when {
                    space.authenticationMethod != NSURLAuthenticationMethodServerTrust || trust == null -> {
                        completion(NSURLSessionAuthChallengePerformDefaultHandling, null)
                    }

                    trustsDemoCa(trust) -> {
                        completion(NSURLSessionAuthChallengeUseCredential, NSURLCredential.credentialForTrust(trust))
                    }

                    else -> {
                        completion(NSURLSessionAuthChallengeCancelAuthenticationChallenge, null)
                    }
                }
            }
        }
    }

/** Evaluates [trust] with the demo CA as its only anchor and an SSL policy for [DEMO_SERVER_NAME]. */
private fun trustsDemoCa(trust: SecTrustRef): Boolean {
    val base64 = DemoCerts.caPem.lineSequence().filter { it.isNotBlank() && !it.startsWith("-----") }.joinToString("")
    val der = NSData.create(base64EncodedString = base64, options = 0u) ?: return false
    val data: CFDataRef = CFBridgingRetain(der)?.reinterpret() ?: return false
    val cert =
        try {
            SecCertificateCreateWithData(null, data) ?: return false
        } finally {
            CFRelease(data)
        }
    val anchors: CFArrayRef = CFBridgingRetain(listOf(CFBridgingRelease(cert)))?.reinterpret() ?: return false
    val name: CFStringRef = CFBridgingRetain(NSString.create(string = DEMO_SERVER_NAME))?.reinterpret() ?: return false
    try {
        val policy = SecPolicyCreateSSL(true, name) ?: return false
        try {
            return SecTrustSetPolicies(trust, policy) == 0 &&
                SecTrustSetAnchorCertificates(trust, anchors) == 0 &&
                SecTrustSetAnchorCertificatesOnly(trust, true) == 0 &&
                SecTrustEvaluateWithError(trust, null)
        } finally {
            CFRelease(policy)
        }
    } finally {
        CFRelease(anchors)
        CFRelease(name)
    }
}
