// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)

package io.kuicksilver.guide.tls

// guide:tls:imports
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.ktor.network.tls
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.PinScope
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.keylogFile
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withTimeout
import kotlin.time.Duration.Companion.seconds

/**
 * The import block docs/guide/tls.md shows for its samples (`guide:tls:imports`), in a package of its own so that every
 * import is a real one: [everyTlsImport] uses each, so a name that moves breaks this file.
 */
suspend fun everyTlsImport(
    chainPem: String,
    keyPem: String,
    caPem: String,
) {
    if (!KslLoader.isAvailable()) return
    val identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
    println(tlsConfig(TlsRole.Server) { this.identity = identity })
    val trust =
        TrustConfig.Pinned(
            pins = setOf(SpkiSha256.parse("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")),
            scope = PinScope.Leaf,
            base = TrustConfig.AnchoredCa(Certificate.parsePem(caPem)),
        )
    val client =
        tlsConfig(TlsRole.Client) {
            serverName = "server.test"
            this.trust = trust
            keylog = keylogFile("/tmp/keys.txt")
        }
    val selector = SelectorManager(Dispatchers.IO)
    val socket = aSocket(selector).tcp().connect("server.test", 443).tls(client)
    socket.openWriteChannel(autoFlush = true).writeStringUtf8("GET / HTTP/1.1\r\n\r\n")
    println(withTimeout(10.seconds) { socket.openReadChannel().readLine(LineEnding.Lenient) })
}
