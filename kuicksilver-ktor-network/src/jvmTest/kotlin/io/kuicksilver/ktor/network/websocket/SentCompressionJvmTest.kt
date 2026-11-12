// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network.websocket

import io.ktor.util.AttributeKey
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketExtension
import io.ktor.websocket.WebSocketExtensionFactory
import io.ktor.websocket.WebSocketExtensionHeader
import io.kuicksilver.ktor.network.SentCompression
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Which way the output guard treats compressed messages ([sentCompression]): Ktor's own `WebSocketDeflateExtension` is
 * recognised by type, not by its class name, which R8 renames in a release build. (The class is final: no subclass can
 * exist.)
 */
class SentCompressionJvmTest {
    @Test fun ktorsExtensionIsPerFrame() =
        assertEquals(
            SentCompression.PerFrame,
            sentCompression(
                listOf(
                    io.ktor.websocket.WebSocketDeflateExtension.install {
                    },
                ),
                perMessageDeflate = true,
            ),
        )

    @Test fun ownExtensionIsChecked() =
        assertEquals(SentCompression.Checked, sentCompression(listOf(PerMessageDeflate.install {}), perMessageDeflate = true))

    /** A class that only has Ktor's name is another implementation: an RFC 7692 sender, never treated as Ktor's. */
    @Test fun negative_aNameAloneIsNotKtorsExtension() =
        assertEquals(SentCompression.PerMessage, sentCompression(listOf(WebSocketDeflateExtension()), perMessageDeflate = true))

    @Test fun noDeflateNegotiatedIsChecked() =
        assertEquals(
            SentCompression.Checked,
            sentCompression(
                listOf(
                    io.ktor.websocket.WebSocketDeflateExtension.install {
                    },
                ),
                perMessageDeflate = false,
            ),
        )

    /** Answers to permessage-deflate; its class has the simple name of Ktor's. */
    private class WebSocketDeflateExtension : WebSocketExtension<Unit> {
        override val factory: WebSocketExtensionFactory<Unit, WebSocketDeflateExtension> = Factory
        override val protocols = listOf(WebSocketExtensionHeader("permessage-deflate", emptyList()))

        override fun clientNegotiation(negotiatedProtocols: List<WebSocketExtensionHeader>) = true

        override fun serverNegotiation(requestedProtocols: List<WebSocketExtensionHeader>) = protocols

        override fun processOutgoingFrame(frame: Frame) = frame

        override fun processIncomingFrame(frame: Frame) = frame

        object Factory : WebSocketExtensionFactory<Unit, WebSocketDeflateExtension> {
            override val key = AttributeKey<WebSocketDeflateExtension>("named-like-ktor")
            override val rsv1 = true
            override val rsv2 = false
            override val rsv3 = false

            override fun install(config: Unit.() -> Unit) = WebSocketDeflateExtension()
        }
    }
}
