// Copyright 2014-2021 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Vendored from Ktor 3.6.0 ktor-server-cio CIOApplicationResponse.kt (internal there), adapted: Alt-Svc for HTTP/3 (RFC 7838),
// `Connection: close` once the server is stopping.
package io.kuicksilver.ktor.server.h1

import io.ktor.http.HeadersBuilder
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.cio.RequestResponseBuilder
import io.ktor.http.cio.encodeChunked
import io.ktor.http.content.OutgoingContent
import io.ktor.server.engine.BaseApplicationResponse
import io.ktor.server.response.ResponseHeaders
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.cancel
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writePacket
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.withContext
import kotlin.coroutines.CoroutineContext

internal class H1Response(
    call: H1Call,
    private val output: ByteWriteChannel,
    private val input: ByteReadChannel,
    private val engineDispatcher: CoroutineContext,
    private val userDispatcher: CoroutineContext,
    private val upgraded: CompletableDeferred<Boolean>?,
    private val altSvc: String?,
    /** True once the connection ends after this response (the server is stopping): it then says `Connection: close`. */
    private val closing: () -> Boolean = { false },
) : BaseApplicationResponse(call) {
    private var statusCode: HttpStatusCode = HttpStatusCode.OK
    private val headersBuilder = HeadersBuilder()

    private var chunkedChannel: ByteWriteChannel? = null

    private var chunkedJob: Job? = null

    override val headers =
        object : ResponseHeaders() {
            override fun engineAppendHeader(
                name: String,
                value: String,
            ) {
                headersBuilder.append(name, value)
            }

            override fun getEngineHeaderNames(): List<String> = headersBuilder.names().toList()

            override fun getEngineHeaderValues(name: String): List<String> = headersBuilder.getAll(name).orEmpty()
        }

    override suspend fun responseChannel(): ByteWriteChannel {
        sendResponseMessage(false)
        return preparedBodyChannel()
    }

    override suspend fun respondUpgrade(upgrade: OutgoingContent.ProtocolUpgrade) {
        sendResponseMessage(contentReady = false)

        try {
            val upgradedJob = upgrade.upgrade(input, output, engineDispatcher, userDispatcher)
            upgradedJob.join()
        } finally {
            output.flushAndClose()
            input.cancel()
        }
    }

    override suspend fun respondFromBytes(bytes: ByteArray) {
        sendResponseMessage(contentReady = true)
        val channel = preparedBodyChannel()
        return withContext(Dispatchers.Unconfined) {
            channel.writeFully(bytes)
            channel.flushAndClose()
        }
    }

    override suspend fun respondNoContent(content: OutgoingContent.NoContent) {
        sendResponseMessage(contentReady = true)
        output.flushAndClose()
    }

    override suspend fun respondOutgoingContent(content: OutgoingContent) {
        if (content is OutgoingContent.ProtocolUpgrade) {
            upgraded?.complete(true) ?: throw IllegalStateException(
                "Unable to perform upgrade as it is not requested by the client: " +
                    "request should have Upgrade and Connection headers filled properly",
            )
        } else {
            upgraded?.complete(false)
        }

        super.respondOutgoingContent(content)
        chunkedChannel?.flushAndClose()
        chunkedJob?.join()
    }

    override fun setStatus(statusCode: HttpStatusCode) {
        this.statusCode = statusCode
    }

    private suspend fun sendResponseMessage(contentReady: Boolean) {
        // HTTP/3 on the same port is announced on every response that does not carry its own Alt-Svc (RFC 7838)
        if (altSvc != null && headersBuilder["Alt-Svc"] == null && statusCode.value != 421) headersBuilder.append("Alt-Svc", altSvc)
        // the server is stopping and reads no further request here: say so (RFC 9112 section 9.6), as Go's Shutdown does
        if (closing() && statusCode != HttpStatusCode.SwitchingProtocols) headersBuilder[HttpHeaders.Connection] = "close"
        val builder = RequestResponseBuilder()
        try {
            builder.responseLine("HTTP/1.1", statusCode.value, statusCode.description)
            for (name in headersBuilder.names()) {
                for (value in headersBuilder.getAll(name)!!) {
                    builder.headerLine(name, value)
                }
            }
            builder.emptyLine()
            output.writePacket(builder.build())

            if (!contentReady) {
                output.flush()
            }
        } finally {
            builder.release()
        }
    }

    private fun preparedBodyChannel(): ByteWriteChannel {
        val chunked = headers[HttpHeaders.TransferEncoding] == "chunked"
        if (!chunked) return output

        val encoderJob = encodeChunked(output, Dispatchers.Unconfined)
        val chunkedOutput = encoderJob.channel

        chunkedChannel = chunkedOutput
        chunkedJob = encoderJob.job

        return chunkedOutput
    }
}
