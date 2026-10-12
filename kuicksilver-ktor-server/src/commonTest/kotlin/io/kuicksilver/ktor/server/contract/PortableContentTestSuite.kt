// Copyright 2014-2025 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// The portable part of Ktor 3.6.0 ktor-server/ktor-server-test-suites/jvm/src/io/ktor/server/testing/suites/ContentTestSuite.kt,
// adapted to common code so it runs on every Kuicksilver target: respondTextWriter and WriterContent (JVM Writer) become
// respondBytesWriter and ChannelWriterContent. The tests on files, class-path resources and java.io streams stay in the JVM
// ContentTestSuite, which remains the authority there: on the JVM this port does not run (vendoredJvmContentSuite).
package io.kuicksilver.ktor.server.contract

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.http.content.*
import io.ktor.server.engine.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.utils.io.*
import io.ktor.utils.io.charsets.*
import kotlinx.coroutines.withContext
import kotlin.coroutines.coroutineContext
import kotlin.test.*

/** True where the vendored JVM ContentTestSuite runs (the JVM): the portable content suite then has nothing to add. */
internal expect val vendoredJvmContentSuite: Boolean

abstract class PortableContentTestSuite<TEngine : ApplicationEngine, TConfiguration : ApplicationEngine.Configuration>(
    hostFactory: ApplicationEngineFactory<TEngine, TConfiguration>,
) : EngineTestBase<TEngine, TConfiguration>(hostFactory) {
    private fun contentTest(
        http1Only: Boolean = false,
        block: suspend kotlinx.coroutines.CoroutineScope.() -> Unit,
    ) = if (vendoredJvmContentSuite) {
        skipTest(
            "the vendored ContentTestSuite covers the JVM",
        )
    } else {
        runTest(http1Only = http1Only, block = block)
    }

    @Test
    fun testTextContent() =
        contentTest {
            createAndStartServer {
                handle {
                    call.respondText("test")
                }
            }

            withUrl("/") {
                assertEquals(200, status.value)

                val fields = HeadersBuilder()
                fields.appendAll(headers)

                fields.remove(HttpHeaders.Date) // Do not check for Date field since it's unstable

                // Check content type manually because spacing and case can be different per engine
                val contentType = fields.getAll(HttpHeaders.ContentType)?.single()
                fields.remove(HttpHeaders.ContentType)
                assertNotNull(contentType) // Content-Type should be present
                val parsedContentType = ContentType.parse(contentType) // It should parse
                assertEquals(ContentType.Text.Plain.withCharset(Charsets.UTF_8), parsedContentType)

                assertEquals("4", headers[HttpHeaders.ContentLength])
                assertEquals("test", bodyAsText())
            }
        }

    @Test
    fun testStream() =
        contentTest {
            createAndStartServer {
                handle {
                    call.respondBytesWriter(ContentType.Text.Plain) {
                        writeStringUtf8("ABC")
                        flush()
                        writeStringUtf8("123")
                        flush()
                    }
                }
            }

            withUrl("/") {
                assertEquals(200, status.value)
                assertEquals("ABC123", bodyAsText())
            }
        }

    @Test
    fun testBinaryUsingChannel() =
        contentTest {
            createAndStartServer {
                handle {
                    call.respondBytesWriter {
                        writeByte(25)
                        writeByte(37)
                        writeByte(42)
                    }
                }
            }

            withUrl("/") {
                assertEquals(200, status.value)
                assertEquals(ContentType.Application.OctetStream, contentType())
                assertTrue(byteArrayOf(25, 37, 42).contentEquals(readRawBytes()))
            }
        }

    @Test
    fun testRequestContentFormData() =
        contentTest {
            createAndStartServer {
                handle {
                    val parameters = runCatching { call.receive<Parameters?>() }.getOrNull()
                    if (parameters != null) {
                        call.respond(parameters.formUrlEncode())
                    } else {
                        call.respond(HttpStatusCode.UnsupportedMediaType)
                    }
                }
            }

            withUrl(
                "/",
                {
                    method = HttpMethod.Post
                    setBody(TextContent(parametersOf("a", "1").formUrlEncode(), ContentType.Application.FormUrlEncoded))
                },
            ) {
                assertEquals(200, status.value)
                assertEquals("a=1", bodyAsText())
            }

            withUrl("/") {
                assertEquals(HttpStatusCode.UnsupportedMediaType.value, status.value)
            }
        }

    @Test
    open fun testChunked() =
        contentTest(http1Only = true) {
            val data = ByteArray(16 * 1024) { it.toByte() }
            val size = data.size.toLong()

            createAndStartServer {
                get("/chunked") {
                    call.respond(
                        object : OutgoingContent.WriteChannelContent() {
                            override suspend fun writeTo(channel: ByteWriteChannel) {
                                channel.writeFully(data)
                                channel.flushAndClose()
                            }
                        },
                    )
                }
                get("/pseudo-chunked") {
                    call.respond(
                        object : OutgoingContent.WriteChannelContent() {
                            override val contentLength: Long get() = size

                            override suspend fun writeTo(channel: ByteWriteChannel) {
                                channel.writeFully(data)
                                channel.flushAndClose()
                            }
                        },
                    )
                }
                get("/array") {
                    call.respond(
                        object : OutgoingContent.ByteArrayContent() {
                            override val contentLength: Long get() = size

                            override fun bytes(): ByteArray = data
                        },
                    )
                }
                get("/array-chunked") {
                    call.respond(
                        object : OutgoingContent.ByteArrayContent() {
                            override fun bytes(): ByteArray = data
                        },
                    )
                }
                get("/read-channel") {
                    call.respond(
                        object : OutgoingContent.ReadChannelContent() {
                            override fun readFrom(): ByteReadChannel = ByteReadChannel(data)
                        },
                    )
                }
                get("/fixed-read-channel") {
                    call.respond(
                        object : OutgoingContent.ReadChannelContent() {
                            override val contentLength: Long get() = size

                            override fun readFrom(): ByteReadChannel = ByteReadChannel(data)
                        },
                    )
                }
            }

            withUrl("/array") {
                assertEquals(size, headers[HttpHeaders.ContentLength]?.toLong())
                assertNotEquals("chunked", headers[HttpHeaders.TransferEncoding])
                assertContentEquals(data, call.response.readRawBytes())
            }

            withUrl("/array-chunked") {
                assertEquals("chunked", headers[HttpHeaders.TransferEncoding])
                assertEquals(1, headers.getAll(HttpHeaders.TransferEncoding)!!.size)
                assertContentEquals(data, call.response.readRawBytes())
                assertNull(headers[HttpHeaders.ContentLength])
            }

            withUrl("/chunked") {
                assertEquals("chunked", headers[HttpHeaders.TransferEncoding])
                assertEquals(1, headers.getAll(HttpHeaders.TransferEncoding)!!.size)
                assertContentEquals(data, call.response.readRawBytes())
                assertNull(headers[HttpHeaders.ContentLength])
            }

            withUrl("/fixed-read-channel") {
                assertNotEquals("chunked", headers[HttpHeaders.TransferEncoding])
                assertEquals(size, headers[HttpHeaders.ContentLength]?.toLong())
                assertContentEquals(data, call.response.readRawBytes())
            }

            withUrl("/pseudo-chunked") {
                assertNotEquals("chunked", headers[HttpHeaders.TransferEncoding])
                assertEquals(size, headers[HttpHeaders.ContentLength]?.toLong())
                assertContentEquals(data, call.response.readRawBytes())
            }

            withUrl("/read-channel") {
                assertNull(headers[HttpHeaders.ContentLength])
                assertEquals("chunked", headers[HttpHeaders.TransferEncoding])
                assertEquals(1, headers.getAll(HttpHeaders.TransferEncoding)!!.size)
                assertContentEquals(data, call.response.readRawBytes())
            }
        }

    @Test
    fun testStreamNoFlush() =
        contentTest {
            createAndStartServer {
                handle {
                    call.respondBytesWriter(ContentType.Text.Plain) {
                        writeStringUtf8("ABC")
                        writeStringUtf8("123")
                    }
                }
            }

            withUrl("/") {
                assertEquals(200, status.value)
                assertEquals("ABC123", bodyAsText())
            }
        }

    @Test
    fun testSendTextWithContentType() =
        contentTest {
            createAndStartServer {
                handle {
                    call.respondText("Hello")
                }
            }

            withUrl("/") {
                assertEquals(200, status.value)
                assertEquals("Hello", bodyAsText())

                val contentType = ContentType.parse(headers[HttpHeaders.ContentType]!!)
                val pattern = ContentType.Text.Plain
                assertTrue(contentType.match(pattern))
            }
        }

    @Test
    fun testRequestBodyAsyncEcho() =
        contentTest {
            createAndStartServer {
                route("/echo") {
                    handle {
                        val response = call.receiveChannel().toByteArray()
                        call.respond(
                            object : OutgoingContent.ReadChannelContent() {
                                override fun readFrom() = ByteReadChannel(response)
                            },
                        )
                    }
                }
            }

            withUrl(
                "/echo",
                {
                    method = HttpMethod.Post
                    setBody(
                        ChannelWriterContent(
                            {
                                writeStringUtf8("POST test\n")
                                writeStringUtf8("Another line")
                                flush()
                            },
                            ContentType.Text.Plain,
                        ),
                    )
                },
            ) {
                assertEquals(200, status.value)
                assertEquals("POST test\nAnother line", bodyAsText())
            }
        }

    @Test
    fun testRequestContentString() =
        contentTest {
            createAndStartServer {
                post("/") {
                    call.respond(call.receiveText())
                }
            }

            withUrl(
                "/",
                {
                    method = HttpMethod.Post
                    setBody("Hello")
                },
            ) {
                assertEquals(200, status.value)
                assertEquals("Hello", bodyAsText())
            }
        }

    @Test
    open fun testMultipartFileUpload() =
        contentTest {
            createAndStartServer {
                post("/") {
                    val response = StringBuilder()
                    call.receiveMultipart().forEachPart { part ->
                        when (part) {
                            is PartData.FormItem -> {
                                response.append("${part.name}=${part.value}\n")
                            }

                            is PartData.FileItem -> {
                                response.append(
                                    "file:${part.name},${part.originalFileName},${
                                        part.provider().readBuffer().readText()
                                    }\n",
                                )
                            }

                            is PartData.BinaryItem -> {}

                            is PartData.BinaryChannelItem -> {}
                        }
                    }

                    call.respondText(response.toString())
                }
            }

            withUrl(
                "/",
                {
                    method = HttpMethod.Post
                    val contentType =
                        ContentType.MultiPart.FormData
                            .withParameter("boundary", "***bbb***")
                            .withCharset(Charsets.ISO_8859_1)

                    setBody(
                        ChannelWriterContent(
                            {
                                writeStringUtf8("--***bbb***\r\n")
                                writeStringUtf8("Content-Disposition: form-data; name=\"a story\"\r\n")
                                writeStringUtf8("\r\n")
                                writeStringUtf8(
                                    "Hi user. The snake you gave me for free ate all the birds. " +
                                        "Please take it back ASAP.\r\n",
                                )
                                writeStringUtf8("--***bbb***\r\n")
                                writeStringUtf8("Content-Disposition: form-data; name=\"attachment\"; filename=\"original.txt\"\r\n")
                                writeStringUtf8("Content-Type: text/plain\r\n")
                                writeStringUtf8("\r\n")
                                writeStringUtf8("File content goes here\r\n")
                                writeStringUtf8("--***bbb***--\r\n")
                                flush()
                            },
                            contentType,
                        ),
                    )
                },
            ) {
                assertEquals(200, status.value)
                assertEquals(
                    "a story=Hi user. The snake you gave me for free ate all the birds. " +
                        "Please take it back ASAP.\nfile:attachment,original.txt,File content goes here\n",
                    bodyAsText(),
                )
            }
        }

    @Test
    open fun testMultipartFileUploadLarge() =
        contentTest {
            val numberOfLines = 10000

            createAndStartServer {
                post("/") {
                    val response = StringBuilder()
                    call.receiveMultipart(formFieldLimit = 1 * 1024 * 1024).forEachPart { part ->
                        when (part) {
                            is PartData.FormItem -> {
                                response.append("${part.name}=${part.value}\n")
                            }

                            is PartData.FileItem -> {
                                val lineSequence =
                                    part
                                        .provider()
                                        .readBuffer()
                                        .readText()
                                        .lines()

                                response.append("file:${part.name},${part.originalFileName},${lineSequence.count()}\n")
                            }

                            is PartData.BinaryItem -> {
                            }

                            is PartData.BinaryChannelItem -> {}
                        }

                        part.release()
                    }
                    call.respondText(response.toString())
                }
            }

            withUrl(
                "/",
                {
                    method = HttpMethod.Post
                    val contentType =
                        ContentType.MultiPart.FormData
                            .withParameter("boundary", "***bbb***")
                            .withCharset(Charsets.ISO_8859_1)

                    setBody(
                        ChannelWriterContent(
                            {
                                writeStringUtf8("--***bbb***\r\n")
                                writeStringUtf8("Content-Disposition: form-data; name=\"a story\"\r\n")
                                writeStringUtf8("\r\n")
                                writeStringUtf8(
                                    "Hi user. The snake you gave me for free ate all the birds. " +
                                        "Please take it back ASAP.\r\n",
                                )
                                writeStringUtf8("--***bbb***\r\n")
                                writeStringUtf8("Content-Disposition: form-data; name=\"attachment\"; filename=\"original.txt\"\r\n")
                                writeStringUtf8("Content-Type: text/plain\r\n")
                                writeStringUtf8("\r\n")
                                withContext(coroutineContext) {
                                    repeat(numberOfLines) {
                                        writeStringUtf8("File content goes here\r\n")
                                    }
                                }
                                writeStringUtf8("--***bbb***--\r\n")
                                flush()
                            },
                            contentType,
                        ),
                    )
                },
            ) {
                assertEquals(200, status.value)
                assertEquals(
                    "a story=Hi user. The snake you gave me for free ate all the birds. " +
                        "Please take it back ASAP.\nfile:attachment,original.txt,$numberOfLines\n",
                    bodyAsText(),
                )
            }
        }

    @Test
    fun testReceivingBodyWithContentLengthMoreThanMaxInt() =
        contentTest {
            createAndStartServer {
                post("/") {
                    call.receiveChannel()
                    call.respondText { "OK" }
                }
            }

            withUrl(
                "/",
                {
                    method = HttpMethod.Post
                    headers.append("Content-Length", (Int.MAX_VALUE.toLong() + 1).toString())
                    setBody(ByteArray(1))
                },
            ) {
                assertEquals(200, status.value)
                assertEquals("OK", bodyAsText())
            }
        }

    @Test
    fun testAccessingQueryParameterWithoutValue() =
        contentTest {
            createAndStartServer {
                get("/") {
                    call.respondText(call.request.queryParameters["auto"].toString())
                }
            }

            withUrl("/?auto") {
                assertEquals(200, status.value)
                assertEquals("", bodyAsText())
            }
        }
}
