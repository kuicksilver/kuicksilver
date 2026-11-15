// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.setBody
import io.ktor.client.request.url
import io.ktor.http.HttpMethod
import io.ktor.http.content.OutgoingContent
import io.ktor.utils.io.ByteReadChannel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals

/**
 * [prepareFirstContact] reads a body without a length to its end before an HTTP/1.0 server gets it with Content-Length: a
 * body read to its end as the deadline fires (the timeout lands on another thread after the read returned, before the
 * deadline's scope completed) is kept. It was consumed: failing the request then loses a body that cannot be read again.
 */
class FirstContactDeadlineRaceTest {
    @AfterTest fun reset() {
        firstContactBufferedForTest = null
    }

    @Test fun negative_aBodyReadAsTheDeadlineFiresIsKept() =
        runBlocking {
            firstContactBufferedForTest = {
                yield() // the block completes through a resumption, as a real read does
                val job = currentCoroutineContext().job
                while (!job.isCancelled) Thread.onSpinWait() // the deadline fires meanwhile
            }
            val request =
                HttpRequestBuilder()
                    .apply {
                        url("http://example.test/upload")
                        method = HttpMethod.Post
                        // no length: it would go out chunked
                        setBody(
                            object : OutgoingContent.ReadChannelContent() {
                                override fun readFrom(): ByteReadChannel = ByteReadChannel("hello".encodeToByteArray())
                            },
                        )
                    }.build()
            prepareFirstContact(request, 50) // threw "did not end within 50 ms" for a body it had read
            assertContentEquals("hello".encodeToByteArray(), request.firstContactBody())
        }
}
