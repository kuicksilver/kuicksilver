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
import kotlin.concurrent.Volatile
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.fail

/**
 * [prepareFirstContact] reads a body without a length to its end before an HTTP/1.0 server gets it with Content-Length: a
 * body read to its end as the deadline fires (the timeout lands on another thread after the read returned, before the
 * deadline's scope completed) is kept. It was consumed: failing the request then loses a body that cannot be read again.
 */
class FirstContactDeadlineRaceTest {
    @AfterTest fun reset() {
        firstContactBufferedForTest = null
    }

    @Volatile private var reached = false

    /**
     * The read of the body before the hook must end within the deadline for the race to happen (a cold JVM's first channel
     * copy can take longer than 50 ms): a run whose hook was not reached does not count, and the next one gets the deadline
     * doubled.
     */
    @Test fun negative_aBodyReadAsTheDeadlineFiresIsKept() =
        runBlocking {
            firstContactBufferedForTest = {
                yield() // the block completes through a resumption, as a real read does; throws when the deadline fired
                reached = true
                val job = currentCoroutineContext().job
                while (!job.isCancelled) Thread.onSpinWait() // the deadline fires meanwhile
            }
            var within = 50L
            repeat(8) {
                reached = false
                val request = request()
                val outcome = runCatching { prepareFirstContact(request, within) }
                if (reached) {
                    outcome.getOrThrow() // threw "did not end within" for a body it had read
                    assertContentEquals("hello".encodeToByteArray(), request.firstContactBody())
                    return@runBlocking
                }
                within *= 2
            }
            fail("the body read never ended within ${within / 2} ms")
        }

    private fun request() =
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
}
