// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h1

import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.engine.EnginePipeline
import io.ktor.server.engine.handleFailure
import io.ktor.server.logging.mdcProvider
import io.ktor.server.response.respondText
import io.ktor.util.cio.ChannelIOException
import io.ktor.util.pipeline.PipelinePhase
import io.ktor.util.pipeline.execute
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/** The phase of [installH1CallHandling], just before Ktor's own `EnginePipeline.Call`. */
private val H1CallPhase = PipelinePhase("KuicksilverH1Call")

/**
 * Runs the application for an HTTP/1.1 call in place of Ktor's default engine phase (`defaultEnginePipeline`), which it
 * follows with two differences; HTTP/3 calls go on to Ktor's.
 *
 * - A request whose body stopped arriving ([RequestBodyTimeout] in the failure's causes) is answered `408 Request
 *   Timeout` with a fixed body and `Connection: close`, when nothing has answered it yet: the application, StatusPages
 *   included, runs first and its own answer stays. Ktor's handling maps no exception to 408 and would send a 500 with
 *   the exception's message; doing it per call also leaves any other request's 500 alone.
 * - The request body is not read to its end after the application (Ktor discards whatever is left, of any size): the
 *   connection's pipeline settles a body the handler left unread (it drains up to a cap or ends the connection).
 *
 * As in Ktor's phase, a failure that is the connection's own (a `ChannelIOException`: the client went away) gets no
 * answer, and every other one goes to `handleFailure` (logging, then a status from `defaultExceptionStatusCode`).
 */
internal fun EnginePipeline.installH1CallHandling() {
    insertPhaseBefore(EnginePipeline.Call, H1CallPhase)
    intercept(H1CallPhase) {
        val call = context as? H1Call ?: return@intercept
        try {
            call.application.execute(call)
        } catch (error: Throwable) {
            if (error is CancellationException) currentCoroutineContext().ensureActive()
            call.application.mdcProvider.withMDCBlock(call) {
                when {
                    generateSequence(error) { it.cause }.any { it is RequestBodyTimeout } && !call.response.isCommitted -> {
                        // RFC 9110 section 15.5.9; the pipeline has marked the connection to close after this response
                        call.respondText(REQUEST_TIMEOUT_BODY, ContentType.Text.Plain, HttpStatusCode.RequestTimeout)
                    }

                    error is ChannelIOException -> {
                        call.application.environment.log
                            .debug("I/O error on an HTTP/1.1 call: ${error.message}")
                    }

                    else -> {
                        handleFailure(call, error)
                    }
                }
            }
        }
        finish()
    }
}

/** The fixed body of the 408 for a request body that stopped arriving: no exception message reaches the client. */
private const val REQUEST_TIMEOUT_BODY = "Request Timeout"
