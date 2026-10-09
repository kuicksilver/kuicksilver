// Copyright 2014-2024 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Vendored from Ktor 3.6.0 ktor-test-server/src/main/kotlin/test/server/tests/Upload.kt, adapted to the Kuicksilver engine.
package io.kuicksilver.ktor.client.contract

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

internal fun Application.uploadTest() {
    routing {
        route("upload") {
            post("content") {
                val message = call.request.headers[HttpHeaders.ContentType] ?: "EMPTY"
                call.respond(HttpStatusCode.OK, message)
            }
        }
    }
}
