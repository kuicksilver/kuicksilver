// Copyright 2014-2025 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Vendored from Ktor 3.6.0 ktor-client/ktor-client-tests/common/test/io/ktor/client/tests/utils/HttpClient.kt, adapted to the Kuicksilver engine.
package io.kuicksilver.ktor.client.contract

import io.ktor.client.*
import io.ktor.http.*

internal val HttpClient.engineName get() = engine::class.simpleName?.removeSuffix("ClientEngine")

private val allMethods = HttpMethod.DefaultMethods + HttpMethod.Trace

internal fun HttpClient.supportedMethods(): List<HttpMethod> =
    when (engineName) {
        // PATCH is not supported by HttpURLConnection
        // https://bugs.openjdk.org/browse/JDK-7016595
        "Android" -> allMethods - HttpMethod.Patch

        // Js engine throws: TypeError: 'TRACE' HTTP method is unsupported.
        "Js" -> allMethods - HttpMethod.Trace

        else -> allMethods
    }
