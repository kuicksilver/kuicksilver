// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A real third-party HTTP/3 client against the Ktor server (K5 criterion "interop http3"): curl with HTTP/3 support from a
 * Docker image named by `KSL_CURL_H3_IMAGE` (for example `ymuski/curl-http3`, amd64), reaching the host through
 * `host.docker.internal`. Skipped when the variable is unset or Docker is unavailable; `tools/ci/local-matrix.sh
 * --with-interop` sets it.
 */
class CurlHttp3Test {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun curlDownloadsOverHttp3Only() =
        serverTest {
            val image = System.getenv("KSL_CURL_H3_IMAGE")
            if (image.isNullOrBlank()) {
                println("KSL_CURL_H3_IMAGE unset: skipping the curl --http3 run")
                return@serverTest
            }
            val (server, port) =
                tlsServer(connector = {
                    host = "0.0.0.0"
                }) { routing { get("/h3") { call.respondText("hello over ${call.request.httpVersion}") } } }
            try {
                val cmd =
                    listOf(
                        "docker",
                        "run",
                        "--rm",
                        "--platform",
                        "linux/amd64",
                        image,
                        "curl",
                        "-sS",
                        "--http3-only",
                        "-k",
                        "--max-time",
                        "20",
                        "-w",
                        "\n%{http_version}",
                        "https://host.docker.internal:$port/h3",
                    )
                val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
                val out = p.inputStream.bufferedReader().readText()
                val rc = p.waitFor()
                assertEquals(0, rc, "curl failed: $out")
                assertTrue(out.contains("hello over HTTP/3") && out.trim().endsWith("3"), "HTTP/3 answer: $out")
            } finally {
                server.stop(100, 500)
            }
        }
}
