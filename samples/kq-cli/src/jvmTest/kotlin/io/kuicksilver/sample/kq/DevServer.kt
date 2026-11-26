// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.kq

import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking
import java.io.File

/**
 * A local server to point kq at by hand (`./gradlew -p samples/kq-cli devServer --args=4433`): HTTP/1.1, HTTP/2 and HTTP/3
 * on 127.0.0.1 with the sample's test certificate. It writes the test CA to dev-ca.pem in its working directory
 * (samples/kq-cli/build) for `kq --cacert`. Test material: never expose it beyond loopback.
 */
fun main(args: Array<String>): Unit =
    runBlocking {
        val port = args.firstOrNull()?.toInt() ?: 4433
        val ca = File("dev-ca.pem").apply { writeText(SampleCerts.caPem.trimStart() + "\n") }
        val (_, bound) = startServer(port)
        println("kq dev server on https://127.0.0.1:$bound/ (TCP and UDP); CA: ${ca.absolutePath}")
        println("try: kq get -v --cacert ${ca.absolutePath} --repeat 2 https://127.0.0.1:$bound/")
        awaitCancellation()
    }
