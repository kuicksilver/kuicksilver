// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The documented Android form, `FileAltSvcStore(File(context.filesDir, ...))`, on the device's API level: on API 24-25 (no
 * `java.nio.file`) it must load, write and read back like on any later one.
 */
class FileAltSvcStoreAndroidTest {
    @Test fun storeInFilesDirPersistsAcrossInstances() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val f = File(context.filesDir, "altsvc-device-test.tsv")
        f.delete()
        try {
            val expires = System.currentTimeMillis() + 60_000
            FileAltSvcStore(f).put("https://a.test:443", listOf(AltSvcEntry("h3", null, 8443, expires, true)))
            assertEquals(listOf(8443), FileAltSvcStore(f).get("https://a.test:443").map { it.port })
        } finally {
            f.delete()
        }
    }
}
