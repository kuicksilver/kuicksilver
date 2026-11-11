// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.qlog

import android.os.Build
import android.system.Os
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.kuicksilver.tls.TlsRole
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * [qlogDirectory] on a device: an owner-only directory in the app's cache directory that receives traces (API 26 and up);
 * below API 26, where the directory cannot be checked, the helper refuses at once.
 */
@RunWith(AndroidJUnit4::class)
class QlogDirectoryAndroidTest {
    @Test fun traceLandsInAnOwnerOnlyCacheDirectory() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val dir = File(context.cacheDir, "qlog-device-test")
        dir.deleteRecursively()
        try {
            if (Build.VERSION.SDK_INT < 26) {
                assertFailsWith<IllegalArgumentException> { qlogDirectory(context, "qlog-device-test") }
                return
            }
            val sink = qlogDirectory(context, "qlog-device-test")
            assertEquals(0b111_000_000, Os.stat(dir.path).st_mode and 0b111_111_111, "0700")
            val trace = assertNotNull(sink.open("abcd", TlsRole.Server))
            trace.write("{}\n")
            trace.close()
            val files = dir.listFiles().orEmpty()
            assertEquals(1, files.size)
            assertTrue(files[0].name.startsWith("abcd_server_"), files[0].name)
        } finally {
            dir.deleteRecursively()
        }
    }
}
