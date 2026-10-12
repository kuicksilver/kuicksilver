// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(DelicateKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import java.io.File
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Android API 24-25 has no `java.nio.file`: the key log cannot vouch for its file there and refuses it with a clear error. */
class KeylogFileNoNioTest {
    @Test fun negative_keylogFileWithoutNioIsRefused() {
        val f = File(System.getProperty("java.io.tmpdir"), "kuicksilver-keylog-nonio-${System.nanoTime()}.txt")
        val e = assertFailsWith<IllegalArgumentException> { openKeylogFile(f.path, hasNio = false) }
        assertTrue("API 26" in e.message.orEmpty(), e.message)
        assertFalse(f.exists())
    }
}
