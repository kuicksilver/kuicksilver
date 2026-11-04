// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.hpack

import kotlin.test.Test
import kotlin.test.assertEquals

class StaticTableTest {
    @Test
    fun rfc7541AppendixA() {
        assertEquals(61, StaticTable.SIZE)
        assertEquals(":authority" to "", StaticTable.entry(1))
        assertEquals(":method" to "GET", StaticTable.entry(2))
        assertEquals(":status" to "200", StaticTable.entry(8))
        assertEquals("www-authenticate" to "", StaticTable.entry(61))
        assertEquals(2, StaticTable.find(":method", "GET"))
        assertEquals(-1, StaticTable.find(":method", "PATCH"))
        assertEquals(2, StaticTable.findName(":method")) // the lowest index with that name
        assertEquals(32, StaticTable.findName("cookie"))
        assertEquals(-1, StaticTable.findName("x-custom"))
    }
}
