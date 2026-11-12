// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

/**
 * A streaming check that bytes are UTF-8 (RFC 3629 section 4, the syntax RFC 6455 section 8.1 refers to): no overlong
 * form, no surrogate (U+D800-U+DFFF), nothing above U+10FFFF. A character may be split across [feed] calls; [complete]
 * tells whether the bytes so far end between characters.
 */
internal class Utf8Validator {
    private var need = 0
    private var lower = 0x80
    private var upper = 0xBF

    /** Takes [length] more bytes of [bytes] from [offset]; false at the first byte that cannot be UTF-8 here. */
    fun feed(
        bytes: ByteArray,
        offset: Int,
        length: Int,
    ): Boolean {
        for (i in offset until offset + length) {
            val c = bytes[i].toInt() and 0xff
            if (need == 0) {
                if (c < 0x80) continue
                when (c) {
                    in 0xC2..0xDF -> need = 1
                    0xE0 -> start(2, 0xA0, 0xBF)
                    in 0xE1..0xEC, 0xEE, 0xEF -> need = 2
                    0xED -> start(2, 0x80, 0x9F)
                    0xF0 -> start(3, 0x90, 0xBF)
                    in 0xF1..0xF3 -> need = 3
                    0xF4 -> start(3, 0x80, 0x8F)
                    else -> return false
                }
            } else {
                if (c < lower || c > upper) return false
                lower = 0x80
                upper = 0xBF
                need--
            }
        }
        return true
    }

    /** True when the bytes so far end between characters. */
    val complete: Boolean get() = need == 0

    /** Forgets the bytes so far, for the next message. */
    fun reset() {
        need = 0
        lower = 0x80
        upper = 0xBF
    }

    private fun start(
        need: Int,
        lower: Int,
        upper: Int,
    ) {
        this.need = need
        this.lower = lower
        this.upper = upper
    }
}

/** Whether [bytes] from [from] to [to] are UTF-8 and end between characters. */
internal fun isUtf8(
    bytes: ByteArray,
    from: Int,
    to: Int,
): Boolean = Utf8Validator().let { it.feed(bytes, from, to - from) && it.complete }
