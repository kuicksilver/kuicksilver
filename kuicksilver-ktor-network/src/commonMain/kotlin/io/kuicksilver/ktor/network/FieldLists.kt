// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.kuicksilver.annotations.InternalKuicksilverApi

/**
 * The elements of a list-based field (`#element`, RFC 9110 section 5.6.1) received as the field lines [lines], in order:
 * the lines combine into one list (section 5.3), elements are separated by commas with OWS (SP or HTAB, section 5.6.3)
 * around them, and empty elements are ignored, as a recipient MUST (section 5.6.1.2). An empty field value or one of
 * only commas and OWS is a list without elements, not an error. Quoted strings are not looked into: only for lists of
 * tokens, such as `Connection` and `Upgrade`.
 */
@InternalKuicksilverApi
public fun fieldListElements(lines: List<String>): List<String> {
    val out = ArrayList<String>()
    for (line in lines) {
        for (part in line.split(',')) {
            val element = part.trim(' ', '\t')
            if (element.isNotEmpty()) out += element
        }
    }
    return out
}

/**
 * The connection options of the `Connection` field lines [lines] (`Connection = #connection-option`, RFC 9110 section
 * 7.6.1), lowercased: options are case-insensitive. Empty for no field, an empty one, or one with only empty elements.
 * Ktor's `ConnectionOptions.parse` failed with IllegalArgumentException on an empty value, read only one field line,
 * took an option after HTAB as a different one, and kept a trailing comma as part of an option.
 */
@InternalKuicksilverApi
public fun connectionOptions(lines: List<String>): Set<String> = fieldListElements(lines).mapTo(HashSet()) { it.lowercase() }
