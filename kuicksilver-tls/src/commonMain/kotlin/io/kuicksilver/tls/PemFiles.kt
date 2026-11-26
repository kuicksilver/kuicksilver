// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.io.IOException

/**
 * A PEM file that must hold certificates only (`holds`) also holds a private key (`encrypted` says whether it is); the
 * message names the file, never the key. Used by [TrustConfig.fromPemFile] and the server's PEM files.
 */
@InternalKuicksilverApi
public class PrivateKeyInPemFile(
    path: String,
    holds: String,
    encrypted: Boolean = false,
) : IOException("$path contains ${if (encrypted) "an encrypted" else "a"} private key; it must hold $holds only")

/** The most a PEM file of an identity or a CA bundle may hold (a chain of a dozen certificates is a few tens of KiB). */
@InternalKuicksilverApi
public const val MAX_PEM_FILE_BYTES: Long = 1L shl 20

/**
 * The PEM file [path] as text (at most [MAX_PEM_FILE_BYTES]); with [refusePrivateKey], a file that also holds a private key
 * (a combined PEM, or a key file given by mistake) fails with [PrivateKeyInPemFile] before any `String` of it is made, and
 * the characters read are wiped; with [requirePemBlock], so does a file without any `-----BEGIN ` line
 * ([TlsException.Config]), whose bytes may be anything (a DER or PKCS#12 file).
 *
 * @throws IOException when the file cannot be read or is larger than [MAX_PEM_FILE_BYTES].
 */
@InternalKuicksilverApi
public fun readPemText(
    path: String,
    refusePrivateKey: Boolean = false,
    holds: String = "the certificate chain",
    // a file without any PEM block is refused before a String of it is made (a DER key, say, holds no "PRIVATE KEY" text)
    requirePemBlock: Boolean = false,
): String {
    val chars = readSecretFile(path, MAX_PEM_FILE_BYTES)
    try {
        if (requirePemBlock && !chars.containsText("-----BEGIN ")) {
            throw TlsException.Config("$path holds no certificate (-----BEGIN CERTIFICATE-----): no PEM block at all")
        }
        if (refusePrivateKey && chars.containsText("PRIVATE KEY")) {
            // RFC 7468 section 11 (`ENCRYPTED PRIVATE KEY`) or a legacy OpenSSL key's `Proc-Type: 4,ENCRYPTED` header
            throw PrivateKeyInPemFile(path, holds, encrypted = chars.containsText("ENCRYPTED"))
        }
        return chars.concatToString()
    } finally {
        chars.fill('\u0000')
    }
}

/**
 * The bytes of [path] (at most [maxBytes], else [IOException]) as characters, one per byte, every intermediate copy wiped:
 * the platform reader keeps no buffer of its own that outlives the call (a direct buffer wiped on the JVM, an unbuffered
 * `fread` into a wiped array on Kotlin/Native), unlike kotlinx-io's pooled segments. The caller wipes the result.
 */
@InternalKuicksilverApi
public expect fun readSecretFile(
    path: String,
    maxBytes: Long,
): CharArray

private fun CharArray.containsText(needle: String): Boolean {
    var i = 0
    while (i <= size - needle.length) {
        var j = 0
        while (j < needle.length && this[i + j] == needle[j]) j++
        if (j == needle.length) return true
        i++
    }
    return false
}

/**
 * The trust anchors of a PEM text for [TrustConfig.fromPem] and [TrustConfig.fromPemFile]: its `CERTIFICATE` blocks, with a
 * message that says what was found instead when there is none, and a refusal of a text that holds a private key or an
 * encrypted block (a key file given by mistake, or a bundle someone protected with a password) even next to certificates.
 * [what] names the source in the messages (the file, or "the PEM text"); the messages never quote the text.
 */
internal fun pemTrustAnchors(
    pem: String,
    what: String,
): List<Certificate> {
    // RFC 7468 section 2: the label after BEGIN says what a block is; a legacy OpenSSL key says it is encrypted in a header
    if (pem.contains("-----BEGIN ENCRYPTED") || pem.contains("Proc-Type: 4,ENCRYPTED")) {
        throw TlsException.Config(
            "$what holds an encrypted PEM block (a password-protected key); a trust anchor is a CA certificate " +
                "(-----BEGIN CERTIFICATE-----), never a key",
        )
    }
    if (pem.contains("PRIVATE KEY-----")) {
        throw TlsException.Config(
            "$what holds a private key; a trust anchor is a CA certificate (-----BEGIN CERTIFICATE-----): pass the CA's " +
                "certificate, and keep the key out of the application",
        )
    }
    if (!pem.contains("-----BEGIN CERTIFICATE-----")) {
        val labels =
            Regex("-----BEGIN ([A-Z0-9 ]{1,40})-----")
                .findAll(pem)
                .map { it.groupValues[1] }
                .distinct()
                .take(3)
                .toList()
        val found = if (labels.isEmpty()) "no PEM block at all" else "only " + labels.joinToString { "\"$it\"" } + " blocks"
        throw TlsException.Config("$what holds no certificate (-----BEGIN CERTIFICATE-----): $found")
    }
    return Certificate.parsePem(pem)
}
