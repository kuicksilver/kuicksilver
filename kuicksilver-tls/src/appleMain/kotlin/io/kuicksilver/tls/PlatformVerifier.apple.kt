// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.tls

import cnames.structs.__SecCertificate
import kotlinx.cinterop.COpaquePointerVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.interpretCPointer
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.set
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.coroutines.suspendCancellableCoroutine
import platform.CoreFoundation.CFArrayCreate
import platform.CoreFoundation.CFArrayGetCount
import platform.CoreFoundation.CFArrayGetValueAtIndex
import platform.CoreFoundation.CFArrayRef
import platform.CoreFoundation.CFDataCreate
import platform.CoreFoundation.CFDataGetBytePtr
import platform.CoreFoundation.CFDataGetLength
import platform.CoreFoundation.CFDateCreate
import platform.CoreFoundation.CFErrorGetCode
import platform.CoreFoundation.CFErrorRef
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFStringCreateWithCString
import platform.CoreFoundation.CFTypeRef
import platform.CoreFoundation.kCFAllocatorDefault
import platform.CoreFoundation.kCFStringEncodingUTF8
import platform.CoreFoundation.kCFTypeArrayCallBacks
import platform.Security.SecCertificateCopyData
import platform.Security.SecCertificateCreateWithData
import platform.Security.SecCertificateRef
import platform.Security.SecPolicyCreateSSL
import platform.Security.SecTrustCopyCertificateChain
import platform.Security.SecTrustCreateWithCertificates
import platform.Security.SecTrustEvaluateAsyncWithError
import platform.Security.SecTrustRef
import platform.Security.SecTrustRefVar
import platform.Security.SecTrustSetAnchorCertificates
import platform.Security.SecTrustSetAnchorCertificatesOnly
import platform.Security.SecTrustSetVerifyDate
import platform.Security.errSecCertificateExpired
import platform.Security.errSecCertificateNotValidYet
import platform.Security.errSecCertificateRevoked
import platform.Security.errSecHostNameMismatch
import platform.darwin.DISPATCH_QUEUE_PRIORITY_DEFAULT
import platform.darwin.dispatch_async
import platform.darwin.dispatch_get_global_queue
import platform.darwin.dispatch_queue_t
import platform.posix.memcpy
import kotlin.coroutines.resume

internal actual val platformTrustViaOpenSsl: Boolean = false

/**
 * Apple: `SecTrust` with `SecPolicyCreateSSL(server, host)`; host is never nil (ADR-0011). The evaluation may fetch
 * intermediates (AIA) and revocation status (OCSP) over the network, which takes seconds on a slow link, so it never runs on a
 * Kotlin thread: `SecTrustEvaluateAsyncWithError` on a global dispatch queue answers through a callback and the caller only
 * suspends. A slow server's verification therefore holds no thread of `Dispatchers.Default` and cannot stall other
 * connections' handshakes.
 */
internal actual object PlatformVerifier {
    /** The queue the evaluation runs on and calls back from (Security requires both to be the same queue). */
    private val queue: dispatch_queue_t get() = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT.toLong(), 0u)

    /**
     * Starts the evaluation of [trust] on [queue] and calls `done(ok, error)` there; [host] is what the trust was made for.
     * Tests replace it with a slow or stalled evaluator; the default is `SecTrustEvaluateAsyncWithError`. Called on [queue].
     */
    internal var evaluator: (trust: SecTrustRef, queue: dispatch_queue_t, host: String, done: (Boolean, CFErrorRef?) -> Unit) -> Unit =
        { trust, q, _, done ->
            // SecTrust.h: the block runs exactly once when the call answers errSecSuccess, never otherwise
            val status = SecTrustEvaluateAsyncWithError(trust, q) { _, ok, error -> done(ok, error) }
            if (status != 0) done(false, null)
        }

    /**
     * Test hook: extra roots trusted next to the system's (`SecTrustSetAnchorCertificates` with
     * `SecTrustSetAnchorCertificatesOnly(false)`), the way a root installed by a configuration profile (MDM) is trusted.
     */
    internal var extraAnchorsForTest: List<ByteArray> = emptyList()

    /** Test hook: evaluate as of this time (seconds since 1970, `SecTrustSetVerifyDate`) instead of now, so a fixture never expires. */
    internal var verifyDateForTest: Long? = null

    actual suspend fun verify(
        chain: List<Certificate>,
        host: HostName,
        role: TlsRole,
    ): VerifyResult {
        val owned = ArrayList<CFTypeRef?>() // released once the evaluation answered (or could not start)
        val trust =
            try {
                createTrust(chain, host, role, owned) ?: return VerifyResult.Rejected(VerifyReason.BadEncoding)
            } catch (e: IllegalStateException) {
                owned.forEach { it?.let(::CFRelease) }
                return VerifyResult.Rejected(VerifyReason.Custom(e.message ?: "SecTrustCreateWithCertificates failed"))
            }
        return suspendCancellableCoroutine { cont ->
            val q = queue
            dispatch_async(q) {
                evaluator(trust, q, host.value) { ok, error ->
                    // runs on the queue: read the outcome, then release everything; a cancelled caller's resume is ignored
                    val r =
                        try {
                            if (ok) VerifyResult.Accepted(validatedChain(trust) ?: chain) else rejection(error, host, chain)
                        } finally {
                            owned.forEach { it?.let(::CFRelease) }
                        }
                    cont.resume(r)
                }
            }
        }
    }

    /** The SecTrust for [chain] and [host], or null when a certificate does not parse; every created object goes to [owned]. */
    private fun createTrust(
        chain: List<Certificate>,
        host: HostName,
        role: TlsRole,
        owned: MutableList<CFTypeRef?>,
    ): SecTrustRef? =
        memScoped {
            val certs = chain.map { secCertificate(it.encoded) }
            owned += certs
            if (certs.any { it == null }) return null
            val array = cfArray(certs)
            owned += array
            val hostRef = CFStringCreateWithCString(kCFAllocatorDefault, host.value, kCFStringEncodingUTF8)
            owned += hostRef
            val policy = SecPolicyCreateSSL(role == TlsRole.Client, hostRef)
            owned += policy
            val trustVar = alloc<SecTrustRefVar>()
            val status = SecTrustCreateWithCertificates(array, policy, trustVar.ptr)
            val trust = trustVar.value
            owned += trust
            if (status != 0 || trust == null) throw IllegalStateException("SecTrustCreateWithCertificates failed ($status)")
            verifyDateForTest?.let { epoch ->
                val date = CFDateCreate(kCFAllocatorDefault, (epoch - CF_EPOCH_OFFSET).toDouble())
                owned += date
                SecTrustSetVerifyDate(trust, date)
            }
            val extra = extraAnchorsForTest
            if (extra.isNotEmpty()) {
                val anchors = extra.map { secCertificate(it) }
                owned += anchors
                val anchorArray = cfArray(anchors)
                owned += anchorArray
                SecTrustSetAnchorCertificates(trust, anchorArray)
                SecTrustSetAnchorCertificatesOnly(trust, false)
            }
            trust
        }

    private fun secCertificate(der: ByteArray): SecCertificateRef? =
        der.usePinned { p ->
            val data = CFDataCreate(kCFAllocatorDefault, p.addressOf(0).reinterpret(), der.size.toLong())
            val cert = SecCertificateCreateWithData(kCFAllocatorDefault, data)
            data?.let { CFRelease(it) }
            cert
        }

    private fun cfArray(items: List<CFTypeRef?>): CFArrayRef? =
        memScoped {
            val values = allocArray<COpaquePointerVar>(items.size)
            items.forEachIndexed { i, c -> values[i] = c }
            CFArrayCreate(kCFAllocatorDefault, values, items.size.toLong(), kCFTypeArrayCallBacks.ptr)
        }

    private fun rejection(
        error: CFErrorRef?,
        host: HostName,
        chain: List<Certificate>,
    ): VerifyResult.Rejected =
        VerifyResult.Rejected(
            when ((error?.let { CFErrorGetCode(it) } ?: 0L).toInt()) {
                errSecHostNameMismatch -> VerifyReason.HostnameMismatch(host.value, chain[0].dnsNames)

                errSecCertificateExpired -> VerifyReason.Expired

                errSecCertificateNotValidYet -> VerifyReason.NotYetValid

                errSecCertificateRevoked -> VerifyReason.Revoked

                ERR_SEC_INCOMPLETE_CERT_REVOCATION_CHECK -> VerifyReason.UnknownRevocationStatus

                // errSecNotTrusted, errSecVerifyActionFailed (-67901), errSecCreateChainFailed: no path to a trusted anchor
                else -> VerifyReason.UnknownIssuer
            },
        )

    /** The chain SecTrust built (leaf first), or null when it cannot be read. */
    private fun validatedChain(trust: SecTrustRef): List<Certificate>? {
        val validated = SecTrustCopyCertificateChain(trust) ?: return null
        val out = ArrayList<Certificate>()
        for (i in 0 until CFArrayGetCount(validated)) {
            val raw = CFArrayGetValueAtIndex(validated, i) ?: continue
            val cert: CPointer<__SecCertificate> = interpretCPointer(raw.rawValue) ?: continue
            val data = SecCertificateCopyData(cert) ?: continue
            val n = CFDataGetLength(data).toInt()
            val bytes = ByteArray(n)
            val src = CFDataGetBytePtr(data)
            if (src != null && n > 0) bytes.usePinned { dst -> memcpy(dst.addressOf(0), src, n.toULong()) }
            CFRelease(data)
            out += Certificate(bytes)
        }
        CFRelease(validated)
        return out
    }
}

/** Seconds from 1970-01-01 to 2001-01-01, the epoch of `CFAbsoluteTime`. */
private const val CF_EPOCH_OFFSET = 978_307_200L

/** `errSecIncompleteCertRevocationCheck` (SecBase.h): a revocation check required by the policy could not complete. */
private const val ERR_SEC_INCOMPLETE_CERT_REVOCATION_CHECK = -67635
