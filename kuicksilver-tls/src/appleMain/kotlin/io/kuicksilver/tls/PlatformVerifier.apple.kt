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
import platform.CoreFoundation.CFArrayCreate
import platform.CoreFoundation.CFArrayGetCount
import platform.CoreFoundation.CFArrayGetValueAtIndex
import platform.CoreFoundation.CFDataCreate
import platform.CoreFoundation.CFDataGetBytePtr
import platform.CoreFoundation.CFDataGetLength
import platform.CoreFoundation.CFErrorGetCode
import platform.CoreFoundation.CFErrorRefVar
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFStringCreateWithCString
import platform.CoreFoundation.kCFAllocatorDefault
import platform.CoreFoundation.kCFStringEncodingUTF8
import platform.CoreFoundation.kCFTypeArrayCallBacks
import platform.Security.SecCertificateCopyData
import platform.Security.SecCertificateCreateWithData
import platform.Security.SecCertificateRef
import platform.Security.SecPolicyCreateSSL
import platform.Security.SecTrustCopyCertificateChain
import platform.Security.SecTrustCreateWithCertificates
import platform.Security.SecTrustEvaluateWithError
import platform.Security.SecTrustRefVar
import platform.Security.errSecCertificateExpired
import platform.Security.errSecCertificateNotValidYet
import platform.Security.errSecCertificateRevoked
import platform.Security.errSecHostNameMismatch
import platform.posix.memcpy

internal actual val platformTrustViaOpenSsl: Boolean = false

/** Apple: `SecTrust` with `SecPolicyCreateSSL(server, host)`; host is never nil (ADR-0011). Evaluated synchronously on the caller's dispatcher. */
internal actual object PlatformVerifier {
    actual suspend fun verify(
        chain: List<Certificate>,
        host: HostName,
        role: TlsRole,
    ): VerifyResult =
        memScoped {
            val certs: List<SecCertificateRef?> =
                chain.map { c ->
                    c.der.usePinned { p ->
                        val data = CFDataCreate(kCFAllocatorDefault, p.addressOf(0).reinterpret(), c.der.size.toLong())
                        val cert = SecCertificateCreateWithData(kCFAllocatorDefault, data)
                        data?.let { CFRelease(it) }
                        cert
                    }
                }
            if (certs.any { it == null }) {
                certs.forEach {
                    it?.let { c ->
                        CFRelease(c)
                    }
                }
                return VerifyResult.Rejected(VerifyReason.BadEncoding)
            }
            val values = allocArray<COpaquePointerVar>(chain.size)
            certs.forEachIndexed { i, c -> values[i] = c }
            val array = CFArrayCreate(kCFAllocatorDefault, values, chain.size.toLong(), kCFTypeArrayCallBacks.ptr)
            val hostRef = CFStringCreateWithCString(kCFAllocatorDefault, host.value, kCFStringEncodingUTF8)
            val policy = SecPolicyCreateSSL(role == TlsRole.Client, hostRef)
            val trustVar = alloc<SecTrustRefVar>()
            val status = SecTrustCreateWithCertificates(array, policy, trustVar.ptr)
            val trust = trustVar.value
            try {
                if (status != 0 ||
                    trust == null
                ) {
                    return VerifyResult.Rejected(VerifyReason.Custom("SecTrustCreateWithCertificates failed ($status)"))
                }
                val err = alloc<CFErrorRefVar>()
                val ok = SecTrustEvaluateWithError(trust, err.ptr)
                if (!ok) {
                    val code = err.value?.let { CFErrorGetCode(it) } ?: 0L
                    err.value?.let { CFRelease(it) }
                    return VerifyResult.Rejected(
                        when (code.toInt()) {
                            errSecHostNameMismatch -> VerifyReason.HostnameMismatch(host.value, chain[0].dnsNames)

                            errSecCertificateExpired -> VerifyReason.Expired

                            errSecCertificateNotValidYet -> VerifyReason.NotYetValid

                            errSecCertificateRevoked -> VerifyReason.Revoked

                            ERR_SEC_INCOMPLETE_CERT_REVOCATION_CHECK -> VerifyReason.UnknownRevocationStatus

                            // errSecNotTrusted, errSecVerifyActionFailed (-67901), errSecCreateChainFailed: no path to a trusted anchor
                            else -> VerifyReason.UnknownIssuer
                        },
                    )
                }
                val validated = SecTrustCopyCertificateChain(trust) ?: return VerifyResult.Accepted(chain)
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
                VerifyResult.Accepted(out)
            } finally {
                trust?.let { CFRelease(it) }
                policy?.let { CFRelease(it) }
                hostRef?.let { CFRelease(it) }
                array?.let { CFRelease(it) }
                certs.forEach {
                    it?.let { c ->
                        CFRelease(c)
                    }
                }
            }
        }
}

/** `errSecIncompleteCertRevocationCheck` (SecBase.h): a revocation check required by the policy could not complete. */
private const val ERR_SEC_INCOMPLETE_CERT_REVOCATION_CHECK = -67635
