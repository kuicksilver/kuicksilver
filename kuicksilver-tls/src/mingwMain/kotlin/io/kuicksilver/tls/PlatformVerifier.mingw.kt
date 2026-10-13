// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.tls

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.MemScope
import kotlinx.cinterop.UIntVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.allocPointerTo
import kotlinx.cinterop.cstr
import kotlinx.cinterop.get
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.plus
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.set
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.toCPointer
import kotlinx.cinterop.toCValues
import kotlinx.cinterop.value
import kotlinx.cinterop.wcstr
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withContext
import platform.posix.memset
import platform.windows.AUTHTYPE_CLIENT
import platform.windows.AUTHTYPE_SERVER
import platform.windows.CERT_CHAIN_CACHE_END_CERT
import platform.windows.CERT_CHAIN_CONTEXT
import platform.windows.CERT_CHAIN_ENGINE_CONFIG
import platform.windows.CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS
import platform.windows.CERT_CHAIN_POLICY_PARA
import platform.windows.CERT_CHAIN_POLICY_STATUS
import platform.windows.CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT
import platform.windows.CERT_CHAIN_REVOCATION_CHECK_END_CERT
import platform.windows.CERT_CONTEXT
import platform.windows.CERT_E_CN_NO_MATCH
import platform.windows.CERT_E_EXPIRED
import platform.windows.CERT_E_MALFORMED
import platform.windows.CERT_E_PURPOSE
import platform.windows.CERT_E_REVOCATION_FAILURE
import platform.windows.CERT_E_REVOKED
import platform.windows.CERT_E_WRONG_USAGE
import platform.windows.CERT_STORE_ADD_ALWAYS
import platform.windows.CERT_STORE_CREATE_NEW_FLAG
import platform.windows.CRYPT_E_NO_REVOCATION_CHECK
import platform.windows.CRYPT_E_REVOCATION_OFFLINE
import platform.windows.CRYPT_E_REVOKED
import platform.windows.CertAddEncodedCertificateToStore
import platform.windows.CertCloseStore
import platform.windows.CertCreateCertificateChainEngine
import platform.windows.CertFreeCertificateChain
import platform.windows.CertFreeCertificateChainEngine
import platform.windows.CertFreeCertificateContext
import platform.windows.CertGetCertificateChain
import platform.windows.CertOpenStore
import platform.windows.CertVerifyCertificateChainPolicy
import platform.windows.CertVerifyTimeValidity
import platform.windows.HCERTSTOREVar
import platform.windows.HTTPSPolicyCallbackData
import platform.windows.PCCERT_CHAIN_CONTEXTVar
import platform.windows.PCCERT_CONTEXTVar
import platform.windows.TRUST_E_CERT_SIGNATURE
import platform.windows.USAGE_MATCH_TYPE_AND
import platform.windows.X509_ASN_ENCODING
import platform.windows._CERT_CHAIN_PARA
import platform.windows.szOID_PKIX_KP_CLIENT_AUTH
import platform.windows.szOID_PKIX_KP_SERVER_AUTH

internal actual val platformTrustViaOpenSsl: Boolean = false

/**
 * Windows: CryptoAPI, the verifier Schannel and browsers on Windows use (ADR-0011). Runs on [Dispatchers.IO] because chain
 * building may fetch missing intermediates (AIA) and the leaf's revocation status over the network.
 */
internal actual object PlatformVerifier {
    actual suspend fun verify(
        chain: List<Certificate>,
        host: HostName,
        role: TlsRole,
    ): VerifyResult = withContext(Dispatchers.IO) { WindowsTrust.verify(chain, host, role) }
}

/**
 * The Windows chain verification, modelled on Go's `crypto/x509/root_windows.go` and rustls-platform-verifier's
 * `verification/windows.rs` (written independently, no code copied):
 *
 * 1. the presented certificates go into an in-memory store; the leaf's context comes from that store, the rest are the
 *    intermediates `CertGetCertificateChain` may use (it can also fetch missing ones through AIA, as browsers do);
 * 2. the chain is built for the extended key usage of the peer's role (`serverAuth` for a server, `clientAuth` for a
 *    client; a certificate without the extension allows any use) with the leaf's revocation checked, network fetches
 *    bounded by [URL_TIMEOUT_MS] in total;
 * 3. `CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL)` decides, with the reference identifier as the server name
 *    for a server; an unknown revocation status is ignored (soft fail, like rustls-platform-verifier, OpenSSL and Secure
 *    Transport), a revoked leaf is not;
 * 4. the first simple chain of the context is the validated chain pins are compared against.
 *
 * `ksl` still re-checks the name with the shared RFC 9525 matcher when the handshake resumes, so Windows' own matcher
 * (which still falls back to the subject CN when no SAN is present) can only make the decision stricter.
 */
internal object WindowsTrust {
    /** Total time (milliseconds) chain building may spend on AIA and revocation retrieval for one verification. */
    private const val URL_TIMEOUT_MS = 10_000u

    /** `CERT_STORE_PROV_MEMORY` and `CERT_CHAIN_POLICY_SSL` are `(LPCSTR)` integer constants, which cinterop does not bind. */
    private const val CERT_STORE_PROV_MEMORY = 2L
    private const val CERT_CHAIN_POLICY_SSL = 4L

    /**
     * The full `CERT_CHAIN_PARA` (wincrypt.h): mingw-w64 hides the fields after `RequestedUsage` unless
     * `CERT_CHAIN_PARA_HAS_EXTRA_FIELDS` is defined, so the platform bindings stop there. Windows reads only the fields
     * [cbSize][_CERT_CHAIN_PARA.cbSize] covers; the offset of `dwUrlRetrievalTimeout` follows the x64 layout of
     * `RequestedUsage` and `RequestedIssuancePolicy` (two `CERT_USAGE_MATCH`, 24 bytes each, after an 8-byte aligned DWORD).
     */
    private const val CHAIN_PARA_FULL_SIZE = 96
    private const val CHAIN_PARA_URL_TIMEOUT_OFFSET = 56L

    /**
     * Verifies [chain] (leaf first) for a peer whose local side is [role]. [exclusiveRoots], for tests only, replaces the
     * system roots with the given anchors (`hExclusiveRoot`), the way an [TrustConfig.AnchoredCa] would.
     */
    fun verify(
        chain: List<Certificate>,
        host: HostName,
        role: TlsRole,
        exclusiveRoots: List<Certificate>? = null,
    ): VerifyResult {
        if (chain.isEmpty()) return VerifyResult.Rejected(VerifyReason.NoCertificate)
        return memScoped {
            val store =
                memoryStore() ?: return@memScoped VerifyResult.Rejected(VerifyReason.Custom("CertOpenStore failed"))
            var roots: CPointer<*>? = null
            var engine: CPointer<*>? = null
            var leaf: CPointer<CERT_CONTEXT>? = null
            var context: CPointer<CERT_CHAIN_CONTEXT>? = null
            try {
                for ((i, c) in chain.withIndex()) {
                    val added = add(store, c) ?: return@memScoped VerifyResult.Rejected(VerifyReason.BadEncoding)
                    if (i == 0) leaf = added else CertFreeCertificateContext(added)
                }
                if (exclusiveRoots != null) {
                    roots = memoryStore() ?: return@memScoped VerifyResult.Rejected(VerifyReason.Custom("CertOpenStore failed"))
                    for (r in exclusiveRoots) {
                        CertFreeCertificateContext(add(roots, r) ?: return@memScoped VerifyResult.Rejected(VerifyReason.BadEncoding))
                    }
                    engine =
                        exclusiveEngine(roots)
                            ?: return@memScoped VerifyResult.Rejected(VerifyReason.Custom("CertCreateCertificateChainEngine failed"))
                }
                context = buildChain(engine, leaf, store, role)
                    ?: return@memScoped VerifyResult.Rejected(VerifyReason.Custom("CertGetCertificateChain failed"))
                val status =
                    policy(context, host, role)
                        ?: return@memScoped VerifyResult.Rejected(VerifyReason.Custom("CertVerifyCertificateChainPolicy failed"))
                if (status.dwError ==
                    0u
                ) {
                    VerifyResult.Accepted(validatedChain(context))
                } else {
                    VerifyResult.Rejected(reasonOf(status, context, chain, host))
                }
            } finally {
                context?.let { CertFreeCertificateChain(it) }
                leaf?.let { CertFreeCertificateContext(it) }
                engine?.let { CertFreeCertificateChainEngine(it) }
                roots?.let { CertCloseStore(it, 0u) }
                CertCloseStore(store, 0u)
            }
        }
    }

    private fun memoryStore(): CPointer<*>? =
        CertOpenStore(CERT_STORE_PROV_MEMORY.toCPointer<ByteVar>(), 0u, 0uL, CERT_STORE_CREATE_NEW_FLAG.toUInt(), null)

    /** Adds [cert] to [store]; returns a new reference to the store's context, which the caller frees, or null if it does not parse. */
    private fun MemScope.add(
        store: CPointer<*>,
        cert: Certificate,
    ): CPointer<CERT_CONTEXT>? {
        val out = alloc<PCCERT_CONTEXTVar>()
        val ok =
            CertAddEncodedCertificateToStore(
                store,
                X509_ASN_ENCODING.toUInt(),
                cert.der.toUByteArray().toCValues(),
                cert.der.size.toUInt(),
                CERT_STORE_ADD_ALWAYS.toUInt(),
                out.ptr,
            )
        return if (ok == 0) null else out.value
    }

    private fun MemScope.exclusiveEngine(roots: CPointer<*>): CPointer<*>? {
        val config = alloc<CERT_CHAIN_ENGINE_CONFIG>()
        memset(config.ptr, 0, sizeOf<CERT_CHAIN_ENGINE_CONFIG>().toULong())
        config.cbSize = sizeOf<CERT_CHAIN_ENGINE_CONFIG>().toUInt()
        config.hExclusiveRoot = roots
        val engine = allocPointerTo<ByteVar>()
        if (CertCreateCertificateChainEngine(config.ptr, engine.ptr.reinterpret()) == 0) return null
        return engine.value
    }

    private fun MemScope.buildChain(
        engine: CPointer<*>?,
        leaf: CPointer<CERT_CONTEXT>?,
        store: CPointer<*>,
        role: TlsRole,
    ): CPointer<CERT_CHAIN_CONTEXT>? {
        check(sizeOf<_CERT_CHAIN_PARA>() == 32L) { "unexpected CERT_CHAIN_PARA layout" }
        val raw = allocArray<ByteVar>(CHAIN_PARA_FULL_SIZE)
        memset(raw, 0, CHAIN_PARA_FULL_SIZE.toULong())
        val para = raw.reinterpret<_CERT_CHAIN_PARA>().pointed
        para.cbSize = CHAIN_PARA_FULL_SIZE.toUInt()
        val oid = if (role == TlsRole.Client) szOID_PKIX_KP_SERVER_AUTH else szOID_PKIX_KP_CLIENT_AUTH
        val oids = allocArray<CPointerVar<ByteVar>>(1)
        oids[0] = oid.cstr.ptr
        para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND.toUInt()
        para.RequestedUsage.Usage.cUsageIdentifier = 1u
        para.RequestedUsage.Usage.rgpszUsageIdentifier = oids
        (raw + CHAIN_PARA_URL_TIMEOUT_OFFSET)!!.reinterpret<UIntVar>().pointed.value = URL_TIMEOUT_MS
        val flags =
            CERT_CHAIN_REVOCATION_CHECK_END_CERT or CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT or CERT_CHAIN_CACHE_END_CERT
        val out = alloc<PCCERT_CHAIN_CONTEXTVar>()
        if (CertGetCertificateChain(engine, leaf, null, store, para.ptr, flags.toUInt(), null, out.ptr) == 0) return null
        return out.value
    }

    private fun MemScope.policy(
        context: CPointer<CERT_CHAIN_CONTEXT>,
        host: HostName,
        role: TlsRole,
    ): CERT_CHAIN_POLICY_STATUS? {
        val ssl = alloc<HTTPSPolicyCallbackData>()
        memset(ssl.ptr, 0, sizeOf<HTTPSPolicyCallbackData>().toULong())
        ssl.cbStruct = sizeOf<HTTPSPolicyCallbackData>().toUInt()
        if (role == TlsRole.Client) {
            ssl.dwAuthType = AUTHTYPE_SERVER.toUInt()
            ssl.pwszServerName = host.value.wcstr.ptr
        } else {
            ssl.dwAuthType = AUTHTYPE_CLIENT.toUInt()
        }
        val para = alloc<CERT_CHAIN_POLICY_PARA>()
        memset(para.ptr, 0, sizeOf<CERT_CHAIN_POLICY_PARA>().toULong())
        para.cbSize = sizeOf<CERT_CHAIN_POLICY_PARA>().toUInt()
        para.dwFlags = CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS.toUInt()
        para.pvExtraPolicyPara = ssl.ptr
        val status = alloc<CERT_CHAIN_POLICY_STATUS>()
        memset(status.ptr, 0, sizeOf<CERT_CHAIN_POLICY_STATUS>().toULong())
        status.cbSize = sizeOf<CERT_CHAIN_POLICY_STATUS>().toUInt()
        if (CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL.toCPointer<ByteVar>(), context, para.ptr, status.ptr) == 0) return null
        return status
    }

    /** The first simple chain of [context], leaf first, anchor last. */
    private fun validatedChain(context: CPointer<CERT_CHAIN_CONTEXT>): List<Certificate> {
        val ctx = context.pointed
        if (ctx.cChain == 0u) return emptyList()
        val simple = ctx.rgpChain!![0]!!.pointed
        return (0 until simple.cElement.toInt()).mapNotNull { i ->
            val cert =
                simple.rgpElement!![i]
                    ?.pointed
                    ?.pCertContext
                    ?.pointed ?: return@mapNotNull null
            Certificate(cert.pbCertEncoded!!.readBytes(cert.cbCertEncoded.toInt()))
        }
    }

    /** Maps the policy error (an HRESULT) to a [VerifyReason]; unclassified failures are [VerifyReason.UnknownIssuer]. */
    private fun reasonOf(
        status: CERT_CHAIN_POLICY_STATUS,
        context: CPointer<CERT_CHAIN_CONTEXT>,
        presented: List<Certificate>,
        host: HostName,
    ): VerifyReason =
        when (status.dwError.toInt()) {
            CERT_E_CN_NO_MATCH -> VerifyReason.HostnameMismatch(host.value, presented[0].dnsNames)

            CERT_E_EXPIRED -> if (beforeNotBefore(context, status)) VerifyReason.NotYetValid else VerifyReason.Expired

            CRYPT_E_REVOKED, CERT_E_REVOKED -> VerifyReason.Revoked

            CRYPT_E_NO_REVOCATION_CHECK, CRYPT_E_REVOCATION_OFFLINE, CERT_E_REVOCATION_FAILURE -> VerifyReason.UnknownRevocationStatus

            CERT_E_WRONG_USAGE, CERT_E_PURPOSE -> VerifyReason.InvalidPurpose

            TRUST_E_CERT_SIGNATURE -> VerifyReason.BadSignature

            CERT_E_MALFORMED -> VerifyReason.BadEncoding

            // CERT_E_UNTRUSTEDROOT, CERT_E_CHAINING, CERT_E_UNTRUSTEDCA and anything unclassified: no path to a trusted anchor
            else -> VerifyReason.UnknownIssuer
        }

    /** True when the element the policy blamed (the leaf if it named none) is not valid yet rather than expired. */
    private fun beforeNotBefore(
        context: CPointer<CERT_CHAIN_CONTEXT>,
        status: CERT_CHAIN_POLICY_STATUS,
    ): Boolean {
        val ctx = context.pointed
        val chainIndex = status.lChainIndex.coerceAtLeast(0)
        if (chainIndex >= ctx.cChain.toInt()) return false
        val simple = ctx.rgpChain!![chainIndex]!!.pointed
        val elementIndex = status.lElementIndex.coerceAtLeast(0)
        if (elementIndex >= simple.cElement.toInt()) return false
        val info =
            simple.rgpElement!![elementIndex]
                ?.pointed
                ?.pCertContext
                ?.pointed
                ?.pCertInfo ?: return false
        return CertVerifyTimeValidity(null, info) < 0
    }
}
