// Copyright 2014-2021 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Vendored from Ktor 3.6.0 ktor-server-cio CIOApplicationCall.kt (internal there), adapted: TLS scheme, peer certificates.
package io.kuicksilver.ktor.server.h1

import io.ktor.http.cio.Request
import io.ktor.server.application.Application
import io.ktor.server.engine.BaseApplicationCall
import io.ktor.util.network.NetworkAddress
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.kuicksilver.ktor.server.PeerCertificatesKey
import io.kuicksilver.tls.Certificate
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlin.coroutines.CoroutineContext

/** One HTTP/1.1 exchange on a (TLS) TCP connection; [altSvc] is added to responses that do not set their own. */
internal class H1Call(
    application: Application,
    _request: Request,
    input: ByteReadChannel,
    output: ByteWriteChannel,
    engineDispatcher: CoroutineContext,
    appDispatcher: CoroutineContext,
    upgraded: CompletableDeferred<Boolean>?,
    remoteAddress: NetworkAddress?,
    localAddress: NetworkAddress?,
    override val coroutineContext: CoroutineContext,
    scheme: String,
    peerCertificates: List<Certificate>,
    altSvc: String?,
) : BaseApplicationCall(application),
    CoroutineScope {
    override val request = H1Request(this, remoteAddress, localAddress, input, _request, scheme)

    override val response = H1Response(this, output, input, engineDispatcher, appDispatcher, upgraded, altSvc)

    internal fun release() {
        request.release()
    }

    init {
        putResponseAttribute()
        attributes.put(PeerCertificatesKey, peerCertificates)
        // a gateway forwarded it from early data (RFC 8470 section 5.1)
        if (_request.headers[io.kuicksilver.ktor.server.EARLY_DATA_FIELD] != null) {
            attributes.put(io.kuicksilver.ktor.server.ReceivedEarlyKey, true)
        }
    }
}
