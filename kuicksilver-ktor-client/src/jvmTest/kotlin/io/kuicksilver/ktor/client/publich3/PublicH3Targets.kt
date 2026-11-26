// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.publich3

/** The checks of the public HTTP/3 run, in the order of the summary table's columns. */
internal enum class Check(
    val label: String,
) {
    /** `H3Only` GET: HTTP/3 served it, ALPN h3, a QUIC version we offered (and, on Cloudflare, the server saw HTTP/3). */
    Http3("HTTP/3"),

    /** `Auto` from nothing: the first GET over TCP (HTTP/2) carries `Alt-Svc: h3`, a later one goes over HTTP/3 because of it. */
    AltSvc("Alt-Svc"),

    /** `earlyData = true`: a new connection resumes with 0-RTT and the server accepts the early data. */
    ZeroRtt("0-RTT"),

    /** The connection moves to a new local socket (a new port, same interface) and the next request goes on it. */
    Migration("Migration"),

    /** Encrypted Client Hello with the configuration of the target's HTTPS record, over HTTP/3 (where the target publishes one). */
    Ech("ECH"),
}

/**
 * A public HTTP/3 deployment. Each one runs a different QUIC implementation, so a regression that only one stack notices
 * shows; all of them are large, long-lived deployments that announce `h3` in `Alt-Svc` (checked 2026-11-25).
 *
 * @property name the summary's row name.
 * @property host the origin; [path] is fetched (no redirect is followed: any status is an answer).
 * @property stack the server's QUIC implementation, as its operator documents it.
 * @property cloudflareTrace the host serves Cloudflare's `/cdn-cgi/trace`, which reports what the server saw (`http=http/3`,
 *   `sni=encrypted`): the server-side confirmation of the client's diagnostics.
 * @property ech the host's HTTPS record carries an `ech` parameter (RFC 9848) and `h3` in its `alpn`.
 */
internal data class Target(
    val name: String,
    val host: String,
    val path: String = "/",
    val stack: String,
    val cloudflareTrace: Boolean = false,
    val ech: Boolean = false,
) {
    val url: String get() = "https://$host$path"
}

/**
 * The targets (docs/how-we-verify.md, "Public HTTP/3 servers", says why each). Left out: Akamai (`www.akamai.com` answers
 * scripted clients with a bot wall over TCP, and its QUIC stack derives from Google's, already covered), and test servers
 * run by one person (they come and go).
 */
internal val TARGETS =
    listOf(
        Target("Cloudflare", "cloudflare-quic.com", stack = "Cloudflare quiche", cloudflareTrace = true, ech = true),
        Target("Google", "www.google.com", stack = "Google QUICHE"),
        Target("Meta", "www.facebook.com", stack = "mvfst"),
        Target("Fastly", "www.fastly.com", stack = "quicly (H2O)"),
        Target("LiteSpeed", "www.litespeedtech.com", stack = "LSQUIC"),
        Target("nginx", "quic.nginx.org", stack = "nginx QUIC"),
    )
