<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0023. HTTPS proxies in the client engine: TLS to the proxy, HTTP/1.1 only, the proxy's own name and trust

Date: 2026-11-18. Status: accepted; implemented in 0.3.0 (experimental).

## Context

An `https://` proxy is one the client speaks TLS to before anything else: the CONNECT (or, for plain `http`, the
absolute-form request), its `Proxy-Authorization` and the name of the origin then cross the network only inside that
session, and for an `https` origin the origin's own TLS runs inside the tunnel (TLS in TLS). curl has it since 7.52
(`-x https://proxy`, with `--proxy-cacert`, `--proxy-pinnedpubkey`, `--proxy-insecure` and the like as separate
settings, and `--proxy-http2` since 8.1), Chrome through its proxy settings and PAC's `HTTPS host:port` entries. OkHttp
5.3 does not: its `OkHttpClient.Builder.socketFactory` refuses an `SSLSocketFactory`
(`OkHttpClient.kt:884`, `require(socketFactory !is SSLSocketFactory)`) and its `ConnectPlan.connectSocket` opens a plain
socket to an HTTP proxy. Before 0.3.0 the engine refused an `https://` proxy URL, a PAC `HTTPS` entry and `https_proxy`
values with that scheme with `UnsupportedOperationException`. It is item 7 of the 0.3.0 feature-parity plan.

The decision is about security as much as about features: the proxy hop is a man-in-the-middle position by design, the
credentials of an `http://` proxy cross it in clear (CWE-319), and a proxy's certificate checked against the wrong name
or the wrong trust (CWE-295) would hand the CONNECT, the credentials and the origin's name to whoever answers there
([threat model 3.28](../spec/threat-model.md#328-https-proxies-tls-to-the-proxy-cwe-295-cwe-319-cwe-522)).

## Decision

- **`ResolvedProxy.https(host, port, credentials)`**, its `tls` property, and the configuration paths that produce it:
  an `https://` proxy URL off the JVM (Ktor's `ProxyConfig` is a URL there; a `java.net.Proxy` has no scheme, so on the
  JVM a resolver names it), `https_proxy` and the other variables with an `https://` value (port 443 by default, as
  curl (despite its manual's 1080), Chrome and Go), a Windows Internet settings entry whose value starts with
  `https://` (as Chrome reads it; `https=host:port` stays the plain proxy of `https` URLs), and a PAC answer's
  `HTTPS host:port` (Chromium's extension of the grammar). CFNetwork's `kCFProxyTypeHTTPS` keeps its meaning, a plain
  proxy for `https` URLs.
- **The proxy is verified as a server of its own name.** SNI and the reference identifier are the proxy's host as
  configured, never an address the `dns` answered (RFC 9525 section 6.1; an IP literal is an IP-ID and goes without
  SNI, RFC 6066 section 3). The proxy's host goes through the engine's `dns`, as an `http://` proxy's does.
- **The proxy's trust is the origin's by default, without what names the origin**, and configurable separately with
  `proxyTls = { ... }`. A `TrustConfig.ExpectedName` replaces the origin's reference identifier: applied to the proxy hop
  it would accept the origin's certificate from whoever sits there, so it gives way to its base. A `TrustConfig.Pinned`
  lists the origin's keys, which the proxy does not hold, so it gives way to its base too (curl does not apply
  `--pinnedpubkey` to its proxy either; it has `--proxy-pinnedpubkey`, which here is `proxyTls = { trust = Pinned(...) }`).
  The CA set, the platform store, a custom verifier and TOFU stay. The `tls` block applies to the proxy as well when
  `proxyTls` is null (TLS versions, groups), and the client certificate (`identity`) does not: it identifies the client
  to the origin and is not shown to an intermediary unless `proxyTls` sets one.
- **HTTP/1.1 to the proxy, one tunnel per TLS connection**: ALPN offers `http/1.1` alone. CONNECT over HTTP/2 (RFC 9113
  section 8.5) would carry several tunnels on one TLS connection to the proxy and so save handshakes, as Chrome does and
  curl offers behind `--proxy-http2`. It is not offered: a client MAY use it, no RFC asks for it; curl's default and
  OkHttp's (no HTTPS proxies at all) are HTTP/1.1; and it would put every tunnel of a route on one HTTP/2 connection
  with its own flow control and failure modes under the origin's own TLS and HTTP/2, a second multiplexing layer the
  pool, the timeouts and the tests would all have to cover for a gain in handshakes only. A server that picks no ALPN is
  accepted (RFC 7301 section 3.1: the protocol is then the one both know, HTTP/1.1).
- **Inside the proxy's TLS everything is as with an `http://` proxy**: the CONNECT for `https` and WebSockets (with the
  configured or the request's own `Proxy-Authorization`), the absolute form for plain `http`, the 2xx-only tunnel, the
  64 KiB head limit, a 407 that fails the request with `ProxyException` after one CONNECT (never a loop of retries), the
  origin's TLS inside the tunnel with its own SNI, verification, pins and ALPN (`h2` included). The TLS socket to the
  proxy stands where the TCP socket stood, so closing, aborting and the orderly close (close_notify inside, then to the
  proxy) end both layers.
- **Errors say which hop failed.** A failed handshake with the proxy (a certificate that does not verify, an alert, a
  proxy that closes during it) is `ProxyTlsException`, a `ProxyException` whose `cause` is the TLS layer's error; a
  failure of the origin's TLS inside the tunnel stays the origin's `TlsException`. `ProxyException` became `open` and
  takes a `cause` for it.
- **Pooling:** the route key holds the proxy's scheme, so an `https://` and an `http://` proxy at the same host and port
  are two routes and never share a connection.
- **HTTP/3:** none through the proxy, as before: CONNECT runs over TCP and cannot carry QUIC. `ResolvedProxy.carriesHttp3`
  (internal, always false) is the one place the engine asks, for CONNECT-UDP (RFC 9298) later; until an HTTP/3 path
  through such a proxy exists, a proxy that claimed it fails the request rather than being gone around. `H3Only` with a
  proxy fails without contacting it, and `Alt-Svc` and HTTPS records are neither used nor learned through it.

## Consequences

- On the JVM and Android an HTTP `java.net.Proxy` on port 443 as the explicit `proxy` is refused (amended 2026-11-18):
  it has no scheme, `ProxyBuilder.http(Url("https://proxy"))` produces exactly that, and plain HTTP to it would send the
  CONNECT and the credentials in clear. The stricter rule (refused with or without `proxyCredentials`) is kept: without
  credentials the origin's name and the CONNECT still leak, a plain proxy on 443 is rare, and it stays reachable through
  `proxyResolver { ResolvedProxy.http(host, 443) }`; the exception says both ways.
- The proxies' TLS session tickets live in a cache of their own per engine (amended 2026-11-18), never the origins'.
- The credentials of an `https://` proxy never cross the network in clear; those of an `http://` proxy still do, as with
  curl, Go and OkHttp, and the guide and the threat model say so.
- A new connection to the proxy resumes a session of an earlier one from that proxy cache (TLS 1.3 tickets); the origin's
  sessions inside the tunnel resume from the origins' cache as before.
- On the JVM an explicit `ProxyBuilder.http(Url("https://..."))` cannot be told from a plain proxy (Ktor's
  `ProxyConfig` is a `java.net.Proxy` without a scheme); on port 443, where that URL lands, it is refused (above), and an
  `https://` proxy there comes from a resolver. What `ProxySelector.getDefault()` answers on the JVM and Android is a `java.net.Proxy` too, so
  `ProxyResolvers.System` there never yields an `https://` proxy.
- HTTP/2 to the proxy can be added later behind an option without changing this API.
- The QUIC hop to a CONNECT-UDP proxy (`connectUdpProxy`, RFC 9298) follows this decision too (amended 2026-11-20):
  its TLS configuration is the proxy's (`proxyTlsConfigFor`), with the proxy's host as SNI and reference identifier,
  `proxyTls` or the origin's trust without its `ExpectedName` and pins, no client certificate unless `proxyTls` sets one,
  and ALPN `h3` instead of `http/1.1`; a failed handshake with it is `ProxyTlsException`, and its connections leave from
  endpoints of their own whose session cache is the proxies'. It resumes no session (a full handshake each time:
  `Http3Endpoint.connect` takes and stores no ticket), where the TCP hop resumes from its cache; its own endpoints keep
  the separation should it resume one day. The race over the proxy's addresses reports a `ProxyTlsException` from one
  address before a later address's timeout or refusal, until an address of the proxy completed its handshake (from
  then on the CONNECT may have gone out, and a timeout is the timeout). A `proxyTls` that allows TLS 1.2 only cannot reach a CONNECT-UDP
  proxy (QUIC is TLS 1.3, RFC 9001 section 4.2). With ECH (ADR-0019), a configuration `proxyTls` gives the proxy hop is
  offered as given, and a rejection there fails the request with the proxy's retry configurations unused (no retry of
  RFC 9849 section 6.1.6 on the proxy hop, over TCP or QUIC). Before, never released, it took the origin's
  configuration, client certificate included (threat model 3.29). The origin's connection inside the tunnel keeps the
  origin's configuration.
