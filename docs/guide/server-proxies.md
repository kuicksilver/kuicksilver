<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Behind a proxy or load balancer

**What this page is for.** What the server engine does about requests for host names its certificate does not
name (`421 Misdirected Request`), and how it reads the client's address from the PROXY protocol of an L4 load balancer.

**Before you start**

- Load balancers, Kubernetes, QUIC connection IDs and UDP behind them: [Deploying the HTTP/3 server](deployment.md).
- The imports of the code blocks: [Ktor engines: Imports](ktor.md#imports).

## Misdirected requests

A TLS connector answers `421 Misdirected Request` to a request whose host the certificate of its connection does not
name (whatever scheme the request names: the application would see it as https), over HTTP/1.1, HTTP/2 and HTTP/3. The
engine answers it itself: neither routing nor plugins such as StatusPages or CallLogging see that request (RFC 9110
section 7.4: such a request "MUST be rejected"). Browsers send these: they reuse an HTTP/2 or HTTP/3 connection for another host at
the same address, and a 421 makes them retry on a connection of its own. On HTTP/2 and HTTP/3 only that request's stream
ends; the connection serves the others.

The host is checked as a client checks it: against the subjectAltName of the certificate that connection presented (the
`sniSelector`'s choice, or the identity current at its handshake when a `TlsIdentity.Reloadable` rotates), a wildcard
`*.example.com` for one whole left-most label, an IP literal against the certificate's IP addresses, never the subject CN.
The port is not checked: a certificate names none. On a connector with an `sniSelector`, which may give each name its own
certificate, client-certificate requirement and trust, a request must also be for the name the connection was set up for
(its SNI name, or an IP address when the client sent no SNI), so a request cannot reach a name that requires a client
certificate over a connection that asked for none. So a certificate must name every host the server is reached under,
`localhost` and the addresses included where clients use them.

Behind a gateway that terminates TLS and forwards requests for names the certificate here does not carry (it re-encrypts
with an internal certificate), turn the check off for that connector only. RFC 9110 allows it for connections "from a
trusted gateway", so the connector must accept no other clients:

```kotlin
// guide:ktor:trusted-gateway
tlsConnector {
    tls { identity = internalIdentity }
    port = 8443
    allowMisdirectedHosts = true // every client of this port is the gateway
}
```

A plain connector has no certificate at all, so a request whose target is an absolute `https://` URI
(`GET https://example.com/ HTTP/1.1`) gets 421 there too. Origin-form requests (`GET / HTTP/1.1` with any `Host`), which
a gateway in front of the server sends, are served as before. A gateway that forwards absolute `https` targets to a plain
port needs `plainConnector { allowMisdirectedHosts = true }` (delicate) instead of Ktor's `connector { }`.

## PROXY protocol

Behind an L4 load balancer or a TCP proxy (HAProxy, AWS NLB, Envoy, nginx `stream`) the server's TCP peer is the proxy.
A proxy that speaks the PROXY protocol (HAProxy's, versions 1 and 2) sends the client's address first on each
connection, and a connector with `proxyProtocol { }` reports that client as `call.request.origin`:

```kotlin
// guide:ktor:proxy-protocol
plainConnector {
    port = 8080
    proxyProtocol {
        trust("10.0.0.0/8", "2001:db8:1::/48") // the load balancers' addresses
    }
}
```

```kotlin
// guide:ktor:proxy-protocol-origin
get("/") {
    val client = call.request.origin.remoteAddress // the client the header names
    val proxy = call.request.local.remoteAddress // the TCP peer: the load balancer
    val sni = call.request.proxyHeader?.authority // a TLV, when the proxy sends one
    call.respondText("$client via $proxy for $sni")
}
```

`tlsConnector { proxyProtocol { … } }` takes the header before the TLS handshake (HAProxy `send-proxy-v2`
on a TCP-mode backend). The rules ([ADR-0022](../adr/0022-proxy-protocol.md), the details in
[spec-haproxy-proxy-protocol.md](../spec/rfc/spec-haproxy-proxy-protocol.md)):

- Only the sources given to `trust(…)` may send the header, and every connection to the connector must come from one of them: any
  other peer is closed at accept, before a byte is read (an event `connectionRefused` with the reason
  `PROXY protocol untrusted source`, and a warning at most every 10 s). A client that reaches the port around the proxy
  can therefore not choose its own address. List the proxies' own addresses, as the server sees them; an IPv4 proxy
  matches an IPv4 entry also on a dual-stack listener. Where a firewall alone decides who reaches the port, list
  `0.0.0.0/0` and `::/0`: every peer must then send a header.
- Every connection must start with a valid version 1 or 2 header, complete within `headerTimeout` (5 s, at least 3 s, the
  spec's bound for a TCP retransmit; `requestHeaderTimeout` must then be at least 3 s too, or the start fails); otherwise it is reset (reason `PROXY protocol header`). Health checks of the proxy
  must send one too (HAProxy sends LOCAL with `send-proxy-v2`); a LOCAL header, whatever family and length it carries, or
  an `UNKNOWN` one leaves the origin as the connection's.
- `call.request.local` stays the TCP connection, for logs that need the real hop. `XForwardedHeaders` and
  `ForwardedHeaders` overwrite the origin whenever their fields are present, and behind an L4 proxy those fields come
  from the client: install them only when an HTTP proxy in front of the server sets or strips them. `call.request.proxyHeader` gives the whole header:
  version, command, family, both addresses and ports, and the version 2 TLVs (`alpn`, `authority`, `uniqueId`, `ssl`,
  `netns`, any other by type); a CRC32c TLV is verified before the connection is served.
- `http2 { repeatOffenderPenalty }` counts the client the header names and never the proxy (a flood behind a header that
  names no client strikes nobody); `tcp { maxConnectionsPerIp }` counts TCP peers, so on such a connector it limits each proxy's
  connections: leave it off there, or size it for a proxy.
- HTTP/3 on a TLS connector's port takes no header (UDP): its requests report their UDP peer. Set `http3 { altSvc = false }`
  unless the proxy forwards UDP on the same port number.
- `EngineMain`: `kuicksilver.connector.proxyProtocol.trustedSources` (a list or a comma-separated string),
  `kuicksilver.connector.proxyProtocol.headerTimeout` and `kuicksilver.connector.proxyProtocol.maxHeaderSize` turn it on
  for the deployment port; next to Ktor's `-sslPort` connector the start fails.
