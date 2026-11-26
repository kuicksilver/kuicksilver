<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Glossary

**What this page is for.** The words the guides use for HTTP/3, QUIC and Kuicksilver's own parts, each in a few lines,
with the page that explains it in full. Read it when a guide uses a word before it explains it.

| Word | Meaning |
|---|---|
| **origin** | The scheme, host and port of a URL (`https://api.example.com:443`): what a client's connections, `Alt-Svc` entries and trust decisions belong to (RFC 9110 section 4.3.1). |
| **alternative** | Another place where an origin is served: for HTTP/3, the UDP port (and possibly another host) a server names in an `Alt-Svc` header field or an HTTPS DNS record. The client connects there, still checking the origin's certificate ([Discovery and Alt-Svc](client-http3.md#discovery-and-alt-svc)). |
| **Alt-Svc** | The response header field (RFC 7838) by which a server announces an alternative: `alt-svc: h3=":443"; ma=86400` says "HTTP/3 on UDP port 443 of this host, for a day". |
| **route** | What the client's TCP connection pool groups connections by: scheme, host, port and proxy ([Connection pool](client.md#connection-pool)). |
| **race**, **head start** | Once an origin has an HTTP/3 alternative, the client sets up QUIC and, after a short head start, TCP as well, and the request goes over whichever is ready first ([Racing and fallback](client-http3.md#racing-and-fallback)). |
| **broken alternative** | An alternative whose HTTP/3 failed while TCP worked: the client skips it for a while (5 minutes, doubling up to 2 days) and forgets the mark on a network change. |
| **fallback** | A request that HTTP/3 could have served going over TCP (HTTP/2 or HTTP/1.1) instead; `FallbackReason` says why ([troubleshooting](troubleshooting.md#the-ktor-client-never-uses-http3-or-stops-using-it)). |
| **ALPN** | The TLS extension by which client and server agree on the protocol: `h3` over QUIC, `h2` or `http/1.1` over TCP. |
| **0-RTT** | Sending the first requests with the first packets of a resumed connection, one round trip earlier, at the price of possible replay ([0-RTT](zero-rtt.md)). |
| **connection migration** | A QUIC connection that moves to another network path (Wi-Fi to mobile data) without starting over ([Connection migration](client-http3.md#connection-migration)). |
| **SPKI**, **pin** | The SubjectPublicKeyInfo, the public key of a certificate; a pin is its SHA-256 as `sha256/<base64>` ([Certificate pinning](engine-tls.md#certificate-pinning)). |
| **ksl** | Kuicksilver's C library around OpenSSL, shipped inside the `kuicksilver-native` artifact (the JNI library on the JVM and Android, linked in on Kotlin/Native): TLS, QUIC crypto and the accelerated UDP socket. |
| **accelerated socket**, **portable socket** | The two UDP sockets QUIC can run on. The accelerated one is `ksl`'s (batched sends, GSO and GRO on Linux, ECN, Don't Fragment); the portable one is the platform's (NIO on the JVM), used where `ksl` cannot open its socket ([QUIC: Binding an endpoint](quic.md#binding-an-endpoint-and-connecting)). |
| **loop** | One endpoint loop: a coroutine that owns a UDP socket and the QUIC connections on it. `http3 { endpoint { loops } }` runs several on one port ([QUIC: Several loops on one port](quic.md#several-loops-on-one-port)). |
| **Initial**, **Retry** | A client's first QUIC packets are Initial packets; a server under load may answer one with a Retry packet, which makes the client prove its address with a token before the server keeps any state for it ([QUIC: Admission and endpoint limits](quic.md#admission-and-endpoint-limits)). |
| **4-tuple** | Source address and port, destination address and port of a packet: what a NAT or a load balancer usually keys a flow on. QUIC keys connections on connection IDs instead, so a connection survives a change of 4-tuple. |
| **connection ID** | The identifier QUIC packets carry for their connection, chosen by each side; a load balancer can route by it ([Behind a proxy or load balancer](server-proxies.md)). |
| **QUIC-LB** | A scheme (an IETF draft) by which a server encodes its identity in its connection IDs, so a load balancer routes every packet of a connection to the same server ([QUIC: Behind a load balancer](quic.md#behind-a-load-balancer)). |
| **PROXY protocol** | A header an L4 load balancer puts in front of a TCP connection to tell the server the client's real address ([PROXY protocol](server-proxies.md#proxy-protocol)). |
