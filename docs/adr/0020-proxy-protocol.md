<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0020. The PROXY protocol on the server's TCP connectors: trusted sources only, the header first, origin not local

Date: 2026-11-18. Status: accepted; implemented in 0.3.0 (experimental).

## Context

Behind an L4 load balancer or a TCP proxy (HAProxy, AWS NLB, GCP and Azure load balancers, Envoy, nginx `stream`) the
server's TCP peer is the proxy, and the client's address is lost unless the proxy prepends a PROXY protocol header
(HAProxy, "The PROXY protocol", versions 1 and 2) to the connection. nghttpx, nginx, HAProxy, Envoy and Go servers take
it; it is item 5 of the 0.3.0 feature-parity plan. The header carries an address the application then trusts for logs,
rate limits and access rules, so who may send it, and what happens otherwise, is a security decision
([threat model 3.25](../spec/threat-model.md#325-proxy-protocol-client-addresses-from-a-proxy-haproxy-the-proxy-protocol-v1v2-cwe-290-cwe-348)).

## Decision

- **Opt-in per TCP connector** (`proxyProtocol { }` on `plainConnector { }` and `tlsConnector(identity) { }`,
  `kuicksilver.proxyProtocol.*` for `EngineMain`'s deployment port), experimental. Both versions are accepted on the
  same port, told apart by the first byte (the spec's section 2.3).
- **A list of trusted sources is required, and a peer outside it is refused at accept**, before a byte is read: not
  served as if the protocol were off. The spec says the receiver "MUST not try to guess whether the protocol header is
  present or not. This means that the protocol explicitly prevents port sharing between public and private access", and
  "SHOULD ensure proper access filtering so that only trusted proxies are allowed to use this protocol". Serving
  untrusted peers without a header would share the port between public and private access, and would make a
  misconfiguration silent: a proxy left out of the list would have its header parsed as an HTTP request line (or a TLS
  record) and its clients served with the proxy's address, or refused with 400, instead of a refusal that names the
  cause (`connectionRefused`, `PROXY protocol untrusted source`, a rate-limited warning). An IPv4 peer that a dual-stack
  listener reports as `::ffff:a.b.c.d` is matched as IPv4; an IPv4-mapped block of prefix 96 or more is the IPv4 block.
- **The header is mandatory and first** on such a connector, before TLS on a TLS connector; anything else (no header, a
  malformed one, one over `maxHeaderSize` or 107 bytes for version 1, one not complete within `headerTimeout`) resets
  the connection, as the spec asks ("abort the connection"). The header is read from the socket's read channel, which
  then goes on to TLS or HTTP/1.1, so bytes sent with it are not lost.
- **The client goes to `call.request.origin`, not to `call.request.local`.** `local` keeps describing the TCP connection
  (its peer is the proxy) for logs and for whoever needs the real hop, and `origin` is where Ktor already puts a client
  that a forwarding plugin (`XForwardedHeaders`, `ForwardedHeaders`) found; those plugins then start from the PROXY
  client. The header itself is `call.request.proxyHeader` (TLVs, LOCAL, UNIX paths). LOCAL, UNSPEC, `UNKNOWN` and UNIX
  headers leave the origin as the connection's (no client IP address to report).
- **Per-client defences follow the header where they can.** `http2RepeatOffenderPenalty` strikes and refuses the client
  the header names: struck by the proxy's address, one flooder would shut every client of the proxy out.
  `maxTcpConnectionsPerIp` stays per TCP peer: it bounds descriptors at accept, before any byte (and so any header) is
  read, and on such a connector counts the proxy.
- **TCP only.** HTTP/3 on a TLS connector's UDP port takes no header (the protocol defines none in front of a QUIC
  packet; proxies that forward QUIC do not add one). Its requests report their UDP peer; behind an L4 proxy that does not
  forward UDP, `altSvc = false` keeps clients from trying HTTP/3.

## Consequences

- A deployment must list its proxies' addresses; a change of proxy address without a change of the list refuses
  connections loudly instead of serving wrong addresses quietly.
- Health checks from the proxy must send a header too (HAProxy sends LOCAL for its own checks with `send-proxy-v2`).
- The details and the peers' choices are in [spec-haproxy-proxy-protocol.md](../spec/rfc/spec-haproxy-proxy-protocol.md).
