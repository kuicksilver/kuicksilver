<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0022. The PROXY protocol on the server's TCP connectors: trusted sources only, the header first, origin not local

Date: 2026-11-18. Status: accepted; implemented in 0.3.0 (experimental).

## Context

Behind an L4 load balancer or a TCP proxy (HAProxy, AWS NLB, GCP and Azure load balancers, Envoy, nginx `stream`) the
server's TCP peer is the proxy, and the client's address is lost unless the proxy prepends a PROXY protocol header
(HAProxy, "The PROXY protocol", versions 1 and 2) to the connection. nghttpx, nginx, HAProxy, Envoy and Go servers take
it; it is item 5 of the 0.3.0 feature-parity plan. The header carries an address the application then trusts for logs,
rate limits and access rules, so who may send it, and what happens otherwise, is a security decision
([threat model 3.27](../spec/threat-model.md#327-proxy-protocol-client-addresses-from-a-proxy-haproxy-the-proxy-protocol-v1v2-cwe-290-cwe-348)).

## Decision

- **Opt-in per TCP connector** (`proxyProtocol { }` on `plainConnector { }` and `tlsConnector(identity) { }`,
  `kuicksilver.proxyProtocol.*` for `EngineMain`'s deployment port), experimental. Both versions are accepted on the
  same port, told apart by their first bytes (section 2.2: "A receiver may be configured to support both version 1 and
  version 2 of the protocol. Identifying the protocol version is easy :").
- **A list of trusted sources is required, and a peer outside it is refused at accept**, before a byte is read: not
  served as if the protocol were off. Section 2: "The receiver MUST be configured to only receive the protocol described
  in this specification and MUST not try to guess whether the protocol header is present or not. This means that the
  protocol explicitly prevents port sharing between public and private access." and "The receiver SHOULD ensure proper
  access filtering so that only trusted proxies are allowed to use this protocol."; section 5: "accepting the header only
  from a number of known sources should be safe". Serving
  untrusted peers without a header would share the port between public and private access, and would make a
  misconfiguration silent: a proxy left out of the list would have its header parsed as an HTTP request line (or a TLS
  record) and its clients served with the proxy's address, or refused with 400, instead of a refusal that names the
  cause (`connectionRefused`, `PROXY protocol untrusted source`, a rate-limited warning). An IPv4 peer that a dual-stack
  listener reports as `::ffff:a.b.c.d` is matched as IPv4; an IPv4-mapped block of prefix 96 or more is the IPv4 block.
  A deployment that filters with a firewall alone lists `0.0.0.0/0` and `::/0`, and every peer must then send a header.
- **The header is mandatory and first** on such a connector, before TLS on a TLS connector; anything else (no header, a
  malformed one, one over `maxHeaderSize` or 107 bytes for version 1, one not complete within `headerTimeout`, at least
  3 s) resets the connection (section 2.1: "Any sequence which does not exactly match the protocol must be discarded and
  cause the receiver to abort the connection."). A LOCAL header (a health check) is accepted with any length and any
  valid family, as section 2.2 requires. The header is read from the socket's read channel, which
  then goes on to TLS or HTTP/1.1, so bytes sent with it are not lost.
- **The client goes to `call.request.origin`, not to `call.request.local`.** `local` keeps describing the TCP connection
  (its peer is the proxy) for logs and for whoever needs the real hop, and `origin` is where Ktor already puts a client
  that a forwarding plugin (`XForwardedHeaders`, `ForwardedHeaders`) found. Those plugins overwrite the origin whenever
  their header fields are present, and behind an L4 proxy those fields come from the client: install them only when an
  HTTP proxy in front of the server sets or strips them. The header itself is `call.request.proxyHeader` (TLVs, LOCAL, UNIX paths). LOCAL, UNSPEC, `UNKNOWN` and UNIX
  headers leave the origin as the connection's (no client IP address to report).
- **Per-client defences follow the header where they can.** `http2RepeatOffenderPenalty` strikes and refuses the client
  the header names, and on such a connector never the TCP peer: struck by the proxy's address (a flood behind a LOCAL or
  `UNKNOWN` header, which names no client), one flooder would shut every client of the proxy out. Nobody is struck then,
  and the accept-time check of the peer's address is skipped.
  `maxTcpConnectionsPerIp` stays per TCP peer: it bounds descriptors at accept, before any byte (and so any header) is
  read, and on such a connector counts the proxy.
- **TCP only.** HTTP/3 on a TLS connector's UDP port takes no header (the protocol defines none in front of a QUIC
  packet; proxies that forward QUIC do not add one). Its requests report their UDP peer; set `altSvc = false` unless the
  proxy forwards UDP on the same port number, so clients do not try HTTP/3 where nothing answers.

## Consequences

- A deployment must list its proxies' addresses; a change of proxy address without a change of the list refuses
  connections loudly instead of serving wrong addresses quietly.
- Health checks from the proxy must send a header too (HAProxy sends LOCAL for its own checks with `send-proxy-v2`).
- The details and the peers' choices are in [spec-haproxy-proxy-protocol.md](../spec/rfc/spec-haproxy-proxy-protocol.md).
