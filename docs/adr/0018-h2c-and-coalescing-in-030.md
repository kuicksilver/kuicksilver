# ADR-0018. h2c (opt-in) and connection coalescing across origins in 0.3.0

Date: 2026-11-16. Status: accepted (owner decision 2026-11-16, recorded 2026-11-18); not implemented yet. Supersedes in
part [ADR-0017](0017-http2.md): its decision "No h2c" and its decision "No connection coalescing (RFC 9113 section 9.1.1)
in 0.3.0". Everything else in ADR-0017 stands.

## Context

ADR-0017 brought HTTP/2 into 0.3.0 over TLS only, without h2c and without reusing a connection for another origin. On
2026-11-16 the owner widened the 0.3.0 scope to what the established stacks in other languages already do (quic-go,
quiche, OkHttp, Netty, Cronet; [roadmap](../roadmap.md#feature-parity-decided-2026-11-16)). Two of the gaps are in
ADR-0017's own decisions:

- **h2c.** HTTP/2 over cleartext TCP with prior knowledge (RFC 9113 section 3.3) is how HTTP/2 runs behind a
  TLS-terminating proxy or load balancer, inside a service mesh whose sidecar does the TLS, and how most gRPC
  deployments talk between services. Without it, such a deployment falls back to HTTP/1.1 between the proxy and the
  server. Go (`golang.org/x/net/http2/h2c`), Netty and OkHttp (`Protocol.H2_PRIOR_KNOWLEDGE`) offer it.
- **Coalescing.** A client that has an HTTP/2 or HTTP/3 connection to a server whose certificate also covers another
  origin may send that origin's requests on it (RFC 9113 section 9.1.1, RFC 9114 section 3.3). Browsers, OkHttp and
  Cronet do, and it saves a handshake and a congestion window per origin behind one CDN or one wildcard certificate.
  The server side is already in place: a request for a host the connection's certificate does not name gets 421
  ([RFC 9110 §7.4](../spec/rfc/9110.md#s7-4-server-misdirected-requests)).

## Decision

- **h2c with prior knowledge, opt-in on both engines.** A client sends HTTP/2 without TLS only to an `http://` route the
  application has marked for prior knowledge; every other `http://` request stays HTTP/1.1. A server speaks h2c only on a
  plain connector the configuration enables it for, and then recognises the client preface (`PRI * HTTP/2.0`) on that
  connector; without the setting the preface keeps its current answer (505). `Upgrade: h2c` is not implemented (RFC 9113
  section 3.1 deprecates it). An `https://` request never uses h2c, and a failed TLS handshake never falls back to it.
- **Every HTTP/2 limit applies to h2c unchanged**: the flood defences, the field section limits and the connection
  limits of ADR-0017 do not depend on TLS.
- **Coalescing for HTTP/2 and HTTP/3** on the client: a request for origin B may use an open connection to origin A
  when the connection's certificate is valid for B's host under B's trust configuration (the name check, and B's pins
  where B has pins, ADR-0011) and B's host resolves to the address the connection is connected to. A 421 answer to a
  coalesced request is retried once on a connection of B's own, as RFC 9110 section 15.5.20 allows. Connections through
  a proxy, and connections whose trust configuration differs from B's, are never shared.
- **No ORIGIN frame** (RFC 8336) in 0.3.0; it is on the list for after 1.0.

## Consequences

- h2c is cleartext. It is safe only where the network between the two ends is trusted or protected by other means (a
  sidecar's mTLS, a private network); the guide and the threat model say so, and the opt-in is per route and per
  connector so that nothing becomes cleartext by default. The guide will say so, and the threat model will gain the h2c cases (a cleartext peer that is
  not the one meant, request smuggling between an HTTP/1.1 front and an h2c back end).
- Coalescing makes one connection carry several origins, so a certificate or trust mistake affects all of them: the
  conditions above are checked per request, and every coalescing decision has a `negative_*` test (a certificate that
  does not cover B, B's pin not matching, another address, a proxy, a different trust configuration).
- The RFC rows [RFC 9113 §3.1, §3.3](../spec/rfc/9113.md#s3-1-h2c) and
  [RFC 9113 §9.1.1](../spec/rfc/9113.md#s9-1-1-connection-reuse) are planned for 0.3.0 and turn ✅ when the work lands.
- More configuration surface: one client setting (routes with prior knowledge), one server setting (h2c on a plain
  connector), and a client setting for coalescing; whether coalescing is on by default is decided when the work starts.

## Alternatives rejected

- **Keep ADR-0017's "no h2c".** Rejected: deployments behind TLS-terminating proxies and gRPC users would stay on
  HTTP/1.1 between proxy and server, which the peers do not ask of them.
- **`Upgrade: h2c` from HTTP/1.1.** Deprecated by RFC 9113 section 3.1 and rarely deployed; prior knowledge covers the
  use cases above.
- **Coalescing on the certificate alone, without the address check.** It would let a DNS answer the client never got
  decide where B's requests go; RFC 9113 section 9.1.1 asks for both, and doing the same for HTTP/3 keeps one rule.
- **The ORIGIN frame now.** Few servers send it; it can be added later without changing the rule above.
