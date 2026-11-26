# ADR-0018. h2c (opt-in) and connection coalescing across origins (opt-in) in 0.3.0

Date: 2026-11-16. Status: accepted (owner decision 2026-11-16, recorded 2026-11-18; coalescing off by default, owner
decision 2026-11-18); h2c implemented 2026-11-18 (see "Implementation: h2c" below), coalescing implemented 2026-11-26
(see "Implementation: coalescing" below). Supersedes in
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
- **Coalescing for HTTP/2 and HTTP/3** on the client, **off by default and opt-in** (owner decision 2026-11-18): with it
  turned on, a request for origin B may use an open connection to origin A
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
  does not cover B, B's pin not matching, another address, a proxy, a different trust configuration, and a client that
  has not turned coalescing on).
- The RFC rows [RFC 9113 §3.1, §3.3](../spec/rfc/9113.md#s3-1-h2c) and
  [RFC 9113 §9.1.1](../spec/rfc/9113.md#s9-1-1-connection-reuse) were planned for 0.3.0 and are ✅ since the work landed.
- More configuration surface: one client setting (routes with prior knowledge), one server setting (h2c on a plain
  connector), and a client setting that turns coalescing on. Off by default, a client behaves as before (each origin
  gets its own connections) unless the application asks for it: an application that does not know about coalescing is
  not exposed to its trust coupling, and one that wants the saved handshakes opts in. The peers that coalesce by
  default (browsers, OkHttp) differ here on purpose.

## Implementation: h2c (2026-11-18)

The decisions the ADR left to the implementation, with the peers they were weighed against
([RFC 9113 §3.1, §3.3](../spec/rfc/9113.md#s3-1-h2c)):

- **Client: a list of origins, no loopback rule.** `http2 { priorKnowledge: Set<HostPort> }` names the `http://`
  origins; OkHttp's `Protocol.H2_PRIOR_KNOWLEDGE` turns a whole client to h2c (and fails `https` URLs), grpc-go asks for
  `insecure.NewCredentials()` per channel. None of them restricts cleartext to loopback, and neither do we: a sidecar or
  a private network is the use case, and the explicit per-origin entry is the decision that the hop is trusted. No
  fallback from a listed origin, nothing learned, `https://` always by ALPN. Through an HTTP proxy a CONNECT tunnel
  (OkHttp's `Route.requiresTunnel`). No ALTSVC frame is heard on h2c and no `Alt-Svc` of an `http` origin learned, so a
  cleartext hop cannot move requests to HTTP/3.
- **Server: one port, told apart by the preface, or h2c alone.** `plainConnector { h2c = H2cMode.WithHttp11 }` looks
  at the first octets as they arrive (nothing consumed; the first that differs from the preface means HTTP/1.1, so a
  short HTTP/1.1 request is never held; the wait is inside the request-head deadline) as Go's
  `golang.org/x/net/http2/h2c` and Netty's `CleartextHttp2ServerUpgradeHandler` serve both on one port;
  `H2cMode.Only` (a gRPC port; grpc-go's server reads and compares the 24 octets) treats anything else as an invalid
  preface (PROTOCOL_ERROR). A dedicated port is two connectors. `EngineMain`: `kuicksilver.h2c`.
- **`Upgrade: h2c`.** Not implemented, as decided; a server that receives it serves the request as HTTP/1.1 (RFC 9110
  section 7.8 lets it ignore the upgrade), never 101. The JDK's HttpClient, which has only the upgrade, is thus served
  HTTP/1.1 on a `WithHttp11` port.

## Implementation: coalescing (2026-11-26)

`KuicksilverEngineConfig.connectionCoalescing` (experimental, false by default). The decisions the ADR left to the
implementation, with the RFC text they rest on ([RFC 9113 §9.1.1](../spec/rfc/9113.md#s9-1-1-connection-reuse)):

- **The certificate: every check of a new connection, not the name alone.** RFC 9113 section 9.1.1: "The certificate
  presented by the server MUST satisfy any checks that the client would perform when forming a new TLS connection for
  the host in the URI"; RFC 9114 section 3.3: "clients MUST validate the certificate presented by the server for the new
  origin server using the process described in Section 4.3.4 of [HTTP]". `verifyForReuse` (kuicksilver-tls, internal
  API) runs the chain the server presented through the host's own TLS configuration: OpenSSL's verification for the
  anchors (CRLs, purpose, validity at the current time), or the platform's or a `Custom` verifier asked about the new
  host (an Android per-domain configuration may differ from the first host's), then the pins on the validated chain, the
  shared name matcher and the security level, and the OCSP response the connection's server stapled: under
  `RequireStapled`, or for a must-staple leaf (RFC 7633), there must have been one, and it must still be fresh (its
  nextUpdate, as a resumption requires). OkHttp checks the hostname verifier and the certificate pinner only; we do not
  take the trust manager's verdict for the first host as the new host's. Checked once per connection and host, as the
  handshake's own verdict holds for the first origin; a refusal, and a 421, are remembered for the connection for good
  (hosts compared as reference identifiers: case and a trailing dot make no other host). The new host's name is kept from
  the verifier's network requests (RFC 9849 section 10.7) when the connection's ECH was accepted or a new connection to
  the host would offer ECH.
- **The address: per request.** RFC 9110 section 4.3.3: "In practice, a client will make a DNS query to check that the
  origin's host contains the same server IP address as the established connection". The request's resolution (the
  engine's `dns`, NAT64 synthesis included) must contain the literal the connection's Happy Eyeballs race won with,
  port included, at every request, so a changed answer moves the next request; over HTTP/3 the name resolved is that of
  the request's own HTTP/3 endpoint (RFC 9114 section 3.3: "the IP address and port might be derived from a URI, a
  selected alternative service"). Coalescing does not discover HTTP/3: it only spares the handshake of a request that
  has an HTTP/3 endpoint already.
- **A failure that applies to the connection's own origin retires it.** RFC 9114 section 3.3: "If the reason the
  certificate cannot be verified might apply to other origins already associated with the connection, the client SHOULD
  revalidate the server certificate for those origins". On any failure but a name mismatch the chain is revalidated for
  the connection's own origin (the host it was set up for) at once: when that fails too (expired, revoked, a stale
  staple, an anchor no longer trusted), the connection is retired (GOAWAY over HTTP/2, no new request over HTTP/3) and a
  Warn line says why (RFC 9110 section 4.3.4: "Automated clients MUST log the error to an appropriate audit log (if
  available)": once per connection, with the own origin's reason and the new host's, and both host names); its origins'
  next requests open a new connection, whose handshake verifies again. When the connection's own origin still passes (a
  custom verifier or a policy that refuses the new host alone), only the new host is refused.
- **Each request uses only what it checked.** Over HTTP/3 a destination is filed under another origin's connection by the
  request that checked it; a filing a concurrent request made is checked again (at most three rounds, then the request
  connects on its own). Refusals per connection are bounded (4096; past them every new host is refused).
- **421: once, on the origin's own connection, whatever the method.** RFC 9110 section 15.5.20: the client "MAY retry
  the request, whether or not the request method is idempotent, over a different connection, such as a fresh connection
  specific to the target resource's origin". The repeat and every later attempt of the call do not coalesce; a streamed
  body the first attempt consumed fails the call with `H3BodyConsumed`, as after the other 421s. A 421 on the origin's own
  connection is returned. OkHttp does not retry a 421 by itself.
- **What is never coalesced.** A connection or request through a proxy (any kind: the application's choice of route
  is kept both ways), h2c (no certificate), WebSockets and WebTransport (a session takes a connection of its own origin),
  `TrustConfig.Tofu` (a key is learned for a name only from a handshake with that name; a Tofu refusal never retires the
  connection), `TrustConfig.ExpectedName`, also under `Pinned` (the certificate is checked against a configured name,
  and RFC 9110 section 4.3.3 attributes authority over a connection only "if the URI origin's host matches any of the
  hosts present in the server's certificate"), an HTTP/3 connection whose
  handshake is not complete (0-RTT: the server is not authenticated yet), and an HTTP/2 connection without a free
  stream (not waited for). Session tickets, 0-RTT, settings and limits stay the connection's; the client certificate is
  the engine's one identity.
- **ALTSVC frames.** RFC 7838 section 4 ties a frame on a request stream to that stream's origin, which the frame does
  not carry: on a connection that carried another origin such frames are ignored (Alt-Svc is advisory), and each
  response's `Alt-Svc` field is learned for the response's own origin.
- **HPACK across origins.** RFC 7541 section 7.1: a shared compression context lets requests the attacker controls
  probe values of others. On an HTTP/2 connection that may carry other origins (coalescing on, direct TLS) `cookie` is
  always sent as a literal never indexed, not only when it is short (section 7.1.3).

## Alternatives rejected

- **Keep ADR-0017's "no h2c".** Rejected: deployments behind TLS-terminating proxies and gRPC users would stay on
  HTTP/1.1 between proxy and server, which the peers do not ask of them.
- **`Upgrade: h2c` from HTTP/1.1.** Deprecated by RFC 9113 section 3.1 and rarely deployed; prior knowledge covers the
  use cases above.
- **Coalescing on the certificate alone, without the address check.** It would let a DNS answer the client never got
  decide where B's requests go; RFC 9113 section 9.1.1 asks for both, and doing the same for HTTP/3 keeps one rule.
- **The ORIGIN frame now.** Few servers send it; it can be added later without changing the rule above.
