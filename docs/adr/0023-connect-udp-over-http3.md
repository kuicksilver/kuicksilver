<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0023. CONNECT-UDP (RFC 9298) over HTTP/3 only, in `kuicksilver-http3`, with proxied QUIC through `DatagramIo`

Date: 2026-11-18. Status: proposed (0.3.0 feature-parity item 4).

## Context

RFC 9298 tunnels UDP through an HTTP proxy, MASQUE's way of running QUIC and HTTP/3 through a proxy. It defines the
request for HTTP/1.1 (an `Upgrade: connect-udp` GET, section 3.2), HTTP/2 and HTTP/3 (Extended CONNECT, sections 3.3 and
3.4), and carries UDP payloads as HTTP datagrams (RFC 9297), which on HTTP/1.1 and HTTP/2 can only be DATAGRAM capsules on
the stream. The library has Extended CONNECT, HTTP/3 datagrams and the Capsule Protocol on HTTP/3 only; HTTP/2 has
Extended CONNECT (RFC 8441) for WebSockets but no Capsule Protocol. A proxy is a request-forgery tool unless it filters
its targets (section 7). A client that wants QUIC through the tunnel needs the tunnel where QUIC reads and writes UDP:
`DatagramIo` (ADR-0006), which a `QuicEndpointConfig.io` factory already lets the application supply.

## Decision

- **HTTP/3 only, both sides.** The client (`Http3Connection.connectUdp` → `UdpTunnel`) and the proxy (`UdpProxy.serve`)
  speak RFC 9298 sections 3.4 and 3.5. HTTP/1.1 and HTTP/2 (sections 3.2, 3.3) are not offered: section 6 says UDP
  proxying "SHOULD be performed over HTTP/3", over TCP every datagram would be a capsule behind head-of-line blocking,
  and the Capsule Protocol would have to be built for both versions first.
- **In `kuicksilver-http3`**, next to the capsules and datagrams it uses: the template, the target syntax, the address
  classes and the Context ID filter of the Capsule parser are sans-IO (`message`); the proxy and the tunnel are
  coroutines (`connectudp`). The proxy opens its target sockets through a `socketFactory` (`DatagramIo.open` by default),
  so it needs nothing above the QUIC layer.
- **Safe defaults for the proxy**: only globally reachable unicast targets (`UdpTargetFilter.PublicOnly`), checked on the
  resolved addresses with the socket sending to the address that passed; per-tunnel rate and unanswered-packet limits;
  tunnel limits in all and per client address; a two-minute idle timeout, the floor of section 3.1; `capsule-protocol:
  ?1` required (configurable). Authentication stays with the application.
- **Proxied QUIC through `DatagramIo`**: `UdpTunnel.asDatagramIo()` is a socket with one peer (the target), no ECN, GSO or
  Don't Fragment, as quiche's tokio-quiche models a MASQUE flow as a connected socket (`tokio-quiche/src/socket/connected.rs`).
  Any `QuicEndpoint` or `Http3Endpoint` then runs through the proxy without a change to the QUIC core.

## Consequences

- MASQUE-style HTTP/3 through a proxy works at the HTTP/3 level; the Ktor engines do not offer it yet (the client's proxy
  settings still mean HTTP/1.1 through an HTTP or SOCKS proxy, and the server has no CONNECT-UDP route).
- The connection to the proxy must carry 1200-byte inner datagrams plus framing: a path MTU above about 1250, found by
  DPLPMTUD on sockets that set Don't Fragment; over a 1200-byte path proxied QUIC cannot work (RFC 9000 section 14).
- The ICMP Packet Too Big of section 6.1 is not sent (no raw sockets in a library): the RFC row records the deviation.
- A proxy operator must add the proxy's own public addresses to the filter (`UdpTargetFilter.excluding`).

## Alternatives rejected

- **HTTP/2 as well**: the Capsule Protocol on HTTP/2 and DATAGRAM capsules for every payload, for a transport the RFC
  advises against; can be added later without changing this API.
- **Proxied QUIC inside the QUIC core** (a "proxy path" in `ConnectionCore`, as picoquic's `picomask` hooks its packet
  loop, `picohttp/picomask.c:473-504`, `:531-563`): couples the transport to HTTP/3 against ADR-0005 and the sans-IO core; the
  `DatagramIo` seam already carries it.
- **A connected UDP socket per tunnel** instead of source validation on an unconnected one: `DatagramIo` has no connect;
  section 3.1 allows either.
