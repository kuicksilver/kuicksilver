<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Deploying the HTTP/3 server

This guide is for running `embeddedServer(Kuicksilver)` in production with HTTP/3 working: what has to reach the server,
what the host and the network in front of it need, and how to check from both ends why a client does or does not use
HTTP/3. The engine's options are in [Ktor: Server](ktor.md#server) and the
[configuration reference](configuration.md#ktor-server-engine); error messages are in
[troubleshooting](troubleshooting.md). This page links there instead of repeating them.

Statements about other products (Docker, Kubernetes, cloud load balancers, proxies) were checked against their
documentation on 2026-11-05 and link to it. Products and details this page does not name were not checked: read their
documentation before you rely on them.

## How a client gets to HTTP/3

1. The client connects over TCP and TLS (HTTP/1.1; the TCP side's ALPN is `http/1.1`).
2. The response carries `Alt-Svc: h3=":<port>"; ma=86400` (RFC 7838): HTTP/3 is on UDP, on that port of the same host,
   for 24 hours.
3. The client opens QUIC to that UDP port. The TLS handshake there uses the origin's host name (SNI) and checks the
   same certificate, with ALPN `h3`.
4. The client caches the alternative. If UDP does not get through it falls back to TCP; the Kuicksilver client then
   marks the alternative broken for a while ([Ktor: Racing and fallback](ktor.md#racing-and-fallback)).

So the TCP port, the UDP port, the `Alt-Svc` header and the certificate all have to work for HTTP/3. When one of them
is missing, clients quietly stay on HTTP/1.1.

## Ports and Alt-Svc

Every `tlsConnector` serves HTTP/1.1 on TCP and HTTP/3 on UDP **with the same port number** and the same `host`
(default `0.0.0.0`), and so does a plain connector when the configuration has an `identity` (with `EngineMain`, the
`kuicksilver.tls.*` keys). The engine binds both as a pair: a fixed port whose UDP side is taken fails the start
([Ktor: HTTP/3 on the server](ktor.md#http3-on-the-server)). Open, forward and publish **both** `<port>/tcp` and
`<port>/udp` everywhere on the way.

The engine's `Alt-Svc` names the port it bound, `h3=":<bound port>"` (no host: the same host as the request).
That is right only when clients reach the UDP port under the same number. When a NAT, a container port mapping or a
load balancer exposes another number, clients would try the wrong port. Two fixes:

- Map the same number on both sides (`443` outside to `443` inside), so the engine's header is right as it is.
- Or let the application send its own `Alt-Svc`. The engine never replaces an `Alt-Svc` the application set, so the
  application then also follows the run-time switch `engine.http3Advertising` (below) itself. Use it only on
  connectors that do serve HTTP/3: not on a plain connector without TLS, not on one with an `sniSelector`, and not when
  the start logged "HTTP/3 is not served ..." (a UDP bind failure, a platform without a QUIC server, `udpSocketCount`
  above what the platform allows); there the header would send clients to a port where nothing answers:

```kotlin
// guide:deployment:public-alt-svc
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val publicPort = 443   // the UDP port clients reach (the load balancer's or the NAT's), not the one bound here
lateinit var engine: KuicksilverApplicationEngine
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector(identity) { port = 8443 }
}) {
    intercept(ApplicationCallPipeline.Plugins) {
        // an Alt-Svc the application sets is never replaced, so it follows engine.http3Advertising itself
        val h3 = engine.http3Advertising == Http3Advertising.On
        call.response.header("Alt-Svc", if (h3) "h3=\":$publicPort\"; ma=86400" else "clear")
    }
}
engine = server.engine
```

The sample also sends its header on HTTP/3 responses, where the engine sends none under `On`; that only repeats what the
client already uses.

The client side has its own rule: the Kuicksilver client ignores an alternative on an unprivileged port (1024 and up) for
an origin on a privileged one, as Chromium does ([Ktor: Discovery and Alt-Svc](ktor.md#discovery-and-alt-svc)).
So for an origin on `https://host/` (port 443), HTTP/3 must also be reachable on a port below 1024, in practice UDP 443.

`ma=86400` means clients remember the alternative for a day. To withdraw HTTP/3, use `Clear` or `Drain` (below), which
send `Alt-Svc: clear`, rather than closing the UDP port, and keep that mode for at least 24 hours: `clear` only reaches
clients that come back over TCP, so a client that cached the alternative and returns within its `ma` still tries QUIC.
Clients that find the UDP port closed wait for their QUIC attempt to time out before they fall back. `altSvc = false` (`kuicksilver.altSvc` with `EngineMain`) stops the
engine's header entirely: then only clients that try HTTP/3 without being told (the Kuicksilver client's `Preferred`
mode or `quicHints`, `curl --http3`) use it.

The engine does not publish DNS HTTPS records (RFC 9460). The Kuicksilver client does not look them up yet either
(`AlternativeSource.HttpsRecord` is reserved for that). Publishing one in your DNS zone is up to you.

## Firewalls and security groups

- Allow inbound **UDP** on the port, next to TCP: in the host firewall (`ufw`, `firewalld`, `nftables`; Windows
  Defender Firewall, see [troubleshooting: Windows](troubleshooting.md#windows)) and in the cloud's security group or
  network ACL. A rule for TCP 443 alone is the most common reason a server serves HTTP/1.1 but no client ever arrives over
  QUIC.
- Answers leave from the same UDP port, and from the address the kernel's route picks (the address the client sent to
  only on a host with one address; see [Reply addresses](#reply-addresses)). A stateful firewall allows them once the
  inbound flow is allowed. A stateless
  network ACL needs an outbound rule for UDP from the port to the clients' ports.
- Many corporate and guest networks block UDP 443 on the client side. You cannot fix that from the server. Clients
  fall back to TCP: the Kuicksilver client reports `FallbackReason.HandshakeTimeout` and then `BrokenAlternative`
  ([Ktor: Why did this request not use HTTP/3?](ktor.md#why-did-this-request-not-use-http3)).

## Containers

### Docker

Docker publishes TCP unless a mapping says `/udp`; publish both protocols on the same number
([Docker: port publishing](https://docs.docker.com/engine/network/port-publishing/): "`-p 8080:80/udp` Map port `8080` on
the Docker host to UDP port `80` in the container"):

```sh
docker run -p 443:443/tcp -p 443:443/udp my-server-image
```

```dockerfile
EXPOSE 443/tcp 443/udp
```

`EXPOSE` only documents ports; the `-p` mappings publish them. With `-p 8443:443/udp` (another host port) the engine's
`Alt-Svc` names 443, which is wrong outside: map the same number or send your own header ([above](#ports-and-alt-svc)).
On Linux, `--network host` skips Docker's port mapping, and the engine binds the host's ports directly.

The UDP buffer limits are kernel settings of the host ([below](#udp-socket-buffers)). Set them on the host (the
Kubernetes node), not in the image.

### Kubernetes

A `Service` carries the TCP and the UDP port as two entries with the same number:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-server
spec:
  type: LoadBalancer
  externalTrafficPolicy: Local   # keep the client's address (see below)
  selector:
    app: my-server
  ports:
    - name: https
      protocol: TCP
      port: 443
      targetPort: 443
    - name: h3
      protocol: UDP
      port: 443
      targetPort: 443
```

The pod spec should declare `containerPort: 443` with `protocol: TCP` and another with `protocol: UDP` as well
(`containerPort` is informational: the Service's `targetPort` decides where traffic goes).

- **Mixed protocols in one `LoadBalancer` Service** are stable since Kubernetes 1.26 (the `MixedProtocolLBService` gate
  is removed), but "The set of protocols that can be used for load balanced Services is defined by your cloud provider;
  they may impose restrictions beyond what the Kubernetes API enforces"
  ([Kubernetes: Service, load balancers with mixed protocol types](https://kubernetes.io/docs/concepts/services-networking/service/#load-balancers-with-mixed-protocol-types)).
  Check that your provider's load balancer controller supports TCP and UDP on one port. Where it does not, use two
  Services (one TCP, one UDP) behind the same address if the provider can share one, or a load balancer you configure
  yourself.
- **The client's address.** With the default `externalTrafficPolicy: Cluster`, packets may be source-NATed to a
  node's address. "If you set `service.spec.externalTrafficPolicy` to the value `Local`, kube-proxy only proxies proxy
  requests to local endpoints, and does not forward traffic to other nodes. This approach preserves the original source
  IP address" ([Kubernetes: Using Source IP](https://kubernetes.io/docs/tutorials/services/source-ip/)). This matters more
  for QUIC than for TCP. The QUIC endpoint limits connections **per client IP address** (`maxConnectionsPerIp`, 256), and
  that limit cannot be changed from the Ktor engine yet ([Security limits](#security-limits)). Behind a source NAT, every
  client counts against the node's address, and so does the stateless answer limit (8 per second per address): Retry
  packets and refusals beyond it are dropped, and those clients see a handshake timeout instead. Address validation
  tokens are also bound to the address the server sees.
- **Rolling updates.** A graceful stop already does what an HTTP/3 client needs ([Ktor: Graceful stop](ktor.md#graceful-stop)):
  GOAWAY to every live HTTP/3 connection, and new QUIC clients refused with CONNECTION_REFUSED (under the stateless rate
  limit) instead of timing out. Stop the server with Ktor's `shutdownGracePeriod` and `shutdownTimeout`; the larger of the
  two bounds the stop (keep the timeout ≥ the grace period), so keep the `preStop` delay plus `shutdownTimeout` below
  the pod's `terminationGracePeriodSeconds`.
  Clients like the Kuicksilver client recover quickly: it treats `CONNECTION_REFUSED` as transient, and a connection
  the pod closes with H3_NO_ERROR after its GOAWAY (at the end of the grace period) as an orderly end; either way the affected call falls
  back to TCP once (when it may be repeated) and the next one tries HTTP/3 again, which another pod may take. Neither
  marks the alternative broken ([Ktor: Racing and fallback](ktor.md#racing-and-fallback); before 0.3.0 both did, for 5
  minutes doubling up to 2 days). Switching a pod to `Http3Advertising.Drain` before it stops has a cost: its responses send
  `Alt-Svc: clear` for the whole origin, not just that pod, so clients that get one drop the alternative until another
  response announces it again. Use `Drain` to take HTTP/3 out of service, not for routine restarts.

## Load balancers and proxies

### What can sit in front of the server

| In front | HTTP/3 reaches Kuicksilver? | Notes |
|---|---|---|
| Nothing (public address on the host) | yes | the simplest setup |
| An L4 load balancer that passes UDP through (cloud network load balancer, `kube-proxy`, IPVS, nginx `stream`) | yes | per-flow routing, see [connection IDs](#connection-ids-and-several-instances); with direct server return (IPVS-DR, a VIP on `lo`) bind `host` to the VIP, see [reply addresses](#reply-addresses) |
| An L7 proxy that terminates HTTP/3 itself (CDN, nginx `http`, other reverse proxies) | **no** | the proxy speaks HTTP/3 to clients and HTTP/1.1 (or HTTP/2) to the server; Kuicksilver then serves only that TCP side. Set `altSvc = false` (or strip the header at the proxy): the engine's `h3=":<bound port>"` would otherwise pass through and point clients at that port on the proxy's host |

Notes on specific products (checked 2026-11-05):

- **AWS Network Load Balancer.** Listeners support "TCP, TLS, UDP, TCP\_UDP, QUIC, TCP\_QUIC"; "To support both TCP and
  UDP on the same port, create a TCP\_UDP listener", and its target groups must use TCP\_UDP
  ([AWS: NLB listeners](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-listeners.html)).
  Client IP preservation "can't be disabled for UDP, TCP\_UDP, QUIC, and TCP\_QUIC target groups"
  ([AWS: NLB target groups](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-target-groups.html)),
  so the per-IP limit sees real clients. Use TCP\_UDP with Kuicksilver. The QUIC and TCP\_QUIC listeners route by
  QUIC connection ID: **not verified** with Kuicksilver, whose connection IDs carry no load balancer server ID yet (below).
- **Cloudflare** (proxied hostname): HTTP/3 ends at Cloudflare's edge; "HTTP/3 connection to the origin is not yet
  supported" ([Cloudflare: HTTP/3](https://developers.cloudflare.com/speed/optimization/protocol/http3/)). Cloudflare then
  reaches a Kuicksilver origin over TCP, and the origin's UDP port only serves clients that reach it directly. Set
  `altSvc = false` on the origin, so its `Alt-Svc` does not reach clients through Cloudflare.
- **nginx** as an L7 proxy terminates HTTP/3 itself and talks to the upstream with `proxy_http_version 1.0 | 1.1 | 2`
  (HTTP/2 since 1.29.4, HTTP/1.1 the default since 1.29.7;
  [nginx: proxy_http_version](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_http_version)). A
  Kuicksilver upstream serves HTTP/1.1; set `altSvc = false` on it, or drop the header with `proxy_hide_header Alt-Svc`.
  For UDP passthrough, the `stream` module's `listen ... udp`
  "configures a listening socket for working with datagrams", with `reuseport` "to handle packets from the same address
  and port in the same session"
  ([nginx: stream listen](https://nginx.org/en/docs/stream/ngx_stream_core_module.html#listen)). By default nginx connects
  to the upstream from its own address, so every client shares nginx's address against the per-IP limit.
- **Google Cloud (GKE) and Azure:** whether their load balancers take TCP and UDP on one port in one Service was **not
  verified** for this page; see their documentation.
- **HAProxy, Envoy, Caddy, other CDNs:** **not verified**. The table above still applies: find out whether the product
  passes QUIC through at layer 4 or terminates HTTP/3.

### Reply addresses

The engine's UDP socket does not choose the source address of its answers per packet (no `IP_PKTINFO` /
`IPV6_PKTINFO` yet): with the default `host = "0.0.0.0"` the kernel picks it from the route to the client. On a host with
one address that is the address the client sent to. On a host that receives on another address than its route's (a
secondary IP, a floating or virtual IP, a VIP on `lo` for IPVS direct routing or similar direct server return), the
answers leave from the wrong address, the client drops them, and QUIC never connects while TCP works. Until that is
fixed in the engine, bind the connector's `host` to the address clients send to in such setups.

### Connection IDs and several instances

A QUIC connection is identified by connection IDs, not by the 4-tuple, so it survives a client's change of address (NAT
rebinding, Wi-Fi to cellular; [QUIC: Migration and paths](quic.md#migration-and-paths)). An L4 load balancer that hashes
the 4-tuple does not know this:

- While the client's address and port stay the same, all its packets reach the same instance, and everything works.
- When they change, the packets may hash to another instance. That instance has no state for the connection and
  cannot end it either: Stateless Reset tokens come from a key of the endpoint that issued the connection
  ([QUIC: Stateless reset](quic.md#stateless-reset)). The connection then stalls until the client's idle timeout and
  the client reconnects. With a single instance behind the load balancer this cannot happen.
- Retry tokens and NEW_TOKEN address tokens are sealed with keys of one server process. A Retry token is valid for
  10 s and bound to the client's address and port; one that another instance issued does not open, so the attempt is
  refused with a stateless CONNECTION_CLOSE carrying INVALID_TOKEN (RFC 9000 section 8.1.3) and that connection attempt
  fails. Under per-flow routing the Initial after a Retry comes from the same 4-tuple and reaches the same instance, so
  this happens only when the flow moves within those seconds. A NEW_TOKEN token from another instance counts as no
  token ([QUIC: Admission and endpoint limits](quic.md#admission-and-endpoint-limits)): the client may be asked for a
  Retry again, at the cost of a round trip.

Kuicksilver's connection IDs do not follow QUIC-LB (draft-ietf-quic-load-balancers), which lets a load balancer route by
an instance ID encoded in the connection ID. That is planned for 0.3.x
([RFC compliance](../spec/rfc-compliance.md)). Until then, put one instance behind each address, or accept that a
client that changes address while connected to a multi-instance pool reconnects. The engine does not offer a QUIC
preferred address (`QuicServerConfig.preferredAddress`, [QUIC: Migration and paths](quic.md#migration-and-paths)) either;
that needs the QUIC API directly.

## The host

### UDP socket buffers

A QUIC server receives everything through one UDP socket per loop. A burst that does not fit into the socket's receive
buffer is dropped by the kernel, and QUIC sees it as loss. Kuicksilver asks for large buffers itself; the OS caps what
it gets:

| Platform (socket) | What Kuicksilver asks for | What limits it |
|---|---|---|
| Linux, Android (accelerated `ksl` socket) | `SO_RCVBUF` and `SO_SNDBUF` of 7 MiB | `net.core.rmem_max` and `net.core.wmem_max`: Linux silently caps a larger request to them (`socket(7)`). The default is distribution-dependent and often about 208 KiB |
| macOS, iOS (accelerated `ksl` socket) | 7 MiB, halved until the kernel accepts it (the last try is 448 KiB; after that the OS default stays) | `kern.ipc.maxsockbuf` (on macOS 8 MiB by default, less overhead; iOS not checked) |
| Windows (accelerated `ksl` socket) | 7 MiB, once | Windows' own limits |
| JVM portable socket (when `ksl` is not used) | 8 MiB | the same OS limits |

Kuicksilver does not read the size back, does not log it, and does not use `SO_RCVBUFFORCE`. The engine has no option
for it ("UDP socket buffer sizes are not configurable yet", [Ktor: HTTP/3 on the server](ktor.md#http3-on-the-server)).
On Linux, raise the limits so the request is granted in full (values in bytes; 8 MiB, 8 388 608, covers the 7 MiB of
the `ksl` socket and the 8 MiB of the JVM portable socket):

```sh
sysctl net.core.rmem_max net.core.wmem_max          # what the host allows now
sudo sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608
# keep it across reboots
printf 'net.core.rmem_max=8388608\nnet.core.wmem_max=8388608\n' | sudo tee /etc/sysctl.d/90-quic.conf
```

Signs that the buffer is too small: receive errors growing under load (`netstat -su`, "receive buffer errors", or
`RcvbufErrors` in `/proc/net/snmp`) and losses in a qlog trace that the network does not explain. These counters are
per network namespace: for a server in a container, read them inside it (or with `nsenter -t <pid> -n`).

### GSO, GRO and several loops

On Linux and Android the accelerated socket sends runs of equal-sized datagrams with one `sendmsg` and `UDP_SEGMENT`
(GSO), and receives coalesced datagrams with `UDP_GRO`. It probes both when the socket opens, and turns GSO off by itself
if the kernel or the driver fails a send with it. Darwin has neither (one datagram per call). Windows uses USO and URO
where the system grants them. Nothing needs to be set, but older kernels lack the options: UDP GSO arrived in Linux 4.18
and UDP GRO in 5.0. The engine does not log whether they were granted; `DatagramIo.open(...).capabilities`
(`gsoMaxSegments`, `gro`) shows it for a socket you open yourself on the same host
([QUIC: Binding an endpoint and connecting](quic.md#binding-an-endpoint-and-connecting)).

`udpSocketCount` (`kuicksilver.udpSocketCount`, default 1) runs that many endpoint loops on the port, each with its own
socket on `SO_REUSEPORT`, and the kernel spreads client flows over them. That works on Linux and Android with the
accelerated socket only. On macOS, iOS and Windows, and on a JVM that fell back to the portable socket, a value above 1
does not fail the start: the engine logs "HTTP/3 is not served on port <port>: ..." and serves HTTP/1.1 alone, without
`Alt-Svc` ([troubleshooting](troubleshooting.md#unsupportedoperationexception-for-loops--1),
[QUIC: Several loops on one port](quic.md#several-loops-on-one-port)). A connection whose packets the kernel hashes onto
another loop's socket (after a NAT rebinding) is forwarded inside the process, so several loops have none of the
load balancer problems above.

If the accelerated socket cannot open, the JVM falls back to a portable socket without these features, with a warning
in the log; a Kotlin/Native server then serves HTTP/1.1 only
([troubleshooting: The accelerated socket is not used](troubleshooting.md#the-accelerated-socket-is-not-used)).

### MTU

QUIC starts at 1200-byte packets and raises them with DPLPMTUD. Tunnels with a small MTU (VPNs, some overlay networks)
are covered by black-hole detection ([QUIC: Path MTU](quic.md#path-mtu),
[troubleshooting](troubleshooting.md#transfers-stall-over-a-vpn-or-tunnel-mtu-black-hole)).

## Certificates

- One identity serves both sides: the same chain and key over TCP and over QUIC. The certificate must cover the host
  name clients use for the origin. The alternative in `Alt-Svc` has no host of its own, so the name is the same.
- A `tlsConnector` with an `sniSelector` serves no HTTP/3 (warning at start): QUIC cannot pick an identity per SNI name
  yet. Give each name its own connector, or use one certificate for all names.
- Renewed certificates can be put in place without a restart: a `TlsIdentity.Reloadable` and `reload(...)`, or with
  `EngineMain` the key `kuicksilver.tls.reloadInterval` that watches the PEM files of `kuicksilver.tls.certificateChain` and
  `kuicksilver.tls.privateKey` ([Ktor: Certificate rotation](ktor.md#certificate-rotation),
  [TLS: Rotating the server certificate](tls.md#rotating-the-server-certificate)). New handshakes on TCP and QUIC take the
  new certificate; open connections keep theirs.

## Turning HTTP/3 off without a restart

On the server, `engine.http3Advertising` (experimental) is read per response and per new QUIC client
([Ktor: Turning HTTP/3 off on the server](ktor.md#turning-http3-off-on-the-server)):

| Value | Use it when |
|---|---|
| `On` | normal operation |
| `Clear` | HTTP/3 should stop being offered, but connections that use it may finish in their own time |
| `Drain` | HTTP/3 must go now: GOAWAY to live connections, new QUIC clients refused with CONNECTION_REFUSED (within the stateless rate limit; beyond it they time out), so they fall back at once; a Kuicksilver client does not mark the alternative broken for the refusal and is back on HTTP/3 as soon as the server announces it again |

The UDP socket stays bound in every mode. To block UDP for good, use the firewall, after at least 24 hours (`ma=86400`)
in `Drain` or `Clear`, so that returning clients have dropped the cached alternative first; clients that do not come
back within that time have let it expire. The value is per engine and starts at `On`. Behind a load balancer,
set it on every instance.

On the client, an application can switch HTTP/3 off from its remote configuration with `http3 { http3Allowed }` and take
open connections out of use with `client.closeHttp3Connections()`
([Ktor: Turning HTTP/3 off remotely](ktor.md#turning-http3-off-remotely)).

## Security limits

The HTTP/3 listener runs the QUIC endpoint's protections ([QUIC: Admission and endpoint limits](quic.md#admission-and-endpoint-limits),
[threat model 3.1](../spec/threat-model.md#31-amplification) and [3.2](../spec/threat-model.md#32-resource-exhaustion)):

- **Amplification.** Before a client's address is validated, the server sends at most three times what it received
  (RFC 9000 section 8.1).
- **Retry.** `quicAdmission` (a `ConnectionAdmission`) decides per new client. The default asks unvalidated clients for a
  Retry under handshake load; `ConnectionAdmission.AlwaysRetry` always does. Clients that bring a valid address token skip
  it.
- **Hard limits.** `maxConnections` 10 000, `maxConnectionsPerIp` 256 and `acceptQueue` 128 per listener, and stateless
  answers (Retry, refusals, Version Negotiation, Stateless Reset) rate-limited to 8 per second per address and 1000 in
  total; what goes beyond is dropped, and such clients see a handshake timeout. The engine does not let you change these
  yet ([configuration](configuration.md#ktor-server-engine)). This is why a source NAT in front of the server matters
  ([Kubernetes](#kubernetes)): every client behind it shares both limits.
- **Transport and HTTP/3 settings.** `quic` (a `QuicConfig`: idle timeout, windows, congestion control), `http3Settings`,
  and on TCP `requestHeaderTimeoutSeconds` and `connectionIdleTimeoutSeconds` against slow clients
  ([Ktor: Server](ktor.md#server)).

## Observability

- The application's log gets the engine's own messages, such as "HTTP/3 is not served on port ...". The `logger`
  (warnings on standard error by default) gets the QUIC endpoints' diagnostics, such as the fallback to the portable
  socket; `logger = KuicksilverLogger.stderr(LogLevel.Debug)` adds each QUIC connection's lifecycle.
- `eventListener` (`KuicksilverServerEventListener`) hears connections per protocol (`connectionOpened` with
  `HTTP/3.0`), failed TLS handshakes and requests, which you can count; `connectionListener` hears every QUIC connection with its close reason.
- `qlog = AsyncQlogSink(DirectoryQlogSink(dir), sampleEvery = 100)` writes a trace per sampled connection, for
  [qvis](https://qvis.quictools.info/).

See [Ktor: Observability](ktor.md#observability-experimental) for a sample. The engine does not expose the endpoint's
`EndpointStats` counters (refusals, datagrams received). On the server, "does any QUIC arrive at all?" is answered by
`connectionListener`, a debug log, or a packet capture.

## Checking a deployment

From a machine outside your network:

```sh
# 1. TCP side: the Alt-Svc header (h3 with the public port; "clear" under Clear or Drain)
curl -sI https://example.com/ | grep -i '^alt-svc'

# 2. UDP side: HTTP/3 only, no fallback (needs a curl built with HTTP/3: `curl -V` lists HTTP3)
curl --http3-only -sI https://example.com/

# 3. On the server: does UDP arrive at all?
sudo tcpdump -ni any udp port 443
```

`curl --http3-only` tries QUIC on the URL's port. When `Alt-Svc` advertises another port, test that one
(`https://example.com:<advertised port>/`). Run `tcpdump` on the port the engine bound; for a container, inside its
network namespace (`nsenter -t <pid> -n tcpdump ...`) or on the host's published port.

`curl --http3-only` fails when QUIC does not get through, so it tells a blocked UDP path apart from a client that just
chose TCP ([curl: HTTP/3](https://curl.se/docs/http3.html)).

From a Kuicksilver client, every response says how it was served and, if not over HTTP/3, why:
`response.kuicksilverDiagnostics?.fallback`, or one log line per call with `engine { logger = KuicksilverLogger.stderr(LogLevel.Info) }`
([Ktor: Why did this request not use HTTP/3?](ktor.md#why-did-this-request-not-use-http3)). Keep in mind that in `Auto`
mode the first call to an origin goes over HTTP/1.1 (`NoAlternative`) unless a `FileAltSvcStore` remembers the
alternative from an earlier run; HTTP/3 starts from the next call.

## Troubleshooting checklist

| Symptom | Check |
|---|---|
| No `Alt-Svc` in responses | the server log ("HTTP/3 is not served ...": the UDP bind, no QUIC server on the platform, `udpSocketCount` above 1 outside Linux and Android); `http3` and `altSvc` on; an `sniSelector` on the connector; a proxy in front that strips the header ([troubleshooting](troubleshooting.md#the-server-serves-http11-but-no-http3)) |
| `Alt-Svc: clear` | `engine.http3Advertising` is `Clear` or `Drain` |
| `Alt-Svc` names the wrong port | a port mapping or load balancer with another number: map the same number or send your own header ([Ports and Alt-Svc](#ports-and-alt-svc)) |
| `curl --http3-only` times out, `tcpdump` shows nothing | UDP is blocked before the server: firewall, security group, `-p .../udp` missing, the Service has no UDP port, the load balancer has no UDP listener |
| `tcpdump` shows Initials, no answer | the host firewall drops them; the per-IP or stateless rate limit or the admission policy drops them (all clients behind one NAT address); answers leave from another source address ([reply addresses](#reply-addresses)) |
| `curl --http3-only` fails with a TLS error | the certificate does not cover the name, or a connector with `sniSelector` (no HTTP/3) |
| Client `fallback = HandshakeTimeout`, then `BrokenAlternative` | UDP blocked on the client's network or in front of the server |
| Client `fallback = Refused` | the server is in `Drain`, stopping, or its accept queue is full (`h3Failure` code 0x2, CONNECTION_REFUSED: transient, the next call tries HTTP/3 again); another code: the server's QUIC listener |
| Client `fallback = TlsFailure` | the certificate on the UDP side, its `h3` ALPN |
| Client `fallback = NoAlternative` on every call | the client never saw `Alt-Svc` (a proxy strips it), or the alternative's port is unprivileged for a privileged origin |
| Connections drop when clients change networks | an L4 load balancer with several instances ([Connection IDs](#connection-ids-and-several-instances)) |
| Throughput low, loss under load | UDP buffer limits ([UDP socket buffers](#udp-socket-buffers)), GSO missing on an old kernel |
