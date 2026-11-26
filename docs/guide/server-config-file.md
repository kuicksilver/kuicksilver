<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Configuration file (EngineMain)

**What this page is for.** Running the server engine from `application.conf` or `application.yaml` with
`io.kuicksilver.ktor.server.EngineMain`: the keys, their values and how they map to the DSL.

**Before you start**

- A complete example: [Ktor engines: Minimal example](ktor.md#minimal-example) and the
  [http3-server sample](../../samples/http3-server/README.md). Every option with its key: [configuration: HOCON
  keys](configuration.md#hocon-keys).

## EngineMain and configuration keys

`io.kuicksilver.ktor.server.EngineMain` reads the usual `ktor.deployment.*` keys (and on the JVM `-sslPort` with
`ktor.security.ssl.*`). Its own keys work on every platform, and in `application.yaml` as in `application.conf`. A key is
the path of its option in the engine's DSL under `kuicksilver.` (`kuicksilver.http3.endpoint.maxConnections` is
`http3 { endpoint { maxConnections } }`), except the TLS files under `kuicksilver.tls` (the DSL reads them with
`pemFiles`, `clientCaFile` and `ocspStaplingFile`), the `kuicksilver.connector` block for the deployment port (a Ktor
connector, which has no DSL block) and Ktor's own `ktor.deployment.connectionIdleTimeoutSeconds`.

- **Strict.** Every key under `kuicksilver.` must be one of the table's: any other fails the start with an
  `IllegalArgumentException` that names it and the key to use, `kuicksilver.http3.quic.maxConnections is not a Kuicksilver
  key; did you mean kuicksilver.http3.endpoint.maxConnections?`. A key of 0.2.x or of an earlier 0.3.0 snapshot is never
  read: `kuicksilver.altSvc was replaced in 0.3.0 by kuicksilver.http3.altSvc`, and the 0.2.x switch
  `kuicksilver.http3 = true` gives `kuicksilver.http3 = true|false was replaced in 0.3.0 by kuicksilver.http3.enabled`
  (the old and new keys: [configuration reference](configuration.md#migrating-from-02x)). HOCON keeps the last of two
  definitions of one path, so a file with both `kuicksilver.http3 = true` and a `kuicksilver.http3 { }` block is read
  as whichever comes last: write the block only.
- **Values.** A switch is `true` or `false`, nothing else; a duration is what `kotlin.time.Duration.parse` reads (`30s`,
  `1h`, `PT30S`); an enumeration's name in any case (`required`, `tls12And13`, `withHttp11`). "None" or "no limit" is
  `off` for the keys that have one, where `0` is refused with "use off instead of 0". A value the option refuses fails
  the start with the key in front of the option's message.

| Key | Meaning |
|---|---|
| `kuicksilver.requestHeaderTimeout` | `requestHeaderTimeout`: the time for a complete request head on every protocol (`30s`); see [Server](server.md) |
| `kuicksilver.tls.certificateChain`, `kuicksilver.tls.privateKey` | PEM files (`tls { pemFiles(…) }`); the deployment port then serves TLS, HTTP/2 and HTTP/3 |
| `kuicksilver.tls.reloadInterval` | `tls { reloadInterval }`: how often those PEM files, and the `kuicksilver.tls.clientCa` and `kuicksilver.tls.ocspStapling` files, are checked for a renewed certificate, CA bundle or response (`30m`, `1h`; `off` or unset: never; at least `1s`); see [Certificate rotation](engine-tls.md#certificate-rotation) |
| `kuicksilver.tls.clientAuth` | `tls { clientAuth }`: ask for a client certificate on the deployment port: `none` (unset), `optional` or `required`; anything but `none` needs `kuicksilver.tls.clientCa` |
| `kuicksilver.tls.clientCa` | `tls { clientCaFile(…) }`: PEM file of the CA certificates client certificates are verified against; needs the identity files and `kuicksilver.tls.clientAuth` `optional` or `required` |
| `kuicksilver.tls.versions` | `tls { versions }`: the TLS versions of the deployment port: `tls13` (unset) or `tls12And13`; needs the identity files, and is refused next to `-sslPort`, whose key is `ktor.security.ssl.enabledProtocols`; see [TLS 1.2 on the server](engine-tls.md#tls-12-on-the-server) |
| `kuicksilver.tls.keyExchangeGroups` | `tls { keyExchangeGroups }`: the key-exchange groups of the deployment port, the server's most preferred first: a list of `KeyExchangeGroups` names (`["X25519MLKEM768", "x25519", "secp256r1"]`, case ignored), or one string of them separated by `:` or `,` (`-P:` keys, `${?ENV}`); unset: the default list; needs the identity files, and is refused next to `-sslPort`; an unknown name or a duplicate fails the start; see [TLS: Key exchange groups](tls.md#key-exchange-groups) |
| `kuicksilver.tls.ocspStapling` | `tls { ocspStaplingFile(…) }`: a file with a DER OCSP response (RFC 6960) for the identity's certificate, stapled on TCP and QUIC when it is fresh and for the certificate sent; read again every `kuicksilver.tls.reloadInterval` (put a fresh response in place before nextUpdate; without the interval, a restart reads it); a response that is not stapled is logged as a warning at startup, and so is one that stops being stapled (expired, or for a certificate that was reloaded); needs the identity files, and is refused next to `-sslPort`; see [Certificate revocation](tls.md#certificate-revocation) |
| `kuicksilver.tls.echKeys` | `tls { echKeys }`: Encrypted Client Hello keys of the deployment port: a list of PEM files, each what `openssl ech -public_name <name>` writes (the private key and its ECHConfigList; every one is sent in retry configurations), or one comma-separated string; read once at startup (rotate in code with `EchServerKeys.rotate`); needs the identity files, and is refused next to `-sslPort`; see [Encrypted Client Hello on the server](engine-tls.md#encrypted-client-hello-on-the-server) |
| `kuicksilver.connector.allowMisdirectedHosts` | `true`: every client of the deployment port is a trusted gateway (RFC 9110 section 7.4), so no request is answered `421 Misdirected Request`: with the identity files, for a host the certificate does not name; without them, for an absolute-form `https` target on the cleartext port behind a TLS-terminating proxy (`false`); with the identity files it is refused next to `-sslPort`, and without them it is accepted there but exempts only the cleartext port, never Ktor's `-sslPort` connector; see [Misdirected requests](server-proxies.md#misdirected-requests) |
| `kuicksilver.connector.h2c` | HTTP/2 over cleartext TCP with prior knowledge on the plain deployment port: `off` (unset), `withHttp11` (both on one port, told apart by the preface) or `only`; refused with the identity files; see [h2c on the server](server.md#h2c-on-the-server) |
| `kuicksilver.connector.proxyProtocol.trustedSources`, `.headerTimeout`, `.maxHeaderSize` | the PROXY protocol on the deployment port: the proxies allowed to send the header (a list, or one comma-separated string; unset: off), how long it may take (`5s`) and its largest size in bytes (`4096`); the other two need `trustedSources`; refused next to `-sslPort`; see [PROXY protocol](server-proxies.md#proxy-protocol) |
| `kuicksilver.http1.allowBareLf` | `http1 { allowBareLf }`: let a bare LF end a line of an HTTP/1.1 request head or trailer section (`false`: 400); see [Server](server.md) |
| `kuicksilver.http2.enabled` | `http2 { enabled }`: serve HTTP/2 on TLS connectors (`true`); see [HTTP/2 on the server](server.md#http2-on-the-server) |
| `kuicksilver.http2.repeatOffenderPenalty` | `http2 { repeatOffenderPenalty }`: refuse an address that keeps flooding HTTP/2 for this long (`off`; e.g. `30s`); see [HTTP/2 on the server](server.md#http2-on-the-server) |
| `kuicksilver.http3.enabled` | `http3 { enabled }`: serve HTTP/3 (`true`) |
| `kuicksilver.http3.altSvc` | `http3 { altSvc }`: announce HTTP/3: `Alt-Svc` on HTTP/1.1 and HTTP/2 responses, plus ALTSVC frames on HTTP/2 (`true`) |
| `kuicksilver.http3.earlyData.enabled` | `http3 { earlyData { enabled } }`: accept 0-RTT (`false`); the policy (`replayable`, a predicate) is code only; see [0-RTT](zero-rtt.md) |
| `kuicksilver.http3.endpoint.loops` | `http3 { endpoint { loops } }`: endpoint loops on the UDP port (`1`) |
| `kuicksilver.http3.endpoint.maxConnections` | `http3 { endpoint { maxConnections } }`: QUIC connections each HTTP/3 listener holds (`10000`); see [Connection limits](server.md#connection-limits) |
| `kuicksilver.http3.endpoint.maxConnectionsPerIp` | `http3 { endpoint { maxConnectionsPerIp } }`: QUIC connections of one client IP (`256`; `off` behind a NAT or kube-proxy) |
| `kuicksilver.http3.endpoint.acceptQueue` | `http3 { endpoint { acceptQueue } }`: handshaken connections waiting for the accept loop (`128`) |
| `kuicksilver.http3.endpoint.expert.connectionIdLength` | `http3 { endpoint { expert { connectionIdLength } } }`: the length of the listeners' connection IDs, 4..20 (`8`) |
| `kuicksilver.http3.quic.maxIdleTimeout`, `.handshakeTimeout`, `.keepAlive`, `.maxBidiStreams` | `http3 { quic { … } }`: the idle timeout (`30s`; `off` advertises none), the handshake deadline (`10s`), the PING interval of a quiet connection (`off`) and the request streams a client may have open (`100`) |
| `kuicksilver.http3.quic.pathMtu.maxReceive`, `.initial`, `.maxSend`, `.discovery` | `http3 { quic { pathMtu { … } } }`: the advertised `max_udp_payload_size` (1200..1500, the endpoint's datagram slots), the datagram size a connection starts with, the largest datagram sent and DPLPMTUD; see [Tunnels and NAT paths](quic.md#tunnels-and-nat-paths-wireguard) |
| `kuicksilver.http3.quic.migration.allow` | `http3 { quic { migration { allow } } }`: follow a client to a new address (`true`) |
| `kuicksilver.http3.quic.expert.maxUniStreams` | `http3 { quic { expert { maxUniStreams } } }`: unidirectional streams a client may open, at least 3 (`100`, raised to fit WebTransport) |
| `kuicksilver.webSockets.overHttp2`, `.overHttp3` | `webSockets { overHttp2, overHttp3 }`: accept RFC 8441 and RFC 9220 WebSockets (`true`); see [WebSockets over HTTP/2](realtime.md#websockets-over-http2) |
| `kuicksilver.webSockets.maxMessageSize` | `webSockets { maxMessageSize }`: the largest WebSocket message a client may send, in bytes (`16777216`) |
| `kuicksilver.tcp.maxConnections` | `tcp { maxConnections }`: TCP connections a connector holds at once (`10000`); see [Connection limits](server.md#connection-limits) |
| `kuicksilver.tcp.maxConnectionsPerIp` | `tcp { maxConnectionsPerIp }`: TCP connections of one client address on a connector (`off`; e.g. `256` for a server that faces clients directly); see [Connection limits](server.md#connection-limits) |
| `ktor.deployment.connectionIdleTimeoutSeconds` | Ktor's key, read into `tcp { idleTimeout }` (`45`) |

The QUIC transport keys set `http3 { quic { } }` as the DSL does. Every key with its type and release is in the
[configuration reference](configuration.md#hocon-keys).

An `application.conf` (HOCON) for a TLS and HTTP/3 server on port 443 whose certificate certbot renews; every key not
set keeps the default of the table above. The `kuicksilver-ktor-server` tests load this block as it stands (with their
own paths, port and module), so its keys stay current:

```hocon
ktor {
    deployment {
        port = 443                     # TCP for HTTP/2 and HTTP/1.1 over TLS and UDP for HTTP/3, the same number
    }
    application {
        modules = [ com.example.ApplicationKt.module ]
    }
}
kuicksilver {
    tls {
        certificateChain = "/etc/letsencrypt/live/example.com/fullchain.pem"
        privateKey = "/etc/letsencrypt/live/example.com/privkey.pem"
        reloadInterval = 1h
    }
    http3.endpoint.maxConnectionsPerIp = 4096   # behind a NAT or kube-proxy; see deployment.md
}
```

[samples/http3-server](../../samples/http3-server/README.md) is such a server, with `kuicksilver.http2.enabled`,
`kuicksilver.http3.altSvc` and `kuicksilver.connector.proxyProtocol.trustedSources` taken from environment variables (`${?NAME}`), and a
test that starts it with its `application.conf`.

The application's main class is `io.kuicksilver.ktor.server.EngineMain` (in Gradle: `application { mainClass.set("io.kuicksilver.ktor.server.EngineMain") }`),
and `-config=<file>` picks another file, as with Ktor's own engines. The private key must be an unencrypted PKCS#8 file
(`-----BEGIN PRIVATE KEY-----`, which certbot writes); convert an older `BEGIN RSA PRIVATE KEY` or `BEGIN EC PRIVATE KEY`
file with `openssl pkcs8 -topk8 -nocrypt -in old.pem -out privkey.pem`. `TlsIdentity.fromPem` has a `password`
parameter, but encrypted keys are refused with `TlsException.Config` whatever it holds: decrypt the key before.
