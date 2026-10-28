<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Troubleshooting

Symptoms you may see with Kuicksilver, what causes them and what to do. Names of types, options and messages are the
ones in the code; a message shown as `"…"` is the exception's or log line's text with the variable parts in angle
brackets. Every option is listed with its default in the [configuration reference](configuration.md).

Start with [Getting more information](#getting-more-information): most questions are answered faster by a log line, a
counter or a qlog trace than by guessing.

## Getting more information

| Tool | How to turn it on | What it tells you |
|---|---|---|
| Logger | `QuicEndpointConfig.logger = KuicksilverLogger.stderr(LogLevel.Debug)`; Ktor client `engine { logger = … }`; Ktor server `logger = …` | `Debug`: each connection's lifecycle (`"<client\|server> connection <id> opened, peer <address>"`, `"connection <id> handshake complete, ALPN <alpn>"`, `"connection <id> path changed (<reason>): <old> -> <new>"`, `"connection <id> closed[ before its handshake completed]: <reason>"`); `Info`: an endpoint shutting down or closing; `Warn`: degradations such as the fallback to the portable socket; `Error`: an endpoint loop that died. Lines on standard error start with `kuicksilver: <LEVEL>` |
| Connection listener | `QuicEndpointConfig.listener` (Ktor: `http3 { connectionListener }`, server `connectionListener`) | `onOpened`, `onHandshakeCompleted`, `onZeroRtt`, `onPathChanged` and `onClosed` with the `QuicException.ConnectionLost` reason |
| Endpoint counters | `QuicEndpoint.stats` / `Http3Endpoint.stats` (`EndpointStats`) | refusals (`connectionsRefusedAcceptQueue`, `connectionsRefusedAdmission`, `connectionsRefusedLimits`, `connectionsRefusedShutdown`, `initialsDropped`), failed handshakes (`handshakesFailedTimeout`, `handshakesFailedTls`, `handshakesFailedOther`), 0-RTT, datagrams dropped at the socket or in a queue, path validations, internal failures (`uncaughtFailures`, `sendFailures`, `listenerFailures`) |
| Connection counters | `QuicConnection.stats` (`ConnectionStats`) | `smoothedRtt`, `minRtt`, `cwnd`, `bytesInFlight`, `lostPackets`, `ptoCount`, `pathMtu`, `ecnState`, `datagramsDropped`, `datagramsDroppedSend`, `datagramsDroppedSocket`, `glitchTokensSpent`, `authenticationFailures`, `invalidResets` |
| qlog | `quicConfig { qlog = AsyncQlogSink(DirectoryQlogSink(dir)) }`; Ktor client `http3 { qlog = … }`; Ktor server `qlog = …` | one `<odcid>_<client\|server>_<random>.sqlog` file (JSON-SEQ) per connection, in a directory only this user can change, readable with qvis; `ConnectionInfo.id` and the logger's `<id>` are the same original destination connection ID |
| Ktor client events | `engine { eventListener = object : KuicksilverEventListener() { … } }` | why a protocol was chosen (`protocolSelected` with a `ProtocolReason`), the race (`raceEnded`), `altSvcUsed`, `altSvcMarkedBroken`, `fallback`, `retry`, pool reuse |
| Ktor server events | `eventListener = object : KuicksilverServerEventListener() { … }` | connections per protocol, `tlsHandshakeFailed`, requests with their failure |
| Key log | `tlsConfig(…) { keylog = keylogFile(path) }` (`@DelicateKuicksilverApi`) | TLS secrets for Wireshark; see [Key logging is refused](#key-logging-is-refused) |

The logger, the listeners and the newer `EndpointStats` counters are experimental API (`@ExperimentalKuicksilverApi`, see
[stability](../stability.md)); `QuicConnection.stats` and the first `EndpointStats` counters are stable. None of it costs
anything per packet. Details: [QUIC: Observability](quic.md#observability),
[QUIC: qlog](quic.md#qlog), [Ktor: Observability](ktor.md#observability-experimental).

A failed connection's cause is always a `QuicException`: `QuicConnection.closed` completes with it, and every waiting
call (`openBidi`, `acceptStream`, the stream channels, `sendDatagram`) fails with the same instance. Look at its type and
fields before its message.

## Connecting

### `connect` fails with "Handshake timeout after 10s"

`QuicException.ConnectionLost.Timeout` with `kind = TimeoutKind.Handshake`: nothing the handshake needed came back
within `QuicConfig.handshakeTimeout` (10 s).

| Cause | How to tell | Fix |
|---|---|---|
| UDP is blocked between client and server (corporate firewall, captive portal, a cloud security group open for TCP 443 only) | the server's `EndpointStats.datagramsReceived` does not move; TCP to the same port works | open UDP on the port; with the Ktor client use `Http3DiscoveryMode.Auto` or `Preferred`, which fall back to HTTP/1.1 ([below](#the-ktor-client-never-uses-http3-or-stops-using-it)) |
| The server refuses silently: `maxConnections` (10 000) or `maxConnectionsPerIp` (256) reached | server `EndpointStats.connectionsRefusedLimits`, `initialsDropped` | raise the limits in `quicEndpointConfig { }` or spread the load |
| Wrong address or port, nothing listening | no server traffic at all; on Kotlin/Native a QUIC server needs the accelerated socket | check `QuicEndpoint.localAddress` on the server and the address the client resolved |
| Heavy loss on the first flight (radio links, a peer using `X25519MLKEM768`, whose first flights span two datagrams) | the qlog shows Initial retransmissions at 1 s, 2 s, 4 s | lower `QuicConfig.initialRtt` (default 333 ms, at most 10 s), see [QUIC: Configuration](quic.md#configuration); a client endpoint that already finished a connection to the same server address starts from its last smoothed RTT on its own |
| The client's platform verifier waits on slow OCSP or AIA fetches (`TrustConfig.Platform` on Apple and Windows) | the handshake stalls after the server's certificate arrives (qlog) | allow the verifier's network access, or verify against `AnchoredCa` |

With `ConnectionLost.VersionNegotiation` instead ("version negotiation failed: server offers [<versions>], we support
[<versions>]") the server speaks none of `QuicConfig.versions`; add `VersionProfile.V2` or `V1` as the server expects.

### `connect` fails at once with `TransportClosed(code = 0x02)`

"transport closed by Peer: code 0x2": the server refused with CONNECTION_REFUSED. A Kuicksilver server does that
statelessly when its accept queue is full (`QuicEndpointConfig.acceptQueue`, 128 connections waiting for `accept()`)
or while it shuts down (`QuicEndpoint.shutdown`, the Ktor server's `stop`). A handshake that completes into a full
queue is closed with the reason "accept queue full". The server counts them in `connectionsRefusedAcceptQueue` and
`connectionsRefusedShutdown`.

Fix on the server: accept faster (one coroutine per connection, `incomingConnections()`), or raise `acceptQueue` for
bursty arrivals. On the client, retry after a delay; during a shutdown, connect to another instance.

### The handshake fails with a certificate error

The client closes with a TLS alert: `TransportClosed(code = 0x0100 + alert, initiator = Local)` whose `cause` is a
`TlsException.Verify` with a `reason: VerifyReason`; over TCP you get the `TlsException.Verify` itself (on the JVM a
`javax.net.ssl.SSLException`). The server sees `TransportClosed(initiator = Peer)` with a `TlsException.AlertReceived`
("TLS alert received from the peer: <description> (<code>)") and counts it in `handshakesFailedTls`.

Decide on `reason`, not on the message text ("certificate verification failed: <reason>", for example
`Expired` or `HostnameMismatch(expected=…, presented=[…])`):

| `VerifyReason` | Alert | Usual cause and fix |
|---|---|---|
| `UnknownIssuer` | 48 | the chain does not lead to a trusted root: a private CA without `TrustConfig.AnchoredCa`, a server that does not send its intermediates, the JVM's `cacerts` lacking a corporate root (the JVM verifier uses the JDK store, not the OS store). Also the fallback for platform failures without a better mapping |
| `HostnameMismatch(expected, presented)` | 42 | the certificate's names (`presented`) do not include `serverName`; connecting by IP literal to a certificate without that IP is the common case. Fix the name, or use `TrustConfig.ExpectedName` behind a proxy; the check cannot be disabled |
| `PinMismatch(chainPins)` | 42 | no pin of `TrustConfig.Pinned` matches the validated chain (or a `TrustConfig.Tofu` key changed); `chainPins` lists what the chain has, leaf first. Rotate pins before rotating keys |
| `Expired`, `NotYetValid` | 45 | certificate dates, or a wrong device clock |
| `Revoked`, `UnknownRevocationStatus` | 44, 48 | the platform verifier's revocation policy (JVM PKIX, Apple, Windows soft-fail on the leaf) |
| `InvalidPurpose` | 43 | the key usage or extended key usage forbids TLS server (or client) authentication |
| `BadSignature`, `BadEncoding`, `NoCertificate` | 42 | a damaged chain, or a server that requires a client certificate the client did not configure (`identity`) |
| `CertificateTransparency` | 46 | Android's CT policy rejected the chain |
| `Custom(text)` | 46 | your `CertificateVerifier` or the platform said `text` |

Linux Kotlin/Native without a CA store (distroless or `scratch` images) fails earlier, when the client configuration
is built: `TlsException.Config` "invalid TLS configuration: ksl: no CA certificates for TrustConfig.Platform; searched
<paths>; install ca-certificates, set SSL_CERT_FILE or SSL_CERT_DIR, or use AnchoredCa". When `SSL_CERT_FILE` or
`SSL_CERT_DIR` is set, only those are searched ([TLS: Linux trust store](tls.md#linux-trust-store)).

### `QuicClientConfig` or `QuicServerConfig` cannot be built

`TlsException.Config` from `build()` means the `TlsConfig` cannot carry QUIC (RFC 9001 section 4): "QUIC requires TLS
1.3 only", "QUIC requires a non-empty ALPN list", "TLS_AES_128_CCM_8_SHA256 is not allowed in QUIC", or "sniSelector is
not supported for QUIC sessions in v1 …". A client without a reference identity fails with "a client needs serverName
(or ExpectedName) as the reference identifier". `IllegalArgumentException` from a builder names the value out of range,
for example "keepAlive must be at most 3/4 of maxIdleTimeout", "initialRtt must be positive and at most 10 s" or
"server QuicConfig.connectionIdLength (<n>) must equal the endpoint's connectionIdLength (<m>) …".

## Connections that end

### "Idle timeout after 30s"

`ConnectionLost.Timeout` with `kind = TimeoutKind.Idle`: nothing arrived for the idle timeout both peers agreed on, the
smaller of our `QuicConfig.maxIdleTimeout` (30 s) and the peer's, never below 3 x PTO; `duration` is that value. No
CONNECTION_CLOSE is sent.

- **A quiet but wanted connection** (a push channel waiting for events): set `QuicConfig.keepAlive` to a PING interval
  of at most 3/4 of `maxIdleTimeout`, for example `keepAlive = 10.seconds`; PINGs then go out at least every half of the
  effective idle timeout, also when the peer's is shorter. A NAT on the path may forget an idle UDP mapping sooner than
  30 s; keep-alive covers that too.
- **The peer's timeout is shorter**: the effective value is the minimum; raise it on both sides, or keep the connection busy with `keepAlive`. The Ktor server takes
  `quicMaxIdleTimeout` (when `quic` is not assigned; otherwise set `maxIdleTimeout` in `quic`).
- **The peer vanished** (a server restarted without a Stateless Reset, a phone lost coverage): the timeout is the
  intended outcome. A client that follows networks ([Network changes](quic.md#network-changes)) survives a change of
  network instead.
- **A stalled sender**: if the application had data to send, check `QuicConnection.stats` (`cwnd`, `bytesInFlight`,
  `ptoCount`) and the qlog; report the trace if the connection stopped sending with credit available.

`maxConnectionLifetime` on the server endpoint ends connections deliberately: `TransportClosed(code = 0)` with the
reason "connection lifetime reached". The Ktor client's `idleTimeout` (5 minutes) is a separate pool timer that closes
unused connections on the client side.

### `StatelessReset` or `ApplicationClosed`

- `ConnectionLost.StatelessReset` ("stateless reset received"): the peer lost the connection's state (a restart, a
  crash, a load balancer that sent the packets to another instance). Reconnect; behind a load balancer, route QUIC by
  connection ID or keep clients on one instance.
- `ConnectionLost.ApplicationClosed` ("application closed by <Local|Peer>: code <n> (<reason>)"): an application
  `close(code, reason)`. Over HTTP/3, `Http3Exception.fromQuic(e)` reads the code as an HTTP/3 error
  (`Http3Exception.Protocol` with an `Http3ErrorCode`, `H3_NO_ERROR` after a graceful GOAWAY).

### `TransportClosed` with a protocol error

"transport closed by <Local|Peer>: code 0x<code> (<reason>)". `code` is a `TransportError` (RFC 9000 section 20),
`frameType` the frame that triggered it (0 if none), `initiator` who detected it.

| Code | Typical reason | Meaning |
|---|---|---|
| 0x03 `FLOW_CONTROL_ERROR` | "data beyond the flow control limit: <end> > <limit>" | the peer sent beyond the window we granted: a peer bug |
| 0x04 `STREAM_LIMIT_ERROR` | "stream <id> exceeds the limit of <n>" | the peer opened more streams than `maxBidiStreams` / `maxUniStreams` allowed |
| 0x0a `PROTOCOL_VIOLATION` | "excessive peer activity (<frame types>)" | glitch protection: the peer kept sending frames that do no work ([QUIC: Glitch protection](quic.md#glitch-protection)); `glitchProtection = false` turns it off for a peer you trust |
| 0x0f `AEAD_LIMIT_REACHED` | "AEAD integrity limit reached", "AEAD confidentiality limit reached without a possible key update" | too many forged packets, or a peer that never allowed a key update |
| 0x0100 + alert | the TLS message | see [certificate errors](#the-handshake-fails-with-a-certificate-error) |

`ConnectionLost.Internal` is a bug or a failing endpoint loop: the connection is dropped without CONNECTION_CLOSE (the
peer sees an idle timeout). A loop that died is logged at `Error` ("endpoint <address> loop <n>: <what>; closing the
endpoint"), and exceptions that escaped a loop coroutine are counted in `EndpointStats.uncaughtFailures`. Please report
it with the stack trace of its `cause`.

### 0-RTT is rejected

- `StreamError.EarlyDataRejected` on a stream opened before the handshake completed: the server rejected 0-RTT, and the
  client reset every such stream (RFC 9001 section 4.6.2); nothing of it reached the server. Send it again on a new
  stream after `awaitHandshake()` (the HTTP/3 client does this itself for its early requests).
- `ConnectionLost.ZeroRttRejected` ("0-RTT rejected"): the server rejected 0-RTT and chose another ALPN than the ticket's,
  or the client asked for `EarlyDataState.Required` and got no 0-RTT. Retry on a new connection with `connectEarly` off
  or `Allowed`.
- 0-RTT never happens: the server needs `QuicServerConfig.earlyData = true` (Ktor server `quicEarlyData`), it is
  refused with client certificates, a ticket is single-use and lives in the endpoint (or Ktor engine) that received
  it, and a server whose configuration changed (ALPN, transport limits, HTTP/3 SETTINGS) refuses old tickets. The
  counters `zeroRttOffered`, `zeroRttAccepted` and `zeroRttRejected`, and `ConnectionListener.onZeroRtt`, show the
  outcome. Background: [ADR-0015](../adr/0015-0rtt-implementation.md).

## Migration and network changes

### `migrate` throws `PathValidationException`

`PathValidationException` is an `IllegalStateException` with a `reason: PathFailureReason`; the connection stays on
its old path and the new socket is closed.

| `reason` | Message | Cause and fix |
|---|---|---|
| `ValidationTimeout` | "path validation failed" | no `PATH_RESPONSE` within max(3 x PTO, 6 x `initialRtt`): the new network cannot reach the server (a captive portal, no route, UDP blocked there) |
| `NoSpareConnectionId` | "path validation failed: no spare connection ID from the peer" | the network changed before the server's spare connection IDs arrived (right after the handshake) and none came in time; retry, which `NetworkMigrator` does on its own as soon as one arrives |

`migrate` and `addPath` also throw `IllegalStateException` for "only a client migrates (RFC 9000 section 9)",
"migration before the handshake is confirmed (RFC 9000 section 9)", "the peer advertised disable_active_migration"
(reconnect instead) and "at most 4 paths". When the active path fails and no other validated path remains, the
connection ends with `ConnectionLost.NoViablePath` ("no viable path"). The same reasons arrive as
`PathEvent.Failed.reason` and `ConnectionEvent.PathFailed.reason`.

### `NetworkMigrator` reports `Failed` or `SourceFailed`

`MigrationEvent.Failed(network, cause)`: the migration to `network` failed (the causes above, or `openIo` threw); the
connection stays where it was. `MigrationEvent.SourceFailed(cause)` is the last event: the network flow threw (on
Android, `TooManyRequestsException` when the app registers more than about 100 network callbacks; `followDefaultNetwork`
shares one callback per `ConnectivityManager` to avoid it). `NetworkLost` means no network for now; the connection
waits for its idle timeout. Android needs `ACCESS_NETWORK_STATE`, which the `kuicksilver-quic` AAR declares.

### `PathEvent.SocketLost` after an iOS app comes back

iOS reclaims the sockets of a suspended app; `sendmsg`/`recvmsg` then fail with `ENOTCONN`, `EBADF`, `EPIPE` or
`ENOTSOCK`, and a vanished interface with `ENETDOWN`, `ENETUNREACH` or `EHOSTUNREACH`. Kuicksilver turns these into
`SocketDefunctException`, stops using the socket and reports `PathEvent.SocketLost(path, cause)`; the connection is not
closed. Call `QuicConnection.rebind()` (or let `followDefaultNetwork` / `NetworkMigrator` do it). A client endpoint whose
own socket is gone refuses new connections with `SocketDefunctException` "the endpoint's socket is gone: bind a new
endpoint"; bind a new `QuicEndpoint`. A server endpoint's socket loss ends the endpoint. Details:
[QUIC: Suspended apps and lost sockets](quic.md#suspended-apps-and-lost-sockets).

## Throughput and packet size

### Transfers stall over a VPN or tunnel (MTU black hole)

DPLPMTUD raises the packet size above 1200 bytes only on sockets that set DF. A path that silently drops large packets
(a tunnel with a small MTU that does not send ICMP) is detected: three lost packets above 1200 bytes, or two PTOs in a
row while a large packet is unanswered, bring the connection back to 1200 and pause the search for 60 s
([QUIC: Path MTU](quic.md#path-mtu)). Each drop costs a few round trips.

- Watch `ConnectionStats.pathMtu`, `ConnectionEvent.MtuUpdated` and the qlog.
- On a path you know is constrained, set `QuicConfig.pmtud = false` (stays at 1200) or lower `maxUdpPayloadSize`
  (default 1452, 1200..65527; a `QuicEndpoint` refuses more than 1500 with "maxUdpPayloadSize <n> exceeds the endpoint
  runtime's 1500-byte datagram slots").
- `pathMtu` stuck at 1200 on a healthy path means the socket has no DF: the portable socket is in use
  ([below](#the-accelerated-socket-is-not-used)).

### Throughput is far below the link

- **Loss-based collapse** on lossy paths (radio, long-haul): try `quicConfig { congestionController = { Bbr() } }`
  (experimental; [QUIC: Choosing a congestion controller](quic.md#choosing-a-congestion-controller)).
- **Receive windows**: a slow reader keeps the initial windows (512 KiB per stream, 768 KiB per connection); they grow
  to `maxStreamWindow` (6 MiB) and `maxConnectionWindow` (15 MiB) only while the application reads a whole window in
  under four RTTs. On a long fat path, raise `initialStreamWindow` / `initialConnectionWindow` and the maxima.
- **Send buffer**: `maxSendBuffer` (4 MiB) bounds unacknowledged data per connection; writers wait beyond it.
- **The socket refuses datagrams**: a rising `ConnectionStats.datagramsDroppedSocket` (or `EndpointStats.datagramsDroppedSocket`)
  means the send buffer, not the network, is the bottleneck.
- **ECN**: `ConnectionStats.ecnState` is `Failed` when a path bleached or mangled marks; that is harmless, ECN is just off.

## Platforms

### The accelerated socket is not used

The accelerated `ksl` socket brings batching, ECN, DF (so PMTUD) and, on Linux, GSO/GRO. When it cannot open, the
endpoint uses the portable socket (NIO on the JVM, `ktor-network` on Kotlin/Native): MTU 1200, no ECN marks read, one
datagram per call.

- When a bind of the accelerated socket is refused, the logger says once per process at `Warn`: "accelerated UDP socket
  refused on <address> (<reason>); using the portable socket". The reason is the failing system call and its error
  ("<step>: <strerror>", on Windows "<step>: WSA error <n>").
- When the one-time loopback probe fails, for example because a sandbox refuses every `bind`, the same once-per-process
  warning reads "accelerated UDP socket unavailable (<reason>); using the portable socket". Without a logger line (a
  `KuicksilverLogger.None` endpoint), tell by `QuicConnection.stats.pathMtu` staying at 1200 and `ecnState` never
  reaching `Capable`.
- A QUIC server on Kotlin/Native needs the accelerated socket; without it `bind` with a `server` throws
  `UnsupportedOperationException` ("a QUIC server on Kotlin/Native needs the accelerated ksl socket (Linux, Apple,
  Windows), which is unavailable here"), and the Ktor server serves HTTP/1.1 only, logging "HTTP/3 is not served on port
  <port>: <reason>".

### `UnsupportedOperationException` for `loops > 1`

Several endpoint loops on one port need kernel `SO_REUSEPORT` flow hashing: Linux and Android only. On macOS, iOS and
Windows `bind` throws "loops > 1 needs SO_REUSEPORT, which this platform/socket does not grant"; with a custom `io` or
the portable socket "loops > 1 needs the accelerated transport…". Use `loops = 1` there (Ktor server:
`udpSocketCount = 1`), or several processes behind a QUIC-aware load balancer.

### Windows

- The accelerated socket is Winsock with `SO_EXCLUSIVEADDRUSE`: a port another socket holds is refused, and only one
  loop per port runs. ECN needs a Windows that accepts `IP_ECN` (probed when the socket opens, verified on Windows 11); USO/URO are used where Windows grants them
  (`DatagramIo.capabilities` tells).
- A wildcard bind (`0.0.0.0` or `::`) is dual-stack; on a host without IPv6, `0.0.0.0` falls back to an IPv4 socket.
- `TrustConfig.Platform` verifies with CryptoAPI and the Windows root store, fetching missing intermediates through
  AIA; a revoked leaf is `Revoked`, an unknown revocation status is ignored.
- A server must be allowed through the Windows firewall for inbound UDP and TCP on its port.
- `keylogFile` on the JVM is refused (Windows has no POSIX permission view); on Kotlin/Native the file is only
  created ([below](#key-logging-is-refused)).

### macOS and iOS

- **App Sandbox (macOS)**: a client needs `com.apple.security.network.client`, an app that accepts connections (a
  QUIC endpoint with `server`, the Ktor server) also `com.apple.security.network.server`. Test the signed, sandboxed
  build: a refused bind may only show as the [portable-socket symptoms](#the-accelerated-socket-is-not-used).
  [Publishing on the App Store](app-store.md#4-infoplist-and-entitlements) has the entitlement templates.
- **Local network (iOS 14+, macOS 15+)**: talking to LAN devices needs `NSLocalNetworkUsageDescription` (and
  `NSBonjourServices` for Bonjour); without it the system blocks the traffic. Loopback and Internet traffic need
  neither.
- **App Transport Security** does not apply to Kuicksilver's own sockets.
- One endpoint loop per port; no GSO/GRO on Darwin.
- See [iOS](ios.md#networking-rules-on-ios) for NAT64, backgrounding and the device checklist.

### Android

`INTERNET` (declared by the `kuicksilver-native` AAR) and `ACCESS_NETWORK_STATE` (by `kuicksilver-quic`, for
`followDefaultNetwork`) come with the libraries. Doze and app standby cut network access whatever Kuicksilver does; a
frozen background process reconnects when it runs again.

Code shrinking (R8, `isMinifyEnabled` or `optimization { enable = true }`): `libksl`'s `JNI_OnLoad` finds the natives
of `io.kuicksilver.native.KslNative` and the field `PacketBuffer.buffer` by name, so R8 must neither remove nor rename
them. The `kuicksilver-native` AAR carries these rules as `proguard.txt`, and R8 applies them without any setup (since
0.2.1; with 0.2.0 a minified release build failed to load the library, `KslLoader.availability()` answered
`Unavailable` with `LoadFailed`, while debug builds worked). Add them to the app's own rules only if the build ignores
consumer rules from dependencies:

```proguard
-keep,includedescriptorclasses class io.kuicksilver.native.KslNative {
    native <methods>;
}
-keep class io.kuicksilver.native.PacketBuffer {
    java.nio.ByteBuffer buffer;
}
```

A JVM application that shrinks its jar (ProGuard in a Compose Desktop release build, R8 for a server) needs the same
rules. The `kuicksilver-native` jar carries them as `META-INF/proguard/kuicksilver-native.pro`, which R8 reads by
itself; with ProGuard, add the lines above to its configuration unless your setup applies rules embedded in jars.

The Ktor client engine is found by `HttpClient()` (without an engine argument) through `ServiceLoader`, which creates
`io.kuicksilver.ktor.client.KuicksilverEngineContainer` by name. The `kuicksilver-ktor-client` AAR and jar carry its keep
rule in the same way (`proguard.txt`, `META-INF/proguard/kuicksilver-ktor-client.pro`; since 0.2.1). Without it, a
shrunk JVM application lost the class and its `META-INF/services` entry, and `HttpClient()` picked another engine or
none. With ProGuard, or a build that ignores embedded rules, add:

```proguard
-keep class io.kuicksilver.ktor.client.KuicksilverEngineContainer {
    public <init>();
}
```

## Native library

### `KslException.NativeLoad` or `KslLoader.availability()` is `Unavailable`

Check once at startup with `KslLoader.isAvailable()` / `availability()` (experimental) instead of catching the
exception from the first connection. `NativeUnavailableReason`:

| Reason | Message (in `KslException.NativeLoad`, "cannot load libksl for <platform>/<classifier>: <reason>") | Fix |
|---|---|---|
| `NoLibraryForPlatform` | "resource META-INF/native/<name> not on the classpath" | the JVM jar has no library for this OS and CPU (see [stability: Platforms](../stability.md#platforms)); musl (Alpine) is not supported |
| `LoadFailed` | the `UnsatisfiedLinkError` text "…; if the work directory is mounted noexec set -Dkuicksilver.native.workdir" | the extraction directory (`<java.io.tmpdir>/kuicksilver-native-<user>`) is `noexec`: point `-Dkuicksilver.native.workdir` at an executable directory you own |
| `IntegrityMismatch` | "work directory <dir> is a symbolic link / is not a directory / is owned by <owner>, not by this user / keeps group/other permissions …; set -Dkuicksilver.native.workdir to a directory only you own", or "sha256 mismatch for <file>: resource was tampered with or corrupted", "duplicate native resources with different content on the classpath" | use a private directory; remove the second, different copy of `kuicksilver-native` from the classpath (two Kuicksilver versions) |
| `AbiMismatch` | `KslException.AbiMismatch` "ksl ABI <n> in the native library, <m> expected" | the native library belongs to another Kuicksilver release, usually through `-Dkuicksilver.native.path` or `-Dkuicksilver.native.system=true`; use the library of the same version ([stability](../stability.md#the-native-library-abi-ksl)) |

`KslException.Version` ("OpenSSL <found> found, OpenSSL 3.5+ (not 4.x) required") and `KslException.MissingSymbol`
appear only with a library built against a system OpenSSL, as does `KslException.NativeLoad` "SSLKEYLOGFILE is set and
the system libssl may honour it; unset it (keylog)": such a library refuses to load while `SSLKEYLOGFILE` is set. The outcome of the first load attempt is cached for the
process: fix the cause and restart.

## Ktor engines

### The engine fails to start with a Ktor version error

`IllegalStateException`: "Kuicksilver's Ktor engines support Ktor 3.6.x, but <artifact> <version> is on the classpath.
…". Creating `HttpClient(Kuicksilver)` checks `ktor-client-core`, `ktor-http-cio`, `ktor-network`, `ktor-io` and
`ktor-websockets`; starting the server checks `ktor-server-core`, `ktor-http-cio`, `ktor-network` and `ktor-io`. Align every `io.ktor` dependency to 3.6.x, best with
`platform("io.ktor:ktor-bom:3.6.<patch>")`, and look for a library that pulls a newer Ktor
(`./gradlew dependencies`). `-Dkuicksilver.ktor.versionCheck=false` skips the check at your own risk
([Ktor: Supported Ktor versions](ktor.md#supported-ktor-versions)).

### The Ktor client never uses HTTP/3, or stops using it

Check `KuicksilverEventListener.protocolSelected`'s `ProtocolReason`:

| Reason | Meaning and fix |
|---|---|
| `Configuration` | `discovery` is `H1Only` |
| `NotSecure` | the URL is not `https` (or `wss`): HTTP/3 needs TLS |
| `Proxy` | a proxy applies to the URL: HTTP/3 never goes through one (QUIC is UDP); exempt the host from the proxy for HTTP/3 |
| `NoAlternative` | `Auto` mode and the origin has not announced `h3` in `Alt-Svc` yet, or the entry expired; the first request always goes over HTTP/1.1. Use `quicHints` or `Preferred` for origins you know speak HTTP/3, and `FileAltSvcStore` to keep alternatives across restarts |
| `BrokenAlternative` | HTTP/3 to this origin failed while HTTP/1.1 worked (UDP blocked, a QUIC error), so the alternative is skipped for 5 minutes, doubling per repeat up to 2 days; `altSvcMarkedBroken` reported it. Set `networkId` so a network change forgets the marks |
| `Race` | the race went to HTTP/1.1: QUIC did not finish within its head start (1.5 x the origin's smoothed RTT, 250 ms without history, 100 ms..2 s; `hardDelay` overrides it), and on a network where QUIC was never seen working HTTP/1.1 starts after 10 ms. The QUIC setup goes on and serves the next requests |

An alternative on an unprivileged port (1024 and up) is ignored for an origin on a privileged port, and only `h3`
alternatives over verified TLS count ([Ktor: Discovery and Alt-Svc](ktor.md#discovery-and-alt-svc)).

### Requests go through a proxy, or not, unexpectedly

The Ktor client follows the platform's proxy settings by default (`proxyResolver = ProxyResolvers.System`), so a
request may go through a proxy you did not configure in code, over HTTP/1.1 (`protocolSelected` reports
`ProtocolReason.Proxy`). Set `proxyResolver = ProxyResolvers.None` to connect directly, exempt the host in the
settings (`no_proxy`, the OS bypass list), or set `proxy` explicitly. On macOS, iOS and Windows a proxy
auto-configuration (PAC script or WPAD) is not run: the engine logs one warning ("proxy auto-configuration ... does not
run") and those requests connect directly; set `proxy` or a `proxyResolver` of your own where a PAC decides the route.
A request that fails with `UnsupportedOperationException` naming a proxy scheme (`socks4://`, `https://`) has a proxy
setting the engine cannot use; it is never bypassed.

### `H3Only` requests time out

With `Http3DiscoveryMode.H3Only` there is no fallback: when UDP is blocked the call fails with Ktor's
`ConnectTimeoutException` (the engine's `connectTimeout`, 10 s, or `HttpTimeout`'s connect timeout) or the QUIC
`ConnectionLost.Timeout` ("Handshake timeout after 10s"), whichever comes first. Use `Preferred` where TCP must remain
possible.

### Requests wait and then fail with `ConnectTimeoutException`

HTTP/1.1 requests beyond `maxConnectionsPerRoute` (100) or `maxConnectionsCount` (1000) wait in FIFO order and share
the connect timeout. A pile-up usually means response bodies that are never read or closed, which keep their
connections. Read or cancel every body; raise the limits only for real concurrency. HTTP/3 requests instead wait for
the server's stream credit (MAX_STREAMS) until the request or socket timeout
([Ktor: Connection pool](ktor.md#connection-pool)).

A WebSocket over HTTP/1.1 fails with `ConnectTimeoutException` ("The WebSocket was not connected within the connect
timeout") when the server accepted the connection but did not answer the opening handshake within the connect timeout.
WebSockets to one IP address connect one at a time (RFC 6455 section 4.1), so the next one to that address waited for
this one until then.

### `H3BodyConsumed`

"421 Misdirected Request from the alternative, and the request body was already consumed": a streamed
`ReadChannelContent` body that HTTP/3 already read cannot be replayed on another connection. Send bodies the engine can
replay (bytes, a `WriteChannelContent` writer) when such retries matter.

### The server serves HTTP/1.1 but no HTTP/3

The server logs why:

- "HTTP/3 is not served on <host>:<port>: sniSelector is not supported by QUIC in v1": a `tlsConnector` with an
  `sniSelector`.
- "HTTP/3 is not served on port <port>: <reason>": the platform cannot run a QUIC server here.
- "HTTP/3 is not served: no free UDP port next to an ephemeral TCP one after 16 attempts (<cause>)": `port = 0` and
  no free UDP twin.
- A fixed port whose UDP side is taken fails the start instead.

Without HTTP/3 the server sends no `Alt-Svc`. Also check `http3 = true`, that a firewall passes UDP to the port, and
that `altSvc` is on so clients learn about HTTP/3.

## Key logging is refused

`keylogFile(path)` (`@DelicateKuicksilverApi`) refuses with `IllegalArgumentException` a path that is a symbolic link
or not a regular file, a file with other hard links or owned by another user, and a file system without POSIX
permissions ("keylog file <path>: the file system has no POSIX permissions, refusing to log secrets there", which
includes the JVM on Windows); on Android below API 26 "… java.nio.file is unavailable (Android below API 26), refusing
to log secrets there". Kotlin/Native says "keylog file <path> refused: not a regular file of this user, a symlink, or
not writable". On Android, `keylogFile(context)` returns `null` in a non-debuggable build. Use a fresh path in a
directory only you can write. `SSLKEYLOGFILE` is never read implicitly; `keylogFromEnvironment()` reads it when you
ask ([TLS: Key logging](tls.md#key-logging)).
