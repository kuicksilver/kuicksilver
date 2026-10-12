# QUIC with Kuicksilver

Kuicksilver's QUIC layer (`io.kuicksilver:kuicksilver-quic`) implements QUIC v1 (RFC 9000/9001/9002) and, when
configured, the compatible version negotiation of RFC 9368/9369 towards QUIC v2 (RFC 9369). There are two levels of
API: a coroutine wrapper (`QuicEndpoint`/`QuicConnection`/`QuicStream`) for applications, and a sans-IO core
(`ConnectionCore`/`EndpointCore`) for callers with their own event loop (ADR-0004). The code blocks below compile and
run as `GuideSamplesTest` (`kuicksilver-quic/src/jvmTest`).

## Configuration

A `QuicConfig` is immutable; build it with the `quicConfig` DSL. It carries the transport settings
(windows, idle timeout, versions, congestion controller, migration, resource limits); TLS identity and trust come from the usual `TlsConfig`
(`docs/guide/tls.md`). The configs that wrap it have DSL entry points of their own: `quicClientConfig(tls) { }`,
`quicServerConfig(tls) { }` and `quicEndpointConfig { }` (each `Builder` stays available).

```kotlin
// guide:quic:config
val quic = quicConfig {
    maxIdleTimeout = 30.seconds
    initialStreamWindow = 512 * 1024L
    maxBidiStreams = 100
    versions = listOf(VersionProfile.V1)   // preference order; listOf(VersionProfile.V2, VersionProfile.V1) opts into v2 (RFC 9368/9369)
    greaseQuicBit = true                    // RFC 9287
}
```

QUIC is stricter than TLS over TCP about the `TlsConfig` it accepts (RFC 9001 section 4): TLS 1.3 only, a non-empty
`alpn` list, no `TLS_AES_128_CCM_8_SHA256`, and no `sniSelector` in v1. Building a `QuicClientConfig` or
`QuicServerConfig` from a config that breaks one of these throws `TlsException.Config` right away, not at the first
`connect`.

`initialRtt` is the round-trip time assumed before the first sample (default 333 ms, RFC 9002 §6.2.2; allowed range
(0, 10 s]). Until an ACK gives a real sample, a lost flight is resent after a PTO of 3 x `initialRtt`, doubling each
time: 1 s, 2 s, 4 s at the default, so a handshake under heavy loss gets three retransmissions within a peer's typical
10 s handshake timeout. A lower value repairs a lost first flight sooner at the price of spurious retransmissions when
the real RTT is longer (quic-go starts at 100 ms: 300 ms, 600 ms, 1.2 s ...). Consider lowering it when the peers use
`X25519MLKEM768` (each first flight spans two datagrams, so a loss is twice as likely) or for mobile clients on lossy
radio links with modest RTTs; keep the default for satellite or other long-RTT paths. It also sets the floor of a path
validation, max(3 x PTO, 6 x `initialRtt`) (RFC 9000 §8.2.4).

```kotlin
val lossyMobile = quicConfig { initialRtt = 100.milliseconds }
```

A client that prefers v2 but must start in v1 (the widely deployed version) sets `initialVersion = VersionProfile.V1`
with `versions = listOf(VersionProfile.V2, VersionProfile.V1)`: the first flight is v1, the server upgrades it through
compatible version negotiation (RFC 9368 section 2.3).

## Binding an endpoint and connecting

A socket error inside the endpoint loop ends the endpoint: every connection fails with `ConnectionLost.Internal`,
`accept()` and `connect()` throw `EndpointClosing`. A send that the socket refuses (a packet filter answering EPERM, an
unreachable route) only loses that batch of datagrams; loss detection resends what mattered. `close()` closes the socket
first, waits for a receive that is still inside the socket call, and frees the packet buffers only then. On a closed
connection `trySendDatagram` throws the connection's `ConnectionLost` instead of answering `QueueFull`, and a write on a
stream the peer stopped with `STOP_SENDING` fails with `ClosedWriteChannelException` whose cause is
`StreamError.Stopped`, including `flushAndClose()`.

`QuicEndpoint.bind` starts one endpoint loop that drives every connection it owns (docs/architecture.md, `kuicksilver-quic`). A client-only endpoint
needs no `server` in its `QuicEndpointConfig`.

The endpoint's socket comes from `DatagramIo.open(local, prefer)`. On Linux and Android the default
(`IoPreference.Accelerated`) is the `ksl` socket: batches of up to 64 datagrams per syscall with UDP GSO and GRO,
ECN marks read and written per datagram, DF in probe mode for PMTUD, and `SO_REUSEPORT` for several loops on one
port. On Windows (Kotlin/Native and the JVM) the `ksl` socket is Winsock: `WSASendMsg`/`WSARecvMsg`, USO/URO and ECN
where the Windows version grants them (`io.capabilities` tells), DF, an exclusive bind and no `SO_REUSEPORT` (one loop
per port). Everywhere else, or with `IoPreference.Portable`, the portable socket is used (NIO on the JVM, `ktor-network` on
Native); `io.capabilities` says what the socket can do and the core adapts (ECN validation, PMTUD) per path. A QUIC
server on Kotlin/Native needs the accelerated socket (Linux, Windows): on Apple `bind` with a `server` throws
`UnsupportedOperationException`, since the portable Native socket is client-only (ADR-0006).

```kotlin
// guide:quic:client-connect
val client = QuicEndpoint.bind(InetSocketAddress("0.0.0.0", 0))
val connection = client.connect(
    serverAddress,   // an InetSocketAddress; the TLS config carries the name to verify
    quicClientConfig(tlsClientConfig) { this.quic = quic },
)
```

## Opening a stream and echoing

`QuicStream` exposes a ktor-io `ByteReadChannel`/`ByteWriteChannel` pair; closing `output` sends a FIN, cancelling
`input` sends `STOP_SENDING` and the connection survives.

```kotlin
// guide:quic:echo
val stream = connection.openBidi()
stream.output.writeStringUtf8("ping\n")
stream.output.flushAndClose()
val reply = stream.input.readUTF8Line()
connection.close(code = 0, reason = "done")
```

## Accepting on the server

The server side accepts connections whose handshake already completed, then streams the peer opened in id order.

```kotlin
// guide:quic:server-accept
val server = QuicEndpoint.bind(
    InetSocketAddress("0.0.0.0", 4433),
    quicEndpointConfig { this.server = quicServerConfig(tlsServerConfig) { this.quic = quic } },
)
val incoming = server.accept()
val echoed = incoming.acceptStream()
echoed.output.writeStringUtf8(echoed.input.readUTF8Line() ?: "")
echoed.output.flushAndClose()
```

## Serving many connections

`incomingConnections()` turns `accept()` into a `Flow` that completes when the endpoint closes, and
`incomingStreams()` does the same for `acceptStream()`: it completes when the connection ends for any reason, whose
cause stays in `closed`. Cancelling a collector leaves the endpoint or the connection alone.

```kotlin
// guide:quic:incoming
supervisorScope {                                     // one failing connection or stream does not stop the others
    server.incomingConnections().collect { connection ->
        launch {
            connection.incomingStreams().collect { stream ->
                launch {
                    try {
                        if (stream.isUnidirectional) { stream.input.discard(); return@launch }   // a peer's uni stream: input only
                        val line = stream.input.readUTF8Line() ?: return@launch
                        stream.output.writeStringUtf8(line + "\n")
                        stream.output.flushAndClose()
                    } catch (e: IOException) { /* the peer reset the stream or left */ }
                }
            }
        }
    }
}
```

A stream id says who opened it and in which directions (RFC 9000 section 2.1): `isUnidirectional` and
`isClientInitiated` read it. A unidirectional stream has one half: ours only `output`, the peer's only `input`; touching
the missing half throws `IllegalStateException`.

## Congestion control

Every path runs CUBIC with HyStart++ (RFC 9438, RFC 9406) by default; NewReno stays available through
`quicConfig { congestionController = { NewReno() } }`, and any `CongestionController` implementation can be plugged in.
The controller sees packets sent, acknowledged and lost, ECN marks, MTU changes and RTT samples (`onRttSample`), and
answers with the window, the pacing rate and the burst size. A connection that migrates to a new IP starts the new path
from the initial window; a NAT rebinding keeps the state.

When the socket refuses datagrams (a send that fails, or a full send buffer that takes only part of a batch; the portable
JVM socket waits up to 5 ms once for room), the rest of the batch is lost: loss recovery repairs it and
`stats.datagramsDroppedSocket` counts it per connection. A steady rise there means the socket, not the network, is the
bottleneck.

## Path MTU

Datagrams start at 1200 bytes. On a socket that sets DF, DPLPMTUD (RFC 8899) probes upwards with PING+PADDING packets
towards min(`maxUdpPayloadSize`, the peer's `max_udp_payload_size`) (1452 by default; `QuicEndpoint` refuses a value above
its 1500-byte datagram slots at `bind`/`connect`, the sans-IO core takes up to 65527), twenty bytes at a time, at most three tries per
size; probes are not congestion controlled and their loss is not a congestion signal. Three consecutive lost large
packets, or two PTOs in a row while sending above 1200, mean the path shrank: the connection drops back to 1200, tells
the congestion controller, waits a minute, and searches again; a successful search repeats every ten minutes. The core
raises `MtuUpdated(path, mtu)`, `stats.pathMtu` and `maxDatagramSize` follow, and queued datagrams that no longer fit are
dropped (`stats.datagramsDroppedSend`). `pmtud = false` keeps 1200. The portable socket does not set DF, so there the MTU
stays 1200; the accelerated socket of Linux and Android sets DF in probe mode and the search runs (1452 on loopback).

## ECN

Each path validates ECN before relying on it (RFC 9000 section 13.4): the first ten packets go out with ECT(0); the peer's
ACK_ECN counts must appear, never shrink and cover every newly acknowledged marked packet, and the path must not lose all
ten test packets. A path that fails never marks again; a new path validates afresh. Received marks are counted per packet
number space only for datagrams whose packets were processed, and a CE increase reported by the peer is one congestion
event per recovery period. The portable socket marks every datagram through IP_TOS (`ecnSend`) but cannot read marks, so
with it the peer's validation of our direction needs an accelerated socket on the peer; the accelerated socket of Linux
and Android marks and reads per datagram, and two of them validate both directions (`Capable`). Because the portable socket
marks the whole socket, a failed validation on any of its paths clears IP_TOS for every connection on it (they all
show `Disabled` from then on: a socket's `capabilities` that lose `ecnSend` or `df` reach the paths already on it, which
stop marking or stop PMTUD and fall back to 1200 bytes; a gain applies to new paths only); the accelerated
socket keeps marking, and only the failed path sends NotEct, so one client whose path bleaches marks does not turn ECN off
for the server's other clients. `stats.ecnState` (an `EcnState`) says
where a connection stands: `Disabled`, `Testing`, `Unknown`, `Capable` or `Failed`.

## Key update

The core rotates 1-RTT keys as RFC 9001 section 6 describes: the next generation is derived when the current one is
installed, a peer's update is followed automatically, and packets of the previous phase still decrypt for three PTOs.
A caller driving `ConnectionCore` directly can start an update once the handshake is confirmed:

```kotlin
// guide:quic:key-update
if (core.initiateKeyUpdate(now)) println("key phase ${core.stats.keyUpdates}")   // false while RFC 9001 section 6.1 forbids it
```

The coroutine API exposes the same as `QuicConnection.keyUpdate()`, which suspends until RFC 9001 section 6.1 allows
the update:

```kotlin
// guide:quic:key-update-api
connection.keyUpdate()
println(connection.stats.keyUpdates)   // ours and the peer's
```

The AEAD limits of RFC 9001 section 6.6 are enforced without configuration: at 7/8 of the confidentiality limit of an
AES-GCM key the core updates keys on its own, and a connection that cannot update in time closes with
`AEAD_LIMIT_REACHED`; too many packets failing authentication close it the same way (`stats.authenticationFailures`).

## Stateless reset

When a peer loses its state (a restart, a crash) it answers our packets with a Stateless Reset (RFC 9000 section 10.3).
The connection then completes `closed` with `QuicException.ConnectionLost.StatelessReset`, every stream fails with the
same cause, and nothing more is sent. Tokens are derived from a per-endpoint key that lives inside the native layer, so
a server that restarts cannot reset connections of its previous life; a client has no way to learn the key from the
connection IDs it sees. Datagrams that merely look like a reset are counted in `stats.invalidResets` and ignored.

## Migration and paths

A server follows a client that changes address (RFC 9000 section 9). The first 1-RTT packet from a new address opens a
path under validation: the server sends a `PATH_CHALLENGE` there (and to the previous address, against an off-path
attacker replaying the client's packets), limits what it sends to the unvalidated address to three times what it
received from it, and moves the connection only on a non-probing packet with the highest packet number seen. A NAT
rebinding (same IP, new port) keeps the congestion window and RTT; a new IP starts from the initial window. When the
new path never answers within max(3 × PTO, 6 × initial RTT) the server returns to the last validated path. A rebinding
that happens before the handshake is complete (the client's retransmitted Initials arrive from a new port) cannot be
answered yet: the server follows the latest decrypted Initial or Handshake packet, with a fresh three-times budget for
the new address, sends a `PATH_CHALLENGE` there first and repeats it every PTO (the client answers once it holds
1-RTT keys), and lets the handshake itself validate the address: a challenge that is never answered settles the path
rather than closing the connection. A `PATH_CHALLENGE` of the active path always travels in its own 1200-byte
datagram ahead of everything else, and no PMTU probe goes to an address still under validation. The core
reports `PathEvent.Changed(old, new, reason)`, `PathEvent.Validated(path)` and `PathEvent.Failed(path)` events, and `pathState(id)`
answers for any path (`Closed` once a path was closed or evicted, `Unknown` for an id never issued). Every migration and every 10 000 packets the connection switches to an unused connection ID of the
peer and retires the old one; a connection ID the peer retired keeps routing for 3 × PTO so packets in flight still
arrive. `allowMigration = false` advertises `disable_active_migration` and drops datagrams from other addresses; a
move to a loopback or link-local address from a connection that did not start on one is refused unless
`allowMigrationToLoopback` is set.

A client moves on its own with a second socket:

```kotlin
// guide:quic:migration
val change = connection.migrate(DatagramIo.open(InetSocketAddress("0.0.0.0", 0)))   // addPath + probe + switchTo
println("now on ${change.new.localAddress} (${change.reason})")
```

`addPath(io)` opens a path through another socket, `probe()` validates it with a `PATH_CHALLENGE` (and re-validates a path
already validated), `switchTo()` moves the connection, `close()` forgets the path and closes its socket on the loop (on the active path it
throws `IllegalStateException` and changes nothing). `migrate` does the
three in a row and throws `IllegalStateException("path validation failed")` when the new socket never hears back, leaving the
connection where it was. `paths` lists the live paths (the first is the one the connection started on), `activePath` is the one it sends on now,
and `pathEvents` reports `Validated`, `Failed` and `Changed`, for
the peer's moves too. Migration needs a confirmed handshake and a server that did not advertise `disable_active_migration`;
when the active path fails validation and no other validated path remains, the connection closes with
`ConnectionLost.NoViablePath` (`TimeoutKind.PathValidation` exists in the API but is not produced in this version).

## Glitch protection

Every connection carries a token bucket (1000 tokens, 33 back per second) that pays for work the peer makes us do
without moving anything forward: a `*_BLOCKED` frame repeating the same limit, a `NEW_CONNECTION_ID` for a sequence
number we already hold, a `RETIRE_CONNECTION_ID` for an ID that is already retired (one for a sequence number we never issued is a
`PROTOCOL_VIOLATION`), a third PING-only packet within one
RTT (the two probes of a PTO may both be PING-only, so a pair is free). A 1-RTT packet that fails to decrypt is discarded silently and spends nothing: anyone who has seen a connection ID
can forge such packets (RFC 9000 section 12.2). A `MAX_DATA`, `MAX_STREAM_DATA` or `MAX_STREAMS` that raises nothing is
ignored for free: it is what a retransmitted or reordered update looks like (quic-go repeats `MAX_STREAMS` in every
packet until it is acknowledged, a thousand times in one interop run). An empty
bucket closes the connection with `PROTOCOL_VIOLATION` and the reason `excessive peer activity (0x10=…)`, listing the frame types that spent the tokens; `closed` then
completes with `ConnectionLost.TransportClosed(code = 0x0a)`. Honest peers never spend: retransmitted data,
keep-alive PINGs and real flow-control updates cost nothing, and `stats.glitchTokensSpent` stays at zero through a
lossy transfer. Set `glitchProtection = false` in `quicConfig { }` to turn it off for a connection.

## Several loops on one port

A server endpoint can run `loops` endpoint loops: each has its own accelerated socket bound with `SO_REUSEPORT`,
its own single-threaded dispatcher, its own admission state and its own Retry and reset keys. The kernel hashes every
client flow onto one socket, and the loop that admits a connection owns it for life: its index is the routing byte of
every connection ID that loop issues. A datagram that lands on another loop after a NAT rebind is copied to the owner;
no loop ever answers a Stateless Reset for a connection ID that names another loop. `accept()` is one queue over all
loops, `connect` picks loops in turn. `loops > 1` needs a server and the accelerated transport (Linux, Android); elsewhere
`bind` throws `UnsupportedOperationException`. Inside each loop a flush visits only the connections something happened to
since the last one, and the timers sit in a heap, so neither grows with the number of idle connections.

```kotlin
// guide:quic:loops
val withLoops = QuicEndpointConfig.Builder().apply { this.server = serverConfig; loops = 4 }.build()
```

`QuicEndpoint.bind(InetSocketAddress("0.0.0.0", 4433), withLoops)` then starts the four loops on port 4433.

## Admission and endpoint limits

A server decides per new client Initial whether to create a connection. `handleDatagram` runs only cheap checks on an
unknown Initial (1200 bytes, a supported version, a DCID of at least 8 bytes, no reflective source port such as 53 or
123) and copies it into a bounded queue of `initialQueueCap` (1024) entries; the loop then calls `processPending` once
per receive batch. That step checks the Retry token, the hard limits (`maxConnections`, `acceptQueue`,
`maxConnectionsPerIp`, 256 per IP by default) and asks `ConnectionAdmission.admit(attempt)`, which answers `Allow`,
`Retry`, `Drop` or `Close(code)`. `acceptQueue` counts only the connections waiting for `accept()`, not the handshakes
in flight (unvalidated Initials from spoofed sources must not lock real clients out), and the queue never holds more: a
handshake that completes while `acceptQueue` connections wait is closed with CONNECTION_REFUSED (0x02). Handshakes in
flight are bounded by `maxConnections`, `maxConnectionsPerIp` and the admission policy (Retry).

```kotlin
// guide:quic:admission
val config = quicEndpointConfig {
    server = serverConfig
    admission = ConnectionAdmission.default(maxInflightHandshakes = 256, maxHandshakeBufferBytes = 8L * 1024 * 1024)
    maxConnectionsPerIp = 64
    maxConnectionLifetime = 12.hours        // closed with NO_ERROR when it passes
}
```

The default policy asks for a Retry when the attempt would be more than `maxInflightHandshakes` concurrent handshakes
or the unfinished handshakes already hold more than `maxHandshakeBufferBytes`; `ConnectionAdmission.AlwaysRetry` makes
every unvalidated client prove its address first. A `Retry` for an attempt whose token already validated the address is
a contract violation: the endpoint drops the Initial and counts it in `EndpointStats.admissionContractViolations`
instead of sending a second Retry. An exception out of `admit` is treated as `Drop` and counted the same way. Stateless
answers (Retry, Version Negotiation, Stateless Reset, INVALID_TOKEN close) are rate limited per address
(`statelessPerAddressPerSecond`, 8) and in total (`statelessTotalPerSecond`, 1000). `EndpointCore.stats` exposes every
counter.

## Datagrams (RFC 9221)

Both sides advertise `max_datagram_frame_size` (65 535 by default; `maxDatagramFrameSize = 0` turns the extension off and
rejects DATAGRAM frames). On the sans-IO core, `maxDatagramPayload` says how many bytes fit one frame for the current
peer and MTU, less 32 bytes kept for a short ACK next to a full-size datagram (0 when the peer does not support datagrams); a `DatagramSender` set on the core is asked for frames while
each 1-RTT packet is built with an open congestion window, and learns through `onAcked` / `onLost` what became of each
id — datagrams are never retransmitted. Received payloads wait in a queue of 128 (`datagramReceiveQueue`); when it is
full the oldest is dropped and counted in `stats.datagramsDropped` (which also counts received UDP datagrams the connection
discarded unprocessed: from an unknown server address, a late Initial, a full undecryptable-packet buffer). The core raises `DatagramsReadable` and hands them out
with `readDatagram`.

On a `QuicConnection`:

```kotlin
// guide:quic:datagrams
connection.sendDatagram(reading, DatagramPolicy.LatestWins(key = "temperature"))   // replaces a queued reading of the same key
when (val r = connection.trySendDatagram(frame, DatagramPolicy.Reject)) { DatagramSendResult.QueueFull -> dropFrame(); DatagramSendResult.Closed -> stop(); else -> {} }
peer.datagrams.collect { d -> handle(d.data) }   // on the receiving end (the other connection of the pair)
```

`sendDatagram` copies the payload into the loop's send queue of 32 datagrams / 1 MiB (`datagramSendQueue`,
`datagramSendQueueBytes`). `DropOldest` (the default) and `LatestWins` never wait: a full queue drops its oldest entry, or
the entry with the same key. The hand-over to the loop is bounded too (at most another `datagramSendQueue` datagrams), so
a burst that outruns the loop drops its oldest datagrams even on an idle network; send a burst you cannot lose under
`Reject`. `Reject` makes `trySendDatagram` answer `QueueFull` and `sendDatagram` suspend until room
returns. `trySendDatagram` never enters the loop and allocates only the copy plus a small wrapper. A payload above
`maxDatagramSize` (a `StateFlow`, following the path MTU) gives `TooLarge` / `DatagramTooLarge`; without datagram support
on either side you get `Unsupported` / `DatagramUnsupported`. `datagrams` reads the core's 128-entry queue directly, so
what nobody collected in time is dropped there and counted in `stats.datagramsDropped` (beside the UDP datagrams the
connection discarded unprocessed).

## Testing your application

`io.kuicksilver.testing.MemoryNetwork` (module `kuicksilver-testing`) is a UDP network in memory: every `open(address)`
binds a `DatagramIo` there, and a datagram reaches the socket bound to its destination or vanishes. Give it to endpoints
through `QuicEndpointConfig.io` and the whole stack runs unchanged, OpenSSL TLS included, on every platform and without
ports. `cut(address)` makes an address go dark (and `restore` brings it back), `mtu` drops larger datagrams, `dropped`
counts what vanished; it is safe to share between endpoint loops on different threads. Like a UDP socket, each socket
holds at most `receiveBuffer` unread datagrams (256 by default) and drops what arrives on top, a datagram larger than the
receiver's slot is dropped rather than truncated, and `open` on port 0 binds a free ephemeral port (49152 and up) unless
`assignEphemeralPorts = false`. Marks are always bleached: sockets report no ECN.

```kotlin
// guide:quic:memory-network
val network = MemoryNetwork()
val wifi = InetSocketAddress("10.0.0.1", 50000)
val server = QuicEndpoint.bind(InetSocketAddress("10.0.0.2", 443), quicEndpointConfig { this.server = serverConfig; io = { network.open(it) } })
val client = QuicEndpoint.bind(wifi, quicEndpointConfig { io = { network.open(it) } })
val connection = client.connect(server.localAddress, quicClientConfig(tlsClientConfig))
val accepted = server.accept()
echo(connection, accepted, 1024)                                       // ... the application talks
network.cut(wifi)                                                      // the Wi-Fi goes dark
connection.migrate(network.open(InetSocketAddress("10.0.0.3", 50000)))   // and the client moves to LTE
```

`samples/realtime-telemetry` is a complete application built this way: its common tests run over `MemoryNetwork`,
its JVM and macOS tests over real UDP.

## Lifecycle and errors

A connection ends exactly once, and `closed` completes with the reason: `ApplicationClosed` (ours or the peer's
`close(code)`), `TransportClosed` (a protocol error, a TLS alert as `0x0100 + alert`), `Timeout`, `StatelessReset`,
`NoViablePath`, `VersionNegotiation` or `Internal`. From then on everything that waits on the connection fails with that
same exception: `openBidi`, `acceptStream`, `sendDatagram`, `keyUpdate`, `addPath`, `exportKeyingMaterial`, the stream
channels (a writer waiting for send-buffer room gets `ClosedWriteChannelException` with it as the cause) and the
`datagrams` flow, which throws it even after a local `close`; `incomingStreams()` completes instead. `trySendDatagram`
throws it too rather than answering `QueueFull`, so a caller retrying on `QueueFull` cannot spin on a dead connection.
Cancelling your own coroutine is never turned into a `QuicException`; a cancelled `connect` closes the connection it
started (CONNECTION_CLOSE, then the closing period). After `QuicEndpoint.close()`, `accept()` throws `EndpointClosing`
even for connections that had completed their handshake and were still waiting in the accept queue.

`close(code, reason)` suspends until the CONNECTION_CLOSE is sent; `close()` from `AutoCloseable` sends code 0 without
waiting. `QuicEndpoint.close()` is asynchronous too: it closes every connection and the socket on the loop after it
returns, and `connect`/`accept` throw `EndpointClosing` from then on. `pathEvents` is a hot flow without replay, so start
collecting it before `migrate` or `probe`. `stats` can be read from any thread; it is a snapshot whose fields are read
without a lock.

## qlog

`DirectoryQlogSink` writes one JSON-SEQ file per connection (schema `draft-ietf-quic-qlog-main-schema`/`quic-events`
0.3), named after the connection's original destination CID.

```kotlin
val qlogDir = "/var/log/kuicksilver/qlog"
// guide:quic:qlog
val quicWithQlog = quicConfig { qlog = DirectoryQlogSink(qlogDir) }
```

## The sans-IO core directly

`ConnectionCore` has no coroutines and no sockets (ADR-0004): `handleDatagram` feeds it a received datagram,
`poll` fills a `PacketBatch` with what it wants to send, `nextTimeoutOrNever`/`onTimeout` drive its one timer, `nextEvent`
drains application-visible events. A caller with its own loop (for example a real-time protocol with its own
scheduler) can drive it directly instead of going through `QuicEndpoint`.

```kotlin
// guide:quic:core-loop
val core = ConnectionCore.client(quic, tlsClientConfig, KslQuicCrypto, remote, Random, now)
val out = PacketBatch(capacity = 4)
try {
    while (running) {
        val n = core.poll(out, now)
        for (i in 0 until n) send(out.buffer(i), out.length(i), out.address(i)!!)
        val deadline = core.nextTimeoutOrNever()          // TimeMark.NEVER when no timer is armed; nextTimeout() is the nullable form
        val datagram = receiveOrWaitUntil(deadline)       // your socket; returns null when the deadline passed first
        now = clock()
        if (datagram != null) core.handleDatagram(datagram.buffer, datagram.length, datagram.from, Ecn.NotEct, now)
        else if (deadline <= now) core.onTimeout(now)
        while (true) { val event = core.nextEvent() ?: break; handle(event) }
    }
} finally { out.close() }
```

Stream events tell such a loop when to retry instead of polling: `StreamReadable` after new data, an end or a reset;
`StreamWritable` once acknowledgements free send-buffer room after `writeStream` took fewer bytes than offered, or once the
peer's `MAX_STREAM_DATA`/`MAX_DATA` gives credit to data that was waiting; `StreamsAvailable` once `MAX_STREAMS` raises a
limit that refused `openStream`; `StreamFinished` once a stream is done in both directions and retired.

`core` is reached through `QuicConnection.core` too (`@ExperimentalKuicksilverApi`), but it must only be touched from
the endpoint loop that owns it when the connection came from `QuicEndpoint`.
