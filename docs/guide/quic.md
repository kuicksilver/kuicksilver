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
`quicServerConfig(tls) { }` and `quicEndpointConfig { }` (each `Builder` stays available). Every option with its default
and range is in the [configuration reference](configuration.md).

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

Flow control: each stream starts with a receive window of `initialStreamWindow` (default 512 KiB) and the connection
with `initialConnectionWindow` (768 KiB). A window is updated each time the application has read a quarter of it and
doubles, up to `maxStreamWindow` (6 MiB) / `maxConnectionWindow` (15 MiB), only while the application reads a whole
window in less than four smoothed RTTs, that is faster than the window lets the peer send (quic-go's auto-tuning rule);
the connection window stays at least 1.5 x the largest stream window. A busy reader's window settles at 4–8 x the
bandwidth-delay product, a slow reader keeps the initial window, and the ceilings bound the unread data one connection
can hold. The defaults are quic-go's. A sender blocked by a window repeats `DATA_BLOCKED` / `STREAM_DATA_BLOCKED` while
it stays blocked, and the receiver answers a stale report with its current limit, so a lost window update costs a few
PTOs, not a stall. The repeats come 1, 2, 4 and then 8 PTOs apart for the first 32, then twice as far apart each time,
up to a third of the idle timeout (the smaller of both sides' `maxIdleTimeout`; 10 s when both are zero). They are
acknowledged, so a connection blocked because its peer stopped reading stays open, at the cost of about three small
packets per idle period (about 95 in 10 minutes with the default 30 s); bound such a wait in the application if it must
not last. A report at a new limit goes out at once and starts the fast gaps again.

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
port. On macOS and iOS (JVM and Kotlin/Native) it is the same `ksl` socket without GSO and GRO, which Darwin lacks:
batches leave as one `sendmsg` per datagram, ECN marks and DF work as on Linux, and `SO_REUSEPORT` is not offered.
On Linux, Android and Apple a wildcard address (`0.0.0.0` or `::`) gives a dual-stack socket, as NIO does: one socket
bound to `::` sends to and receives from IPv4 and IPv6 peers, and IPv4 peers appear as IPv4 addresses. A specific address
keeps its own family. On Windows (Kotlin/Native and the JVM) the `ksl` socket is Winsock: `WSASendMsg`/`WSARecvMsg`,
USO/URO and ECN where the Windows version grants them (`io.capabilities` tells), DF, an exclusive bind and no
`SO_REUSEPORT` (one loop per port); a wildcard address gives a dual-stack socket there too (on a host without IPv6,
`0.0.0.0` falls back to an IPv4 socket).
With `IoPreference.Portable`, or where `ksl` cannot open its socket, the portable socket is used (NIO on the JVM,
`ktor-network` on Native); `io.capabilities` says what the socket can do and the core adapts (ECN validation, PMTUD) per
path. A QUIC server on Kotlin/Native needs the accelerated socket (Linux, Apple, Windows): without it `bind` with a `server` throws
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

## 0-RTT (opt-in, experimental)

0-RTT lets a returning client send data with its first flight instead of one round trip later (RFC 9001 section 4.6;
design in [ADR-0015](../adr/0015-0rtt-implementation.md)). It is off on both sides by default.

> **Replay warning.** An attacker who sees the client's first flight can send it to the server again (RFC 8446
> section 8). Write early only what is safe to execute twice, and act on anything else only after
> `awaitHandshake()`. The server limits replays (OpenSSL's ±10 s ticket-age check, one use per ticket in a replay
> register shared by the endpoint's loops, tickets bound to the configuration that issued them), but a replay into
> another server process with shared ticket keys passes the age check alone.

```kotlin
val server = QuicEndpoint.bind(addr, quicEndpointConfig {
    this.server = quicServerConfig(tlsServerConfig) { earlyData = true }   // tickets that allow 0-RTT
})
val client = QuicEndpoint.bind(InetSocketAddress("0.0.0.0", 0))
val config = quicClientConfig(tlsClientConfig) { earlyData = EarlyDataState.Allowed }
client.connect(addr, config).close()                 // a full handshake leaves a ticket in this endpoint
val c = client.connectEarly(addr, config)            // returns once the 0-RTT keys exist
val s = c.openBidi(); s.output.writeFully(safeRequest); s.output.flush()   // travels in 0-RTT
c.awaitHandshake()                                   // from here the connection is authenticated
```

- **Tickets** are kept per client endpoint, used once, and checked against the current trust again before use. The
  remembered transport parameters (RFC 9000 section 7.4.1) set the limits of 0-RTT. Closing the endpoint drops them.
- **Rejection.** When the server refuses 0-RTT (a changed configuration, a stale or replayed ticket), the transport
  sends the same stream data again in 1-RTT, and `earlyDataAccepted` is false. If the new limits cannot hold what was
  already sent, or `EarlyDataState.Required` was asked for, the connection closes with
  `QuicException.ConnectionLost.ZeroRttRejected`.
- **Server side.** With `earlyData = true`, `accept()` returns a connection as soon as its 0-RTT is accepted, so the
  application can answer in 0.5-RTT. `QuicStream.receivedEarly` marks streams whose data came in 0-RTT.
  `earlyDataContext` binds application settings into tickets, and `Http3Endpoint` puts its SETTINGS there. 0-RTT
  cannot be combined with client certificates.
- **Keys.** The client drops its 0-RTT key when the 1-RTT key arrives. The server drops its 0-RTT key 3 PTO after the
  first 1-RTT packet (RFC 9001 section 4.9.3).

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

### Choosing a congestion controller

| Controller | Select with | When |
|---|---|---|
| `Cubic` (default) | nothing | general use; shares a bottleneck predictably with TCP and other QUIC stacks |
| `NewReno` | `congestionController = { NewReno() }` | reference behaviour, tests |
| `Bbr` (experimental) | `congestionController = { Bbr() }` | lossy paths (radio, long-haul) and deep buffers where a loss-based controller collapses or bloats the queue |

`Bbr` implements BBRv3 as specified by draft-ietf-ccwg-bbr-06: it paces at a windowed maximum of measured delivery rates and
keeps about two bandwidth-delay products in flight, probes for more bandwidth every 2 to 3 seconds (or sooner on short
paths), and drains the queue for 200 ms every 5 seconds (ProbeRTT) to refresh its minimum RTT. Loss counts only above 2 %
of a probe's flight, and outside probes it trims the short-term model by 30 % per lossy round; an ECN-CE mark counts as a
loss. When every packet of a loss episode is acknowledged after all (reordering, a delay spike), BBR undoes the episode:
window, bounds and the interrupted probe or Startup come back. After an idle period it paces at its bandwidth estimate
instead of bursting its window, and it is paced even on sub-millisecond paths. A new peer address starts a fresh model; a
NAT rebinding keeps it. PMTUD changes keep the model in bytes and move the 4-datagram floor.

When to use it: lossy paths (radio, long-haul) where a loss-based controller collapses, deep buffers where it bloats the
queue, and paths with reordering. Keep CUBIC where the flow shares a bottleneck with TCP or other QUIC stacks and fairness
matters more than throughput.

On the simulator (virtual time; 50 Mbit/s, 40 ms, a buffer of one BDP unless noted; mean of 3 seeds; queue is the
bottleneck's time-averaged queueing delay; `BbrSimulationTest`, `BbrHarshScenarioTest`, `BbrHighRateScenarioTest`):

| Scenario | BBR | CUBIC |
|---|---|---|
| 1 % random loss | 37-40 Mbit/s | 2.7-2.9 Mbit/s |
| 10 % random loss | 1.3 Mbit/s | 0.7 Mbit/s |
| 1 % reordered by 8 ms | 43.5 Mbit/s | 3.0 Mbit/s |
| clean, 4 BDP buffer | 46.7 Mbit/s, queue 2.2 ms, no loss | 48.1 Mbit/s, queue 111 ms |
| clean, 8 BDP buffer | 46.7 Mbit/s, queue 2.3 ms | 48.0 Mbit/s, queue 274 ms |
| 0.25 BDP buffer | 46.7 Mbit/s | 47.6 Mbit/s |
| ACKs aggregated into 8 ms batches | 47.1 Mbit/s, queue 5.2 ms | 48.1 Mbit/s, queue 33.9 ms |
| 3 of 4 ACKs lost | 43.5 Mbit/s, queue 3.2 ms | 43.7 Mbit/s, queue 26.9 ms |
| 300 ms RTT | 44.9 Mbit/s, queue 76 ms | 47.4 Mbit/s, queue 211 ms |
| 1 ms RTT | 47.6 Mbit/s | 48.3 Mbit/s |
| 50 -> 5 -> 50 Mbit/s steps | 4.8 Mbit/s at 5, 46.7 after the rise | 4.8, 48.2 |
| 2 s blackhole | half the link 0.4 s after it ends | 1.2 s |
| ECN marking above 5 ms of queue | 46.5 Mbit/s, queue 0.3 ms | 43.3 Mbit/s, queue 1.5 ms |
| 1 Gbit/s, 10 ms, after 8 s idle | 948 Mbit/s, no stall | 955 Mbit/s |
| 1 Gbit/s, 0.2 ms RTT | 965 Mbit/s | 965 Mbit/s |

Caveats: BBR is experimental here (the draft is, too) and its API may change. Next to a loss-based flow it takes more or
less than half depending on the buffer: sharing one BDP of buffer with CUBIC, BBR took 67-74 % (3 seeds); in an 8 BDP
buffer the two split about evenly but CUBIC keeps the queue at 245 ms. Two BBR flows converge slowly: a flow starting 2 s after another had
29-35 % of its rate over 5-10 s, 41-48 % over 15-20 s and 43-59 % over 20-40 s (3 seeds); with 40 ms against 100 ms RTT the
longer flow got 55 % of the shorter one's rate. After the bottleneck rate drops, BBR keeps the old estimate for up to two
probe cycles and fills the buffer as CUBIC does (400 ms of queue at 5 Mbit/s in the step scenario). Above about 2 % random loss BBRv3 backs off every lossy round by design and
runs near its 4-datagram floor. At RTTs above about 1.5 s the 5 s ProbeRTT interrupts Startup's 3-round plateau test, so
Startup ends only on loss (a finite buffer ends it). Pass `Bbr(random = ...)` to seed the probe jitter; without it the
jitter is derived from send and ACK times. Each path gets its own controller, so return a fresh `Bbr()` from the factory.

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
stays 1200; the accelerated socket sets DF (in probe mode on Linux, Android and Windows; Darwin has no probe mode) and the
search runs (1452 on loopback).

## ECN

Each path validates ECN before relying on it (RFC 9000 section 13.4): the first ten packets go out with ECT(0); the peer's
ACK_ECN counts must appear, never shrink and cover every newly acknowledged marked packet, and the path must not lose all
ten test packets. A path that fails never marks again; a new path validates afresh. Received marks are counted per packet
number space only for datagrams whose packets were processed, and a CE increase reported by the peer is one congestion
event per recovery period. The portable socket marks every datagram through IP_TOS (`ecnSend`) but cannot read marks, so
with it the peer's validation of our direction needs an accelerated socket on the peer; the accelerated socket (Linux,
Android, Apple, and Windows 10 2004+ / Server 2022) marks and reads per datagram, and two of them validate both directions
(`Capable`). Because the portable socket
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
arrive (at most 32 retired IDs per connection route at once; beyond that the oldest stops early). `allowMigration = false` advertises `disable_active_migration` and drops datagrams from other addresses; a
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
three in a row and throws `PathValidationException` (an `IllegalStateException`, "path validation failed") when the new
socket never hears back, leaving the connection where it was.

Migration timing: a probe on a new path must carry a connection ID of the server that no other path used, so an
observer cannot link the two networks (RFC 9000 section 9.5). The server issues its spare IDs, up to the client's
`active_connection_id_limit` (default 4), in its first 1-RTT flight (section 5.1.1), so they normally arrive with the
handshake. If the network changes before they did (a lost datagram, a peer that issues late), `probe()` does not
reuse the active path's ID: it waits up to max(3 × PTO, 6 × initial RTT) for a `NEW_CONNECTION_ID`, probes as soon as
one arrives, and otherwise fails with `PathFailureReason.NoSpareConnectionId` (`PathEvent.Failed.reason`,
`PathValidationException.reason`) rather than as a silent path. Migrating right after `connect()` therefore needs no
wait of its own. `paths` lists the live paths (the first is the one the connection started on), `activePath` is the one it sends on now,
and `pathEvents` reports `Validated`, `Failed` and `Changed`, for
the peer's moves too, and `SocketLost` when the system took a path's socket away (see
[Suspended apps and lost sockets](#suspended-apps-and-lost-sockets)). Migration needs a confirmed handshake and a server that did not advertise `disable_active_migration`;
when the active path fails validation and no other validated path remains, the connection closes with
`ConnectionLost.NoViablePath`.

## Network changes

A phone moves between Wi-Fi and cellular; the connection can follow it instead of dying with the old network.
`NetworkMigrator` (experimental) watches a `Flow` of the platform's network handles and migrates a client connection
whenever the network changes:

```kotlin
// guide:quic:network-migrator
val migrator = NetworkMigrator(connection, networks, { DatagramIo.open(InetSocketAddress("0.0.0.0", 0)) }, scope)
val log = scope.launch { migrator.events.collect { println("network: $it") } }
migrator.start()
```

The first network the flow reports is the one the connection is on already. Each different network gets a socket from
`openIo` and a `migrate` (new path, `PATH_CHALLENGE`, switch); on success the previous path and its socket are closed and
`events` reports `MigrationEvent.Migrated(old, new, path)`. When the new network never answers, `openIo` throws or the
server advertised `disable_active_migration` (RFC 9000 section 18.2), the new socket is closed, the connection stays
where it was and `events` reports `Failed(network, cause)`. When the cause is a `PathValidationException` with
`NoSpareConnectionId` (the network changed before the server's spare connection IDs arrived and none came in time),
the migrator tries the same network again as soon as one arrives, unless the network changed meanwhile. A `null` means no network: `NetworkLost` is reported and the
migrator waits; the connection is not closed (its idle timeout decides), and if the same network comes back nothing
moves. Repeated values are ignored, and a change during a migration supersedes it: the unfinished path is closed and
nothing is reported for it (`openIo` itself is not cancelled, so keep it short: the socket it returns is closed). The
path closed after a migration is the one the connection was really on, also when it moved since (a fallback, the peer).
`network` is the network the connection is on as far as the migrator knows. `close()` (thread-safe, like `start()`)
stops following: a migration that has not switched yet is abandoned and its path and socket closed, one already
switching completes and reports `Migrated`; the connection stays open. The migrator also stops when the connection
ends, without a `Failed` for the migration it cut short. If the network flow throws, `SourceFailed(cause)` is the last
event and the migrator stops; the exception never reaches `scope`. Only a client migrates (RFC 9000 section 9): a
server connection is refused with `IllegalArgumentException`.

On Android, `followDefaultNetwork` does the wiring (API 24+):

```kotlin
val cm = context.getSystemService(ConnectivityManager::class.java)
val migrator = connection.followDefaultNetwork(cm, lifecycleScope)   // started; migrator.close() stops it
lifecycleScope.launch { migrator.events.collect { Log.i("quic", "$it") } }
```

It feeds `ConnectivityManager.registerDefaultNetworkCallback` into a started `NetworkMigrator` (`cm.defaultNetworks()`
is the flow alone). All migrators of one `ConnectivityManager` share a single callback, registered with the first and
unregistered after the last, because Android refuses more than about 100 callbacks per app (`TooManyRequestsException`,
reported as `SourceFailed`). It opens each new socket with
`DatagramIo.open(local, network, prefer)`, which binds it to that network with `Network.bindSocket` before it carries a
datagram: the portable socket before `bind`, the accelerated one through a duplicate of its descriptor that is closed
again. The default network at the call is taken as the one the connection is on (a socket that is not bound to a
network follows the default one). The AAR declares `ACCESS_NETWORK_STATE`, which the callback needs; nothing else is
added to the manifest. What stays with the app: the callback only fires while the process runs, so a connection in a
background process that Android froze or killed moves (or is lost) when the app is back; Doze and app standby cut
network access whatever the default network is; and a server that advertised `disable_active_migration` is never moved
(`Failed` events), so the app reconnects instead. As in Chromium's QUIC session pool, losing the network does not close
the connection: if no network returns within the idle timeout, the connection closes as usual.

On iOS and macOS, `followDefaultNetwork(scope)` does the same with the Network framework:

```kotlin
val migrator = connection.followDefaultNetwork(scope)   // started; migrator.close() stops it
scope.launch { migrator.events.collect { println("quic: $it") } }
```

`nwPathUpdates()` is the flow alone: one `NWPathMonitor` (C API, on its own dispatch queue) per process, started with the
first collector and cancelled after the last, reporting an `NwPathKey` for a satisfied path (the preferred interface's
index and kind, `Wifi`, `Cellular`, `Wired`, `Loopback` or `Other`) and `null` while the path is not satisfied; a path
update that keeps the interface (a new address, a DNS change) is not a new network. Each new socket comes from
`DatagramIo.open(local, interfaceIndex, prefer)`, which sets `IP_BOUND_IF` (`IPV6_BOUND_IF` for an IPv6 address) on the
accelerated socket before it carries a datagram, so the connection leaves through the new interface even before the system
prefers it. The portable socket cannot be bound: when the accelerated one is refused it is unbound and follows the default
route. No entitlement or `Info.plist` key is needed for a client; a server on the local network needs
`NSLocalNetworkUsageDescription`.

### Suspended apps and lost sockets

iOS reclaims the sockets of an app it suspends: back in the foreground, `sendmsg` and `recvmsg` fail with `ENOTCONN`,
`EBADF` or `EPIPE`, and an interface that went away answers `ENETDOWN`, `ENETUNREACH` or `EHOSTUNREACH`. Both transports
(the accelerated `ksl` socket and the portable `ktor-network` one) turn these errors into `SocketDefunctException`; a custom
`DatagramIo` throws it for the same conditions. The endpoint loop then stops reading and writing that socket, without
retrying it in a loop, and every connection reports `PathEvent.SocketLost(path, cause)` for its paths on it; the
connection is not closed. Recovery is a move to a fresh socket:

```kotlin
connection.pathEvents.collect { e ->
    if (e is PathEvent.SocketLost && e.path.id == connection.activePath?.id) connection.rebind()
}
```

`rebind(local, prefer)` opens `DatagramIo.open` on the wildcard address of the peer's family, `migrate`s there (the new path
is validated first) and closes the path it left. Like any migration it needs an unused connection ID of the server (RFC
9000 section 9.5), which arrives within a round trip after the handshake: the probe waits for one, and if none comes in
time the move fails with `PathValidationException` (`PathFailureReason.NoSpareConnectionId`) and the connection stays
where it was. A `NetworkMigrator` (and so `followDefaultNetwork`) does this on its own when the active path's socket is
lost while a network is up, reported as `Migrated` with `old == new`, and tries again once a spare ID arrives. Until a
move, the connection's idle timeout runs: a suspension longer than the idle timeout (and than the server's) ends the
connection as usual, so an app that returns after minutes reconnects, ideally with 0-RTT. A client endpoint whose own
socket was lost keeps its connections for the move but refuses `connect` at once with `SocketDefunctException`: bind a
new endpoint. A server endpoint's own socket is the exception: its clients address that port, so a lost server socket
ends the endpoint as before. iOS gives a suspended app no CPU, so nothing runs during the suspension;
`beginBackgroundTask` buys about 30 seconds to finish a transfer, and only the foreground can serve.

## Glitch protection

Every connection carries a token bucket (1000 tokens, 33 back per second) that pays for work the peer makes us do
without moving anything forward: a `DATA_BLOCKED` or `STREAM_DATA_BLOCKED` (per stream) less than one RTT after the
previous one (a stale one that comes later is answered with the current `MAX_DATA` / `MAX_STREAM_DATA` at once), a
`STREAMS_BLOCKED` repeating the same limit, a `NEW_CONNECTION_ID` for a sequence
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
loops, `connect` picks loops in turn. `loops > 1` needs a server and the accelerated transport with kernel flow hashing (Linux, Android); elsewhere,
macOS included (Darwin hands a port's unicast datagrams to one `SO_REUSEPORT` socket only) and Windows (the socket is bound
with `SO_EXCLUSIVEADDRUSE`), `bind` throws
`UnsupportedOperationException`. Inside each loop a flush visits only the connections something happened to
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
per receive batch. That step checks the Retry token, the accept queue, the hard limits (`maxConnections`,
`maxConnectionsPerIp`, 256 per IP by default) and asks `ConnectionAdmission.admit(attempt)`, which answers `Allow`,
`Retry`, `Drop` or `Close(code)`. `acceptQueue` (128 by default, shared by all loops) counts only the connections
waiting for `accept()`, not the handshakes in flight (unvalidated Initials from spoofed sources must not lock real
clients out). While it is full, a new client Initial is answered statelessly with an Initial CONNECTION_CLOSE carrying
CONNECTION_REFUSED (0x02), under the same rate limits as Retry and Version Negotiation: the client's `connect` fails
at once with `ConnectionLost.TransportClosed(code = 0x02)` and no TLS handshake is spent on it. The queue never holds
more: a handshake admitted earlier that completes while `acceptQueue` connections wait is closed with
CONNECTION_REFUSED as well. An application whose `accept()` loop lags behind bursts raises `acceptQueue`. Handshakes in
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
(`statelessPerAddressPerSecond`, 8) and in total (`statelessTotalPerSecond`, 1000). `QuicEndpoint.stats` exposes every
counter, summed over the loops (see [Observability](#observability)).

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

## Observability

Everything below is experimental (`@ExperimentalKuicksilverApi`) except `QuicConnection.stats`, `QuicEndpoint.stats` with
the first `EndpointStats` counters (`initialsDropped` to `connectionsCreated`) and `DirectoryQlogSink`, which are stable
([stability](../stability.md)). None of it costs anything per packet unless you turn it on: the counters are plain fields of the endpoint loop, and the logger and the listener are called per connection
event, not per datagram.

**Counters.** `QuicEndpoint.stats` is an `EndpointStats` snapshot summed over every loop, cheap enough to scrape every
few seconds from any thread (fields are read without a lock and may lag the loop by a few events):

| Group | Fields |
|---|---|
| Connections | `connectionsActive`, `connectionsCreated`, `connectionsAccepted` (handed to `accept()`) |
| Refusals | `connectionsRefusedAcceptQueue`, `connectionsRefusedAdmission` (policy `Drop`/`Close`), `connectionsRefusedLimits` (`maxConnections`, `maxConnectionsPerIp`), `connectionsRefusedShutdown` |
| Handshakes | `handshakesCompleted`, `handshakesFailedTimeout`, `handshakesFailedTls` (a TLS alert either way), `handshakesFailedOther` |
| 0-RTT | `zeroRttOffered`, `zeroRttAccepted`, `zeroRttRejected` |
| Datagrams | `datagramsReceived`, `datagramsSent`, `datagramsDroppedSocket`, `datagramsDroppedQueue`, `datagramsDroppedUndecryptable`, `datagramsDroppedStateless` |
| Stateless work | `initialsDropped` (new Initials discarded: a full Initial queue, `maxConnections`, `maxConnectionsPerIp`, reflective source ports, admission `Drop`), `retriesSent`, `invalidTokens`, `versionNegotiations`, `statelessResets`, `statelessRateLimited` |
| Paths | `pathValidations`, `pathValidationFailures` |
| Internal failures | `uncaughtFailures`, `sendFailures`, `listenerFailures`, `admissionContractViolations` |

```kotlin
// guide:quic:stats
val stats = server.stats
println("${stats.connectionsActive} live, ${stats.handshakesCompleted} handshakes, ${stats.connectionsRefusedAcceptQueue} refused")
```

`QuicConnection.stats` has the per-connection view (RTT, congestion window, losses, path MTU).

**Logger.** `QuicEndpointConfig.logger` takes a `KuicksilverLogger`: two methods, `isEnabled(level)` and
`log(level, message, cause)`, so bridging it to SLF4J, Logcat or `os_log` is a few lines and the library depends on no
logging framework. The default, `KuicksilverLogger.Stderr`, writes warnings and errors to standard error (what the
library did before it had a logger); `KuicksilverLogger.None` drops everything and `KuicksilverLogger.stderr(level)`
picks another threshold. `Debug` logs each connection's lifecycle (opened, handshake complete, path change, 0-RTT outcome,
close with its reason), `Info` the endpoint's (shutting down, closing), `Warn` degradations (a fallback to the portable
socket, a failing listener or qlog sink), `Error` a loop that died. A logger that throws is ignored and counted in
`listenerFailures`. A line is built only when its level is enabled. The library never
logs secrets: keys, traffic secrets, session tickets, Retry and address-validation tokens and reset tokens stay out of
every level; connection IDs and addresses are logged.

**Connection listener.** `QuicEndpointConfig.listener` takes a `ConnectionListener` whose callbacks report
`onOpened`, `onHandshakeCompleted`, `onZeroRtt` (accepted or rejected), `onPathChanged` and `onClosed` with the
`ConnectionLost` reason: who closed (`initiator`), the code and, for a transport error, the frame type. They run on the
loop that owns the connection, in order, exactly once each for opened and closed, so they must not block; an exception
out of one, a `CancellationException` included, is logged and counted in `listenerFailures`, and the connection goes on. `ConnectionInfo.id` is the original destination connection ID in
hex, the same name the connection's qlog trace has.

```kotlin
// guide:quic:observability
val observed = quicEndpointConfig {
    this.server = quicServerConfig(tlsServerConfig)
    logger = KuicksilverLogger.stderr(LogLevel.Info)
    listener = object : ConnectionListener {
        override fun onClosed(connection: ConnectionInfo, reason: QuicException.ConnectionLost) {
            println("${connection.id} ${connection.remoteAddress}: ${reason.message}")
        }
    }
}
```

## Graceful shutdown

`QuicEndpoint.shutdown(grace)` takes an endpoint out of service without cutting connections short. From the call on, a
new client's Initial is refused at once with a stateless CONNECTION_CLOSE carrying CONNECTION_REFUSED (the refusal of a
full accept queue, under the same rate limits; counted in `connectionsRefusedShutdown`) and `connect` throws
`EndpointClosing`; handshakes already in flight go on and still reach `accept()`. The live connections get `grace` to
finish; QUIC itself has no "go away" signal, so tell your peers through your application protocol (HTTP/3 has GOAWAY:
`Http3Endpoint.shutdown` and the Kuicksilver Ktor server's `stop(gracePeriod, timeout)` send it). Once the last
connection has closed, or at the deadline, whatever is left is closed with an application CONNECTION_CLOSE (`code`, 0 by
default) and the endpoint closes; `shutdown` returns when the socket is released, like `closeAndJoin`. Calling it again,
or `close()`, ends the grace period at once.

```kotlin
// guide:quic:shutdown
server.shutdown(grace = 30.seconds)
```

## qlog

`DirectoryQlogSink` writes one JSON-SEQ file per connection (schema `draft-ietf-quic-qlog-main-schema`/`quic-events`
0.3), named after the connection's original destination CID.

```kotlin
val qlogDir = "/var/log/kuicksilver/qlog"
// guide:quic:qlog
val quicWithQlog = quicConfig { qlog = DirectoryQlogSink(qlogDir) }
```

A sink is called on the endpoint loop, so a file sink on a slow disk would slow every connection of the loop. Wrap it in
`AsyncQlogSink`: the loop only queues records, and one writer on `Dispatchers.IO` (one thread at a time) opens, writes and
closes the files. Its queue holds `queueCapacity` records (8192) over all connections; a record that finds it full is
dropped and counted in `dropped`, so a stalled disk loses trace lines, never throughput. `sampleEvery = n` traces one
connection in n; `flush()` waits for what is queued and `close()` stops the writer after it.

```kotlin
// guide:quic:qlog-async
val quicWithAsyncQlog = quicConfig { qlog = AsyncQlogSink(DirectoryQlogSink(qlogDir), sampleEvery = 10) }
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
