# ADR-0004. The QUIC core is sans-IO

Date: 2026-10-02. Status: accepted (approved by the owner 2026-10-02).

## Context

The QUIC transport is hard to test: loss, timers, migration. quinn-proto and quiche showed that a pure state machine without I/O gives deterministic tests and reuse.

## Decision

`ConnectionCore` is a pure state machine: `handleDatagram(bytes, from, ecn, now)`, `poll(out, now)`, `nextTimeout()`, `onTimeout(now)`, `events()`. Clocks, randomness and I/O are outside. The coroutine API (`QuicConnection`) is a thin wrapper over the core. Both levels are public.

## Consequences

- A deterministic network simulator with a seed; fuzzing of the state machine; identical behaviour on every platform.
- Consumers with their own loop (for example, a real-time protocol with its own scheduler) get a low-level API.
- The price: the discipline "not a single `suspend` and not a single socket inside the core", enforced by review and an architecture test.

## Implementation (2026-10-02)

`ConnectionCore` (one connection) and `EndpointCore` (routing by DCID, Version Negotiation, accepting new connections before `accept()`) implement the decision as is: `handleDatagram`/`poll`/`nextTimeout`/`onTimeout`/`nextEvent`, with no `suspend` and no I/O of their own. The rule is checked by two scripts, both dependencies of the `check` task of the `kuicksilver-quic` module:

- `tools/check/sans-io.sh` (task `checkQuicArchitecture`) greps the packages `io.kuicksilver.quic.{wire,crypto,recovery,flow,stream,core,endpoint}` for `suspend`, `kotlinx.coroutines`, socket imports `io.ktor.network.{selector,sockets.(aSocket|Socket|Datagram|Connected|Bound|Server|TcpSocket|UDPSocket)}`, `TimeSource`, `Random.Default`, `Clock.System`.
- `tools/check/quic-imports.sh` checks the layer rule: from `kuicksilver-native`, main source sets (`*Main`, not tests) may import only `PacketBuffer` (+ `of`, `toByteArray`) and annotations.

The only approved deviation: `io.ktor.network.sockets.InetSocketAddress` is allowed in the same packages as a pure value type (the peer address), although the `io.ktor.network.sockets` package is otherwise banned — the socket itself and its methods (`connect`, `bind`, `receive`, `send`) do not enter the core. `NullTlsSession` moved to the root package `io.kuicksilver.quic` (the change "keep the scripted TLS session out of the sans-IO packages"): its `verifyPeer` is `suspend` by the original TLS contract, so it cannot live inside the checked sans-IO packages.

## Implementation (2026-10-08): several loops and dirty connections

- `EndpointCore` keeps a list of "dirty" connections (`dirtyConnections`/`markDirty`/`clearDirty`): a datagram, a timer, an application command or creation marks a connection, and `EndpointLoop.flush` visits only those; the loop's timers are a binary heap keyed by `nextTimeoutOrNever()` (`runtime/TimerHeap.kt`, the key and the index are stored in `ConnectionCore`), updated for dirty connections after a flush. Neither the flush nor the timer costs O(connections) per datagram any more.
- `LoopGroup` (`runtime/LoopGroup.kt`) is N `EndpointLoop`s on one port via `KslDatagramIo.open(reusePort = true)`; each has its own `EndpointCore(loopIndex)` (its own Retry and reset keys), the CID routing byte = the loop index (`ServerCidFormat`). `EndpointCore.ownerLoop(data, length)` reads the routing byte from a DCID in our format (−1 for Initial, VN, Retry, a client endpoint and a foreign format); a loop that does not find the connection locally copies the datagram into the owner's channel (`forwarded`, 1024 entries, overflow is a loss, the peer retransmits). An Initial is always accepted where it lands: the kernel hashes the flow by 4-tuple, forwarding is needed only after a rebind.
- Verification: `EndpointCoreTest.ownerLoopFromRoutingByte/cidRoutingByteIsLoopIndex/flushVisitsOnlyDirtyConnections`, `TimerHeapTest` (exhaustive search against a model — caught a heap removal bug that could keep a PTO timer from firing), `MultiLoopTest` (Linux: 4 loops × 100 connections × 1 MiB, forwarding to the owner without reset, rejecting `loops > 1` without the accelerated transport). The four-loop test also exposed a race in `ksl_udp`: send and receive shared one scratch buffer — the socket now has two (`udp_concurrent_send_recv_same_socket`).
