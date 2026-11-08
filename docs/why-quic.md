<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Why QUIC

What HTTP/3 over QUIC changes against HTTP/1.1 and HTTP/2 over TCP, measured: downloads under delay and loss,
head-of-line blocking, connection setup, and an address change in the middle of a download. Every number in the tables
below comes from [benchmarks/why-quic.csv](benchmarks/why-quic.csv) (one row per run), and `tools/bench/why-quic.sh
table` writes the tables from it and from [benchmarks/why-quic-env.txt](benchmarks/why-quic-env.txt). They are one
machine's measurements over an emulated network, not promises. Read [How it was measured](#how-it-was-measured) first,
and [When QUIC does not help](#when-quic-does-not-help) too.

<!-- why-quic:begin env -->
- Measured 2026-11-08T18:48:58Z on commit `bc8ac9e1d270` (the tree had uncommitted edits to: CHANGELOG.md README.md).
- Host: Apple M4 Max, 14 CPUs, Darwin 25.6.0; Docker: server 29.9.2, linux/arm64 (Docker Desktop, kernel 7.0.14-linuxkit, 14 CPUs, 15690371072 bytes).
- openjdk version "21.0.12.1" 2026-08-18; OkHttp `okhttp-jvm-5.3.2`.
- Network: loopback, MTU 1500, TSO/GSO/UDP segmentation off, tcp_no_metrics_save=1, netem delay RTT/2 per crossing (RTT/4 for rebind), loss 1-in-N per packet on ingress, no rate limit, VM netdev_max_backlog 100000 during the run; 0 packets dropped by the kernel's input backlog during the run (netdev_max_backlog 100000).
- Runs: download,hol,connect,rebind; 15 per cell, 5 per download cell with loss; 2 warm-up runs per cell; timeout 600 s per run. The download cells with loss ran at the same time, one container per RTT and loss; every other cell ran alone.
<!-- why-quic:end env -->

In short, on this setup:

- **Under loss** HTTP/3 finished a 10 MiB download sooner than every TCP client in 8 of the 9 lossy cells; at 200 ms and
  1 % loss it was level with OkHttp's HTTP/2 within the spread of 5 runs. The gap was small at 1 % loss and larger at
  3 % and 5 %.
- **A new connection** answered after about two round trips over HTTP/3 and one with 0-RTT, against three or more over
  TCP.
- **An address change** (a NAT rebinding, emulated by a relay) cost the HTTP/3 download a fraction of a second; every TCP
  download was reset by the relay and needed a second request to finish.
- **Twenty small requests under loss** took about as long over HTTP/3 as over HTTP/2, and six HTTP/1.1 connections were
  faster than both.

## How it was measured

- **One container, one emulated network.** The Kuicksilver Ktor server (HTTP/1.1 and HTTP/2 over TLS 1.3 on TCP, HTTP/3
  on UDP, the same port and certificate) and the client run in one Linux container, and every packet between them
  crosses the container's loopback once. `tc netem` delays every packet by half the round-trip time (RTT), and a `tc`
  drop on the loopback's input loses packets at random in both directions: 1 % is one in 100, 2 % one in 50, 3 % one
  in 33, 5 % one in 20. The drop sees single packets, after the kernel has cut a UDP GSO batch or a TCP segment burst
  into packets, so QUIC and TCP lose packets alike. There is no bandwidth limit: the times are set by the RTT, the
  losses and each stack's congestion control and recovery, not by a link's rate. The kernel's TCP metrics cache is
  off, so each TCP connection starts fresh like each QUIC connection.
- **The clients.** Kuicksilver's Ktor engine over HTTP/3 (`H3Only`), over HTTP/2 and over HTTP/1.1 (`H1Only`, with and
  without `http2 { enabled }`), and OkHttp 5 over HTTP/2 and HTTP/1.1 on the same JVM. OkHttp is the reference for TCP
  here: it uses the JDK's TLS and the kernel's TCP as most JVM applications do. HTTP/1.1 clients open up to 6
  connections to the server, as browsers do; HTTP/2 and HTTP/3 use one. Ktor's CIO engine is not in the tables: its
  TLS stops at 1.2, and the Kuicksilver server speaks TLS 1.3 only.
- **Kuicksilver's own TCP client was slower than OkHttp at 100 and 200 ms without loss.** During one such download the
  receive buffer of its socket (`ss -tmi` in the container) stayed near 150 KiB, while OkHttp's grew to megabytes; why
  was not established, and the engine's TCP throughput is being worked on separately, so these columns will be measured
  again. Read the OkHttp columns for what TCP does here. With loss the TCP clients are close to each other.
- **The server is Kuicksilver for every protocol**, so the HTTP/1.1 and HTTP/2 columns measure Kuicksilver's TCP
  server as well. Both stacks use CUBIC: Kuicksilver's own for QUIC, the Linux kernel's for TCP.
- **Each cell is a fresh client process** that runs two unrecorded warm-up runs over the bare loopback; then the
  emulated network is switched on and the recorded runs follow, each on a new client (a new connection with a full
  handshake) unless the scenario says otherwise. The p90 of 5 runs is the slowest of them.

## Downloads under delay and loss

One `GET` of 10 MiB on a new connection.

<!-- why-quic:begin download -->
| RTT | loss | Kuicksilver h3 | Kuicksilver h2 | Kuicksilver h1 | OkHttp h2 | OkHttp h1 | h3 / fastest TCP |
|---|---|---|---|---|---|---|---|
| 20 ms | 0 % | 0.42 / 0.59 | 0.90 / 1.65 | 1.98 / 5.06 | 1.18 / 1.97 | 0.86 / 1.34 | 0.49 |
| 20 ms | 1 % | 11.46 / 12.38 | 14.03 / 14.51 | 14.43 / 15.34 | 14.92 / 16.41 | 13.01 / 16.13 | 0.88 |
| 20 ms | 3 % | 21.86 / 24.20 | 30.74 / 32.12 | 31.58 / 33.41 | 30.93 / 33.08 | 31.21 / 32.62 | 0.71 |
| 20 ms | 5 % | 30.61 / 33.90 | 43.15 / 46.98 | 47.04 / 52.42 | 49.21 / 54.73 | 45.67 / 48.17 | 0.71 |
| 100 ms | 0 % | 1.45 / 1.51 | 8.02 / 12.95 | 6.99 / 13.81 | 3.97 / 6.56 | 3.01 / 4.16 | 0.48 |
| 100 ms | 1 % | 51.28 / 54.84 | 57.35 / 60.52 | 58.92 / 65.08 | 57.45 / 65.80 | 58.86 / 66.92 | 0.89 |
| 100 ms | 3 % | 97.23 / 104.24 | 131.24 / 133.39 | 122.39 / 129.06 | 121.94 / 135.23 | 129.68 / 138.81 | 0.80 |
| 100 ms | 5 % | 134.40 / 137.61 | 173.04 / 192.66 | 175.67 / 183.06 | 179.13 / 183.56 | 177.56 / 187.17 | 0.78 |
| 200 ms | 0 % | 2.64 / 2.73 | 17.96 / 25.44 | 10.56 / 20.67 | 4.67 / 8.07 | 3.68 / 5.76 | 0.72 |
| 200 ms | 1 % | 100.47 / 116.03 | 107.82 / 114.99 | 104.04 / 130.81 | 101.78 / 106.90 | 107.23 / 120.83 | 0.99 |
| 200 ms | 3 % | 186.41 / 204.80 | 230.62 / 244.38 | 231.50 / 256.13 | 236.26 / 253.54 | 234.52 / 241.38 | 0.81 |
| 200 ms | 5 % | 255.36 / 261.38 | 327.42 / 329.19 | 310.98 / 346.55 | 328.12 / 343.87 | 336.14 / 347.55 (1 of 5 failed) | 0.82 |

Seconds to the last byte of 10 MiB on a new connection (handshake included), median / p90 of 5 or 15 runs per cell (failed runs are counted, not timed). The last column: Kuicksilver h3's median over the smallest median of the TCP columns.
<!-- why-quic:end download -->

With loss, the HTTP/3 median is below every TCP median of its row in 8 of the 9 cells. The exception is 200 ms and 1 %
loss, where it is level with OkHttp's HTTP/2 within the spread of 5 runs. At 1 % loss the last column stays close to 1;
at 3 % and 5 % it is lower. Both stacks run CUBIC, so the difference lies in how each detects and repairs losses
(RFC 9002 against the kernel's TCP recovery), which this run does not take apart. Without loss HTTP/3 is also ahead,
but this network has no bottleneck: the time is the climb of the congestion window, and the TCP runs spread more from
run to run (compare the p90s), so those rows say little about throughput on a real link.

## Head-of-line blocking

Twenty `GET`s of 50 KiB issued at once, the way a page loads its resources. Over HTTP/2 they share one TCP connection,
so a lost packet holds up every stream behind it until it is retransmitted; over HTTP/3 a loss holds up only its own
stream; HTTP/1.1 spreads them over 6 connections.

<!-- why-quic:begin hol -->
| RTT | loss | Kuicksilver h3 | Kuicksilver h2 | Kuicksilver h1 | OkHttp h2 | OkHttp h1 |
|---|---|---|---|---|---|---|
| 100 ms | 0 % | 0.80 / 0.83 | 1.66 / 1.70 | 0.90 / 0.92 | 1.36 / 1.83 | 0.72 / 0.73 |
| 100 ms | 2 % | 7.89 / 10.85 | 9.24 / 13.16 | 1.55 / 1.73 | 8.19 / 10.62 | 1.72 / 2.00 |

Seconds from issuing 20 requests of 50 KiB at once to the last response's last byte, after one request opened the first connection (HTTP/1.1 opens its other 5 connections, handshakes included, inside the timed window); median / p90 of 15 runs per cell.
<!-- why-quic:end hol -->

Without loss both HTTP/2 clients took longer than HTTP/3 and HTTP/1.1; both talk to Kuicksilver's HTTP/2 server, which
this run does not separate from the clients. At 2 % loss HTTP/3 and HTTP/2 were close, and the six HTTP/1.1 connections were the fastest by a wide margin. The time
to the last of 20 responses is set less by head-of-line blocking than by how fast one connection's congestion window
grows back after its losses: six TCP connections have six windows. HTTP/3 removes the blocking between streams, not
the cost of sharing one congestion controller; a page whose first responses matter more than its last may gain more
than this "all 20 done" figure shows, which this run does not measure.

## Connection setup

Time from the call to the response head of a 1-byte `GET` on a new connection, RTT 100 ms, no loss. TCP needs one round
trip for its handshake, TLS 1.3 one more, then the request one more; QUIC carries the TLS handshake in its own first
round trip; with 0-RTT (`earlyData = true` in the client, `quicEarlyData = true` on the server;
[0-RTT](guide/ktor.md#0-rtt-opt-in-experimental)) a client that holds a session ticket from an earlier connection sends
the request in its first flight. The 0-RTT runs reuse one client: its connections are closed between runs
(`closeHttp3Connections()`), and each run's new connection resumes with a ticket from the one before.

<!-- why-quic:begin connect -->
| client | time to first byte, ms (median / p90) | in RTTs (median) | runs |
|---|---|---|---|
| Kuicksilver h3 | 227 / 231 | 2.3 | 15 |
| Kuicksilver h3 0-RTT | 114 / 120 | 1.1 | 15 |
| Kuicksilver h2 | 443 / 457 | 4.4 | 15 |
| Kuicksilver h1 | 334 / 342 | 3.3 | 15 |
| OkHttp h2 | 481 / 492 | 4.8 | 15 |
| OkHttp h1 | 492 / 501 | 4.9 | 15 |
<!-- why-quic:end connect -->

Three of the TCP rows take one round trip more than TCP and TLS 1.3 need. Packet captures in the container showed where,
not why:

- **Kuicksilver h2**: the first request left only after the server's second flight had arrived, one round trip after
  the client's TLS Finished. This is being worked on separately, and the row will be measured again.
- **OkHttp** on the JDK (the h1 capture; the h2 row takes as long): the client's 6-byte ChangeCipherSpec record went out
  on its own, and its Finished and the request followed only after the server had acknowledged it.

## Address change mid-download

A 50 MiB download through a relay in front of the server (`RebindRelay` in `kuicksilver-soak`, in the server process)
that stands in for a NAT losing its mapping, as home routers and carrier NATs do after a timeout or a restart. The relay
runs on the same loopback, and there is no loss; the delay per loopback crossing is a quarter of the 100 ms RTT.

- **UDP** is forwarded datagram by datagram: the QUIC connection is one end-to-end path with a 100 ms RTT. Once 25 MiB
  have passed towards the client, the relay sends the client's datagrams from a new port and closes the old one; the
  server takes this as a NAT rebinding (RFC 9000 section 9.3), validates the new path and carries on.
- **TCP** is relayed as two connections, client to relay and relay to server, each with a 50 ms RTT and its own
  congestion control. That favours TCP in the "without" column: two short control loops climb faster than one long
  one. Once 25 MiB have passed, the relay closes both connections with `SO_LINGER` 0, so each end gets a reset at once.
  A real NAT does not do that: a server answers segments from a new port with a reset, but the client hears of it only
  when its own next segment goes out from the new mapping, and a NAT that drops the old mapping's packets silently
  leaves the client waiting for its read timeout.

After a failed request the client does what a download manager does: it asks for the rest with `Range` on a new
connection. "Without" is the same download through the relay with no rebinding.

<!-- why-quic:begin rebind -->
| client | finished in one request | requests (median) | seconds with the rebind (median / p90) | seconds without (median / p90) | cost of the rebind (median) |
|---|---|---|---|---|---|
| Kuicksilver h3 | 15 of 15 | 1 | 4.14 / 5.53 | 3.60 / 6.14 | +0.54 s |
| Kuicksilver h2 | 0 of 15 | 2 | 7.99 / 9.58 | 4.58 / 6.64 | +3.41 s |
| Kuicksilver h1 | 0 of 15 | 2 | 8.51 / 23.27 | 5.34 / 16.41 | +3.16 s |
| OkHttp h2 | 0 of 15 | 2 | 7.47 / 10.17 | 4.20 / 5.79 | +3.27 s |
| OkHttp h1 | 0 of 15 | 2 | 8.35 / 9.70 | 5.17 / 9.28 | +3.19 s |

The download is 50 MiB through the NAT relay at an RTT of 100 ms; "with the rebind" counts the runs that got every byte, resumed ones included.
<!-- why-quic:end rebind -->

Every HTTP/3 download finished in its one request; no TCP download did. The TCP cost here is a kind case: the reset
reaches the client at once, and the client resumes with `Range`; a client without resume logic fails the download. A
device that
moves to another network (Wi-Fi to cellular) gets a new address rather than a new port; Kuicksilver follows it with
`Http3ConnectionMigration` ([Connection migration](guide/ktor.md#connection-migration)), which this run does not
measure.

## When QUIC does not help

- **A clean network with a low RTT.** At 20 ms and no loss each download here took two seconds or less over any
  protocol, and a client that keeps its connections open pays the handshake once; the gains above need delay, loss or
  new connections.
- **Many parallel requests under loss**, as in [Head-of-line blocking](#head-of-line-blocking): one HTTP/3 connection
  was about as fast as one HTTP/2 connection, and several HTTP/1.1 connections were faster than both.
- **CPU.** QUIC runs in user space and encrypts every packet on its own, so Kuicksilver's HTTP/3 spends more CPU per GB than
  OkHttp over the kernel's TCP; [Benchmarks](benchmarks.md#cpu-per-gb) has the server and client figures over bulk transfers.
  The client side of the downloads above (Kuicksilver's own TCP client spent more than either; its rows will be measured
  again with the engine's TCP work):

<!-- why-quic:begin cpu -->
| client | client CPU s per GB (median / p90) | runs |
|---|---|---|
| Kuicksilver h3 | 12.4 / 20.0 | 15 |
| Kuicksilver h2 | 29.6 / 46.7 | 15 |
| Kuicksilver h1 | 37.2 / 72.5 | 15 |
| OkHttp h2 | 10.5 / 19.1 | 15 |
| OkHttp h1 | 8.6 / 20.0 | 15 |

The client JVM's process CPU time (user and system, all threads, garbage collection and JIT included) over the 10 MiB downloads at 20 ms and no loss, per 10^9 bytes. Each run includes a new client and a full handshake, so fixed costs weigh in; the kernel's TCP and UDP work on the receive path is only partly in it.
<!-- why-quic:end cpu -->

- **UDP blocked or throttled.** Some networks drop UDP to port 443 or slow it down. The engine's default discovery
  learns HTTP/3 from `Alt-Svc` and races it against TCP, falling back to TCP and marking the alternative broken
  ([Racing and fallback](guide/ktor.md#racing-and-fallback)); `H3Only` has no fallback and fails there. On such a
  network nothing above applies.

## Reproducing

```bash
./gradlew --max-workers=2 :kuicksilver-soak:installWhyQuic     # the server and the clients (JVM)
bash tools/interop/build-image.sh                               # kuicksilver-interop:local and the Linux libksl
bash tools/bench/why-quic.sh --dry-run                          # the matrix; fails without tc in the image
KSL_WHYQUIC_LOSSY_REPS=5 KSL_WHYQUIC_PARALLEL=1 bash tools/bench/why-quic.sh run --out build/bench/why-quic
cp build/bench/why-quic/why-quic.csv docs/benchmarks/why-quic.csv
cp build/bench/why-quic/env.txt docs/benchmarks/why-quic-env.txt
bash tools/bench/why-quic.sh table                              # rewrites the tables of this page
```

The published run took about three hours. The full matrix (`KSL_WHYQUIC_REPS=15` everywhere, one cell after the other)
would take about a day on the host above: one 10 MiB download at 200 ms and 5 % loss takes about five minutes over
either protocol. The published run therefore made 5 runs per download cell with loss instead of 15, and ran those
cells at the same time, one container per RTT and loss (`KSL_WHYQUIC_PARALLEL=1`; they wait on the network, not on the
CPU). Every other cell ran alone, before them, with 15 runs. The script raises the Docker VM's
`net.core.netdev_max_backlog` from 1000 to 100000 for the run and restores it after: at 1000 the loopback's input
backlog dropped thousands of the packets netem releases in bursts, at 0 % loss, and TCP retransmitted them. The
environment above counts the drops during the run. The one failed OkHttp run (200 ms, 5 % loss) ended with "unexpected
end of stream" before its response head; its row's `seconds` is the 600 s timeout, which the harness at the measured
commit wrote for every failed run (it now writes how long the run took to fail). The commit line of
`why-quic-env.txt` was edited by hand after the run: the script wrote "(with local changes)" for the uncommitted
CHANGELOG.md and README.md edits, and now names such files itself. The published run also predates the script's
recording of the TCP congestion control and HyStart setting and of the SHA-256 of the soak jar and `libksl`, so the
environment above does not show them; the relay's closing of the old UDP socket and its pruning of idle flows also
came after it (during the run the old socket stayed open and dropped what reached it).
