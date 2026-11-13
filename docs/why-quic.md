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
- Measured 2026-11-09T01:48:12Z on commit `4c246665652e`.
- Host: an Apple Silicon Mac (arm64), 14 CPUs, a recent macOS; Docker: server 29.9.2, linux/arm64 (Docker Desktop, kernel 7.0.14-linuxkit, 14 CPUs, 15690371072 bytes).
- openjdk version "21.0.12.1" 2026-08-18; OkHttp `okhttp-jvm-5.3.2`.
- TCP: congestion control cubic, cubic hystart 1 (detect 3); libksl linux-aarch_64/libksl_7_linux_aarch_64.so sha256 c59eb480e6df4cdbe49f5884b0c4c6e6c7156ecd90f7f7a0fb31e6f5657f2f27; kuicksilver-soak jar sha256 7209450e1d0343a51a0bd86191450316ad364fcfd47c55c2df4135f89f3a60c5.
- Network: loopback, MTU 1500, TSO/GSO/UDP segmentation off, tcp_no_metrics_save=1, netem delay RTT/2 per crossing (RTT/4 for rebind), loss 1-in-N per packet on ingress, rate 200mbit end to end (twice that per crossing for rebind), netem queue = the rate's bytes in twice the one-way delay + 50 ms (at least 1000 packets); 0 packets dropped by the kernel's input backlog during the run (VM netdev_max_backlog 100000 for the run).
- Runs: download,hol,connect,rebind; 15 per cell, 5 per download cell with loss; 2 warm-up runs per cell; timeout 600 s per run. The download cells with loss ran at the same time, one container per RTT and loss; every other cell ran alone.
<!-- why-quic:end env -->

In short, on this setup:

- **Under loss** HTTP/3 finished a 10 MiB download sooner than every TCP client in all 9 lossy cells; at 200 ms and
  1 % loss the lead was 5 %, within the spread of 5 runs. The gap was small at 1 % loss and larger at 3 % and 5 %.
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
  into packets, so QUIC and TCP lose packets alike. The published run has a 200 Mbit/s bottleneck
  (`KSL_WHYQUIC_RATE=200mbit`): a netem rate on the loopback, end to end (a rebind cell's packets cross the loopback
  twice, so they get twice the rate per crossing), with a queue of what the rate sends in twice the one-way delay plus
  50 ms (the one qdisc carries both directions) rather than one that would add seconds of delay. The environment above
  records it, with the packets lost to a full queue rather than to the configured loss: none. The kernel's TCP metrics
  cache is off, so each TCP connection starts fresh like each QUIC connection.
- **The clients.** Kuicksilver's Ktor engine over HTTP/3 (`H3Only`), over HTTP/2 and over HTTP/1.1 (`H1Only`, with and
  without `http2 { enabled }`), and OkHttp 5 over HTTP/2 and HTTP/1.1 on the same JVM. OkHttp is the reference for TCP
  here: it uses the JDK's TLS and the kernel's TCP as most JVM applications do. HTTP/1.1 clients open up to 6
  connections to the server, as browsers do; HTTP/2 and HTTP/3 use one. Ktor's CIO engine is not in the tables: its
  TLS stops at 1.2, and the Kuicksilver server speaks TLS 1.3 only.
- **Why the rate.** An earlier run of this page without a rate, where netem hands over a whole window at once, gave TCP
  downloads without loss that varied by a factor of ten from run to run (1.6 to 16.7 s for Kuicksilver's HTTP/1.1 at
  100 ms, 1.7 to 6.8 s for OkHttp's; that run also predates this release's changes to Kuicksilver's TCP client), so
  those rows compared run-to-run luck more than clients. With the rate the same rows spread far less (1.6 to 2.5 s for
  Kuicksilver's HTTP/1.1 at 100 ms), and Kuicksilver's and OkHttp's TCP medians are within each other's spread.
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
| 20 ms | 0 % | 0.60 / 0.61 | 0.72 / 0.79 | 0.76 / 0.87 | 0.83 / 0.92 | 0.78 / 0.90 | 0.83 |
| 20 ms | 1 % | 11.70 / 11.89 | 13.45 / 15.23 | 14.29 / 14.80 | 13.33 / 14.34 | 13.18 / 14.85 | 0.89 |
| 20 ms | 3 % | 21.16 / 23.07 | 28.85 / 30.45 | 26.95 / 29.32 | 27.52 / 31.24 | 32.23 / 34.23 | 0.79 |
| 20 ms | 5 % | 29.05 / 31.08 | 41.69 / 46.05 | 42.95 / 46.40 | 48.03 / 51.15 | 49.51 / 54.24 | 0.70 |
| 100 ms | 0 % | 1.45 / 1.48 | 1.76 / 2.24 | 1.75 / 2.49 | 1.98 / 2.34 | 1.96 / 2.32 | 0.83 |
| 100 ms | 1 % | 49.34 / 61.35 | 61.24 / 67.30 | 58.56 / 64.97 | 60.79 / 65.54 | 56.74 / 63.28 | 0.87 |
| 100 ms | 3 % | 96.71 / 103.21 | 122.96 / 125.79 | 124.54 / 128.11 | 125.92 / 137.09 | 129.29 / 141.10 | 0.79 |
| 100 ms | 5 % | 133.02 / 136.45 | 177.63 / 187.92 | 181.43 / 191.85 | 196.40 / 199.07 | 173.47 / 184.31 | 0.77 |
| 200 ms | 0 % | 2.62 / 2.70 | 3.21 / 4.22 | 3.58 / 4.19 | 3.38 / 4.09 | 3.66 / 4.45 | 0.82 |
| 200 ms | 1 % | 88.20 / 98.26 | 101.22 / 112.85 | 92.77 / 114.75 | 97.63 / 114.28 | 118.84 / 123.05 | 0.95 |
| 200 ms | 3 % | 186.35 / 194.72 | 232.54 / 242.56 | 224.37 / 246.52 | 242.01 / 268.51 | 232.69 / 243.77 | 0.83 |
| 200 ms | 5 % | 258.30 / 261.77 | 324.54 / 333.92 | 345.19 / 353.64 | 319.39 / 343.81 | 328.87 / 334.62 | 0.81 |

Seconds to the last byte of 10 MiB on a new connection (handshake included), median / p90 of 5 or 15 runs per cell (failed runs are counted, not timed). The last column: Kuicksilver h3's median over the smallest median of the TCP columns.
<!-- why-quic:end download -->

With loss, the HTTP/3 median is below every TCP median of its row in all 9 cells. The closest is 200 ms and 1 % loss,
where HTTP/3's p90 is above the fastest TCP median: within the spread of 5 runs. At 1 % loss the last column stays
close to 1; at 3 % and 5 % it is lower. Both stacks run CUBIC, so the difference lies in how each detects and repairs
losses (RFC 9002 against the kernel's TCP recovery), which this run does not take apart. Without loss HTTP/3 is ahead
by about a sixth at every RTT, but 10 MiB take only 0.42 s at 200 Mbit/s: those rows are mostly the handshake and the
climb of the congestion window, not throughput.

## Head-of-line blocking

Twenty `GET`s of 50 KiB issued at once, the way a page loads its resources. Over HTTP/2 they share one TCP connection,
so a lost packet holds up every stream behind it until it is retransmitted; over HTTP/3 a loss holds up only its own
stream; HTTP/1.1 spreads them over 6 connections.

<!-- why-quic:begin hol -->
| RTT | loss | Kuicksilver h3 | Kuicksilver h2 | Kuicksilver h1 | OkHttp h2 | OkHttp h1 |
|---|---|---|---|---|---|---|
| 100 ms | 0 % | 0.78 / 0.79 | 1.06 / 1.28 | 0.86 / 0.86 | 1.00 / 2.16 | 0.70 / 0.71 |
| 100 ms | 2 % | 8.64 / 9.14 | 7.31 / 9.90 | 1.47 / 1.83 | 8.14 / 11.77 | 1.68 / 2.02 |

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
| Kuicksilver h3 | 225 / 229 | 2.3 | 15 |
| Kuicksilver h3 0-RTT | 114 / 118 | 1.1 | 15 |
| Kuicksilver h2 | 321 / 328 | 3.2 | 15 |
| Kuicksilver h1 | 324 / 328 | 3.2 | 15 |
| OkHttp h2 | 469 / 476 | 4.7 | 15 |
| OkHttp h1 | 472 / 478 | 4.7 | 15 |
<!-- why-quic:end connect -->

Kuicksilver's TCP rows take the three round trips TCP and TLS 1.3 need; its HTTP/2 client sends the first request
right after its connection preface, without waiting for the server's (RFC 9113 section 3.4). The OkHttp rows take one
round trip more. Packet captures in the container showed where, not why: on the JDK (the h1 capture; the h2 row takes
as long) the client's 6-byte ChangeCipherSpec record went out on its own, and its Finished and the request followed
only after the server had acknowledged it.

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
| Kuicksilver h3 | 15 of 15 | 1 | 3.70 / 12.46 | 3.53 / 3.96 | +0.17 s |
| Kuicksilver h2 | 0 of 15 | 2 | 4.54 / 8.87 | 3.35 / 5.49 | +1.19 s |
| Kuicksilver h1 | 0 of 15 | 2 | 5.51 / 8.04 | 3.65 / 9.48 | +1.86 s |
| OkHttp h2 | 0 of 15 | 2 | 6.13 / 8.90 | 3.45 / 5.47 | +2.68 s |
| OkHttp h1 | 0 of 15 | 2 | 5.09 / 7.90 | 3.69 / 5.52 | +1.40 s |

The download is 50 MiB through the NAT relay at an RTT of 100 ms; "with the rebind" counts the runs that got every byte, resumed ones included.
<!-- why-quic:end rebind -->

Every HTTP/3 download finished in its one request; no TCP download did. The TCP cost here is a kind case: the reset
reaches the client at once, and the client resumes with `Range`; a client without resume logic fails the download. A
device that
moves to another network (Wi-Fi to cellular) gets a new address rather than a new port; Kuicksilver follows it with
`Http3ConnectionMigration` ([Connection migration](guide/ktor.md#connection-migration)), which this run does not
measure.

## When QUIC does not help

- **A clean network with a low RTT.** At 20 ms and no loss each download here took one second or less over any
  protocol, and a client that keeps its connections open pays the handshake once; the gains above need delay, loss or
  new connections.
- **Many parallel requests under loss**, as in [Head-of-line blocking](#head-of-line-blocking): one HTTP/3 connection
  was about as fast as one HTTP/2 connection, and several HTTP/1.1 connections were faster than both.
- **CPU.** QUIC runs in user space and encrypts every packet on its own, so Kuicksilver's HTTP/3 spends more CPU per GB than
  OkHttp over the kernel's TCP; [Benchmarks](benchmarks.md#cpu-per-gb) has the server and client figures over bulk transfers.
  The client side of the downloads above (Kuicksilver's own TCP client spent more than either, about three times
  OkHttp's):

<!-- why-quic:begin cpu -->
| client | client CPU s per GB (median / p90) | runs |
|---|---|---|
| Kuicksilver h3 | 16.2 / 22.9 | 15 |
| Kuicksilver h2 | 39.1 / 44.8 | 15 |
| Kuicksilver h1 | 35.3 / 47.7 | 15 |
| OkHttp h2 | 14.3 / 21.9 | 15 |
| OkHttp h1 | 11.4 / 20.0 | 15 |

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
KSL_WHYQUIC_RATE=200mbit KSL_WHYQUIC_LOSSY_REPS=5 KSL_WHYQUIC_PARALLEL=1 \
  bash tools/bench/why-quic.sh run --out build/bench/why-quic
cp build/bench/why-quic/why-quic.csv docs/benchmarks/why-quic.csv
cp build/bench/why-quic/env.txt docs/benchmarks/why-quic-env.txt
bash tools/bench/why-quic.sh table                              # rewrites the tables of this page
```

`KSL_WHYQUIC_RATE` takes any `tc` rate (digits, an optional `k`, `m` or `g`, then `bit` or `bps`); without it the
loopback has no rate limit. `--dry-run` refuses a value that is not a rate.

The published run took about two and a half hours. The full matrix (`KSL_WHYQUIC_REPS=15` everywhere, one cell after the other)
would take about a day on the host above: one 10 MiB download at 200 ms and 5 % loss takes about five minutes over
either protocol. The published run therefore made 5 runs per download cell with loss instead of 15, and ran those
cells at the same time, one container per RTT and loss (`KSL_WHYQUIC_PARALLEL=1`; they wait on the network, not on the
CPU). Every other cell ran alone, before them, with 15 runs. The script raises the Docker VM's
`net.core.netdev_max_backlog` from 1000 to 100000 for the run and restores it after: at 1000 the loopback's input
backlog dropped thousands of the packets netem releases in bursts, at 0 % loss, and TCP retransmitted them. The
environment above counts the drops during the run. Only the TCP rebind runs failed, by design: the relay resets them,
and the table counts them as resumed.
