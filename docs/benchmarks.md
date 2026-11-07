<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Benchmarks

Goodput, CPU time per transferred GB and handshakes per second of Kuicksilver against quiche, quinn and msquic, one
host. Every cell with a Kuicksilver endpoint was measured on 2026-10-21 on the 0.2.1 performance work (commit
`01da5c08`: the client's receive path and the server's profiling fixes, see [0.2.1: before and
after](#021-before-and-after)); the pairs of two peers and the amd64 calibration rows are from the run of 2026-10-20 on
commit `c08bc57b` (0.2.0 plus 17 commits), which is also the "before" of that section. They are measurements, not
promises, and the comparison has limits that matter more than the numbers. Read the next section first.

The raw data is in [benchmarks/](benchmarks/) (`goodput.csv`, `cpu.csv`, `handshakes.csv`, and `env.txt` with the host,
Docker and every image digest). `tools/bench/run-table.sh` regenerates all of it (see [Reproducing](#reproducing)).

## Read this first

- **The amd64 peers run emulated.** The host is an Apple Silicon Mac (M4 Max, 14 cores) with Docker Desktop (arm64
  Linux VM, 14 vCPUs, 15 GB). The quiche and msquic interop images exist only for amd64, so they ran under Rosetta 2
  emulation inside the VM; quinn's image, Kuicksilver's images and the runner's simulator are native arm64. Every
  number of an emulated implementation is a lower bound on what it does on real amd64 hardware. To size the
  penalty, Kuicksilver's own Kotlin/Native endpoint was also built for amd64 and measured the same way: on this code,
  emulation cost **3–5 % more CPU per GB** and **25 % more CPU per handshake** (rows "kuicksilver Native (amd64,
  emulated)" below). That is our code under Rosetta, not theirs: their crypto and I/O paths may lose more or less.
  Where an emulated peer looks slower than Kuicksilver, this run does not show that Kuicksilver is faster; where it
  looks faster even emulated (msquic, below), it is.
- **These are the peers' interop endpoints, not their tuned servers.** Each image is what the QUIC Interop Runner runs:
  test clients and servers with the flags their maintainers chose for interop (quiche runs `--disable-gso
  --disable-pacing` and logs to a file; quinn's image `stammw/quinn-interop:latest` was built on 2024-09-02 and logs at
  `info`). Kuicksilver's interop endpoint is no better: its client buffers the whole download before writing it, and its
  server writes a file in 1 MiB pieces (it read the whole file into memory per request until 0.2.1). None of this is how
  a production deployment would run.
- **Goodput is capped by the simulated link.** The runner's goodput measurements run over a 10 Mbit/s link with 15 ms
  delay each way; every implementation fills it. They show that nothing is broken and how the congestion controller
  shares the link with TCP, not which stack is faster.
- **One host, two days.** The morning images measured again in the 2026-10-21 session were within 2 % of their
  2026-10-20 numbers (client CPU per GB from quinn 18.20 vs 18.17, Kuicksilver against itself 6.74 vs 6.68 and 5.48 vs
  5.44; handshakes 1745–1767 vs 1748 and 1348–1384 vs 1390 per second), so the rows of the two runs compare.
- **One host.** No other build or container set ran during the measurements; the Docker VM is shared with
  macOS. Results from Linux hosts, or from GitHub-hosted runners, will differ.

## Goodput

The QUIC Interop Runner's `goodput` (one 10 MB download) and `crosstraffic` (one 25 MB download while a TCP CUBIC
iperf flow competes for the same link) measurements, in its ns-3 simulator (`simple-p2p --delay=15ms --bandwidth=10Mbps
--queue=25`), runner `740c05a` (`tools/interop/runner.lock`), five repetitions per cell. Goodput is the runner's own
number: file bits over the time between the first and the last 1-RTT packet from the server in the client-side trace.
In every cell the **server sends the data**, so the server's congestion controller decides the crosstraffic share; in
the rows where Kuicksilver is the client, the peer's controller is measured more than Kuicksilver.

kbit/s per repetition: median [min–max] (n repetitions). The runner stops a cell at its first failed repetition.

| server | client | goodput kbit/s | crosstraffic kbit/s | failed |
|---|---|---|---|---|
| kuicksilver JVM | quiche (amd64, emulated) | 9273 [9265–9275] (n=5) | 5392 [5364–5956] (n=5) | 0 |
| kuicksilver JVM | quinn | 9401 [9400–9401] (n=5) | 3903 [3743–4042] (n=5) | 0 |
| kuicksilver JVM | msquic (amd64, emulated) | 9429 [9423–9431] (n=5) | – | 1 (see below) |
| kuicksilver Native | quiche (amd64, emulated) | 9286 [9261–9290] (n=5) | 5812 [5458–5967] (n=5) | 0 |
| kuicksilver Native | quinn | 9404 [9396–9409] (n=5) | 4186 [3896–4443] (n=5) | 0 |
| kuicksilver Native | msquic (amd64, emulated) | 9434 [9430–9441] (n=5) | – | 1 (see below) |
| quiche (amd64, emulated) | kuicksilver JVM | 9378 [9320–9387] (n=5) | 5008 [4774–5644] (n=5) | 0 |
| quinn | kuicksilver JVM | 9313 [9277–9359] (n=5) | 3826 [3118–4471] (n=5) | 0 |
| msquic (amd64, emulated) | kuicksilver JVM | 9204 [8849–9384] (n=5) | 7978 [6807–8686] (n=5) | 0 |
| quiche (amd64, emulated) | kuicksilver Native | 9386 [9368–9392] (n=5) | 5378 [5042–5441] (n=5) | 0 |
| quinn | kuicksilver Native | 9348 [9311–9355] (n=5) | 3898 [3125–4102] (n=5) | 0 |
| msquic (amd64, emulated) | kuicksilver Native | 9248 [8970–9412] (n=5) | 8732 [7422–8868] (n=5) | 0 |

- **Kuicksilver server, msquic client, crosstraffic:** msquic's interop client gives a download 50 s
  (`-test:D -timeout:50000` in its `run_endpoint.sh`). 25 MB in 50 s needs 4.0 Mbit/s, about what Kuicksilver's CUBIC
  takes against the TCP flow (4.2 Mbit/s in the 2026-10-20 run); msquic's client ended the first repetition of either
  image at 49.9 s ("Request closed incomplete"), and the runner stops a cell at its first failed repetition. These cells
  are censored by the peer's timeout, not failed transfers.
- **msquic server, Kuicksilver client, goodput:** some repetitions are 2–6 % slower, with either client: three of five
  with each here, four of five (JVM) and two of five (Native) on 2026-10-20. The packet captures show the cause on
  msquic's side; see [msquic's goodput outlier](#msquics-goodput-outlier).
- **Against the 0.2.0 check** (a local run of the 0.2.0 release check on 2026-10-16, logs not published; JVM image,
  quinn and ngtcp2; quinn is the overlap): kuicksilver→quinn goodput median 9389 then, 9401 now; crosstraffic 4409 then, 3903 now; quinn→kuicksilver
  goodput 9310 then, 9313 now; crosstraffic 3238 then, 3826 now. Every floor in `tools/interop/perf-thresholds.json` for
  these cells is met. The JVM server's crosstraffic share against quinn's client came out lower than on 2026-10-20
  (3903 [3743–4042] vs 4234 [4063–4460]). Measured again alone, 16 rounds each of the 2026-10-20 image, the
  receive-path image and the merged image interleaved (A, B, C, A, B, C, …; one repetition each, laptop on AC power,
  `pmset` every 30 s: 100 % charged, no thermal or performance warnings in 172 samples), the three overlap: median
  4100, 4089 and 3961 kbit/s, ranges 3693–4542, 3568–4436 and 3596–4319; the merged image was below the 2026-10-20 one
  in 8 of 16 rounds (two-sided permutation test p = 0.26; the receive-path image p = 0.96). Per repetition the share
  follows the server's losses against the TCP flow and its mean congestion window (qlog: 88–142 losses, 26–33 kB, in
  all three), and the server's ACK-arrival-to-next-send gaps are the same in all three (median 0.16 ms, 90th
  percentile 0.34 ms, 2 % of them 1 ms or more), so the 1 ms socket wait does not delay its sends. The earlier
  difference is within this cell's spread between runs; at 16 rounds a difference of a few percent cannot be excluded,
  and the qlog gaps show no mechanism for one.

## CPU per GB

One bulk download (hq-interop `GET` of a 1 GiB random file, the runner's `transfer` case) between two interop images
over a plain Linux router instead of the simulator: no rate limit, no added delay, kernel forwarding between two Docker
bridges (`tools/bench/compose.yml`). CPU is the cgroup v2 `cpu.stat` `usage_usec` (user + system) of each endpoint's
container, read inside the container:

- **server:** the server process stays up for the whole pair; it serves one unmeasured warm-up transfer, then its CPU is
  read just before each new client container starts and just after it exits, so the server is warm (a JIT has compiled
  its hot path) and only that transfer and its handshake are counted;
- **client:** a new client container per transfer, counted over its whole life, start-up included;
- **per GB:** five rounds of one 1 GiB and one 1 MiB transfer; each big transfer's CPU minus the median CPU of the
  small ones, over the 1 073 741 824 − 1 048 576 bytes between them, scaled to 10⁹ bytes. Process start-up, the
  handshake and a JVM's start-up cancel; a JVM client's JIT compilation does not.

Kernel work done in softirq context (most of the receive path and the forwarding) is not charged to any container, so
these numbers undercount every implementation's networking cost, more so for those that receive more packets.

Each implementation against itself, median [min–max] of the five big transfers. Datagram = the server's mean IP packet
size; ACK ratio = packets from the client per 100 from the server (both from the router's interface counters); wall
Gbit/s = file bits over the client container's life (start-up included), indicative only.

| implementation | server CPU s/GB | client CPU s/GB | server system time | datagram bytes | ACK ratio | wall Gbit/s |
|---|---|---|---|---|---|---|
| kuicksilver JVM | 2.72 [2.63–3.65] | 4.91 [4.88–4.97] | 62 % | 1494 | 9.5 | 2.60 |
| kuicksilver Native | 3.47 [3.44–3.62] | 3.64 [3.61–3.70] | 50 % | 1491 | 9.3 | 2.16 |
| quiche (amd64, emulated) | 11.47 [11.42–12.44] | 7.38 [7.35–7.56] | 31 % | 1392 | 10.0 | 0.66 |
| quinn | 15.56 [15.50–15.69] | 13.69 [13.59–13.83] | 71 % | 1440 | 30.2 | 0.65 |
| msquic (amd64, emulated) | 1.86 [1.84–1.93] | 2.68 [2.66–2.71] | 67 % | 1506 | 1.0 | 1.01 |
| *calibration:* kuicksilver Native (amd64, emulated), `c08bc57b` | 5.62 [5.62–5.73] | 5.70 [5.69–5.80] | 46 % | 1494 | 6.4 | 1.31 |

The calibration row is the morning's code; on that code the arm64 Native image measured 5.43 (server) and 5.44 (client)
s/GB, so emulation added 3–5 %.

What this says, and what it does not:

- **msquic uses less CPU per GB than Kuicksilver even under emulation**: 1.9 vs 2.7–3.5 s/GB as a server, 2.7 vs
  3.6–4.9 s/GB as a client. It sends 1506-byte packets and its client acknowledges about one packet in a hundred.
- Kuicksilver is below **quiche and quinn as their interop images run here** — quiche emulated, with GSO and pacing
  off; quinn from a 2024 build whose client acknowledges every third packet and whose server spends 71 % of its CPU
  in the kernel. That is a statement about these images on this host, not about quiche or quinn.
- **The JVM server's system-time share rose from 53 to 62 %** because its user time fell (1.85 → 1.03 s/GB: the
  whole-file read and the receive hand-offs are gone) while its system time, mostly `sendmsg` and `recvmsg`, fell less
  (2.05 → 1.73 s/GB).
- **Kotlin/Native costs 28 % more than the JVM as a server** (3.5 vs 2.7 s/GB; 5.4 vs 3.9 before 0.2.1); as a client
  the JVM costs more (4.9 vs 3.6, which includes the JIT's compilation and the interop client's whole-file buffering).

Every pair, median of the five big transfers (row: server, column: client; `failed`: the transfer did not complete in
any round — quiche's client against msquic's server, a peer pair, not investigated):

Server CPU s/GB:

| server \ client | kuicksilver JVM | kuicksilver Native | quiche (amd64, emulated) | quinn | msquic (amd64, emulated) |
|---|---|---|---|---|---|
| kuicksilver JVM | 2.72 | 2.55 | 2.51 | 3.12 | 2.20 |
| kuicksilver Native | 3.68 | 3.47 | 3.20 | 4.08 | 2.99 |
| quiche (amd64, emulated) | 12.17 | 12.33 | 11.47 | 13.11 | 11.34 |
| quinn | 12.65 | 12.27 | 12.27 | 15.56 | 12.71 |
| msquic (amd64, emulated) | 2.74 | 2.71 | failed | 2.83 | 1.86 |

Client CPU s/GB:

| server \ client | kuicksilver JVM | kuicksilver Native | quiche (amd64, emulated) | quinn | msquic (amd64, emulated) |
|---|---|---|---|---|---|
| kuicksilver JVM | 4.91 | 3.34 | 5.57 | 6.22 | 2.59 |
| kuicksilver Native | 4.96 | 3.64 | 5.56 | 6.18 | 2.42 |
| quiche (amd64, emulated) | 5.93 | 5.32 | 7.38 | 7.34 | 3.55 |
| quinn | 8.42 | 7.37 | 7.75 | 13.69 | 6.01 |
| msquic (amd64, emulated) | 4.65 | 3.46 | failed | 5.26 | 2.68 |

The server's cost depends on its client (how often it acknowledges) and the client's on its server (how the data
arrives), so a row or a column alone is not one implementation's cost.

## Handshakes per second

The server under the same load for every row: 8 client containers of Kuicksilver's Kotlin/Native interop image (arm64,
native) started together, each running the runner's `multiconnect` case over 1500 requests of a 32-byte file — one new
connection per request, one after another, with the runner's certificate (ECDSA P-256, chain length 1) and the
default key exchange of each side. A warm-up batch of 100 connections per client runs first against the same server
process. Rate = 12 000 handshakes over the time from the first client's start to the last client's exit (container
times, so client start-up is in it); server CPU from its cgroup over the measured batch. Five runs per server, median
[min–max].

| server | handshakes/s | server CPU ms per handshake | server cores busy |
|---|---|---|---|
| kuicksilver JVM | 1750 [1739–1753] | 0.95 [0.94–0.96] | 1.66 |
| kuicksilver Native | 1524 [1503–1530] | 0.79 [0.79–0.80] | 1.21 |
| quiche (amd64, emulated) | 228 [214–232] | 4.40 [4.33–4.68] | 1.00 |
| quinn | 3452 [3427–3462] | 0.53 [0.52–0.53] | 1.82 |
| msquic (amd64, emulated) | 3543 [3532–3567] | 0.70 [0.69–0.71] | 2.50 |
| *calibration:* kuicksilver Native (amd64, emulated), `c08bc57b` | 1100 [1091–1108] | 1.15 [1.14–1.16] | 1.27 |

- This is comparative because the client side is the same for every row; it is a handshake-plus-one-request rate
  (each connection also carries a GET and a close), not a bare TLS handshake rate.
- **quinn handshakes at two thirds of Kuicksilver's CPU (Native) and twice its rate; msquic, emulated, at 0.7 ms and 2.5
  cores.** In a trial with 16 clients × 750 connections, quinn's rate was within 5 % of this one, so the load generator
  was not what held quinn back at ~3500/s; whether quinn or msquic could go higher with more load was not explored.
- quiche's interop server runs one thread and is pinned at 1.00 core; at 4.4 ms per handshake it was much slower here
  than in a short trial (1.25 ms with 16 × 200 connections), so its cost grows over 12 000 connections in this image.
  Under emulation; not a statement about quiche in production.
- Kuicksilver's server loop (both builds) did not use more than about 1.2 (Native) or 1.7 (JVM, garbage collector and
  JIT threads included) cores here.

## 0.2.1: before and after

Two changes, measured together: the **client's receive path** (the endpoint loop reads the socket on
its own thread while datagrams keep coming, `ksl_udp_recv` takes one system call per datagram on Linux, Android and
Apple) and the **server's profiling fixes** (`PacketBuffer` index checks inline on Kotlin/Native,
timers and the DATAGRAM sender without exceptions, and the interop server streaming files and forgetting ended
connections). "Before" is the run of 2026-10-20 on `c08bc57b`, "after" the merged tree on 2026-10-21 (the tables above);
median of five transfers or runs.

| | before | after |
|---|---|---|
| client CPU s/GB: quinn → kuicksilver JVM | 18.17 | 8.42 |
| quinn → kuicksilver Native | 9.07 | 7.37 |
| quiche → kuicksilver JVM | 13.88 | 5.93 |
| quiche → kuicksilver Native | 12.19 | 5.32 |
| msquic → kuicksilver JVM | 6.81 | 4.65 |
| msquic → kuicksilver Native | 5.09 | 3.46 |
| kuicksilver JVM → JVM | 6.68 | 4.91 |
| kuicksilver Native → Native | 5.44 | 3.64 |
| server CPU s/GB: kuicksilver JVM (own client) | 3.92 | 2.72 |
| kuicksilver Native (own client) | 5.43 | 3.47 |
| kuicksilver JVM → quinn | 5.07 | 3.12 |
| kuicksilver Native → quinn | 5.04 | 4.08 |
| handshakes/s, ms per handshake: kuicksilver JVM | 1748, 1.06 | 1750, 0.95 |
| kuicksilver Native | 1390, 0.92 | 1524, 0.79 |
| wall s, 1 GiB: quinn → JVM, quiche → JVM, JVM → JVM, Native → Native | 9.9, 15.3, 3.9, 5.9 | 8.9, 13.9, 3.3, 4.0 |

Every CPU cell with a Kuicksilver endpoint is at or below its 2026-10-20 value and every bulk transfer is as fast or
faster, and the goodput and crosstraffic cells are unchanged within their spread (one crosstraffic cell that came out
lower was measured again and is spread, see [Goodput](#goodput)). The client column is mostly the receive path (with it
alone, 2026-10-20 evening: quinn → JVM 8.4, quiche → JVM 5.8); the server rows are both (the Native server's 5.4 s/GB
was 3.9 with the receive path alone and 3.3 with the server fixes alone, measured in their own sessions; 3.5 together);
the handshake gains are the server fixes'.

## Where the time went

### The client: 12–18 s/GB against quiche's and quinn's servers

As a client Kuicksilver cost 5.4–7.6 s/GB against Kuicksilver's and msquic's servers but 12–14 against quiche's and
9–18 against quinn's (JVM 18.2: 19.8 s of CPU for a 9.9 s transfer, half of it system time), and sent 14–20 packets per
100 received instead of 6.4.

- **Not the acknowledgement policy.** `recovery/AckTracker.kt` asks for an ACK after two ack-eliciting packets and at
  once after a gap (RFC 9000 §13.2.1–13.2.2), but an ACK leaves only when the loop flushes after a receive batch, so in
  practice there was one ACK per batch. Decrypted captures (100 MiB each) show why the batches differ by sender:
  Kuicksilver's and msquic's servers send GSO trains of 10–40 datagrams that arrive within microseconds, so a batch
  fills the loop's 16 slots (100 / 16 ≈ 6.4 ACKs per 100); quinn's paced bursts of 6 and quiche's bursts of 10 (GSO
  and pacing off, one `sendmsg` per datagram) arrive with 40–180 µs between them, so a batch holds 3–6. quinn's own
  client against quiche's server acknowledges at the same rate (20.7 per 100) for 7.3 s/GB. The packet numbers quiche
  and quinn skip on purpose (single numbers at growing intervals: 74 in 80 000 packets from quiche, 11 in 77 000 from
  quinn; none arrived reordered) each cost at most one early ACK: a receiver cannot tell a skip from a loss, and
  quic-go, quinn and ngtcp2 acknowledge at once after a gap too (quiche acknowledges whatever was elicited whenever it
  sends). `AckTrackerTest.skippedPacketNumbersCostAtMostOneAckEach` pins this.
- **Thread hand-offs per batch.** Per-thread CPU of the JVM client container (`/proc/<pid>/task`, 1 GiB from quinn):
  the dispatcher threads took 5.3 s user and 8.4 s system with 628 000 voluntary context switches, and the
  application's reading thread 155 000 more: about four thread wake-ups per receive batch. Each batch handed the
  socket wait to a `Dispatchers.IO` thread and the batch back to the loop's dispatcher; JFR found almost no Java
  samples, the time was in parking and waking threads. The Native client paid the same per batch but, slower per
  batch, got larger batches (14 ACKs per 100). Under a sender that keeps the socket full the hand-offs are amortised
  over 16 datagrams; under a paced one, over three.
- **Two system calls per datagram.** `ksl_udp_recv` polled before every `recvmsg`; without GRO trains (the senders
  above do not use GSO) that is two calls per datagram.

The fix (`runtime/BatchReceiver.kt`, ADR-0006): while datagrams keep coming the loop reads the socket on its own thread
(what is queued, or what arrives within 1 ms and before its next timer; not on Windows, whose 1 ms poll waits a 15.6 ms
tick), letting the work queued on the loop run after every 16 datagrams or 1 ms as the blocking receive did; and
`ksl_udp_recv` calls `recvmsg` first and polls only when the queue is empty (Linux, Android, Apple; Windows still polls
first). The same transfer from quinn now has 98 000 context switches on the dispatcher threads and 59 000 on the
reading thread. A first version that let queued work run only every 16 rounds or 2 ms (the loop's `WorkLimiter`) starved
the application's reads, which extend the stream's flow-control credit, and made Kuicksilver → Kuicksilver 2.6 times
slower; that is why the receiver yields as often as the blocking receive did, and why the forward loop of a multi-loop
server now yields after every 16 forwarded datagrams too. The loop's dispatcher can therefore block for up to 1 ms in a
socket wait (`QuicEndpointConfig.dispatcher`). The client now acknowledges more often (33 instead of 20 packets per 100
from quinn: a faster loop takes smaller batches), still no more than one ACK per two ack-eliciting packets.

### The server: CPU per GB

Profiled on 2026-10-20 (how in [Profiling](#profiling)). The receive path above was the largest part on Kotlin/Native:
its `Dispatchers.IO` is a worker pool of its own, so each hand-off was a thread wake-up in each direction, up to one
receive round per acknowledgement (about 49 000 per GB at the server); a receive on the loop's own thread took 1.9 s/GB
off the Native server and 0.3 off the JVM server in that session (a first form of the change, which the receive path
above replaced).

- **Kotlin/Native code generation in the QUIC core.** The core benchmark (`CoreThroughputBenchmark`: two cores back to
  back in memory, one thread, M4 Max) moves 2371 MiB/s on the JVM and 586 MiB/s on Kotlin/Native with the Null crypto
  (802 and 472 MiB/s with AES-128-GCM through `ksl`, which costs the JVM more: its JNI calls take direct buffers). In
  the Native profile, 16 % of the time was `PacketBuffer.get`/`set`, which called the shared range check with a `String`
  argument per byte; with the check inline, 747 and 542 MiB/s. Next in that profile: `Duration` arithmetic on the
  per-packet paths (pacer, PTO, ACK delay), enum `==` compiled to a virtual `equals`, list index checks in
  `ConnectionIdManager`, varints read and written byte by byte (thread-local access, 6.5 % of the samples, is a call on
  macOS only). The core benchmark still runs 3.2 times faster on the JVM with the Null crypto, 1.5 times with AES-GCM:
  roadmap.
- **The interop server's whole-file read does skew it, mostly against the JVM.** Reading 1 GiB into one array per
  request (kotlinx-io segments, then a copy) was 90 % of the JVM server's allocation and 0.9 s/GB of its CPU, 0.1 s/GB
  of the Native server's. The server now streams in 1 MiB writes. Not in 8 KiB writes: every write into a QUIC stream is
  a flush that ends in a short packet and sends at once, so 8 KiB writes cost the Native server 10.6 s/GB and the JVM
  server 15.4 (2 and 4 times), with 3 % more packets and 2.8 times the acknowledgements; coalescing writes is on the
  roadmap.
- System time is still about half of either server's CPU (GSO sends and the receive rounds; not broken down further: the
  images carry no `perf`). Per received packet `ksl_open` allocated, copied and wiped a buffer (a client-side cost:
  2.4 % of the core benchmark's samples); since P.2 it decrypts in place.

### The server: handshakes

On Linux the gap to quinn was user time: per handshake the Native server spent 0.72 ms of user and 0.21 ms of system
time, quinn 0.28 and 0.24 ([benchmarks/handshakes.csv](benchmarks/handshakes.csv)). Of the Native server's user time (a `macosArm64` build under
the same load, 12 000 handshakes, 3 940 samples):

| where | share of user time |
|---|---|
| the OpenSSL handshake (`ksl_drive`: key shares, the ECDSA P-256 signature, the key schedule) | 19 % |
| a new `SSL_CTX` per QUIC session (`KslContext.create`) | 8.5 % |
| the interop server: a list of every connection ever accepted, copied on each accept (and kept: 340 MB of heap after 13 000 connections on the JVM) | 8 %, growing |
| the interop server: `Files.read` and `Files.inside` per request | 10 % |
| the Kotlin/Native garbage collector | 10 % |
| exceptions: a `TimeoutCancellationException` per timer expiry, a `CancellationException` per connection (a stack trace and a C++ unwind each on Native) | 3 % |
| the rest: the QUIC core, coroutine dispatch, about 80 KiB of per-connection buffers | 40 % |

- **The key share is not the explanation.** The handshake client (Kuicksilver's) offers X25519MLKEM768 and X25519.
  Kuicksilver's server picks the hybrid; quinn's and msquic's interop servers pick X25519 (`key_share` group 0x11EC vs
  0x001D in the ServerHello; msquic also picks AES-256-GCM). In OpenSSL alone (`tools/bench/ksl-ctx-bench.sh`, M4 Max,
  three runs) the server's share of a handshake is 131 µs with the hybrid and 102 µs with X25519: ML-KEM-768 costs the
  server 29 µs, 3 % of 0.92 ms, plus a ClientHello in two datagrams. The per-session `SSL_CTX` costs 53 µs more; 0.3.0
  shares one per server configuration ([0.3.0 work in progress](#030-work-in-progress)).
- Fixed: the interop server forgets a connection when it ends; the timer waits with `select { onTimeout }`, which does
  not throw; a connection's DATAGRAM sender starts with its first datagram, so most connections never run it and do not
  throw through it when they end. One trap on the way: a 1 MiB read buffer per 32-byte request doubled the Native
  server's system time (0.21 → 0.47 ms per handshake; large Kotlin/Native arrays are mapped and unmapped); the buffer is
  now no larger than the file.
- Measured on the merged tree, the Native server is at 0.79 ms per handshake and 1524 per second, the JVM server at 0.95
  ms and 1750 per second (quinn 0.53 ms). What remains between Kuicksilver and quinn here is the Kotlin side (core,
  coroutines, collector, ~0.45 ms) and the OpenSSL side (~0.18 ms with the per-session context).


## 0.3.0 work in progress

Not comparable with the tables above: in-process microbenchmarks on a host loaded by other builds, to show what a change
did, not how Kuicksilver compares. The rate against quinn (the handshake table above) is measured again on a quiet machine.

### Handshakes (P.3, 2026-11-05)

`HandshakeBenchmark` runs whole QUIC connections between two `ConnectionCore`s under virtual time (a full 1-RTT
handshake with ksl crypto, the client's close, both cores closed); `EndpointHandshakeBenchmark` runs them through two
endpoints over a `MemoryNetwork` (the runtimes, coroutines and timers of both sides included). Both measure client and
server together in one process. Medians of three runs each, before and after interleaved, M4 Max with other builds
running (load average 2–4); JVM: JMH, 1 fork, 3 × 2 s warm-up, 5 × 2 s; Native: kotlinx-benchmark, same iterations.

| connections per second | before | after |
|---|---|---|
| `HandshakeBenchmark`, JVM | 1862 [1840–1887] | 2183 [2144–2226] (+17 %) |
| `HandshakeBenchmark`, Native | 1727 [1723–1803] | 2027 [2024–2104] (+17 %) |
| `EndpointHandshakeBenchmark`, JVM | 1576 [1440–1622] | 1857 [1728–1874] (+18 %) |
| `EndpointHandshakeBenchmark`, Native | 1224 [1197–1342] | 1356 [1351–1490] (+11 %) |

JVM heap allocated per connection (JMH `gc.alloc.rate.norm`): 170 → 108 KB (core), 201 → 136 KB (endpoints).
Exception objects per connection (JFR `jdk.JavaExceptionThrow`): 6 → 2, the two close reasons the API hands out.

Where the Native endpoint benchmark's busy CPU went (`sample`, 10 s, about 7 000 samples on the worker threads each time):

| | before | after |
|---|---|---|
| the OpenSSL handshake (`ksl_drive`: key shares, the ECDSA signature, the key schedule) | 48 % | 53 % |
| a new server `SSL_CTX` per connection (`KslContext.create`) | 9.1 % | 0 |
| a new client `SSL_CTX` per connection | 6.3 % | 7.5 % |
| packet keys (`key_build`: HKDF, cipher set-up) | 7.2 % | 5.3 % |
| building exception objects | 0.3 % | 0.1 % |

- **One `SSL_CTX` per server configuration.** The handshakes of a server configuration share one context per identity
  snapshot (a `TlsIdentity.Reloadable` reload builds one more; the old one goes after its last connection). A TCP server
  whose `sniSelector` returns an override still builds the override's context per connection (only the base context is
  shared). The client still builds one per connection: it is a client-side cost here, and in the handshake table the load
  generator's.
- **No exceptions on the normal path** but the close reasons: a runtime that finished no longer builds an unused
  `ConnectionLost.Internal`, and a connection that never sent a DATAGRAM has no drainer job to cancel.
- **Packet keys:** HKDF and the AEAD and header-protection ciphers are fetched from OpenSSL's provider store once per
  process instead of per key (`tools/bench/ksl-ctx-bench.sh`: an Initial key 4.8 → 3.4 µs, the next key phase 4.0 → 2.7
  µs).
- **Allocations:** the CRYPTO streams' send rings and receive scratch grow on first use (a 4 KiB ring per CRYPTO level
  and a 16 KiB scratch per connection before); `HandshakeAllocationTest` holds a connection under 125 000 bytes.
- Reproduce: `./gradlew :kuicksilver-bench:jvmHandshakeBenchmark` (or `jvmBenchmarkJar`, then run the JMH jar it builds
  with `HandshakeBenchmark -prof gc`) and `:kuicksilver-bench:macosArm64HandshakeBenchmark`, with `sample <pid> 10 1`
  on `macosArm64Benchmark.kexe`.

### Memory (P.5, 2026-11-06)

`tools/bench/memory.sh [connections] [MiB]` runs the memory benchmark (`MemoryBench` in `kuicksilver-bench`) on the JVM
and on Kotlin/Native, each section in a process of its own: the idle process; 1000 idle connections through the QUIC core
alone (`ConnectionCore` pairs under virtual time), through two `QuicEndpoint`s over a `MemoryNetwork`, and as HTTP/3
connections that each carried one GET (control and QPACK streams open, an `acceptRequest` loop per server connection);
then the managed heap allocated per GiB moved (and, since P.2, the same over loopback UDP: the `udp` section). Each idle measurement is taken with both sides, then again after the client
sides closed without telling the server, which leaves the server's share. Client and server run in one process, without
sockets, so the numbers are the library's, not the kernel's. M4 Max, macOS, JVM 21 (`-Xmx1g`), loaded host (load average
3–5), local; single runs, before = `9ed03deb0` (the benchmark), after = `2c0dae80c` (the three `perf(quic)` commits below).

| per idle connection (KB = 1000 bytes) | before | after |
|---|---|---|
| QUIC core, server side, JVM heap | 37.1 KB | 36.1 KB |
| QUIC endpoint, server side, JVM heap | 41.0 KB | 39.9 KB |
| HTTP/3, server side, JVM heap | 291.9 KB | 80.6 KB (80–90 KB between runs) |
| HTTP/3, client and server, JVM heap | 572.3 KB | 166.6 KB |
| QUIC core, client and server, Native RSS | 198.4 KB | 195.4 KB |
| QUIC endpoint, client and server, Native RSS | 225.8 KB | 222.2 KB |
| HTTP/3, client and server, Native RSS | 1023.6 KB | 488.6 KB |
| OpenSSL (C heap, Native), server / client side | 36.7 / 56.1 KB | 36.7 / 56.1 KB |

- **Per 1000 idle connections** (after): HTTP/3 on the JVM, 77 MiB of heap for the server's side and 159 MiB for client
  and server; on Kotlin/Native 466 MiB of RSS for 1000 client-and-server pairs (212 MiB for plain QUIC). Native RSS is only
  measured for both sides together: memory the client sides give back stays in the process. The JVM's RSS per
  connection is not given: its heap grows with garbage and does not shrink, so it says nothing per connection.
- **Idle process:** JVM 74 MiB RSS at start, 106 MiB after one connection (classes, JIT, OpenSSL loaded), 3 MiB live
  heap; Native 7.6 MiB RSS at start, 14.9 MiB after one connection.
- **Kotlin/Native heap:** the default allocator's figure counts pages, which per-connection objects allocated in turn
  keep partly filled (HTTP/3: 392 KB per pair). Linked with `-Pkuicksilver.memory.allocator=std` the figure is the live
  objects: 46 KB (core), 55 KB (endpoint) and 118 KB (HTTP/3) per server connection, 1.3 to 1.5 times the JVM's (8-byte
  references and headers).
- **Allocation per GiB moved:** the core with ksl crypto allocates nothing (0 bytes over 256 MiB, as `CoreAllocationTest`
  gates); through the endpoints, client and server together, the JVM allocates 2.5–2.9 GiB per GiB (four runs) and
  Kotlin/Native 0.5–1.0 GiB per GiB (its counter forces a collection every 256 KiB and is a lower bound when the
  collector ran one of its own). On the JVM 47 % of it is the `MemoryNetwork` copying each datagram (a socket would not)
  and 17 % the kotlinx-io segments `StreamInput` fills: P.2's work.
- **Fixed on the way:** a closed endpoint kept every connection it had reachable through its timer heap and its table by
  peer address (`7811c150f`).

What one idle connection holds, from the benchmark's inventory (JVM; every object the connection reaches that a second
connection does not share, charged to the first field path that reaches it; `jvmMemory` prints the whole list):

| | bytes | what |
|---|---|---|
| server core, total | 35 104 | |
| `loss.spaces[*]` | ~13 000 | per packet-number space: ACK ranges (128 longs), the last 64 lost packets (five arrays), the last 32 acknowledged ranges, the sent-packet ring and pool; Initial and Handshake are kept after their keys are discarded |
| `cryptoStreams.send[*].ring` | 3 104 | the Initial and Handshake CRYPTO send rings (2 KiB each), kept after the handshake |
| `builder.scratch`, `streams.scratch` | 4 128 | 2 KiB scratch each (packet building, stream retransmission) |
| `cryptoStreams.scratch` | 1 176 | what TLS was last handed |
| `receiver.ackView.ranges` | 1 040 | the peer's ACK ranges, decoded |
| HTTP/3 server connection, total | 77 000–89 000 | the core above plus (two modes between runs, see below) |
| the six control and QPACK streams in the core | ~6 000 | send rings (1 KiB minimum) on the three local ones, reassembly windows (512 bytes now, 4 KiB before) on the peer's, range arrays |
| the HTTP/3 session and the runtime's streams | ~36 000 | not broken down further: two channels per stream (`readable`, ticker: a 64-slot segment each), coroutine state, kotlinx-io buffers, QPACK state |
| removed by the commits above | 193 000 + 11 000 + 1 000 | a 16 KiB staging array per stream half and 64 KiB for the datagram flow (now one scratch per endpoint loop); 4 KiB reassembly windows; the DATAGRAM ring |

The HTTP/3 figures have two modes from run to run, about 10 KB apart: in some runs the server connection's channel of
accepted streams still references the finished request stream through a resumed waiter in one of its cells, and with it
that stream's input buffer and an 8 KiB kotlinx-io segment (`session.quic.accepted...inChannel.buffer.head.data` in the
inventory). Which mode a run gets depends on whether the request arrived before or after `acceptRequest` was waiting.

Still to reduce, by estimated bytes per connection (each side):

1. **OpenSSL's per-connection state**, 37 KB (server) and 56 KB (client) of C heap after the handshake: the largest item
   of a QUIC connection on Kotlin/Native and invisible to the JVM heap. Not yet broken down: what the `SSL` object keeps
   after the handshake (the handshake transcript and buffers, the peer's chain on the client) has to be measured with
   OpenSSL's allocation hooks before anything is freed early.
2. **Discarded packet-number spaces**, about 8 KB: the Initial and Handshake spaces keep their loss-detection arrays after
   their keys are discarded (RFC 9001 section 4.9); release them there, and start the arrays of every space small (the
   application space's 128 ACK ranges and 64-entry loss history grow only under loss): about 2 KB more.
3. **Scratch arrays in the core**, about 6 KB: packet building, stream retransmission, ACK decoding and the CRYPTO hand-off
   each keep their own array; one set per endpoint loop (the loop runs one connection at a time) or released after the
   handshake.
4. **CRYPTO send rings of discarded levels**, about 3 KB: released when the level's keys are.
5. **The finished request stream kept by the accept channel** (above), about 10 KB in the runs where it happens: done in
   P.2 (below): it was the HTTP/3 accept loop's coroutine frame, not the channel.
6. **HTTP/3 streams**: the three control and QPACK send rings start at 1 KiB for a few bytes (start smaller, as the
   reassembly window now does: about 2 KB); the session and the runtime's streams (about 36 KB) are the next inventory
   to break down.
7. **Allocation per GiB through the runtime** (not per connection): `StreamInput` copies through a kotlinx-io buffer whose
   segments are allocated as data arrives; writing into the segments directly would also save the copy. P.2 (below)
   measured it over real sockets too, where the segments are a small part.

Not measured here: the HTTP/2 and HTTP/1.1 servers. Their connections are TCP sockets in the Ktor engine, which this
in-process benchmark does not drive; the soak harness (`kuicksilver-soak`) runs them and samples RSS, but not per
connection.

### Allocation-free packet path (P.2, 2026-11-06)

The memory benchmark's allocation per GiB went over a `MemoryNetwork` only, whose per-datagram copy a socket does not
make; its `udp` section (`tools/bench/memory.sh`, `MemoryBench`) now moves the same stream over loopback through the
accelerated socket (`KslDatagramIo`), client and server in one process with ksl crypto. M4 Max, macOS, JVM 21, loaded
host (load average 2-9), local; single runs, before = `614733d0d` (P.5), after = `6db77c3e3`.

| | before | after |
|---|---|---|
| JVM, managed heap per GiB, loopback UDP | 234-259 MiB | 132-139 MiB |
| JVM, managed heap per GiB, `MemoryNetwork` | 2785-2842 MiB | 2041-2045 MiB |
| JVM, QUIC core with ksl crypto (`CoreAllocationTest`) | 0 | 0 |
| Native, managed heap per GiB, loopback UDP | 188-346 MiB | 154-315 MiB |
| `ksl_open`, C heap per received packet | one `malloc` (payload size), copy, wipe | none |
| `UdpThroughputBenchmark` (accelerated socket, CUBIC, Null crypto) | 28.1 ± 3.2 MiB/s | 34.6 ± 3.9 MiB/s (within this host's noise: 26-35 between runs of one build; not attributable) |
| `CoreThroughputBenchmark`, ksl crypto | 794.9 ± 16.7 ops/s | 828.8 ± 21.6 ops/s after the `ksl_open` change, 758.7 ± 56.9 at load 5.4 (within this host's noise; not attributable) |

What went, by commit (each measured on its own, JVM loopback UDP; the order is the order they landed):

- `ksl_open` decrypts in the packet's buffer; a packet whose tag fails has its payload wiped, so it still leaves no
  plaintext behind (one pass, cheaper under a forged-packet flood than restoring the ciphertext). Not visible in the JVM
  figure (C heap), counted by the C tests through the sanitizers' malloc hooks.
- The connection ID table routes each datagram without boxing its SipHash key (an open-addressed table on the hash):
  one 16-byte object per datagram, 7.3 % of the figure before; 234-259 -> 219 MiB.
- The loop takes a flowing socket's batch without a coroutine frame, a boxed `TimeMark` and two boxed `Duration`s: within
  the spread at this size (219 -> 225 MiB).
- A flush on the accelerated socket (whose `send` never suspends) runs as a plain function: no frame for the flush,
  `sendOut` and `sendOrLose`, no copy of the dirty list, no iterators: 225 -> 145 MiB.
- A stream's output hands the core its head segment in place instead of through a `peek()` and the loop's scratch:
  145 -> 130 MiB (`MemoryNetwork`: 2726 -> 2079 MiB).
- The HTTP/3 accept loop no longer keeps its last request stream (an idle server connection: 78.6-79.6 K in every run,
  instead of 88.6-89.4 K in about a third of them; `IdleFootprintTest`'s ceiling is now 85 000).

What the loopback-UDP figure still holds (JFR, JVM): no allocation per datagram on the packet path itself; what is left
is per wake-up of a coroutine. The timer coroutine's `select` with `onTimeout` (about 10 %: the select, its clauses, a
delayed task), the application's hops onto the loop (`withContext` in `StreamOutput.flush` and `StreamInput.awaitContent`:
a dispatched continuation, a scoped coroutine and its context), the channels that wake readers and writers, and the
kotlinx-io segments `StreamInput` fills (about 7 %, from the pool's second level). The Kotlin/Native figure moves within
its run-to-run spread on this host (its counter forces a collection every 256 KiB and attributes nothing); the Native
bindings' per-call `memScoped` arena and pinning are per batch, not per datagram, and were not changed. Off-heap
buffers through FFM are left for later.

### Several loops on one socket (S3.4, 2026-11-07)

`MultiLoopBenchmark` (`./gradlew --max-workers=2 :kuicksilver-bench:jvmLoopsBenchmark` and `macosArm64LoopsBenchmark`):
one server endpoint with `loops` endpoint loops on `127.0.0.1:0` and 8 client endpoints (one loop and one socket each),
all in one process over loopback UDP through the accelerated socket. On macOS the loops share one socket and its receiver
thread (in-process routing, [Several loops on one port](guide/quic.md#several-loops-on-one-port)); on Linux each loop has
its own `SO_REUSEPORT` socket and the kernel balances the 8 client flows. `handshake`: whole connections with ksl crypto
(P-256 certificate), 4 at a time per client, the client connects and closes; `bulk8`: 8 connections, one per client, each
moving 16 MiB to the server with ksl crypto (AES-GCM); `bulk8null`: the same with the Null crypto provider, the upper bound
the receive path leaves. Medians of 5 iterations of 2 s after 3 of warm-up, [min–max] in brackets; JVM: JMH, 1 fork.
M4 Max (10 performance and 4 efficiency cores), macOS 26.7, JVM 21; Linux: the same JVM benchmark in Docker Desktop's
`linux/arm64` VM (14 CPUs, kernel 7.0, Temurin 21) against the manylinux `libksl.so`. Measured on `9869a72a3` plus the
benchmark; no other build ran, but the host was not quiet (load average 4–9 with the runs, macOS background daemons at
times). Windows: not measured yet; the manual `windows-loops-bench` job of `build.yml` (workflow_dispatch with
`only=windows-loops-bench`) runs the JVM benchmark on windows-2025 and keeps the JMH report.

| handshakes/s | loops 1 | 2 | 4 | 8 |
|---|---|---|---|---|
| macOS, Native | 2237 [2164–2380] | 4651 (2.08×) | 7733 (3.46×) | 7595 (3.39×) |
| macOS, JVM | 2383 [2338–2419] | 4724 (1.98×) | 7798 (3.27×) | 7693 (3.23×) |
| Linux, JVM (kernel balancing) | 2278 [2206–2301] | 2257 (0.99×) | 7062 (3.10×) | 8644 (3.79×) |

| MiB/s, 8 connections | loops 1 | 2 | 4 | 8 |
|---|---|---|---|---|
| macOS, Native, ksl | 220 [215–221] | 271 (1.23×) | 275 (1.25×) | 272 (1.23×) |
| macOS, Native, Null | 231 [230–234] | 295 (1.28×) | 276 (1.20×) | 290 (1.25×) |
| macOS, JVM, ksl | 240 [232–242] | 299 (1.25×) | 280 (1.17×) | 308 (1.28×) |
| macOS, JVM, Null | 258 [256–261] | 313 (1.22×) | 322 (1.25×) | 299 (1.16×) |
| Linux, JVM, ksl (kernel balancing) | 335 [334–342] | 222 (0.66×) | 212 (0.63×) | 201 (0.60×) |
| Linux, JVM, Null (kernel balancing) | 382 [378–390] | 220 (0.57×) | 199 (0.52×) | 207 (0.54×) |

The receiver thread on macOS and the datagrams the dispatch dropped (`EndpointStats.datagramsDispatchDropped`, whole
trial). JVM: the receiver's CPU time over the time the operations ran (`ThreadMXBean`, warm-up iterations included),
from the runs in the table. Native: the share of its samples outside `poll` in `sample <pid> 5 1`, taken during the
warm-up of a separate run with only that parameter set.

| receiver busy, dropped | loops 2 | 4 | 8 |
|---|---|---|---|
| handshake, JVM / Native | 31 % / 12 %, 0 | 46 % / 23 %, 0 | 44 % / 23 %, 0 |
| bulk8, JVM / Native | 93 % / 86 %, 4 400–7 700 | 82 % / 92 %, 3 000–3 800 | 92 % / 93 %, 0 |
| bulk8null, JVM / Native | 98 % / 90 %, 500–1 200 | 95 % / 89 %, 25–4 600 | 85 % / 95 %, 930–1 600 |

- **Handshakes scale until the host runs out of cores.** 4 loops complete 3.3–3.5 times the handshakes of one (the
  plan's estimate before measuring: 3.3–3.7). 8 loops add nothing here: at 4 loops the process already keeps about 10
  cores busy (`sample`: the 8 client endpoints do as much TLS work as the server), which is all the performance cores
  of this host. The receiver is not the limit: a quarter of a core on Native.
- **Bulk transfers are capped by the one receiver,** at 1.2–1.3 times one loop with either crypto. The receiver is
  busy 82–98 % of the time, and 78–86 % of its samples are in the `recvmsg` system call itself: Darwin has no GRO or
  `recvmmsg`, so it is one system call per datagram, about 3 µs each at 300 MiB/s. The Null crypto rows end at the same
  ceiling: decryption runs on the loops, which are not the limit, and the copy and routing after `recvmsg` take under a
  tenth of the receiver's samples. When the receiver falls behind, the kernel's buffer and the loops' rings drop
  datagrams (counted above) and loss recovery resends them. The benchmark's own thread, which runs all 8 writers and
  8 readers, used 20–25 % of a core in `bulk8` (JVM; 16–37 % on Linux), so the clients are not the limit. With one
  connection, more loops never help: it lives on one loop.
- **Linux (kernel balancing), as a control.** Handshakes scale with how the 8 client flows hash onto the sockets (a
  client's connections share its 4-tuple; at 2 loops this run measured 0.99×, an earlier one 1.69×). Bulk transfers
  are slower with more than one loop (0.52–0.66×). This is not the kernel mode itself, nor Docker: forcing in-process
  routing on the same Linux host gives the same 214–236 MiB/s, nothing is forwarded between loops, no datagram is
  dropped at the server, and GSO and GRO are granted on every socket. It is one connection's own rate showing through.
  A single connection over loopback moves about 25 MiB/s (Linux) or 32 MiB/s (macOS) with a third to half of a core
  busy, its window large (160–290 KiB at a 60–140 µs RTT): the connection waits rather than works, which is also the
  28–35 MiB/s of `UdpThroughputBenchmark`. One loop serving all 8 connections stays busy (4.2 cores in the process,
  datagrams queued at every receive), and that hides the wait; spread over 2 to 8 loops each loop runs idle between
  datagrams (1.8 cores in the process, RTT down from milliseconds to about 100 µs), and 8 connections move about 8 times
  that single rate (200–220 MiB/s). Where that wait came from, and the same table after the fix: [One connection over
  loopback](#one-connection-over-loopback-2026-11-08).

### One connection over loopback (2026-11-08)

One connection over loopback moved 25–35 MiB/s with a third to half of a core busy. Sampled every 0.5 ms during a
256 MiB transfer (JVM, the setup of `UdpThroughputBenchmark`, Null crypto, CUBIC; M4 Max, macOS, quiet host):

| | before | after |
|---|---|---|
| bytes in flight, p10 / p50 / p90 | 0 / 0 / 31 KiB | 10–11 / 22–24 / 31 KiB |
| congestion window | 221–249 KiB | 221–606 KiB |
| samples with bytes in flight within one datagram of the window | 0 % | 0 % |
| stream bytes the writer was ahead of the reader, p50 / max | 5 / 80 KiB | 12–13 / 36–37 KiB |
| packets lost | 0 | 0 |
| smoothed RTT, p50 | 182 µs | 67–70 µs |
| throughput (second of two transfers) | 28–35 MiB/s | 250–253 MiB/s |
| process CPU per GiB (second transfer) | 21 s | 10.6–10.7 s |

Nothing of RFC 9002 or flow control was the limit: the window was never full, nothing was lost, pacing is off below
1 ms of RTT for CUBIC (`Pacer`), and a stream window of 512 KiB and more never ran out with the writer at most 80 KiB
ahead. The sender had nothing to send: the application's writer was. Each `writeFully` of 16 KiB flushes (`autoFlush`)
by hopping onto the loop's dispatcher (`withContext`). The loop's receiver, reading the socket on the loop's own thread
while datagrams flow (`runtime/BatchReceiver.kt`), let queued work run only every 16 datagrams or 1 ms, and waited up
to 1 ms in the socket with that work queued. The client's loop receives a few ACKs per millisecond, so the writer's hop
waited up to a millisecond for each 16 KiB: about 16–30 MiB/s. Giving each endpoint a caller-supplied dispatcher, on
which the receiver never waits, moved the same transfer at 195–233 MiB/s, which located the wait.

The fix: the loop's own dispatcher counts the tasks queued on it (`runtime/LoopDispatcher.kt`, no allocation per task),
and the receiver lets them run before its next batch; with the socket empty it yields to them first and only then waits
in the socket. A stream reader's hop and the timer coroutine are not counted (`LoopDispatcher.Batched`) and run every
16 datagrams or 1 ms as before: a first version that counted the readers too moved one connection a little faster
(250–262 MiB/s in `UdpThroughputBenchmark`) but cost the JVM client a third more CPU per GB from quinn's paced server
(below), one hand-off back to the reading thread per batch of a few datagrams.

Medians of 5 iterations of 2 s after 3 of warm-up, ± the 99.9 % interval (one operation is one MiB from a cold start of
the writer and reader, so the tail of each MiB weighs more than in the 256 MiB transfer above):

| | before (`8603c0e29`) | after |
|---|---|---|
| `UdpThroughputBenchmark`, JVM | 29.1 ± 8.4 MiB/s | 213.2 ± 6.3 MiB/s |
| `UdpThroughputBenchmark`, Kotlin/Native (macOS) | 26.9 ± 1.1 MiB/s | 209.0 ± 1.0 MiB/s |

The paced case: client CPU of a 1 GiB transfer from quinn's interop server to the JVM interop client
(`tools/bench/cpu-transfer.sh stammw/quinn-interop:latest <client> 1073741824 1048576 <reps>`, Docker Desktop
`linux/arm64`, the median 1 MiB transfer's CPU subtracted; the "Where the time went" figure of 18 s/GB is the same
measurement before 0.2.1):

| client CPU s/GB, quinn → kuicksilver JVM | median, [min–max] of the big transfers | wall s |
|---|---|---|
| before (`8603c0e29`), 3 transfers | 8.76 [8.74–8.82] | 8.9–9.0 |
| readers counted as queued work, 3 transfers | 11.76 [11.61–11.79] | 8.9–9.1 |
| after, 5 transfers | 8.83 [8.62–9.45] | 8.9–9.0 |

`MultiLoopBenchmark`, MiB/s of 8 bulk connections (ksl / Null crypto), medians [min–max]. macOS, JVM: before and after
on the quiet host. Linux, JVM (Docker `linux/arm64`, kernel balancing): before is the S3.4 run above (loaded host, so
compare the ratios to one loop), after on the quiet host.

| MiB/s, 8 connections | loops 1 | 2 | 4 | 8 |
|---|---|---|---|---|
| macOS, JVM, ksl, before | 228 [223–230] | 302 (1.33×) | 286 (1.26×) | 305 (1.34×) |
| macOS, JVM, ksl, after | 222 [217–227] | 317 (1.43×) | 335 (1.51×) | 338 (1.53×) |
| macOS, JVM, Null, before | 246 [242–247] | 321 (1.31×) | 320 (1.30×) | 320 (1.30×) |
| macOS, JVM, Null, after | 245 [241–247] | 310 (1.26×) | 332 (1.35×) | 339 (1.38×) |
| Linux, JVM, ksl, before | 335 [334–342] | 222 (0.66×) | 212 (0.63×) | 201 (0.60×) |
| Linux, JVM, ksl, after | 345 [340–350] | 474 (1.37×) | 1097 (3.18×) | 921 (2.67×) |
| Linux, JVM, Null, before | 382 [378–390] | 220 (0.57×) | 199 (0.52×) | 207 (0.54×) |
| Linux, JVM, Null, after | 393 [391–395] | 549 (1.40×) | 758 (1.93×) | 704 (1.79×) |

On Linux, where each loop has its own socket, more loops now move more: 3.2 times one loop at 4 loops instead of 0.6.
On macOS the one receiver thread stays the cap (98–99 % busy in `bulk8`, as in S3.4); the loops gain a little. One
loop serving 8 connections was busy before and is unchanged. Handshakes are unchanged within the spread (JVM, macOS:
2294–7783/s after, 2349–7699/s before; Linux: 2207/s at one loop, 3.63× at 8).

What is left on one connection: bytes in flight still sit far below the window (p50 24 KiB), so the application's
hops are still what paces it. A task queued while the receiver is already waiting in the socket waits until a datagram
arrives (at most 1 ms): ending that wait at once needs a wake-up of the socket wait from another thread (`ksl_udp` has a
wake pipe, used only for close today). A writer that hands over 16 KiB per hop pays two thread hand-offs per 16 KiB;
larger writes, or a writer that buffers several before hopping, would amortise them. And a reader waits for the
receiver's regular yield, which costs the 1 MiB operations of `UdpThroughputBenchmark` about a sixth (the counted-reader
variant above), and in request/response traffic a reply's read can wait up to 1 ms in the socket wait once the socket goes
quiet (as before this change).

## msquic's goodput outlier

Some repetitions are 2–6 % slower, with either client (2026-10-20: four of five JVM, two of five
Native in the morning, two of five each in the evening; 2026-10-21: three of five each). In every slow repetition the
runner's captures show the same thing: from some point to the end of the transfer msquic sends a steady 12.7 Mbit/s
(server side of the simulator, 250 ms bins) into the 10 Mbit/s link, and about 60 of its packets per 250 ms are dropped
at the 25-packet queue; it never backs off. In the fast repetitions it sends 10.0 Mbit/s after slow start with a drop
every two seconds. The client's side is the same in both: ACKs leave 0.07–0.09 ms (JVM) and 0.15–0.20 ms (Native)
after the packet they acknowledge, every acknowledged packet number was received (none of the ~1 900 dropped packets of
a slow repetition was acknowledged), and the stream flow-control updates match. Nothing in Kuicksilver changes it;
msquic runs emulated here, and why its congestion controller keeps that rate was not investigated.

## Still open

- **CPU per handshake:** 0.79 ms (Native) and 0.95 ms (JVM) against quinn's 0.53 ms. 0.3.0 shares the server's `SSL_CTX`
  ([0.3.0 work in progress](#030-work-in-progress)); the handshake table is to be measured again; the Kotlin side is on
  the roadmap.
- **The Kotlin/Native server** costs 28 % more CPU per GB than the JVM server (3.5 vs 2.7 s/GB).
- **One connection over loopback** now moves 210–250 MiB/s ([One connection over
  loopback](#one-connection-over-loopback-2026-11-08)), still paced by the application's hops onto the loop rather than
  by the window: a wake-up of the receiver's socket wait and fewer hand-offs per write are not done.
- **Acknowledgements:** fewer ACKs per byte would need the receiver side of the ack-frequency extension
  (draft-ietf-quic-ack-frequency).

## Reproducing

From the repository root, with Docker, `jq`, `tshark` (Wireshark) and the runner's Python environment as
`tools/interop/run-local.sh` sets them up:

```bash
# the images under test (the tables: the images built from 01da5c08; their "before" and the carried-over rows: from c08bc57b)
KSL_INTEROP_TAG=bench bash tools/interop/build-image.sh
KSL_INTEROP_TAG=bench bash tools/interop/build-image.sh --native
KSL_INTEROP_PLATFORMS=linux/amd64 KSL_INTEROP_TAG=bench-amd64 bash tools/interop/build-image.sh --native   # calibration
# everything: about 2 h of goodput, 3 h of CPU pairs, 40 min of handshakes on the host above
bash tools/bench/run-table.sh --tag bench --out build/bench/my-run
# or one phase: --phases goodput | cpu | handshakes | table
```

`run-table.sh` writes `goodput.csv` (one row per runner repetition, from each repetition's `output.txt`; the runner's
logs and pcaps stay under `build/interop/<run>/`), `cpu.csv` (one row per transfer: phase, bytes, wall time, server
and client CPU total/user/system, the router's packet and byte counts), `handshakes.csv` (one row per run), `env.txt`
and `tables.md` (`tools/bench/table.py`, the tables above). It waits while a Gradle build runs on the machine, and runs
one container set at a time. The pieces run on their own too: `tools/bench/cpu-transfer.sh <server image> <client
image> <big> <small> <rounds>` and `tools/bench/handshakes.sh <server image> <clients> <connections>`.

Two details of the published run: the router's interface counters of the first three pairs (Kuicksilver JVM server)
were recorded with the two directions swapped and were swapped back in `cpu.csv` (the server's direction is the one
that carries the file); and the client's counters were then read through a bind mount, which lost the file of 8
transfers in three pairs (quiche server with each Kuicksilver client and quinn's client), so those three pairs were
measured again with the script as it is now, which copies them out of the stopped container.

`kuicksilver-bench` (JMH: the QUIC core over an in-memory loopback, a UDP loopback transfer, and several server loops
on one port: `./gradlew --max-workers=2 :kuicksilver-bench:jvmLoopsBenchmark` and `macosArm64LoopsBenchmark`, on Windows
the `windows-loops-bench` job) measures Kuicksilver alone and is not part of this table; it answers "did this change make the core slower", this page "how does it compare".

### Profiling

How the profiles in [Where the time went](#where-the-time-went) were taken:

- **The JVM server in the benchmark's container:** `KSL_BENCH_JAVA_OPTS` becomes the server's `JAVA_OPTS`, and
  `$KSL_BENCH_WORK/profile` (default `build/bench/profile`) is mounted at `/profile`; the scripts then stop the server
  gracefully, so the recording is written:
  `KSL_BENCH_JAVA_OPTS="-XX:StartFlightRecording=filename=/profile/hs.jfr,settings=profile,delay=8s" bash
  tools/bench/handshakes.sh kuicksilver-interop:bench 8 1500`, then `jfr view allocation-by-site
  build/bench/profile/hs.jfr`. On this host JFR's execution sampler recorded almost nothing (21 samples in 71 s), its
  native-method samples and allocation sites were usable.
- **Kotlin/Native:** no `perf` in the images, so on the Mac: `./gradlew
  :kuicksilver-interop:linkReleaseExecutableMacosArm64` and run `kuicksilver-interop.kexe` with `ROLE=server
  TESTCASE=multiconnect CERTS=… WWW=…` (and a second one with `ROLE=client REQUESTS=…` against `127.0.0.1:443`), then
  `sample <pid> 10 1 -file out.txt`. Loopback bulk transfers on macOS drop datagrams at the receiver (one `recvmsg` per
  datagram, no GRO), so only handshakes are representative there; for the per-packet path, `./gradlew
  :kuicksilver-bench:macosArm64CoreBenchmark` (and `jvmCoreBenchmark` for the JVM) runs `CoreThroughputBenchmark` with
  the Null and the `ksl` crypto, and `sample macosArm64Benchmark.kexe 12 1` profiles it.
- **OpenSSL alone:** `tools/bench/ksl-ctx-bench.sh` prints the server's share of a handshake with the hybrid key share
  and with X25519 only, and the cost of a server `SSL_CTX`.
- **The key-exchange group a peer picks:** `tcpdump -w` inside the client container (the interop images carry it) and
  `tshark -r c.pcap -Y 'tls.handshake.type == 2' -T fields -e tls.handshake.extensions_key_share_group` (QUIC Initial
  packets decrypt without keys).

Versions (all digests in [benchmarks/env.txt](benchmarks/env.txt)):

| implementation | image | arch | image built |
|---|---|---|---|
| kuicksilver JVM | `kuicksilver-interop` built from `01da5c08` (OpenJDK 21, `libksl` 6; later commits change only the forward loop of multi-socket groups, which the interop image does not use, and tests and docs), measured 2026-10-21; "before": `kuicksilver-interop:bench-c08bc57b` | arm64 | 2026-10-21; 2026-10-20 |
| kuicksilver Native | `kuicksilver-interop-native` built from `01da5c08`, measured 2026-10-21; "before" and the amd64 calibration: `kuicksilver-interop-native:bench-c08bc57b[-amd64]` | arm64 | 2026-10-21; 2026-10-20 |
| quiche | `cloudflare/quiche-qns@sha256:a960608c…` | amd64 | 2026-10-06 |
| quinn | `stammw/quinn-interop@sha256:5205c84e…` | arm64 | 2024-09-02 |
| msquic | `ghcr.io/microsoft/msquic/qns@sha256:ef95e1bc…` | amd64 | 2026-10-05 |
| simulator | `martenseemann/quic-network-simulator@sha256:c23d82a5…` | arm64 | |
| crosstraffic TCP flow | `martenseemann/quic-interop-iperf-endpoint@sha256:cb50cc80…` | amd64 | |
