<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Benchmarks

Goodput, CPU time per transferred GB and handshakes per second of Kuicksilver against quiche, quinn and msquic, one
host. Every cell with a Kuicksilver endpoint was measured on 2026-10-21 on the 0.2.1 performance work (branch
`k8/perf-merge`: the client's receive path and the server's profiling fixes, see [0.2.1: before and
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
- **Against the 0.2.0 check** (`build/release-checks/perf-20261016-200424`, JVM image, quinn and ngtcp2; quinn is the
  overlap): kuicksilver→quinn goodput median 9389 then, 9401 now; crosstraffic 4409 then, 3903 now; quinn→kuicksilver
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
  difference was this cell's spread between runs, not the code.

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

Two changes, measured together: the **client's receive path** (`k8/perf-client`: the endpoint loop reads the socket on
its own thread while datagrams keep coming, `ksl_udp_recv` takes one system call per datagram on Linux, Android and
Apple) and the **server's profiling fixes** (`k8/perf-server`: `PacketBuffer` index checks inline on Kotlin/Native,
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
  images carry no `perf`). Per received packet `ksl_open` allocates, copies and wipes a buffer (a client-side cost:
  2.4 % of the core benchmark's samples).

### The server: handshakes

On Linux the gap to quinn was user time: per handshake the Native server spent 0.72 ms of user and 0.21 ms of system
time, quinn 0.28 and 0.24 (`benchmarks/handshakes.csv`). Of the Native server's user time (a `macosArm64` build under
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
  server 29 µs, 3 % of 0.92 ms, plus a ClientHello in two datagrams. The per-session `SSL_CTX` costs 53 µs more; sharing
  one per server configuration is on the roadmap.
- Fixed: the interop server forgets a connection when it ends; the timer waits with `select { onTimeout }`, which does
  not throw; a connection's DATAGRAM sender starts with its first datagram, so most connections never run it and do not
  throw through it when they end. One trap on the way: a 1 MiB read buffer per 32-byte request doubled the Native
  server's system time (0.21 → 0.47 ms per handshake; large Kotlin/Native arrays are mapped and unmapped); the buffer is
  now no larger than the file.
- Measured on the merged tree, the Native server is at 0.79 ms per handshake and 1524 per second, the JVM server at 0.95
  ms and 1750 per second (quinn 0.53 ms). What remains between Kuicksilver and quinn here is the Kotlin side (core,
  coroutines, collector, ~0.45 ms) and the OpenSSL side (~0.18 ms with the per-session context).


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

- **CPU per handshake:** 0.79 ms (Native) and 0.95 ms (JVM) against quinn's 0.53 ms; the per-session `SSL_CTX` and the
  Kotlin side are on the roadmap.
- **The Kotlin/Native server** costs 28 % more CPU per GB than the JVM server (3.5 vs 2.7 s/GB).
- **Acknowledgements:** fewer ACKs per byte would need the receiver side of the ack-frequency extension
  (draft-ietf-quic-ack-frequency).

## Reproducing

From the repository root, with Docker, `jq`, `tshark` (Wireshark) and the runner's Python environment as
`tools/interop/run-local.sh` sets them up:

```bash
# the images under test (the tables: tag k8-perf-merge; their "before" and the carried-over rows: bench-c08bc57b)
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

`kuicksilver-bench` (JMH: the QUIC core over an in-memory loopback, and a UDP loopback transfer) measures Kuicksilver
alone and is not part of this table; it answers "did this change make the core slower", this page "how does it compare".

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
| kuicksilver JVM | `kuicksilver-interop:k8-perf-merge` (OpenJDK 21, `libksl` 6; commit `01da5c08`), measured 2026-10-21; "before": `kuicksilver-interop:bench-c08bc57b` | arm64 | 2026-10-21; 2026-10-20 |
| kuicksilver Native | `kuicksilver-interop-native:k8-perf-merge` (commit `01da5c08`), measured 2026-10-21; "before" and the amd64 calibration: `kuicksilver-interop-native:bench-c08bc57b[-amd64]` | arm64 | 2026-10-21; 2026-10-20 |
| quiche | `cloudflare/quiche-qns@sha256:a960608c…` | amd64 | 2026-10-06 |
| quinn | `stammw/quinn-interop@sha256:5205c84e…` | arm64 | 2024-09-02 |
| msquic | `ghcr.io/microsoft/msquic/qns@sha256:ef95e1bc…` | amd64 | 2026-10-05 |
| simulator | `martenseemann/quic-network-simulator@sha256:c23d82a5…` | arm64 | |
| crosstraffic TCP flow | `martenseemann/quic-interop-iperf-endpoint@sha256:cb50cc80…` | amd64 | |
