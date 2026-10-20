<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Benchmarks

Goodput, CPU time per transferred GB and handshakes per second of Kuicksilver against quiche, quinn and msquic: one run
on 2026-10-20, commit `c08bc57b` (0.2.0 plus 17 commits: interop and release tooling and three fixes to address
validation and migration during the handshake), one host. They are measurements,
not promises, and the comparison has limits that matter more than the numbers. Read the next section first.

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
- **These are the peers' interop endpoints, not their tuned servers.** Each image is what the QUIC Interop Runner
  runs: test clients and servers with the flags their maintainers chose for interop (quiche runs `--disable-gso
  --disable-pacing` and logs to a file; quinn's image `stammw/quinn-interop:latest` was built on 2024-09-02 and logs at
  `info`). Kuicksilver's interop endpoint is no better: its server reads the whole file into memory per request, and
  its client buffers the whole download before writing it. None of this is how a production deployment would run.
- **Goodput is capped by the simulated link.** The runner's goodput measurements run over a 10 Mbit/s link with 15 ms
  delay each way; every implementation fills it. They show that nothing is broken and how the congestion controller
  shares the link with TCP, not which stack is faster.
- **One host, one day.** No other build or container set ran during the measurements; the Docker VM is shared with
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
| kuicksilver JVM | quiche (amd64, emulated) | 9257 [9237–9258] (n=5) | 5246 [5194–5729] (n=5) | 0 |
| kuicksilver JVM | quinn | 9388 [9349–9390] (n=5) | 4234 [4063–4460] (n=5) | 0 |
| kuicksilver JVM | msquic (amd64, emulated) | 9408 [9407–9413] (n=5) | 4207 (n=1) | 1 (see below) |
| kuicksilver Native | quiche (amd64, emulated) | 9269 [9247–9284] (n=5) | 5465 [5344–5994] (n=5) | 0 |
| kuicksilver Native | quinn | 9389 [9317–9394] (n=5) | 4166 [3942–5431] (n=5) | 0 |
| kuicksilver Native | msquic (amd64, emulated) | 9422 [9419–9424] (n=5) | – | 1 (see below) |
| quiche (amd64, emulated) | kuicksilver JVM | 9370 [9355–9385] (n=5) | 4996 [4516–5385] (n=5) | 0 |
| quinn | kuicksilver JVM | 9315 [9293–9354] (n=5) | 3242 [2987–3557] (n=5) | 0 |
| msquic (amd64, emulated) | kuicksilver JVM | 8878 [8792–9375] (n=5) | 7175 [6394–8884] (n=5) | 0 |
| quiche (amd64, emulated) | kuicksilver Native | 9372 [9360–9380] (n=5) | 5371 [4945–5601] (n=5) | 0 |
| quinn | kuicksilver Native | 9357 [9297–9422] (n=5) | 3575 [3446–4668] (n=5) | 0 |
| msquic (amd64, emulated) | kuicksilver Native | 9397 [8953–9420] (n=5) | 8665 [7570–8963] (n=5) | 0 |

- **Kuicksilver server, msquic client, crosstraffic:** msquic's interop client gives a download 50 s
  (`-test:D -timeout:50000` in its `run_endpoint.sh`). 25 MB in 50 s needs 4.0 Mbit/s; Kuicksilver's CUBIC took
  4.2 Mbit/s against the TCP flow in the first JVM repetition (49.8 s) and a little less in the next one, which msquic's
  client then ended at 50 s with about 22 MB received ("Request closed incomplete"); the Native image's first
  repetition ended the same way (about 23 MB in 50 s, 3.7 Mbit/s). These cells are censored by the peer's timeout, not failed transfers; the share
  itself is in line with the quinn cells (4.2 Mbit/s).
- **msquic server, Kuicksilver JVM client, goodput:** four of five repetitions are 8.8–9.1 Mbit/s, where the Native
  client gets 9.3–9.4 Mbit/s from the same server (and the JVM client 9.3–9.4 from quiche and quinn). See
  [Worth a look](#worth-a-look).
- **Against the 0.2.0 check** (`build/release-checks/perf-20261016-200424`, JVM image, quinn and ngtcp2; quinn is the
  overlap): kuicksilver→quinn goodput median 9389 then, 9388 now; crosstraffic 4409 then, 4234 now; quinn→kuicksilver
  goodput 9310 then, 9315 now; crosstraffic 3238 then, 3242 now. No regression; every floor in
  `tools/interop/perf-thresholds.json` for these cells is met.

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
| kuicksilver JVM | 3.92 [3.78–4.57] | 6.68 [6.63–6.87] | 53 % | 1493 | 6.5 | 2.22 |
| kuicksilver Native | 5.43 [5.39–5.46] | 5.44 [5.43–5.46] | 50 % | 1494 | 6.4 | 1.46 |
| quiche (amd64, emulated) | 11.47 [11.42–12.44] | 7.38 [7.35–7.56] | 31 % | 1392 | 10.0 | 0.66 |
| quinn | 15.56 [15.50–15.69] | 13.69 [13.59–13.83] | 71 % | 1440 | 30.2 | 0.65 |
| msquic (amd64, emulated) | 1.86 [1.84–1.93] | 2.68 [2.66–2.71] | 67 % | 1506 | 1.0 | 1.01 |
| *calibration:* kuicksilver Native (amd64, emulated) | 5.62 [5.62–5.73] | 5.70 [5.69–5.80] | 46 % | 1494 | 6.4 | 1.31 |

What this says, and what it does not:

- **msquic uses about half of Kuicksilver's CPU per GB even under emulation** (1.9 vs 3.9–5.4 s/GB as server, 2.7 vs
  5.4–6.7 s/GB as client). It sends 1506-byte packets and its client acknowledges about one packet in a hundred.
- Kuicksilver is below **quiche and quinn as their interop images run here** — quiche emulated, with GSO and pacing
  off; quinn from a 2024 build whose client acknowledges every third packet and whose server spends 71 % of its CPU
  in the kernel. That is a statement about these images on this host, not about quiche or quinn.
- **Kotlin/Native costs more than the JVM as a server** (5.4 vs 3.9 s/GB); as a client the JVM costs more (6.7 vs 5.4,
  which includes the JIT's compilation and the interop client's whole-file buffering).

Every pair, median of the five big transfers (row: server, column: client; `failed`: the transfer did not complete in
any round — quiche's client against msquic's server, a peer pair, not investigated):

Server CPU s/GB:

| server \ client | kuicksilver JVM | kuicksilver Native | quiche (amd64, emulated) | quinn | msquic (amd64, emulated) |
|---|---|---|---|---|---|
| kuicksilver JVM | 3.92 | 6.62 | 3.57 | 5.07 | 3.18 |
| kuicksilver Native | 4.27 | 5.43 | 3.74 | 5.04 | 3.51 |
| quiche (amd64, emulated) | 13.34 | 13.59 | 11.47 | 13.11 | 11.34 |
| quinn | 14.50 | 11.57 | 12.27 | 15.56 | 12.71 |
| msquic (amd64, emulated) | 2.92 | 2.95 | failed | 2.83 | 1.86 |

Client CPU s/GB:

| server \ client | kuicksilver JVM | kuicksilver Native | quiche (amd64, emulated) | quinn | msquic (amd64, emulated) |
|---|---|---|---|---|---|
| kuicksilver JVM | 6.68 | 5.88 | 5.57 | 6.99 | 2.75 |
| kuicksilver Native | 7.62 | 5.44 | 5.53 | 6.16 | 2.47 |
| quiche (amd64, emulated) | 13.88 | 12.19 | 7.38 | 7.34 | 3.55 |
| quinn | 18.17 | 9.07 | 7.75 | 13.69 | 6.01 |
| msquic (amd64, emulated) | 6.81 | 5.09 | failed | 5.26 | 2.68 |

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
| kuicksilver JVM | 1748 [1743–1766] | 1.06 [1.04–1.08] | 1.86 |
| kuicksilver Native | 1390 [1375–1393] | 0.92 [0.92–0.93] | 1.28 |
| quiche (amd64, emulated) | 228 [214–232] | 4.40 [4.33–4.68] | 1.00 |
| quinn | 3452 [3427–3462] | 0.53 [0.52–0.53] | 1.82 |
| msquic (amd64, emulated) | 3543 [3532–3567] | 0.70 [0.69–0.71] | 2.50 |
| *calibration:* kuicksilver Native (amd64, emulated) | 1100 [1091–1108] | 1.15 [1.14–1.16] | 1.27 |

- This is comparative because the client side is the same for every row; it is a handshake-plus-one-request rate
  (each connection also carries a GET and a close), not a bare TLS handshake rate.
- **quinn handshakes at half Kuicksilver's CPU and twice its rate; msquic, emulated, at 0.7 ms and 2.5 cores.** In a
  trial with 16 clients × 750 connections, quinn's rate was within 5 % of this one, so the load generator was not
  what held quinn back at ~3500/s; whether quinn or msquic could go higher with more load was not explored.
- quiche's interop server runs one thread and is pinned at 1.00 core; at 4.4 ms per handshake it was much slower here
  than in a short trial (1.25 ms with 16 × 200 connections), so its cost grows over 12 000 connections in this image.
  Under emulation; not a statement about quiche in production.
- Kuicksilver's server loop (both builds) did not use more than about 1.3 (Native) or 1.9 (JVM, garbage collector and
  JIT threads included) cores here.

## Worth a look

Not regressions — nothing here is worse than at 0.2.0 where 0.2.0 was measured — but outliers for a later release:

- **The Kuicksilver client's CPU per GB doubles against quiche's and quinn's servers.** As client, 5.4–7.6 s/GB against
  Kuicksilver's and msquic's servers, 12–14 against quiche's and 9–18 against quinn's (JVM 18.2: 19.8 s of CPU for a
  9.9 s transfer, half of it system time). In those pairs it sends 14–20 packets per 100 received, against 6.4 with
  Kuicksilver's and msquic's servers; quinn's client receiving from the same quiche server costs 7.3 s/GB. The
  acknowledgement policy (`recovery/AckTracker.kt`: an ACK after two ack-eliciting packets, and at once on any gap in
  packet numbers, RFC 9000 §13.2.1) meets packets that arrive spread out rather than in bursts. It is not a busy loop:
  sampled once a second at the runner's 10 Mbit/s, the Native client used 0.2 of a core (quinn's client 0.14).
- **msquic server → Kuicksilver JVM client goodput** is 4–6 % below the Native client's in four of five repetitions
  (above).
- **The Kotlin/Native server costs 40 % more CPU per GB than the JVM server** (5.4 vs 3.9 s/GB) and more per handshake
  than quinn (0.92 vs 0.53 ms). Profiled and partly fixed after this run: see the next section.

## Where the server's time goes

The two server outliers above, profiled on 2026-10-20 (branch `k8/perf-server`; how in [Profiling](#profiling)), what
was fixed, and what remains. The tables above are still the published run of `c08bc57b`; the numbers in this section
come from `tools/bench/cpu-transfer.sh` and `handshakes.sh` with the published images as "before" and the branch's as
"after", the images measured one after the other in turn (three runs of each, median [min–max]); the host's numbers
drift by a few percent between sessions, so compare within this section.

### Before and after

Two sessions: the published images against a build of the branch that yielded after every receive, then that build
against the final one (they differ only in the receive loop's yields, see below). "After" is the final build:

| | before | after |
|---|---|---|
| Native server, CPU s/GB (own client) | 5.48 [5.46–5.60] | 3.32 [3.32–3.34] |
| JVM server, CPU s/GB (own client) | 3.96 [3.80–5.19] | 2.87 [2.64–3.40] |
| Native client, CPU s/GB (own server) | 5.53 | 3.59 |
| JVM client, CPU s/GB (own server) | 6.76 | 5.28 |
| Native server, ms per handshake | 0.930 [0.927–0.979] | 0.805 [0.803–0.814] |
| Native server, handshakes/s | 1380 [1323–1390] | 1520 [1500–1527] |
| JVM server, ms per handshake | 1.056 [1.040–1.074] | 0.934 [0.927–0.935] |
| JVM server, handshakes/s | 1744 [1712–1761] | 1772 [1767–1779] |

The Native server's CPU per GB is now within 16 % of the JVM server's (it was 38 % above it); per handshake it is
below the JVM's as before and 0.3 ms above quinn's (0.53 in the published run).

### CPU per GB

- **The receive path, Kotlin/Native above all.** Every receive went to `Dispatchers.IO` to wait for the socket and came
  back to the endpoint loop: two dispatches per receive round, up to one round per acknowledgement (about 49 000 per GB
  at the server). Kotlin/Native's IO dispatcher is a worker pool of its own, so each hop is a thread wake-up in each
  direction; on the JVM, `Dispatchers.IO` shares the scheduler with the default dispatcher. A receive now takes what the
  socket already holds on the loop's own thread (a non-blocking poll) and waits on `Dispatchers.IO` only when nothing is
  there: the Native server's CPU per GB fell by 1.9 s (5.0 → 3.1 with the other fixes in place), the JVM server's by
  0.3 s. Its rounds no longer suspend, so the receive loop yields after 4 rounds instead of 16 (a yield per round cost the
  Native bulk server 0.3 s/GB; 16 rounds cost 10 % of the handshake rate).
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

### Handshakes

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
- What remains between Kuicksilver and quinn here is the Kotlin side (core, coroutines, collector, ~0.45 ms) and the
  OpenSSL side (~0.18 ms with the per-session context).

## Reproducing

From the repository root, with Docker, `jq`, `tshark` (Wireshark) and the runner's Python environment as
`tools/interop/run-local.sh` sets them up:

```bash
# the images under test (the published run used the tag bench-c08bc57b)
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

How the profiles in [Where the server's time goes](#where-the-servers-time-goes) were taken:

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
| kuicksilver JVM | `kuicksilver-interop:bench-c08bc57b` (OpenJDK 21, `libksl` 6) | arm64 | 2026-10-20 |
| kuicksilver Native | `kuicksilver-interop-native:bench-c08bc57b` | arm64 | 2026-10-20 |
| quiche | `cloudflare/quiche-qns@sha256:a960608c…` | amd64 | 2026-10-06 |
| quinn | `stammw/quinn-interop@sha256:5205c84e…` | arm64 | 2024-09-02 |
| msquic | `ghcr.io/microsoft/msquic/qns@sha256:ef95e1bc…` | amd64 | 2026-10-05 |
| simulator | `martenseemann/quic-network-simulator@sha256:c23d82a5…` | arm64 | |
| crosstraffic TCP flow | `martenseemann/quic-interop-iperf-endpoint@sha256:cb50cc80…` | amd64 | |
