<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Benchmarks

Goodput, CPU time per transferred GB and handshakes per second of Kuicksilver against quiche, quinn and msquic, one
host, 2026-10-20. Every cell with a Kuicksilver endpoint in it was measured again that evening on the 0.2.1 receive path
(commits `78701eaa` and `af6e26d2`: the loop reads the socket on its own thread while datagrams keep coming, and
`ksl_udp_recv` takes one system call per datagram on Linux, Android and Apple; [Worth a look](#worth-a-look)) — all CPU and handshake cells, and the goodput cells against msquic; the
other goodput cells, the pairs of two peers and the amd64 calibration rows are from the morning run on commit
`c08bc57b` (0.2.0 plus 17 commits: interop and release tooling and three fixes to address validation and migration
during the handshake). They are measurements, not promises, and the comparison has limits that matter more than the
numbers. Read the next section first.

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
| kuicksilver JVM | msquic (amd64, emulated) | 9410 [9408–9413] (n=5) | 4207 (n=1) | 1 (see below) |
| kuicksilver Native | quiche (amd64, emulated) | 9269 [9247–9284] (n=5) | 5465 [5344–5994] (n=5) | 0 |
| kuicksilver Native | quinn | 9389 [9317–9394] (n=5) | 4166 [3942–5431] (n=5) | 0 |
| kuicksilver Native | msquic (amd64, emulated) | 9423 [9419–9427] (n=5) | – | 1 (see below) |
| quiche (amd64, emulated) | kuicksilver JVM | 9370 [9355–9385] (n=5) | 4996 [4516–5385] (n=5) | 0 |
| quinn | kuicksilver JVM | 9315 [9293–9354] (n=5) | 3242 [2987–3557] (n=5) | 0 |
| msquic (amd64, emulated) | kuicksilver JVM | 9341 [8964–9371] (n=5) | 7175 [6394–8884] (n=5) | 0 |
| quiche (amd64, emulated) | kuicksilver Native | 9372 [9360–9380] (n=5) | 5371 [4945–5601] (n=5) | 0 |
| quinn | kuicksilver Native | 9357 [9297–9422] (n=5) | 3575 [3446–4668] (n=5) | 0 |
| msquic (amd64, emulated) | kuicksilver Native | 9395 [9245–9406] (n=5) | 8665 [7570–8963] (n=5) | 0 |

- **Kuicksilver server, msquic client, crosstraffic:** msquic's interop client gives a download 50 s
  (`-test:D -timeout:50000` in its `run_endpoint.sh`). 25 MB in 50 s needs 4.0 Mbit/s; Kuicksilver's CUBIC took
  4.2 Mbit/s against the TCP flow in the first JVM repetition (49.8 s) and a little less in the next one, which msquic's
  client then ended at 50 s with about 22 MB received ("Request closed incomplete"); the Native image's first
  repetition ended the same way (about 23 MB in 50 s, 3.7 Mbit/s). These cells are censored by the peer's timeout, not failed transfers; the share
  itself is in line with the quinn cells (4.2 Mbit/s).
- **msquic server, Kuicksilver client, goodput:** some repetitions are 4–5 % slower, with either client: in the morning
  run four of five with the JVM client (8.8–9.1 Mbit/s) and two of five with the Native one, in the evening run (the
  numbers above) two of five with each. The packet captures show the cause on msquic's side; see
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
| kuicksilver JVM | 3.76 [3.26–4.18] | 5.02 [4.92–5.40] | 50 % | 1494 | 9.6 | 2.31 |
| kuicksilver Native | 3.88 [3.83–3.98] | 3.84 [3.79–3.85] | 52 % | 1490 | 9.3 | 1.80 |
| quiche (amd64, emulated) | 11.47 [11.42–12.44] | 7.38 [7.35–7.56] | 31 % | 1392 | 10.0 | 0.66 |
| quinn | 15.56 [15.50–15.69] | 13.69 [13.59–13.83] | 71 % | 1440 | 30.2 | 0.65 |
| msquic (amd64, emulated) | 1.86 [1.84–1.93] | 2.68 [2.66–2.71] | 67 % | 1506 | 1.0 | 1.01 |
| *calibration:* kuicksilver Native (amd64, emulated), `c08bc57b` | 5.62 [5.62–5.73] | 5.70 [5.69–5.80] | 46 % | 1494 | 6.4 | 1.31 |

The calibration row is the morning's code; on that code the arm64 Native image measured 5.43 (server) and 5.44 (client)
s/GB, so emulation added 3–5 %.

What this says, and what it does not:

- **msquic uses about half of Kuicksilver's CPU per GB as a server even under emulation** (1.9 vs 3.8–3.9 s/GB), and
  2.7 vs 3.8–5.0 s/GB as a client. It sends 1506-byte packets and its client acknowledges about one packet in a hundred.
- Kuicksilver is below **quiche and quinn as their interop images run here** — quiche emulated, with GSO and pacing
  off; quinn from a 2024 build whose client acknowledges every third packet and whose server spends 71 % of its CPU
  in the kernel. That is a statement about these images on this host, not about quiche or quinn.
- **Kotlin/Native and the JVM cost the same as a server** (3.9 vs 3.8 s/GB; 5.4 vs 3.9 before the 0.2.1 receive path);
  as a client the JVM costs more (5.0 vs 3.8, which includes the JIT's compilation and the interop client's whole-file
  buffering).

Every pair, median of the five big transfers (row: server, column: client; `failed`: the transfer did not complete in
any round — quiche's client against msquic's server, a peer pair, not investigated):

Server CPU s/GB:

| server \ client | kuicksilver JVM | kuicksilver Native | quiche (amd64, emulated) | quinn | msquic (amd64, emulated) |
|---|---|---|---|---|---|
| kuicksilver JVM | 3.76 | 3.83 | 3.21 | 4.09 | 2.87 |
| kuicksilver Native | 4.03 | 3.88 | 3.61 | 4.48 | 3.37 |
| quiche (amd64, emulated) | 12.06 | 12.11 | 11.47 | 13.11 | 11.34 |
| quinn | 12.55 | 12.24 | 12.27 | 15.56 | 12.71 |
| msquic (amd64, emulated) | 2.64 | 2.78 | failed | 2.83 | 1.86 |

Client CPU s/GB:

| server \ client | kuicksilver JVM | kuicksilver Native | quiche (amd64, emulated) | quinn | msquic (amd64, emulated) |
|---|---|---|---|---|---|
| kuicksilver JVM | 5.02 | 3.72 | 5.67 | 6.43 | 2.70 |
| kuicksilver Native | 5.10 | 3.84 | 5.51 | 6.24 | 2.42 |
| quiche (amd64, emulated) | 5.81 | 5.46 | 7.38 | 7.34 | 3.55 |
| quinn | 8.38 | 7.55 | 7.75 | 13.69 | 6.01 |
| msquic (amd64, emulated) | 4.52 | 3.73 | failed | 5.26 | 2.68 |

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
| kuicksilver JVM | 1710 [1703–1721] | 1.03 [1.03–1.05] | 1.78 |
| kuicksilver Native | 1344 [1330–1346] | 0.94 [0.93–0.94] | 1.26 |
| quiche (amd64, emulated) | 228 [214–232] | 4.40 [4.33–4.68] | 1.00 |
| quinn | 3452 [3427–3462] | 0.53 [0.52–0.53] | 1.82 |
| msquic (amd64, emulated) | 3543 [3532–3567] | 0.70 [0.69–0.71] | 2.50 |
| *calibration:* kuicksilver Native (amd64, emulated), `c08bc57b` | 1100 [1091–1108] | 1.15 [1.14–1.16] | 1.27 |

- The two Kuicksilver rows are 2–3 % below the morning's (1748 and 1390/s) at the same CPU per handshake. The morning
  images measured again in the evening session gave 1476–1748 (JVM) and 1238–1363/s (Native) in three runs each, so the
  difference is within that session's spread; it was not investigated further.
- This is comparative because the client side is the same for every row; it is a handshake-plus-one-request rate
  (each connection also carries a GET and a close), not a bare TLS handshake rate.
- **quinn handshakes at half Kuicksilver's CPU and twice its rate; msquic, emulated, at 0.7 ms and 2.5 cores.** In a
  trial with 16 clients × 750 connections, quinn's rate was within 5 % of this one, so the load generator was not
  what held quinn back at ~3500/s; whether quinn or msquic could go higher with more load was not explored.
- quiche's interop server runs one thread and is pinned at 1.00 core; at 4.4 ms per handshake it was much slower here
  than in a short trial (1.25 ms with 16 × 200 connections), so its cost grows over 12 000 connections in this image.
  Under emulation; not a statement about quiche in production.
- Kuicksilver's server loop (both builds) did not use more than about 1.3 (Native) or 1.8 (JVM, garbage collector and
  JIT threads included) cores here.

## Worth a look

Two outliers of the morning run, investigated the same day, and one that remains.

**Resolved in 0.2.1: the Kuicksilver client's CPU per GB against quiche's and quinn's servers.** As a client Kuicksilver
cost 5.4–7.6 s/GB against Kuicksilver's and msquic's servers but 12–14 against quiche's and 9–18 against quinn's (JVM
18.2: 19.8 s of CPU for a 9.9 s transfer, half of it system time), and sent 14–20 packets per 100 received instead of
6.4. Morning (`c08bc57b`) and evening (0.2.1 receive path), client CPU s/GB, median of five 1 GiB transfers:

| server → client | before | after | wall s, before → after |
|---|---|---|---|
| quinn → kuicksilver JVM | 18.17 | 8.38 | 9.9 → 8.8 |
| quinn → kuicksilver Native | 9.07 | 7.55 | 8.5 → 8.5 |
| quiche → kuicksilver JVM | 13.88 | 5.81 | 15.3 → 13.7 |
| quiche → kuicksilver Native | 12.19 | 5.46 | 15.6 → 13.8 |
| msquic → kuicksilver JVM | 6.81 | 4.52 | 3.7 → 3.2 |
| kuicksilver JVM → kuicksilver JVM | 6.68 | 5.02 | 3.9 → 3.7 |
| kuicksilver Native → kuicksilver Native | 5.44 | 3.84 | 5.9 → 4.8 |

The servers' CPU fell with it (quinn's from 14.5 to 12.6 s/GB serving the JVM client, Kuicksilver Native's from 5.4 to
3.9). What the cause was, and what it was not:

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
first). The same transfer from quinn now has 98 000
context switches on the dispatcher threads and 59 000 on the reading thread. A first version that let queued work run
only every 16 rounds or 2 ms (the loop's `WorkLimiter`) starved the application's reads, which extend the stream's
flow-control credit, and made Kuicksilver → Kuicksilver 2.6 times slower; that is why the receiver yields as often as
the blocking receive did. The client now acknowledges more often (33 instead of 20 packets per 100 from quinn: a faster
loop takes smaller batches), still no more than one ACK per two ack-eliciting packets.

**msquic server → Kuicksilver client goodput: msquic's, not ours.** Some repetitions are 4–5 % slower, with either
client (morning: four of five JVM, two of five Native; evening: two of five each). In every slow repetition the
runner's captures show the same thing: from some point to the end of the transfer msquic sends a steady 12.7 Mbit/s
(server side of the simulator, 250 ms bins) into the 10 Mbit/s link, and about 60 of its packets per 250 ms are dropped
at the 25-packet queue; it never backs off. In the fast repetitions it sends 10.0 Mbit/s after slow start with a drop
every two seconds. The client's side is the same in both: ACKs leave 0.07–0.09 ms (JVM) and 0.15–0.20 ms (Native)
after the packet they acknowledge, every acknowledged packet number was received (none of the ~1 900 dropped packets of
a slow repetition was acknowledged), and the stream flow-control updates match. Nothing in Kuicksilver changes it;
msquic runs emulated here, and why its congestion controller keeps that rate was not investigated.

**Still open: Kuicksilver's CPU per handshake** (0.94 ms Native, 1.03 ms JVM) is about twice quinn's (0.53 ms).

## Reproducing

From the repository root, with Docker, `jq`, `tshark` (Wireshark) and the runner's Python environment as
`tools/interop/run-local.sh` sets them up:

```bash
# the images under test (the morning run used the tag bench-c08bc57b, the evening one k8-perf-client)
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

Versions (all digests in [benchmarks/env.txt](benchmarks/env.txt)):

| implementation | image | arch | image built |
|---|---|---|---|
| kuicksilver JVM | `kuicksilver-interop:bench-c08bc57b` (OpenJDK 21, `libksl` 6); evening: `kuicksilver-interop:k8-perf-client` | arm64 | 2026-10-20 |
| kuicksilver Native | `kuicksilver-interop-native:bench-c08bc57b`; evening: `kuicksilver-interop-native:k8-perf-client` | arm64 | 2026-10-20 |
| quiche | `cloudflare/quiche-qns@sha256:a960608c…` | amd64 | 2026-10-06 |
| quinn | `stammw/quinn-interop@sha256:5205c84e…` | arm64 | 2024-09-02 |
| msquic | `ghcr.io/microsoft/msquic/qns@sha256:ef95e1bc…` | amd64 | 2026-10-05 |
| simulator | `martenseemann/quic-network-simulator@sha256:c23d82a5…` | arm64 | |
| crosstraffic TCP flow | `martenseemann/quic-interop-iperf-endpoint@sha256:cb50cc80…` | amd64 | |
