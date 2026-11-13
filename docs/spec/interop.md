<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Kuicksilver — interop results

Results of the QUIC Interop Runner matrices, the runner's http3 case, h2spec against the HTTP/2 server, the engine interop bench (the Ktor engines against other HTTP implementations on the JVM) and the browser WebTransport checks, with the analysis of every red cell. They are the evidence for the ✅ rows of the [RFC compliance summary](rfc-compliance.md); `tools/interop/required.json` lists the cells that must stay green and `tools/interop/perf-thresholds.json` the throughput floors.

## Interop matrix (0.2.0, QUIC Interop Runner 740c05a, 2026-10-13)

The pre-release matrix re-run on the 0.2.0 code (with every 0.2.0 change: Retry tokens, path validation and eviction, ECN on the macOS JVM socket, dual-stack wildcard sockets, accept-queue refusal, the reassembly-limit change, 0-RTT) with the runner's two new cases `resumption` and `zerortt`. Same host and images as the pre-release matrix (arm64 Docker Desktop, quiche under amd64 emulation); local runs, logs not published: 20261013-034946 (quic-go), -042956 (ngtcp2), -050959 (quinn), one run each for picoquic, quiche and msquic, two reruns, a run with the JVM and native images rebuilt with the first fix below (quiche and the native subset), one for the client-role `zerortt` after the second fix, and a verification run with both fixes. ✓¹ — red once, green on the rerun of that cell.

JVM image (6 peers × 21 cases × 2 roles: 227 of the 237 cells both sides support are green; every required cell green):

| case | msquic S / C | ngtcp2 S / C | picoquic S / C | quic-go S / C | quiche S / C | quinn S / C |
|---|---|---|---|---|---|---|
| handshake | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| transfer | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| longrtt | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| chacha20 | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ? / ✓ | ✓ / ✓ |
| multiplexing | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✗ / ✓ | ✓ / ✓ |
| retry | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| resumption | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| zerortt | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓¹ | ✓ / ✓ |
| http3 | ? / ? | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| blackhole | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| keyupdate | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ? / ✓ | ✓ / ✓ |
| ecn | ? / ? | ✓ / ✓ | ✓ / ✓ | ? / ? | ? / ? | ✓ / ✓ |
| amplificationlimit | ✓ / ✗ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| handshakeloss | ✓ / ✗ | ✓ / ✓ | ✓ / ✓¹ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| transferloss | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| handshakecorruption | ✓ / ✗ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✗ / ✓ |
| transfercorruption | ✓ / ✓¹ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| ipv6 | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| v2 | ✓ / ✓ | ✓ / ✓ | ✗ / ✓ | ? / ? | ? / ? | ✗ / ? |
| rebind-port | ✓ / ✓ | ✓ / ✓ | ✗ / ✓ | ✓ / ✓ | ✓ / ✗ | ✓ / ✓ |
| rebind-addr | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✗ | ✓ / ✓ |

No regression against the pre-release matrix. Red cells, classified against `required.json` and the pre-release analysis above:

- **Fixed in 0.2.0**: `quiche->kuicksilver:zerortt` — the client's 0-RTT requests (`writeFully`, then `flushAndClose`) left as a data frame and a FIN-only frame in separate packets; quiche's hq server answered the first six and never the requests whose FIN came alone (server log: `stream N has 0 bytes (fin? true)` with no response, then its idle timeout). `flushAndClose` now hands buffered data to the core with the FIN, and the interop client writes the request into the channel's buffer and closes it in one step, so request and FIN share one STREAM frame — `api.StreamBridgeTest.flushAndCloseSendsDataAndFinInOnePacket`; green in the run with the first fix. Not a regression: the case is new in 0.2.0. The client-role `zerortt` cells also needed the second fix described under the native image (requests closed together share packets), which keeps every request in 0-RTT.
- **Known, pre-existing (pre-release analysis, not required)**: `msquic->kuicksilver:amplificationlimit`/`handshakeloss`/`handshakecorruption` (msquic's two connection instances, "Expected exactly 1 handshake. Got: 2"), `kuicksilver->quinn:handshakecorruption` (server role, not required since 2026-10-09), `kuicksilver->quinn:v2` (quinn sends no `version_information`), `kuicksilver->picoquic:v2` (a picoquic defect found before 0.2.0), `kuicksilver->picoquic:rebind-port` (runner artefact: PATH_RESPONSE coalesced behind a Handshake packet, "PATH_CHALLENGE without a PATH_RESPONSE"), `kuicksilver->quiche:multiplexing` (quiche client exits 254 under emulation, also in the run with the first fix), `quiche->kuicksilver:rebind-port`/`rebind-addr` (quiche's `set_active_path` loss detection).
- **Red once, verdict from the saved logs (required, stay required)**: `msquic->kuicksilver:transfercorruption` (the msquic run) — msquic: "Expected exactly 1 handshake. Got: 2". Our Initial pn 0 was lost (pcap right), msquic answered pn 1 with an ACK-only Initial from SCID `231b37a821c415e6` (our original DCID, pn 156) and then sent its ServerHello from SCID `c80d28bc89643bdd4f` (pn 157/158): two server connection IDs for one client connection, the two-instance behaviour of the pre-release `handshakeloss` analysis; our client adopts a new SCID until Initial CRYPTO has arrived on purpose (`core/PacketReceiver.kt`), otherwise the handshake with msquic could not finish. `picoquic->kuicksilver:handshakeloss` (the picoquic run) — picoquic and the scenario: our Initials 0/1 were dropped, picoquic's flight and three of its PTO resends were dropped, and the first RTT sample, taken from its fourth resend acknowledging our Initial 3, was 1.32 s (RFC 9002 §5.3: the first sample is `latest_rtt`, ack delay is not applied), so our PTO became 3.95 s; our Handshake PING probes at 36.93 s and 44.84 s reached picoquic, which answered the second with an ACK-only Handshake packet and resent its data at 36.96 s and 54.92 s, both dropped (pcaps); after the Handshake ACK our client arms no anti-deadlock PTO (RFC 9002 §6.2.2.1: only while no Handshake packet is acknowledged), so it waited for picoquic until its 30 s timeout. Client behaviour per RFC 9002; green in the pre-release matrix and in the first rerun.
- **Verification run with both fixes** (JVM image, all 21 cases against quic-go in both roles; native subset plus `multiplexing` against ngtcp2 in both roles): all green except two cells. `kuicksilver->quic-go:zerortt` — runner capture artefact: "Expected exactly 2 handshakes. Got: 0" because both simulator pcaps hold only the ~20 ICMPv6 packets captured before the transfer (3.6 KB, dumpcap's counter stopped at 20 per interface) while our server and quic-go completed both connections with an RTT of 41–68 ms (client qlog), which only the simulator's 2 × 15 ms link gives — the packets went through the simulator but were not captured; 7 of 7 reruns green with 37–51 KB pcaps. `quic-go->kuicksilver:handshakecorruption` — fixed in 0.2.0: "Expected 50 handshakes. Got: 52". The scenario dropped the first datagram of our two-datagram ClientHello (X25519MLKEM768) four times in a row and one whole round (measured loss 29 % and 31 % for the first and second datagram); our probes at 0, 1, 3, 7, 15 s (333 ms initial RTT, RFC 9002 §6.2.1) left quic-go 6 s without a packet, more than its 5 s handshake idle timeout (`DefaultHandshakeIdleTimeout = 5 * time.Second`, `internal/protocol/params.go`; server log "Destroying connection: timeout: no recent network activity"), so it answered the next probe from a new connection with a new SCID, which the runner counts as another handshake. The references: quic-go starts from 100 ms (PTO 200 ms, cap 60 s), ngtcp2, quiche and msquic from 333 ms without a cap. Fix (RFC 9002 §6.2.2, "MAY use the previous connection's final smoothed RTT"): a client endpoint remembers the final smoothed RTT of its last connection to each server address that ended on its own socket (256 addresses, the least recently stored dropped first; never on a server endpoint; a migrated connection does not count; clamped to 1 ms–10 s) and the next connection to that address starts from it, so the interop client's 49 later connections probe at about 3 × 35 ms — `endpoint.EndpointCoreTest.nextClientConnectionStartsFromTheLastMeasuredRtt`, `negative_rttMemoryBoundedAndClientOnly`. The value comes only from the endpoint's own measurements of its own connections, so only the server it measured can raise it, for connections to itself. With the fix (JVM image rebuilt) the cell was green in 6 of 6 runs and stays in `required.json`.
- **Now green that were red in the pre-release matrix**: `kuicksilver->picoquic:amplificationlimit`, `quiche->kuicksilver:handshakeloss`/`handshakecorruption`, `kuicksilver->msquic:amplificationlimit`/`rebind-port`/`rebind-addr`, `msquic->kuicksilver:rebind-port`/`rebind-addr` (single runs; the not-required ones stay out of `required.json` until they hold over several runs).
- Areas the 0.2.0 work touched (green cells of those both sides support; every red one is classified above): `retry` 12/12, `rebind-port`/`rebind-addr` (path validation and eviction) except the known picoquic/quiche cells, `ecn` 6/6 (ngtcp2, picoquic, quinn), `ipv6` 12/12, `multiplexing` 11/12, `amplificationlimit` 11/12, `v2` 5/7, `handshakeloss`/`handshakecorruption` in the client role 5/6 each, `transferloss`/`transfercorruption` 12/12. The accept-queue refusal and dual-stack sockets have no runner case of their own; every case above runs through them (the server's accept queue, the client's wildcard bind).

`resumption` and `zerortt`: ✓ in both roles against all six peers with both images (after the two fixes); the runner checks that the second connection resumes (no certificate) and, for `zerortt`, that the requests travel in 0-RTT packets. `required.json` gains `resumption` in both roles and `zerortt` in both roles except `quinn->…:zerortt` (the client's ACKs alone bring its 1-RTT payload to 4.3–4.5 KB of the runner's 5000).

Native image (Kotlin/Native linuxArm64, rebuilt with the first fix; the client-role `zerortt` cells again after the second fix; the pre-release subset plus `http3`, `resumption`, `zerortt` and quiche as a sixth peer: 96 of the 99 cells both sides support are green):

| case | msquic S / C | ngtcp2 S / C | picoquic S / C | quic-go S / C | quiche S / C | quinn S / C |
|---|---|---|---|---|---|---|
| handshake | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| transfer | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| retry | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| keyupdate | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ? / ✓ | ✓ / ✓ |
| ecn | ? / ? | ✓ / ✓ | ✓ / ✓ | ? / ? | ? / ? | ✓ / ✓ |
| rebind-port | ✗ / ✓ | ✓ / ✓ | ✗ / ✓ | ✓ / ✓ | ✓ / ✗ | ✓ / ✓ |
| http3 | ? / ? | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| resumption | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| zerortt | ✓ / ✓¹ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓¹ | ✓ / ✓ | ✓ / ✓ |

Red native cells: `kuicksilver-native->picoquic:rebind-port` and `quiche->kuicksilver-native:rebind-port` — the known picoquic runner artefact and quiche `set_active_path` (pre-release analysis); `kuicksilver-native->msquic:rebind-port` — an msquic defect, the pre-release `kuicksilver->msquic:rebind-addr` case: the simulator's rebind at 1 s swallowed our first flight to the old port, the server followed the new port at 2.05 s (after one PTO without packets from the old one) with a 1-RTT PATH_CHALLENGE, and msquic, its handshake still in progress, sent the PATH_RESPONSE inside an Initial packet (pcap `trace_node_left.pcap`, 4.0405 s: Initial pn 216 = ACK + PATH_RESPONSE `92c029af754fe7fb`); RFC 9000 §12.4 (table 3) allows PATH_RESPONSE only in 0-RTT and 1-RTT packets and requires PROTOCOL_VIOLATION otherwise, which our server sends (`frame 0x1b not allowed in Initial`, server qlog). In msquic (`src/core/send.c`, `QuicSendWriteFrames`, main at 638ba5f) the PATH_RESPONSE block is not guarded by the `Is1RttEncryptionLevel` check that the later frames use, so it is written at whatever level the packet being built has. Not required. The same trace shows our server resending its handshake flight to the new port only on its backed-off PTO (4.0 s). The references do not follow a client address change during the handshake at all, so none of them resets its PTO there: ngtcp2's server ignores such packets ("ignore packet from unknown path during handshake", `ngtcp2_conn.c`, states `NGTCP2_CS_SERVER_INITIAL`/`WAIT_HANDSHAKE`), quic-go moves a path only for 1-RTT packets (`connection.go`, path handling after `handleUnpackedShortHeaderPacket`; long-header packets never change the remote address) and quiche keeps long-header packets on the initial path (`lib.rs`: "During handshake, we are on the initial path"). Our server follows the rebind (the pre-release fix for picoquic) and keeps the RFC 9002 backoff; no reference does better, so this stays as it is; `quic-go->kuicksilver-native:zerortt` and `msquic->kuicksilver-native:zerortt` (red in the run with the first fix, green after the second) — the files arrived and the requests did travel in 0-RTT, but the runner allows the client at most 5000 bytes of 1-RTT payload (`0.5 × 250 × 40`): our client (both images) sent each request in a 303-byte packet of its own, so the 12000-byte initial window (RFC 9002 §7.2, the two 1200-byte Initials included) filled before the last requests and they went in 1-RTT after the handshake (qlog: 30 single-request 0-RTT packets, one full packet, the rest at the first RTT), 5168 and 6494 bytes with the client's ACKs (the JVM client, spilling the same way, was at 3.0–4.9 KB). Fixed in 0.2.0: `flushAndClose` yields on the loop after handing its data and FIN to the core, so closes already queued there add their frames to the same packet (`api.StreamBridgeTest.concurrentClosesShareAPacket`: 10 concurrent closes, at most 2 packets, were 10). After the fix every request goes in 0-RTT (10393 bytes) and the client's 1-RTT payload is 2.1–4.5 KB against all six peers, both images (24/24 green); a JVM full-case run against quic-go and a native run against ngtcp2 with the fix are in the verification run. Also benign, in every server log: "IPv6 endpoint not bound: EADDRINUSE" — since 0.2.0 the interop server's `0.0.0.0` endpoint is already dual-stack, so its second bind to `::` fails; IPv6 is served by the first (`ipv6` 12/12).

BBR vs CUBIC (0.2.0, commit d733e20): measurements from one image built from that commit and run twice, `KSL_CC=bbr` (tag `kuicksilver-interop-bbr:local`) and `KSL_CC=cubic` (the same image with the variable overridden), against quic-go and ngtcp2 in both roles (a local run, logs not published), the runner's 10 Mbit/s link, mean ± spread of the runner's 5 repetitions in kbit/s; the host was shared with other builds. Correctness with BBR: all 20 cells (handshake, transfer, longrtt, blackhole, transferloss, handshakeloss × quic-go/ngtcp2 × both roles) green, logs confirm `congestion controller bbr`.

| measurement | role (who sends) | quic-go BBR | quic-go CUBIC | ngtcp2 BBR | ngtcp2 CUBIC |
|---|---|---|---|---|---|
| goodput | kuicksilver server (we send) | 9174 ± 82 | 9350 ± 9 | 9057 ± 162 | 9177 ± 30 |
| goodput | kuicksilver client (peer sends) | 9451 ± 35 | 9448 ± 31 | 9302 ± 94 | 9332 ± 102 |
| crosstraffic | kuicksilver server (we send) | 5467 ± 482 | 4140 ± 99 | 5415 ± 151 | 4350 ± 514 |
| crosstraffic | kuicksilver client (peer sends) | 4751 ± 275 | 4817 ± 525 | 6127 ± 380 | 6616 ± 505 |

Where Kuicksilver sends, BBR keeps goodput within 2 % of CUBIC (−1.9 % quic-go, −1.3 % ngtcp2) and takes a larger share against the competing TCP CUBIC flow (+32 % and +24 %); in the client role the peer's controller sends the data and the two columns differ only by noise. Every ngtcp2 cell, BBR and CUBIC, is above its floor in `perf-thresholds.json` (quic-go has none).

Harness notes (after 0.2.0, 2026-10-20):

- `ngtcp2->kuicksilver[-native]:rebind-addr` stalls whenever its transfer is still running at 11 s: the simulator's binding from 11 s to 16 s is always 193.167.0.155:745 (fixed seed), and ngtcp2's example server drops every datagram from a source port below 1024 (`util::prohibited_port()` in `examples/server.cc`, checked before it logs the datagram). The server-side capture has 7–18 such datagrams per run, the ngtcp2 log none, while it logs every datagram from the other bindings (run 20261020-012547: 2072/2072, 1415/1415, 376/376, 18/0). Our client resumes on the 16 s binding when an ack-eliciting packet is still in flight (PTO probes), and otherwise idles out after 30 s with its download pending: with nothing ack-eliciting in flight no PTO is armed (RFC 9002 §6.2.1), and a keep-alive is optional (RFC 9000 §10.1.2; `QuicConfig.keepAlive` defaults to off, and the interop clients of quic-go, ngtcp2 and quiche send none). At the later start gate (first rebind + 1.25 s) 8 of 15 runs failed that way (5 of 10 JVM, 3 of 5 native), so `tools/interop/sim-entrypoint.sh` keeps rebind-addr's gate at + 0.3 s, where the transfer ends before 11 s. A peer and simulator cause, not a kuicksilver defect.
- `kuicksilver->picoquic:zerortt` (required) timed out in run 20261020-031632 right after the timed-out, not required `kuicksilver->picoquic:v2` cell: the runner's `docker compose stop` after a timeout lacks the cell's variables and fails (`invalid spec: :/www:ro`), compose reused the running simulator (`Container sim Running`), and that simulator kept sending to the previous server container's MAC address, so not one of picoquic's 13 Initials reached our new server (pcap: every Initial to the v2 server's MAC, the new server announcing another one). Reproduced every time with `-t v2,zerortt` and `-t v2,handshake`; `zerortt` alone was green 30/30 with the c193158b image and 30/30 with 49b51adc. `tools/interop/run-local.sh` now has compose recreate the simulator in every cell, and `environment.sh` classifies such a cell as ENVIRONMENT.

## Interop matrix (pre-release, QUIC Interop Runner 740c05a, 2026-10-08)

Images: `kuicksilver-interop:local` (JVM, accelerated UDP through JNI) and `kuicksilver-interop-native:local` (Kotlin/Native linuxArm64). The host is arm64 (Docker Desktop); the quiche image is linux/amd64 under emulation (`run-local.sh` pulls it with `--platform linux/amd64` when it is missing and its manifest list has no arm64 entry, `tools/interop/peer-images.sh`; an image it cannot obtain fails the run up front). Run: `tools/interop/run-local.sh -t <cases> <peer>`, Native — `--image native`. S — kuicksilver server, C — kuicksilver client; "?" — one of the sides answers "not supported".

JVM image (6 peers × 18 cases × 2 roles, 188/216 green; every supported case is ✓ in both roles against ≥ 3 peers):

| case | msquic S / C | ngtcp2 S / C | picoquic S / C | quic-go S / C | quiche S / C | quinn S / C |
|---|---|---|---|---|---|---|
| multiplexing | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✗ / ✓ | ✓ / ✓ |
| amplificationlimit | ✓ / ✗ | ✓ / ✓ | ✗ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| handshakeloss | ✓ / ✗ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✗ | ✗ / ✓ |
| handshakecorruption | ✓ / ✗ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✗ | ✗ / ✓ |
| ipv6 | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| ecn | ? / ? | ✓ / ✓ | ✓ / ✓ | ? / ? | ? / ? | ✓ / ✓ |
| v2 | ✓ / ✓ | ✓ / ✓ | ✗ / ✓ | ? / ? | ? / ? | ✗ / ? |
| rebind-port | ? / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✗ / ✗ | ✓ / ✓ |
| rebind-addr | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✗ | ✓ / ✓ |
| handshake | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| transfer | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| longrtt | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| chacha20 | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ? / ✓ | ✓ / ✓ |
| retry | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| keyupdate | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ? / ✓ | ✓ / ✓ |
| blackhole | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| transferloss | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| transfercorruption | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |

Red cells, analysed (pcap and key log of local runs, not published): `msquic->kuicksilver:rebind-port` (not required since 2026-10-09) — the runner wants the server's first packet on a new path to carry PATH_CHALLENGE; after the third rebind msquic's first packet is an ACK, while our client answered every challenge msquic sent (pcap: PATH_RESPONSE at 1.05 s and 6.05 s); `kuicksilver->msquic:rebind-addr` (not required since 2026-10-09) — msquic's handshake stays in the Initial space (its two connection instances, see `handshakeloss`), and when the 1 s rebind lands there it answers our PATH_CHALLENGE inside an Initial packet; RFC 9000 §12.4 forbids PATH_RESPONSE there and our server closes with PROTOCOL_VIOLATION `frame 0x1b not allowed in Initial`; `kuicksilver->msquic:amplificationlimit` (not required since 2026-10-09) — msquic reads the server's three back-to-back datagrams in one batch, acknowledges them in one datagram and probes once per PTO with exponential backoff, so the eighth datagram the scenario lets through arrives after msquic's own handshake timeout in about half of the runs, while the server, per RFC 9002 §6.2.2.1, arms no PTO (planned: pace the first flight); `msquic->kuicksilver:rebind-addr` (not required since 2026-10-09) — when the simulator's rebind at 1 s swallows msquic's PATH_CHALLENGE to the new address (run 20261009-040848: pn 430 to the new address and pn 431 to the old one both lost), msquic retransmits the challenge only to the old address, keeps sending data to the new one under its amplification limit and idles out; our client never receives a challenge to answer (pcap: no PATH_CHALLENGE reaches the client after the rebind); `handshakecorruption` in the server role (not required since 2026-10-09) — with a client that offers X25519MLKEM768 (quic-go, quiche, our own) the ServerHello and the ClientHello each span two datagrams; under the scenario's 30 % drop the RFC 9002 initial PTO schedule (1 s, 2 s, 4 s with no RTT sample) leaves three retransmissions before the peer client's 10 s handshake timeout, so one connection in fifty times out in roughly a quarter of the runs (quic-go uses a 100 ms initial RTT and fits five; since 0.2.0 `QuicConfig.initialRtt` lets a deployment choose that trade-off, e.g. `100.milliseconds` gives 300 ms, 600 ms, 1.2 s ... — `docs/guide/quic.md`, "Configuration"); the client role waits 30 s in the interop endpoint and stays required; 0.2.0 makes `initialRtt` configurable; `msquic` client role `amplificationlimit`/`handshakeloss`/`handshakecorruption` — msquic answers a two-packet ClientHello from two connection instances with different SCIDs, the runner sees two handshakes; `quinn` server role `handshakeloss`/`handshakecorruption` — one of 50 connections is abandoned by the quinn client on its own timeout while our server, limited by the amplification limit after its first flight, waits for a client packet that the 30 % burst loss does not let through (ngtcp2 and quic-go pass the same scenario); `kuicksilver->quinn:v2` — the quinn client does not send `version_information`; `picoquic` v2 — the peer defect found before 0.2.0; `kuicksilver->picoquic:amplificationlimit` — the picoquic client sends probes with an unbounded exponential backoff, the 8th (the first one not dropped by the scenario) arrives after 12.5 s, after our 10-second handshake timeout; `quiche` — the image runs under emulation, the client exits with code 254 on `multiplexing` and the rebind cases; the server stops the transfer after the port change (130–190 KB of 10 MB, every run): the simulator's 25-packet queue drops a slow-start burst right before the 1 s rebind, quiche's `set_active_path` runs loss detection on the old path once (`Recovery::on_path_change` → `detect_lost_packets`, time and packet threshold against the ACKs seen so far) and never again — the inactive path has no PTO and our ACKs on the new path only drive the new path's recovery — so packets sent in the last ~30 ms before the migration (here pn 300–346, one of them the retransmission of the 153-byte hole at offset 144121) are never retransmitted; the client has acknowledged everything it received, reads up to the hole and the server, already at our 768 KiB connection window (`DATA_BLOCKED`), repeats one later chunk until the idle timeout (run 20261009-013721, `quiche_kuicksilver-native/rebind-port`, server log pn 302 neither acked nor lost). Defects found by the matrix and fixed before 0.2.0: PTO without resending Handshake data (core), the IPv6 client, HelloRetryRequest for X25519 clients (`ksl`), a foreign SCID (RFC 9000 §7.2), the glitch bucket on no-op MAX_STREAMS, the name of the `ecn` case.

Measurements (the runner's 10 Mbit/s link, JVM image; a measurement, not a promise): goodput — kuicksilver server/ngtcp2 client 9293 ± 84 kbit/s, kuicksilver client/ngtcp2 server 9103 ± 19, server/quinn 9300 ± 4, client/quinn 9169 ± 6; crosstraffic (competing with TCP CUBIC) — 7042 ± 165, 5249 ± 674, 3633 ± 355, 4063 ± 329 kbit/s respectively. The host was shared with other builds during the run.

Throughput gate: these eight cells are the floors in `tools/interop/perf-thresholds.json` (key `server->client:measurement`,
kbit/s): the recorded mean minus 25 % for goodput and minus 40 % for crosstraffic, rounded down to 100 kbit/s (6900/6800
goodput, 2100–4200 crosstraffic). `tools/interop/run-local.sh --perf` runs the two measurements against every peer in
that file, and `tools/interop/check-perf.sh` fails when a cell is failed or missing. A cell below its floor only warns
until the floors are measured on more hosts (`"blocking": false` in the thresholds file; CONTRIBUTING.md, Throughput).
`.github/workflows/perf.yml` runs the same on GitHub-hosted runners on manual dispatch only (shared runners are too noisy for a weekly verdict). The floors catch a collapse (a congestion-control or pacing regression), not a few per cent; the native
image has no floors yet.

Native image (linuxArm64, 54/60 green; "?" for `ecn` — quic-go and msquic do not support the case, `rebind-port` for msquic — its client):

| case | msquic S / C | ngtcp2 S / C | picoquic S / C | quic-go S / C | quinn S / C |
|---|---|---|---|---|---|
| handshake | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| transfer | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| retry | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| keyupdate | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| ecn | ? / ? | ✓ / ✓ | ✓ / ✓ | ? / ? | ✓ / ✓ |
| rebind-port | ? / ✓ | ✓ / ✓ | ✗ / ✓ | ✓ / ✓ | ✓ / ✓ |

`kuicksilver-native->picoquic:rebind-port` — analysed in the final review: not Native-specific but a race in the simulator. The runner's first rebind happens at 1 s; when picoquic's first Initial lands 0.5 ms before it, the repeated Initials come from the new port, and the server (before the fix) kept answering to the old one until the handshake timeout expired. Fixed (row "RFC 9000 §9, §8.1 (rebind during the handshake)", [details](rfc/9000.md#s9-rebind-during-the-handshake)): after the fix the handshake completes, the file is downloaded (JVM 13 s, Native 23 s for 10 MiB), the first packet to the new port is a PATH_CHALLENGE and picoquic answers it. The remaining red in the `rebind-*` cells with picoquic (roughly every third run, JVM and Native alike) is a runner artifact: picoquic coalesces the PATH_RESPONSE into one datagram with its Handshake packet, while the runner's check looks only at the first QUIC layer of the datagram (`testcases_quic.py`, `path_response.data` of `p["quic"]`) and considers the challenge unanswered (pcap of local run 20261008-113008, answer at 2.064 s). Therefore the cells `kuicksilver->picoquic:rebind-port/addr` are taken out of `required.json` (marked in `note`), and the server's behaviour is pinned by four tests `core.PathTest.natRebindDuringHandshake*`/`handshakeTimeChallenge*`/`unansweredHandshakeTimeChallenge*`. The same traces show that the server repeats PATH_CHALLENGE to the old address every PTO without exponential backoff (§8.2.4 "no more often than Initial") — deferred as a minor finding.


## Interop http3 (QUIC Interop Runner 740c05a, 2026-10-08)

The runner's `http3` case (three files of 5 KiB / 10 KiB / 500 KiB, one HTTP/3 transaction each, one handshake, ALPN `h3`) is implemented in `kuicksilver-interop` on top of `kuicksilver-http3` (`H3InteropServer`/`H3InteropClient`, commit "feat(interop): the runner's http3 case"). Local runs 20261008-160445 (JVM image) and 20261008-160623 (native image, linux/arm64), logs not published:

| case | msquic S / C | ngtcp2 S / C | picoquic S / C | quic-go S / C | quiche S / C | quinn S / C |
|---|---|---|---|---|---|---|
| http3, JVM | ? / ? | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| http3, native | ? / ? | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |

"?" — msquic does not declare `http3` in the runner's `implementations.json`. All 20 green cells are added to `required.json`.

Third-party clients outside the runner: `curl --http3-only` (the `ymuski/curl-http3` build, quiche 0.18, amd64 under emulation) downloads a Ktor server response over HTTP/3 — `kuicksilver-ktor-server` `CurlHttp3Test.curlDownloadsOverHttp3Only` (enabled by the `KSL_CURL_H3_IMAGE` variable; the official `curlimages/curl` image is built without HTTP/3). h3spec has no ready image (it needs a Haskell stack build); its scenarios are covered by negative tests of `kuicksilver-http3` (threat-model 3.17); an h3spec run is deferred until such an environment exists.

## h2spec: the HTTP/2 server (h2spec 2.6.0, 2026-11-06)

`tools/interop/h2spec.sh` runs `summerwind/h2spec:2.6.0` (`-t -k`, TLS with ALPN `h2`, 5 s per case) against the Ktor
server engine with `http2 = true` and default `Http2Settings` (`tools/interop/h2-server.sh`, `H2specServer.kt` in
`kuicksilver-soak`). Every case must pass and none may be skipped; the script records the number of cases (146) so that a
new image is noticed. The first run had one failure, http2/5.1/12 ("closed: Sends a HEADERS frame": the server answered
with RST_STREAM STREAM_CLOSED, h2spec expects a connection error of that type, which RFC 9113 section 5.1 allows and RFC
7540 section 5.1 required); it is fixed (`core.StreamStateTest.negative_headersOnAClosedStreamIsAConnectionError`).

| server | generic | http2 (RFC 9113) | hpack (RFC 7541) | total |
|---|---|---|---|---|
| JVM (macOS arm64 host; h2spec in Docker Desktop, amd64 under emulation, reaching the host as `host.docker.internal`) | 44 / 44 | 94 / 94 | 8 / 8 | 146 / 146 |
| macosArm64 executable (same host) | 44 / 44 | 94 / 94 | 8 / 8 | 146 / 146 |
| linuxX64 executable (one linux/amd64 container with the h2spec binary) | — | — | — | release gate (`tools/ci/local-matrix.sh`) |

## Engine interop: the Ktor engines against other HTTP stacks (JVM, 2026-11-13)

The QUIC Interop Runner checks the QUIC and HTTP/3 libraries against other QUIC stacks; this bench checks HTTP semantics
through real engines. `kuicksilver-engine-interop` (not published, JVM tests only) starts each server in the test JVM on
a free loopback port and drives it with a client, at least one side Kuicksilver's: `./gradlew --max-workers=2
:kuicksilver-engine-interop:jvmTest`, about 40 s of tests (the step `jvm: engine interop` of the gate and of CI). Every
test asserts what the RFCs require of both ends; a test that a pair overrides documents a peer's behaviour and still
asserts Kuicksilver's side. Waits are on events (an application probe, Ktor's `ApplicationStopPreparing`), never on
sleeps; the only timers are the request timeout under test and a short QUIC idle timeout where a peer goes silent. Both
sides use the test PKI of the C tests (`kuicksilver-native/src/c/test/testdata`: a P-256 test CA and a leaf for
`server.test`, `127.0.0.1` and `::1`), the leaf sent without the CA.

Peers (versions as resolved with Ktor 3.6.1; JDK 21 toolchain):

| Peer | Version | Role | Protocols |
|---|---|---|---|
| Ktor Netty engine | Ktor 3.6.1, Netty 4.2.17.Final (JDK TLS; HTTP/3 through netty-codec-native-quic, quiche) | server | HTTP/1.1 and HTTP/2 over TLS (ALPN), HTTP/3 (`enableHttp3`, experimental), WebSocket |
| Ktor CIO engine | Ktor 3.6.1 | server, client | cleartext HTTP/1.1 and WebSocket (the server has no TLS; the client's TLS is TLS 1.2 only) |
| Plain Netty | Netty 4.2.17.Final, `HttpServerCodec` and `Http2FrameCodec` over JDK TLS | server | HTTP/1.1, HTTP/2: 1xx, trailers, GOAWAY |
| Ktor OkHttp engine, OkHttp | Ktor 3.6.1, OkHttp 5.5.1 | client | HTTP/1.1, HTTP/2, WebSocket (permessage-deflate) |
| Ktor Java engine, JDK HttpClient | Ktor 3.6.1, `java.net.http` of the test JDK (21.0.5 here) | client | HTTP/1.1, HTTP/2, WebSocket over HTTP/1.1 |
| Netty HTTP/3 client | Netty 4.2.17.Final, netty-codec-http3 (quiche) | client | HTTP/3 |

Scenarios of the HTTP pairs (`HttpPairSuite`, the same 19 tests for every pair): GET; POST with an empty, a small, a
1 MiB and a streamed body of unknown length (chunked over HTTP/1.1); a streamed and a fixed-length response; 50 request
fields with one of 2 KiB, inner punctuation and optional whitespace (RFC 9110 section 5.5), and 100 response fields;
a percent-encoded UTF-8 path and query; 200, 201, 204, 400, 404, 418, 500 and 503; HEAD (RFC 9110 section 9.3.2) and a
conditional GET answered 304 with its ETag (sections 13.1.2, 15.4.5); `Expect: 100-continue`; connection reuse; 32
concurrent requests; a response abandoned mid-body (the server's write must fail); a request timeout mid-body; a
graceful stop with a request in flight (RFC 9113 section 6.8, RFC 9114 section 5.2); and a server the client does not
trust (`negative_untrustedServerIsRefused`). The WebSocket pairs (`WebSocketPairSuite`, RFC 6455): text and binary
echo (256 KiB and empty), a message sent in three fragments by the client and by the server, a server Ping answered
with the same data, close codes and reasons both ways, and permessage-deflate (RFC 7692) negotiated by the client
engines that negotiate extensions, with context takeover across large and small messages.

Results (✓ passes as the RFC requires; ✓ᴾ passes asserting our side, the peer's behaviour is described below; — not
applicable to the pair):

| Client → server, protocol | bodies, fields, statuses, HEAD, 304, 100-continue, concurrency | reuse | cancel mid-body | timeout mid-body | graceful stop | untrusted CA | other |
|---|---|---|---|---|---|---|---|
| Kuicksilver → Ktor Netty, HTTP/1.1 over TLS | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | |
| Kuicksilver → Ktor Netty, HTTP/2 | ✓ | ✓ | ✓ | ✓ (fixed, 1) | ✓ | ✓ | field section above Netty's 8192 not sent ✓ |
| Kuicksilver → Ktor Netty, HTTP/3 | ✓ | ✓ | ✓ᴾ (4) | ✓ | ✓ᴾ (5) | ✓ | field section above 8192 not sent ✓ |
| Kuicksilver → Ktor CIO, cleartext HTTP/1.1 | ✓ | ✓ | ✓ | ✓ | ✓ | — | |
| Kuicksilver → plain Netty, HTTP/1.1 and HTTP/2 | | | | | | | 103 Early Hints before 200 ✓, trailers ✓, GOAWAY with a stream in flight (HTTP/2) ✓ |
| Ktor CIO → Kuicksilver, cleartext HTTP/1.1 | ✓ | ✓ᴾ (8) | ✓ | ✓ | ✓ | — | |
| Ktor CIO → Kuicksilver, TLS | — | — | — | — | — | — | refused with `protocol_version` ✓ (9) |
| Ktor OkHttp → Kuicksilver, HTTP/1.1 and HTTP/2 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | |
| Ktor Java → Kuicksilver, HTTP/1.1 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | |
| Ktor Java → Kuicksilver, HTTP/2 | ✓ | ✓ | ✓ | ✓ | ✓ᴾ (6) | ✓ | |
| OkHttp → Kuicksilver | | | | | | | ALPN `h2` / `http/1.1` both ways ✓, WebSocket permessage-deflate ✓, close codes ✓ |
| JDK HttpClient → Kuicksilver | | | | | | | ALPN ✓, HTTP/2 multiplexing ✓ᴾ (7), WebSocket fragments, Ping/Pong, close codes ✓ |
| Netty HTTP/3 → Kuicksilver | GET, 1 MiB POST, 204, 100 fields, UTF-8 target, 10 concurrent streams ✓; HEAD ✓ᴾ (3) | | | | | | |

| WebSocket client → server | text, binary | client fragments | server fragments | Ping → Pong | close codes | permessage-deflate |
|---|---|---|---|---|---|---|
| Kuicksilver → Ktor Netty (wss) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (Ktor's WebSocketDeflateExtension) |
| Kuicksilver → Ktor CIO (ws) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (Ktor's WebSocketDeflateExtension) |
| Ktor CIO → Kuicksilver (ws) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (Ktor's extension against PerMessageDeflate) |
| Ktor OkHttp → Kuicksilver (wss) | ✓ | ✓ᴾ (10) | ✓ | ✓ | ✓ | — (the engine negotiates no extensions; OkHttp's own: above) |
| Ktor Java → Kuicksilver (wss) | ✓ | ✓ | ✓ | ✓ | ✓ | — (no extensions in the JDK) |

Findings:

1. **Ours, fixed.** Over HTTP/2 the client engine failed a body that a request timeout (or the caller) cut short with
   the stream's own `CancellationException("the call ended")` instead of Ktor's `HttpRequestTimeoutException`; HTTP/1.1
   and HTTP/3 already reported the call's cause. The call's end now cancels the body with its cause before the stream is
   released (`ClientH2Test.requestTimeoutDuringTheBodyIsReportedAsSuch`).
2. **Ours, fixed.** Over HTTP/1.1 the server engine took the connection's addresses from `hostname`, which on the JVM is
   a reverse DNS lookup: every accepted connection made one, and `remoteAddress` and `remoteHost` read `localhost` for
   127.0.0.1, where HTTP/2 and HTTP/3 (and Ktor's Netty and CIO engines) give the IP literal
   (`ServerH1Test.connectionPointHasIpLiterals`).
3. **Netty's HTTP/3 codec (4.2.17).** A HEAD response with `content-length: 1000` and no DATA is reported as
   "Expected content-length 1000 != 0". RFC 9114 section 4.1.2: "A response that is defined as never having content,
   even when a Content-Length is present, can have a non-zero Content-Length header field even though no content is
   included in DATA frames." Our server's response is that; the test asserts the head and the empty content.
4. **Ktor's Netty engine over HTTP/3.** After our client abandons a response with STOP_SENDING (in its qlog), the
   server application's write never fails: Ktor's handler stays suspended until the connection ends (our server reports
   `H3_REQUEST_CANCELLED` to its application at once). RFC 9000 section 3.5: "An endpoint that receives a STOP_SENDING
   frame MUST send a RESET_STREAM frame if the stream is in the "Ready" or "Send" state." Whether quiche sent the
   RESET_STREAM is not visible from our side (our qlog lists received packets without their frames); the stream is
   never released to the application either way. The test asserts our STOP_SENDING and the next request.
5. **Ktor's Netty engine over HTTP/3.** Its stop sends nothing more on the connection: no GOAWAY, no rest of the
   response in flight, no CONNECTION_CLOSE (our qlog receives no packet after the stop began). RFC 9114 section 5.2
   describes the graceful shutdown ("Endpoints initiate the graceful shutdown of an HTTP/3 connection by sending a
   GOAWAY frame"). Our client fails the call once the QUIC idle timeout passes (RFC 9000 section 10.1); the test uses a
   3 s idle timeout.
6. **The JDK's HttpClient before 21.0.8** fails every open HTTP/2 stream on any GOAWAY, whatever its last stream
   identifier (JDK-8335181, fixed in 24 and backported to 21.0.8). Our GOAWAY keeps the stream in flight, which OkHttp
   completes; the test expects completion on a fixed JDK and "GOAWAY received" on an older one.
7. **The JDK's HttpClient** opens one connection per request while no HTTP/2 connection to the origin is up yet (20
   concurrent first requests, 20 connections). RFC 9113 section 9.1: "Clients SHOULD NOT open more than one HTTP/2
   connection to a given host and port pair". After a first request, the JDK multiplexes; the test asserts that.
8. **Ktor's CIO client** opens a new connection for every request, against Netty, CIO and our server alike; persistence
   is the client's choice. The test checks that every request succeeds.
9. **Ktor's CIO client** speaks TLS 1.2 only (ktor-network-tls) and our TCP connectors TLS 1.3 only, so there is no
   HTTP-over-TLS pair. Our server ends the handshake as RFC 8446 appendix D.2 requires: "If the "supported_versions"
   extension is absent and the server only supports versions greater than ClientHello.legacy_version, the server MUST
   abort the handshake with a "protocol_version" alert." (`CioToServerTlsTest`).
10. **Ktor's OkHttp engine** sends every `Frame` as a whole message, its `fin` ignored (OkHttp has no fragments in its
    API): three fragments arrive as three messages. Not an error on either side; a fragmented message cannot be sent
    through that engine.

Not in the bench, and why: Ktor's Jetty engine (Jetty 12.1, `ktor-server-jetty-jakarta`) brings Jakarta EE artifacts
(CDI, Interceptors, WebSocket API) signed by keys that no key server has and that no official source lists, so they
could only be pinned by checksum; that waits for a decision on those keys. WebSockets over HTTP/2 (RFC 8441): neither
of our engines offers Extended CONNECT on HTTP/2 yet ([RFC compliance](rfc-compliance.md)), and none of the JVM clients
here has it. HTTP/3 from the JDK's client: JDK 26 (JEP 517); the toolchain is 21. Ktor's Netty engine has no WebSockets
over HTTP/3 (RFC 9220), so the HTTP/3 pair has none.

## Interop WebTransport (browsers, 2026-10-22 and 2026-10-23)

The page `kuicksilver-ktor-server/src/jvmTest/resources/wt/index.html` runs, against the Ktor server's
`webTransport` routes: a 1 MiB bidirectional echo, a unidirectional stream from the server, 100 datagrams (one echoed
back counts: datagrams may be lost), a close by the page with code 7 and "bye", and a close by the server with code 9
and "server-bye".

| browser | draft spoken | how | result |
|---|---|---|---|
| Chrome 155 (macOS, headless) | draft-02 | `ChromeWebTransportTest.chromeDraft02` (opt-in: `-Pkuicksilver.browserTests=true`) | ✅ all steps, 100 of 100 datagrams echoed |
| Chrome 155 with `EnableWebTransportDraft07` | draft-02 (we announce no draft-07 SETTINGS) | `ChromeWebTransportTest.chromeWithDraft07EnabledFallsBackToDraft02` | ✅ |
| Firefox 158 (neqo) | draft-02 | manual, `tools/interop/wt-firefox-manual.sh` (2026-10-23) | ✅ every step of the page (the script prints PASS only when all are ok); the server saw the page's `WT_CLOSE_SESSION` with code 7 and "bye"; Firefox closes the QUIC connection with code 256 right after the session ends |
| Safari 26.4 | draft-14 (second-hand) | manual | not yet run |

webtransport-go's client requires `reset_stream_at`, which the Ktor server now advertises with `webTransport`; neither
direction against webtransport-go is run here (it belongs to the gate's interop image).

