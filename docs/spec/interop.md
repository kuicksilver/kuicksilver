<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Kuicksilver — interop results

Results of the QUIC Interop Runner matrices, the runner's http3 case, h2spec against the HTTP/2 server, h3spec against the HTTP/3 server, the Autobahn|Testsuite against the WebSocket server and client, WebSockets over HTTP/2 against Node.js and Chrome, the engine interop bench (the Ktor engines against other HTTP implementations on the JVM) and the browser WebTransport checks, with the analysis of every red cell. They are the evidence for the ✅ rows of the [RFC compliance summary](rfc-compliance.md); `tools/interop/required.json` lists the cells that must stay green and `tools/interop/perf-thresholds.json` the throughput floors. What Kuicksilver does only to work with a peer that lags behind or breaks a standard is listed, with its removal condition, in [compat-shims.md](compat-shims.md).

## msquic's provisional SCID: the cells expected red (2026-11-21)

Since 0.3.0 the client follows RFC 9000 §7.2 and §7.3 strictly, as quic-go, ngtcp2, quinn and picoquic do; until then it
had an exception for msquic ([compatibility shims](compat-shims.md#removed)). An msquic server answers part of a
ClientHello before its listener has accepted the connection: until then it sends from the client's own DCID (the
IsInitial source CID, `src/core/connection.c`), and only when the whole ClientHello has arrived does the listener give it
a new SCID (`QuicListenerAcceptConnection` → `QuicConnGenerateNewSourceCid`, `src/core/listener.c`), which it puts on the
ServerHello and every later packet and names in `initial_source_connection_id`. It is one connection with two SCIDs (its
packet numbers run on across the switch, 190 → 191 → 192 in the saved pcap), not two connection instances as this page
said before. §7.3 says "Each endpoint includes the value of the Source Connection ID field from the first Initial packet it
sent in the initial_source_connection_id transport parameter"; §7.2 makes a client that took the first Initial "discard any
subsequent packet it receives on that connection with a different Source Connection ID". So the handshake cannot finish;
our client ends it as soon as the switched ServerHello arrives (`ServerConnectionIdChanged`, sending nothing), quic-go and
the others by their timeouts. msquic knows: microsoft/msquic#3762 (open since 2023-07, "We cannot
generate a new CID until the listener has accepted the connection") and #4905 (open: OpenSSL's client with an ML-KEM
ClientHello of three datagrams hangs the same way; neqo's #5557 was closed as its duplicate).

msquic sends that provisional Initial when it acknowledges before it has the whole ClientHello: when the ClientHello needs
3 or more datagrams (it acknowledges after 2 ack-eliciting packets), or when a ClientHello datagram is lost and its
delayed-ACK timer fires. The QUIC Interop Runner counts the distinct SCIDs of server Initials as handshakes ("the SCID of
Initial packets doesn't change"), so it saw the switch as an extra handshake while the exception let ours finish. Cells
expected red because of msquic, out of `required.json`:

- `msquic->kuicksilver:resumption`, `msquic->kuicksilver:zerortt`, `msquic->kuicksilver-native:resumption`,
  `msquic->kuicksilver-native:zerortt`, every run: our resumption ClientHello is 2411 bytes, three datagrams
  (X25519MLKEM768 key share 1258 bytes, GREASE ECH 538 bytes, sized like a real offer as RFC 9849 §6.2.1 asks, PSK 347
  bytes). With the exception the runner said "Expected exactly 2 handshakes. Got: 3"; now the second connection fails.
- `msquic->kuicksilver:handshakeloss`, `handshakecorruption`, `amplificationlimit` (not required before either): the
  extra handshakes the runner counted ("Got: 70", "Got: 73", "Got: 2" of 50, 50 and 1 in the int37 run) were exactly the
  provisional SCIDs, 20, 23 and 1 of them, each from an ACK-only Initial; those connections now fail instead.
- `msquic->kuicksilver:transferloss`, `msquic->kuicksilver:transfercorruption`, now and then: whenever the scenario drops
  or corrupts a ClientHello datagram (the `transfercorruption` red of the 0.2.0 matrix below was this). The scenarios hit
  2 % of the datagrams toward the server (bursts of up to 3), and the first ClientHello takes 2, so roughly 4 to 6 runs in
  100 per cell.

Pinned by `core.ReceivePathTest.negative_msquicProvisionalScidFailsTheHandshakeAtOnceAndSilently` and, through the
Ktor client (the call goes over TCP with `FallbackReason.ServerConnectionIdChanged`), `MsquicProvisionalScidTest`. What applications
see: [troubleshooting](../guide/troubleshooting.md#msquic-servers-and-a-large-clienthello).

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
- **Known, pre-existing (pre-release analysis, not required)**: `msquic->kuicksilver:amplificationlimit`/`handshakeloss`/`handshakecorruption` (msquic's provisional SCID, see [above](#msquics-provisional-scid-the-cells-expected-red-2026-11-21); "Expected exactly 1 handshake. Got: 2"), `kuicksilver->quinn:handshakecorruption` (server role, not required since 2026-10-09), `kuicksilver->quinn:v2` (quinn sends no `version_information`), `kuicksilver->picoquic:v2` (a picoquic defect found before 0.2.0), `kuicksilver->picoquic:rebind-port` (runner artefact: PATH_RESPONSE coalesced behind a Handshake packet, "PATH_CHALLENGE without a PATH_RESPONSE"), `kuicksilver->quiche:multiplexing` (quiche client exits 254 under emulation, also in the run with the first fix), `quiche->kuicksilver:rebind-port`/`rebind-addr` (quiche's `set_active_path` loss detection).
- **Red once, verdict from the saved logs (required, stay required)**: `msquic->kuicksilver:transfercorruption` (the msquic run) — msquic: "Expected exactly 1 handshake. Got: 2". Our Initial pn 0 was lost (pcap right), msquic answered pn 1 with an ACK-only Initial from SCID `231b37a821c415e6` (our original DCID, pn 156) and then sent its ServerHello from SCID `c80d28bc89643bdd4f` (pn 157/158): two server connection IDs for one connection, msquic's provisional SCID ([above](#msquics-provisional-scid-the-cells-expected-red-2026-11-21)); our client then let an ACK-only Initial from its own DCID leave the SCID open, otherwise the handshake with msquic could not finish. Since 0.3.0 the client is strict and the cell is no longer required. `picoquic->kuicksilver:handshakeloss` (the picoquic run) — picoquic and the scenario: our Initials 0/1 were dropped, picoquic's flight and three of its PTO resends were dropped, and the first RTT sample, taken from its fourth resend acknowledging our Initial 3, was 1.32 s (RFC 9002 §5.3: the first sample is `latest_rtt`, ack delay is not applied), so our PTO became 3.95 s; our Handshake PING probes at 36.93 s and 44.84 s reached picoquic, which answered the second with an ACK-only Handshake packet and resent its data at 36.96 s and 54.92 s, both dropped (pcaps); after the Handshake ACK our client arms no anti-deadlock PTO (RFC 9002 §6.2.2.1: only while no Handshake packet is acknowledged), so it waited for picoquic until its 30 s timeout. Client behaviour per RFC 9002; green in the pre-release matrix and in the first rerun.
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
- `kuicksilver[-native]->msquic:zerortt` (required, 2026-11-24) went red in run 20261121-105505 of the 0.3.0 integration matrix with "Client sent too much data in 1-RTT packets": 5503 bytes, where the runner allows the client 5000 (`0.5 × 250 × 40`) over both connections. Sizes here are the runner's unit, a short-header packet's protected payload. msquic's own DPLPMTUD probes take most of that budget. After the handshake it sends a PING+PADDING probe at its next MTU and, once a probe is acknowledged, a larger one (`src/core/mtu_discovery.c`: "If the probe packet is acknowledged, that is set as the current MTU and a new probe packet is sent"; `QuicGetNextProbeSize`: 1280 first, then +80). The probes carry 1207, 1239 and 1319 bytes (IPv4 packets of 1248, 1280 and 1360 bytes): 1239 in the first connection, 1207 then 1239 in the second, 2446–5004 bytes in all in the saved runs. The first connection only fetches the ticket and closes on it, so it sends its 1319-byte probe only when our HANDSHAKE_DONE / NEW_TOKEN packet already acknowledges the 1239-byte one. That depends on whether msquic's Finished and the probe reach our server in one receive batch: 18 µs apart in the red run (server qlog: both read at 99.096 ms, then `ack[[112]],crypto,handshake_done,new_token`), 0.4 ms apart in the green run before it (the probe read 1.5 ms after our HANDSHAKE_DONE left, its ACK 29 ms later). RFC 9000 §13.2.1 requires ack-eliciting 1-RTT packets to be acknowledged within max_ack_delay; it does not require the ACK to ride on the next packet, but allows it, and ngtcp2 (`conn_write_pkt` adds `ngtcp2_acktr_create_ack_frame` to every 1-RTT packet) and quic-go (`composeNextPacket` takes `GetAckFrame` whenever it sends data) send a pending ACK that way too; holding it back to spare msquic a probe would only game the runner. No 0.3.0 integration change touched our ACK or receive batching. Ten reruns of the cell alone with the same image: 9 green (2831–4218 bytes), 1 red (the sixth: 5303 bytes, the same signature, 3984 without the raised 1319-byte probe). Over every saved run of the cell, JVM and native: 2803–5566 bytes; the three reds (5303, 5503 and a native 5566) all have the raised probe in the first connection, and 3984, 4184 and 4247 bytes without it. In no saved run does the client's 1-RTT carry anything but PADDING, PING, ACK, MAX_DATA, MAX_STREAM_DATA and CONNECTION_CLOSE. The cells stay required; `tools/interop/msquic-probe-budget.py` classifies exactly this as ENVIRONMENT (`environment.sh`, `msquic_probe_budget`), so `run-local.sh` reruns the cell (at most `KSL_INTEROP_ENV_RERUNS`; a cell red on every rerun stays red). From the client-side capture and the client's key log it proves that the client's 1-RTT payload is the runner's count; that every client 1-RTT packet, coalesced or not, decodes and carries only frames of an allow-list (PADDING, PING, ACK, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, the application CONNECTION_CLOSE; a transport CONNECTION_CLOSE would mean msquic found an error of ours), so a re-sent request (STREAM) is never excused; that in every connection each larger probe (a lone 1-RTT packet of PING and PADDING only, in a datagram of at least 1200 bytes) followed a server packet acknowledging the probe before it, with at least one such raise in the first connection; and that without the first connection's raised probes the client stays within 5000 bytes. msquic's PTO probe is also a lone PING+PADDING (`loss_detection.c`, `send.c`), as is a retried probe of the same size; neither grows after an ACK of the previous probe, so either, in any connection, keeps the cell red, while a probe that also carries MAX_STREAM_DATA (two green reruns) is no probe: its bytes stay counted (`environment-test.sh`, the `probes:` cases).
- `kuicksilver[-native]->quic-go:zerortt` (required, 2026-11-25) went red in run 20261125-041158 of the 0.3.0 integration matrix (native) and in run 20261120-234311 (JVM) with "Expected exactly 2 handshakes. Got: 1": both simulator pcaps ended 49–72 ms before the quic-go client's last qlog event, and the second connection, about 55 ms long, was not in them. `dumpcap` reads through libpcap with a 250 ms timeout and on Linux gets packets a block at a time (TPACKET_V3); the runner's compose (`--abort-on-container-exit`) signals the simulator 0.1–0.2 s after the client exits, and `tools/interop/sim-entrypoint.sh` forwarded that signal at once, so the open block was never written. Most cells' captures ended 18–72 ms before the client's last qlog event; a cell went red only when a whole short connection fell in that gap (1 of 3 runs of the native cell). The wrapper now forwards the signal 0.5 s late, twice that timeout: 8 of 8 runs green, every capture ending 8–628 ms after the quic-go client's last qlog event (`transfer` and `rebind-port` against quic-go unchanged, green in both roles).

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

Red cells, analysed (pcap and key log of local runs, not published): `msquic->kuicksilver:rebind-port` (not required since 2026-10-09) — the runner wants the server's first packet on a new path to carry PATH_CHALLENGE; after the third rebind msquic's first packet is an ACK, while our client answered every challenge msquic sent (pcap: PATH_RESPONSE at 1.05 s and 6.05 s); `kuicksilver->msquic:rebind-addr` (not required since 2026-10-09) — msquic's handshake stays in the Initial space, and when the 1 s rebind lands there it answers our PATH_CHALLENGE inside an Initial packet; RFC 9000 §12.4 forbids PATH_RESPONSE there and our server closes with PROTOCOL_VIOLATION `frame 0x1b not allowed in Initial`; `kuicksilver->msquic:amplificationlimit` (not required since 2026-10-09) — msquic reads the server's three back-to-back datagrams in one batch, acknowledges them in one datagram and probes once per PTO with exponential backoff, so the eighth datagram the scenario lets through arrives after msquic's own handshake timeout in about half of the runs, while the server, per RFC 9002 §6.2.2.1, arms no PTO (planned: pace the first flight); `msquic->kuicksilver:rebind-addr` (not required since 2026-10-09) — when the simulator's rebind at 1 s swallows msquic's PATH_CHALLENGE to the new address (run 20261009-040848: pn 430 to the new address and pn 431 to the old one both lost), msquic retransmits the challenge only to the old address, keeps sending data to the new one under its amplification limit and idles out; our client never receives a challenge to answer (pcap: no PATH_CHALLENGE reaches the client after the rebind); `handshakecorruption` in the server role (not required since 2026-10-09) — with a client that offers X25519MLKEM768 (quic-go, quiche, our own) the ServerHello and the ClientHello each span two datagrams; under the scenario's 30 % drop the RFC 9002 initial PTO schedule (1 s, 2 s, 4 s with no RTT sample) leaves three retransmissions before the peer client's 10 s handshake timeout, so one connection in fifty times out in roughly a quarter of the runs (quic-go uses a 100 ms initial RTT and fits five; since 0.2.0 `QuicConfig.initialRtt` lets a deployment choose that trade-off, e.g. `100.milliseconds` gives 300 ms, 600 ms, 1.2 s ... — `docs/guide/quic.md`, "Configuration"); the client role waits 30 s in the interop endpoint and stays required; 0.2.0 makes `initialRtt` configurable; `msquic` client role `amplificationlimit`/`handshakeloss`/`handshakecorruption` — msquic answers part of a two-packet ClientHello from a provisional SCID and the rest from a new one ([msquic's provisional SCID](#msquics-provisional-scid-the-cells-expected-red-2026-11-21)), the runner sees two handshakes; `quinn` server role `handshakeloss`/`handshakecorruption` — one of 50 connections is abandoned by the quinn client on its own timeout while our server, limited by the amplification limit after its first flight, waits for a client packet that the 30 % burst loss does not let through (ngtcp2 and quic-go pass the same scenario); `kuicksilver->quinn:v2` — the quinn client does not send `version_information`; `picoquic` v2 — the peer defect found before 0.2.0; `kuicksilver->picoquic:amplificationlimit` — the picoquic client sends probes with an unbounded exponential backoff, the 8th (the first one not dropped by the scenario) arrives after 12.5 s, after our 10-second handshake timeout; `quiche` — the image runs under emulation, the client exits with code 254 on `multiplexing` and the rebind cases; the server stops the transfer after the port change (130–190 KB of 10 MB, every run): the simulator's 25-packet queue drops a slow-start burst right before the 1 s rebind, quiche's `set_active_path` runs loss detection on the old path once (`Recovery::on_path_change` → `detect_lost_packets`, time and packet threshold against the ACKs seen so far) and never again — the inactive path has no PTO and our ACKs on the new path only drive the new path's recovery — so packets sent in the last ~30 ms before the migration (here pn 300–346, one of them the retransmission of the 153-byte hole at offset 144121) are never retransmitted; the client has acknowledged everything it received, reads up to the hole and the server, already at our 768 KiB connection window (`DATA_BLOCKED`), repeats one later chunk until the idle timeout (run 20261009-013721, `quiche_kuicksilver-native/rebind-port`, server log pn 302 neither acked nor lost). Defects found by the matrix and fixed before 0.2.0: PTO without resending Handshake data (core), the IPv6 client, HelloRetryRequest for X25519 clients (`ksl`), a foreign SCID (RFC 9000 §7.2), the glitch bucket on no-op MAX_STREAMS, the name of the `ecn` case.

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

Third-party clients outside the runner: `curl --http3-only` (the `ymuski/curl-http3` build, quiche 0.18, amd64 under emulation) downloads a Ktor server response over HTTP/3 — `kuicksilver-ktor-server` `CurlHttp3Test.curlDownloadsOverHttp3Only` (enabled by the `KSL_CURL_H3_IMAGE` variable; the official `curlimages/curl` image is built without HTTP/3). h3spec runs against the HTTP/3 server since 2026-11-26, from its release binaries ([below](#h3spec-the-http3-server-h3spec-v0115-2026-11-26)).

## h2spec: the HTTP/2 server (h2spec 2.6.0, 2026-11-06)

`tools/interop/h2spec.sh` runs `summerwind/h2spec:2.6.0` (`-t -k`, TLS with ALPN `h2`, 5 s per case) against the Ktor
server engine with `http2 = true` and default `Http2Settings` (`tools/interop/h2-server.sh`, `H2specServer.kt` in
`kuicksilver-soak`). Every case must pass and none may be skipped; the script records the number of cases (146) so that a
new image is noticed. The image is pinned by its registry digest in the script, and since 0.3.0 hosted CI runs it too
(`build.yml`, job `linux-native`, the linuxX64 server); its counts appear on the documentation site's conformance page.
The first run had one failure, http2/5.1/12 ("closed: Sends a HEADERS frame": the server answered
with RST_STREAM STREAM_CLOSED, h2spec expects a connection error of that type, which RFC 9113 section 5.1 allows and RFC
7540 section 5.1 required); it is fixed (`core.StreamStateTest.negative_headersOnAClosedStreamIsAConnectionError`).

h2spec sends the host it connects to as `:authority`. The test identity names 127.0.0.1 but not `host.docker.internal`,
so the servers on the macOS host run with `trusted-gateway`: the misdirected-request check (421, RFC 9110 section 7.4)
is off for them, and every case reaches the application. The linuxX64 executable, which h2spec reaches as 127.0.0.1,
runs with the check on (2026-11-14: 146 / 146). The check itself is covered by `ServerMisdirectedRequestTest`.

| server | generic | http2 (RFC 9113) | hpack (RFC 7541) | total |
|---|---|---|---|---|
| JVM (macOS arm64 host; h2spec in Docker Desktop, amd64 under emulation, reaching the host as `host.docker.internal`; `trusted-gateway`) | 44 / 44 | 94 / 94 | 8 / 8 | 146 / 146 |
| macosArm64 executable (same host; `trusted-gateway`) | 44 / 44 | 94 / 94 | 8 / 8 | 146 / 146 |
| linuxX64 executable (one linux/amd64 container with the h2spec binary; the check on; release gate, `tools/ci/local-matrix.sh`) | 44 / 44 | 94 / 94 | 8 / 8 | 146 / 146 |

## h3spec: the HTTP/3 server (h3spec v0.1.15, 2026-11-26)

`tools/interop/h3spec.sh` runs h3spec v0.1.15 (kazu-yamamoto/h3spec; `-n`, the certificate not validated; 2 s per case)
against the Ktor server engine with HTTP/3 on a TLS connector and 0-RTT accepted (`quicEarlyData`, so the 0-RTT case
runs instead of staying pending), default QUIC settings and `Http3Settings` (`H3specServer.kt` in `kuicksilver-soak`,
in the conformance executable). h3spec is the project's release binary, checked against the sha256 the script pins
(GitHub's digest of the release asset): the macOS arm64 one beside the JVM and macOS servers, the linux-x86_64 one with
the linuxX64 executable in one Debian 13 container (`tools/interop/h3spec.Dockerfile`; the binary needs glibc 2.34 and
libgmp). h3spec reaches every server as 127.0.0.1, so the misdirected-request check stays on. The script records the
number of cases (86) and fails on any failure or pending case except the ones it records as h3spec's own error, which
must fail exactly as recorded. The release gate runs it against the JVM server and the linuxX64 executable, hosted CI
(`build.yml`, job `linux-native`) against the linuxX64 executable.

One case is h3spec's error. "MUST NOT buffer an over-long frame on a control stream [HTTP/3 7.1]" sends a GOAWAY frame
whose Length is 2^30 and expects H3_EXCESSIVE_LOAD (or H3_GENERAL_PROTOCOL_ERROR or H3_INTERNAL_ERROR). A GOAWAY carries
one variable-length integer, at most 8 bytes (RFC 9114 section 7.2.6), so that Length can only mean "a frame payload that
contains additional bytes after the identified fields", which section 7.1 says "MUST be treated as a connection error of
type H3_FRAME_ERROR". The server closes with H3_FRAME_ERROR from the frame's header, before any payload, buffering
nothing (`FrameRules.checkControlLength`: H3_EXCESSIVE_LOAD is its answer for a SETTINGS or PRIORITY_UPDATE frame over
its limit, where the Length itself is not malformed). The script requires that failure message, "frame 0x7 of
1073741824 bytes holds one integer".

| server | QUIC (RFC 9000, RFC 9001) | HTTP/3 (RFC 9114, RFC 9204) | total |
|---|---|---|---|
| JVM (macOS arm64 host, h3spec's macOS binary beside it) | 44 / 44 | 41 / 42 (the recorded case) | 85 / 86 |
| macosArm64 executable (same host) | 44 / 44 | 41 / 42 (the recorded case) | 85 / 86 |
| linuxX64 executable (one linux/amd64 container with h3spec's Linux binary, under emulation on the Mac; release gate and hosted CI) | 44 / 44 | 41 / 42 (the recorded case) | 85 / 86 |

Before 0.3.0 no h3spec run was possible (no ready image; h3spec needs a Haskell build), and its scenarios were covered by
negative tests of `kuicksilver-http3` alone (threat-model 3.17); those stay.

## Autobahn|Testsuite: the WebSocket server and client (25.10.1, 2026-11-26)

`tools/interop/autobahn.sh` runs every case of the Autobahn|Testsuite 25.10.1 (517: framing, pings, reserved bits and
opcodes, fragmentation, UTF-8, the closing handshake, limits, and permessage-deflate, RFC 6455 and RFC 7692) in both
directions: its fuzzing client against the server engine (`server`) and the client engine against its fuzzing server
(`client`). The server and the client are the conformance executable's (`Autobahn.kt` in `kuicksilver-soak`): Ktor's
`WebSockets` plugin with `PerMessageDeflate`, over HTTP/1.1, the engines' default limits, and an echo of every Text
and Binary frame as it came; the engine answers each Ping (`WebSocketPongs`) and Ktor's `DefaultWebSocketSession`
answers the Close, as in an application. The image
(`crossbario/autobahn-testsuite`, linux/amd64 only) is pinned by its digest. A case passes when the suite's verdict is OK
or INFORMATIONAL for the case and for its closing handshake; any other verdict fails the run, except where the script
records the verdicts a case may get with the RFC text that allows them, and the number of cases (517) is recorded too.
The linuxX64 executable runs inside the suite's container; the JVM and macOS ones on the host. Where each runs:

| | linuxX64 server | linuxX64 client | JVM server | JVM client |
|---|---|---|---|---|
| release gate (`tools/ci/local-matrix.sh`, a Mac with Docker Desktop) | ✓ | ✓ | — (see below) | ✓ |
| hosted CI (`build.yml`) | ✓ (job `linux-native`) | ✓ (job `linux-native`) | ✓ (job `linux`, x64) | ✓ (job `linux`, x64) |

In hosted CI Docker runs on the Linux host itself: the suite reaches the JVM server on the host network as 127.0.0.1,
with none of Docker Desktop's forwarding in between. How long each hosted CI run takes (amd64, no emulation) is to be recorded here after its first
run; on the Mac, under emulation, the linuxX64 runs take about 14 minutes per direction and the JVM client about 8.

The first three rows are runs of the final `tools/interop/autobahn.sh`, after both fixes below (2026-11-26):

| run | OK | INFORMATIONAL | recorded (verdict) | other | total |
|---|---|---|---|---|---|
| linuxX64 server (in the suite's container, amd64 under emulation on the Mac; 14 min) | 514 | 3 | 0 | 0 | 517 |
| linuxX64 client (same container) | 433 | 3 | 9 (NON-STRICT), 72 (UNIMPLEMENTED) | 0 | 517 |
| JVM client (macOS arm64 host, the fuzzing server's port published on the host's loopback) | 434 | 3 | 8 (NON-STRICT), 72 (UNIMPLEMENTED) | 0 | 517 |
| JVM server (macOS arm64 host, the fuzzing client reaching it as `host.docker.internal`; two runs before the Pong fix, see below) | 470 | 3 | 7 (NON-STRICT), 36 (UNIMPLEMENTED, 13.3 and 13.5) | 1 (FAILED, 5.6, fixed since: 5.1 to 5.20 OK in 5 of 5 runs after it, 5.15 recorded) | 517 |

**Found and fixed.** 6.4.3 and 6.4.4 (NON-STRICT on the JVM and linuxX64 servers at the first runs): a text frame whose
second chop is not UTF-8 was failed only when its third chop came, a second later, because the frame guard checked the
payload in whole pieces of 16 KiB. It now checks the bytes as they arrive, compressed or not (RFC 6455 section 8.1;
`WebSocketInputRulesTest.negative_invalidUtf8FailsBeforeTheFrameIsComplete`,
`.negative_invalidUtf8InACompressedTextFailsBeforeTheFrameIsComplete`).

**Recorded: a valid message before a violation (3.2 to 3.4, 4.1.3 to 4.2.5, 5.15).** The suite sends a valid message and,
in the same read or octet by octet, a frame the receiver must fail the connection on (a reserved RSV bit or opcode, a
continuation with nothing to continue). OK means the echo of the valid message came before the Close 1002; NON-STRICT,
the suite's "allowed, not the strictest" verdict, that only the Close came. The engines hand Ktor's session a Close 1002
in place of the bad frame and Ktor's `DefaultWebSocketSession` answers it at once from its reading coroutine, while the
application's echo goes through its writing coroutine. On the server the order depends on thread scheduling (OK in the
runs of the table, NON-STRICT for some of these cases in other runs, JVM and linuxX64 alike); on the client the session
also cancels the application's block once both Close frames have passed, often before it read the message, so most of
these cases are NON-STRICT there in most runs. RFC 6455 section 7.1.7 asks the endpoint that fails the connection to send "a Close frame
with an appropriate status code" (1002 in every run); nothing asks for an answer to data that came before the violation.

**Found and fixed: the Pong after the echo (5.6 to 5.8, 5.19, 5.20).** A Ping comes between the fragments of a message;
the suite wants its Pong before the echo of the message. In some runs (2 of 4 of 5.6 on the JVM server, 1 of 2 of 5.19 on
the linuxX64 server) the Pong came right after the echo (FAILED): it was Ktor's `DefaultWebSocketSession`'s, written by a
coroutine of its own that ran after the application had echoed the message. RFC 6455 section 5.5.2: "It SHOULD respond
with Pong frame as soon as is practical", and section 5.4 lets control frames "be injected in the middle of a fragmented
message". The engines now answer a Ping themselves as soon as they read it (`WebSocketPongs`), at the output's next frame
boundary, with the Ping's data (section 5.5.3), and drop the session's own Pong for it
(`WebSocketPongsTest.negative_pingBetweenFragmentsIsAnsweredBeforeTheMessageCompletes`,
`ServerWebSocketGuardTest.negative_oneServerPongPerPing`). These cases are not recorded: they must be OK.

**Recorded: client_max_window_bits (13.3 to 13.6, client).** In these cases the fuzzing server accepts permessage-deflate
only by answering `client_max_window_bits` (9 or 15), which RFC 7692 section 7.1.2.2 forbids when the offer does not
carry it ("the corresponding extension negotiation response to the offer MUST NOT include the "client_max_window_bits"
extension parameter"). `PerMessageDeflate` does not offer it ("A client MAY include" it, the same section): the JVM's
Deflater has a fixed 15-bit window and could not keep to a smaller value. So the suite declines the extension and marks
the case UNIMPLEMENTED. The linuxX64 server runs all of 13 with every offer the suite makes (OK).

**Recorded: server_max_window_bits=9 on the JVM (13.3 and 13.5, JVM server).** Here the fuzzing client offers
`server_max_window_bits=9`. RFC 7692 section 7.1.2.1: a server accepts it "by including the "server_max_window_bits"
extension parameter in the extension negotiation response ... with the same or smaller value", and "declines an extension
negotiation offer with this parameter if the server doesn't support it". The JVM's Deflater has a fixed 15-bit window,
so the JVM server declines and the suite marks the case UNIMPLEMENTED; the linuxX64 server, on zlib, keeps to 9 (OK).

**The JVM and macOS servers on a Mac.** The suite in Docker Desktop reaches a server on the host only through
`host.docker.internal`, where an occasional TCP connect times out whatever the server: 3 of 1,500 connects to a plain
Python TCP server timed out (2026-11-26), and a run of 517 cases opens 517 connections, so most full runs stop part-way
with the suite's "User timeout caused connection failure". That is why the gate runs the linuxX64 server, inside the
suite's own container, and not the JVM one; hosted CI runs the JVM server on its Linux runner. The JVM server's row is
two runs on the Mac: all cases up to 13.7.6 (the next connect timed out), then 13.7.

## WebSockets over HTTP/2 (RFC 8441, 2026-11-12)

Against independent implementations, both directions; each run opens one TLS connection with ALPN `h2`, a WebSocket as
an Extended CONNECT on it, one text message echoed, and a close with 1000 (the tests print what each side saw).

| peer | role of the peer | how | result |
|---|---|---|---|
| Node.js 24.15 `http2` (nghttp2) | client of our server | `NodeH2WebSocketInteropTest.nodeClientAgainstOurServer` (runs when `node` is found; `KSL_NODE`) | ✅ SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 seen, `:status 200` without `sec-websocket-accept`, echo `HTTP/2:node`, our Close 1000 and END_STREAM, the stream closed without a reset |
| Node.js 24.15 `http2` (nghttp2) | server of our client | `NodeH2WebSocketInteropTest.ourClientAgainstNodeServer` | ✅ our client's CONNECT with `:protocol websocket`, `:scheme https`, the path with its query, `sec-websocket-version 13` and no `sec-websocket-key`, `connection`, `upgrade` or `host`; the subprotocol accepted; masked frames; both END_STREAMs, no reset |
| Chrome 157 (macOS, headless, QUIC off) | client of our server | `ChromeWebSocketH2Test.chromeWebSocketOverH2` (opt-in: `-Pkuicksilver.browserTests=true`) | ✅ Chrome sent the page's `wss://` WebSocket on the page's HTTP/2 connection (the route saw `HTTP/2`), echo and close 1000 |

Our client against our server: `ServerWebSocketH2Test.kuicksilverClientOverH2`. OkHttp has no RFC 8441, and the
pinned Docker images at hand (nginx, Caddy) were not run: nginx has no RFC 8441, and Node.js covers nghttp2.

## Engine interop: the Ktor engines against other HTTP stacks (JVM, 2026-11-13)

The QUIC Interop Runner checks the QUIC and HTTP/3 libraries against other QUIC stacks; this bench checks HTTP semantics
through real engines. `kuicksilver-engine-interop` (not published, JVM tests only) starts each server in the test JVM on
a free loopback port and drives it with a client, at least one side Kuicksilver's: `./gradlew --max-workers=2
:kuicksilver-engine-interop:jvmTest`, about 35 s of tests and about a minute with the compilation (the step `jvm: engine interop (Ktor engines, OkHttp, JDK, Netty)` of the gate and of CI). Every
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
| Ktor CIO → Kuicksilver, cleartext HTTP/1.1 | ✓ | ✓ᴾ (7) | ✓ | ✓ | ✓ | — | |
| Ktor CIO → Kuicksilver, TLS | — | — | — | — | — | — | refused with `protocol_version` ✓ (8) |
| Ktor OkHttp → Kuicksilver, HTTP/1.1 and HTTP/2 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | |
| Ktor Java → Kuicksilver, HTTP/1.1 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | |
| Ktor Java → Kuicksilver, HTTP/2 | ✓ | ✓ | ✓ | ✓ | ✓ᴾ (6) | ✓ | |
| OkHttp → Kuicksilver | | | | | | | ALPN `h2` / `http/1.1` both ways ✓, WebSocket permessage-deflate ✓, close codes ✓ |
| JDK HttpClient → Kuicksilver | | | | | | | ALPN ✓, HTTP/2 multiplexing (20 requests on one connection) ✓, WebSocket fragments, Ping/Pong, close codes ✓ |
| h2c (`H2cInteropTest`, 2026-11-18) | | | | | | | OkHttp `H2_PRIOR_KNOWLEDGE` → Kuicksilver (`Only` and `WithHttp11`) ✓, Ktor OkHttp engine with it ✓, JDK HttpClient (`HTTP_2` sends `Upgrade: h2c`, no prior knowledge) → `WithHttp11` served HTTP/1.1 ✓ and → `Only` refused ✓, Kuicksilver → plain Netty h2c (trailers, reuse) ✓, Kuicksilver → Ktor Netty `enableH2c` ✓; by hand: curl 8.7.1 `--http2-prior-knowledge` → the h2spec server's h2c connector ✓ |
| Netty HTTP/3 → Kuicksilver | GET, 1 MiB POST, 204, 100 fields, UTF-8 target, 10 concurrent streams, HEAD (Content-Length without content) ✓ | | | | | | |

| WebSocket client → server | text, binary | client fragments | server fragments | Ping → Pong | close codes | permessage-deflate |
|---|---|---|---|---|---|---|
| Kuicksilver → Ktor Netty (wss) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (Ktor's WebSocketDeflateExtension) |
| Kuicksilver → Ktor CIO (ws) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (Ktor's WebSocketDeflateExtension) |
| Ktor CIO → Kuicksilver (ws) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (Ktor's extension against PerMessageDeflate) |
| Ktor OkHttp → Kuicksilver (wss) | ✓ | ✓ᴾ (9) | ✓ | ✓ | ✓ | — (the engine negotiates no extensions; OkHttp's own: above) |
| Ktor Java → Kuicksilver (wss) | ✓ | ✓ | ✓ | ✓ | ✓ | — (no extensions in the JDK) |

Findings:

1. **Ours, fixed.** Over HTTP/2 the client engine failed a body that a request timeout (or the caller) cut short with
   the stream's own `CancellationException("the call ended")` instead of Ktor's `HttpRequestTimeoutException`; HTTP/1.1
   and HTTP/3 already reported the call's cause. The call's end now cancels the body with its cause before the stream is
   released (`ClientH2Test.requestTimeoutDuringTheBodyIsReportedAsSuch`).
2. **Ours, fixed.** Over HTTP/1.1 the server engine took the connection's addresses from `hostname`, which on the JVM is
   a reverse DNS lookup: every accepted connection made one, and `remoteAddress` and `remoteHost` read `localhost` for
   127.0.0.1, where HTTP/2 and HTTP/3 give the IP literal (`ServerH1Test.connectionPointHasIpLiterals`). Ktor's Netty
   and CIO engines give the literal for `remoteAddress` and `localAddress` and a name for `remoteHost` and `localHost`
   (`InetSocketAddress.getHostName()`, a lookup on first use); ours keep the literal there too, as over HTTP/2 and
   HTTP/3, a deliberate difference.
3. **Ours, fixed.** A stop of our server took 3 s longer while an HTTP/1.1 client over TLS kept its connection in a
   pool (OkHttp, the JDK's HttpClient), idle or just answered: the server sent its close_notify and then waited up to
   3 s for the client's, which such a client never sends, as it reads nothing until its next request. RFC 8446 section
   6.1: "Both parties need not wait to receive a "close_notify" alert before closing their read side of the
   connection". A stopping server now closes without that wait (`StopWithPooledClientsJvmTest`); the bench's graceful
   stop tests bound the stop's duration. Of RFC 9112 section 9.6's staged close only the first half remains during a
   stop: the write side closes first (everything queued, close_notify, FIN), then the read side stops at once, as for a
   refusal. The section's "reasonably certain that its own TCP stack has received the client's acknowledgement" is not
   checked: bytes a client sends after our close (a pipelined request, a late WINDOW_UPDATE) can make the kernel reset
   the connection, and the close goes without a reset only while the client sends nothing more.
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
   completes; the test expects completion on a fixed JDK and "GOAWAY received" on an older one. Both branches ran:
   "GOAWAY received" on the toolchain's Zulu 21.0.5, completion on JetBrains Runtime 21.0.8 (the JDK pairs run on it
   once through a Gradle init script that sets the test task's `executable`).
7. **Ktor's CIO client** opens a new connection for every request, against Netty, CIO and our server alike; persistence
   is the client's choice (RFC 9112 section 9.3). The test asserts five requests from five client ports.
8. **Ktor's CIO client** speaks TLS 1.2 only (ktor-network-tls) and our TCP connectors are TLS 1.3 only by default, so
   the bench, which keeps the default, has no HTTP-over-TLS pair. Our server ends the handshake as RFC 8446 appendix D.2
   requires: "If the "supported_versions" extension is absent and the server only supports versions greater than
   ClientHello.legacy_version, the server MUST abort the handshake with a "protocol_version" alert."
   (`CioToServerTlsTest`). TLS 1.2 on the server is available as an opt-in, off by default:
   `tlsConnector(identity) { versions = TlsVersions.Tls12And13 }` ([TLS 1.2 on the
   server](../guide/ktor.md#tls-12-on-the-server)).
9. **Ktor's OkHttp engine** sends every `Frame` as a whole message, its `fin` ignored (OkHttp has no fragments in its
   API): three fragments arrive as three messages. Not an error on either side; a fragmented message cannot be sent
   through that engine.

A pitfall of the test code, not of either side: Netty's HTTP/3 validation recognises a HEAD request by comparing the
`:method` it was given with `AsciiString` equality, which is false for a Kotlin `String`, and then holds the HEAD
response to its Content-Length; the bench's Netty HTTP/3 client passes the method as an `AsciiString`.

Not in the bench, and why: Ktor's Jetty engine (Jetty 12.1, `ktor-server-jetty-jakarta`) brings Jakarta EE artifacts
(CDI, Interceptors, WebSocket API) signed by keys that no key server has and that no official source lists, so they
could only be pinned by checksum; that waits for a decision on those keys. WebSockets over HTTP/2 (RFC 8441): both of
our engines have it (Extended CONNECT on HTTP/2, server and client; [WebSockets over
HTTP/2](#websockets-over-http2-rfc-8441-2026-11-12) has the runs against Node.js and Chrome), but none of the JVM clients
here has it, and our client opens a WebSocket over HTTP/2 only to a server whose SETTINGS enable Extended CONNECT, so
the WebSocket pairs here run over HTTP/1.1. HTTP/3 from the JDK's client: JDK 26 (JEP 517); the toolchain is 21. Ktor's Netty engine has no WebSockets
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
| Safari 27.2 (macOS 26.7.2) | draft-14 | manual, `ManualWebTransportServer` with the `serverCertificateHashes` page (2026-11-25) | ✅ connect, 1 MiB bidirectional echo, uni from the server, datagrams (100 of 100 echoed), the page's close and the server's close, on a build without compatibility shim 3 (an earlier run of the same day failed only the datagram step, on a page bug: `wt.datagrams.writable` is `createWritable()` in the current W3C API, fixed since). Safari's SETTINGS: `H3_DATAGRAM=1`, draft-14's `SETTINGS_WT_MAX_SESSIONS=1`, `0xc671706a=1` (a codepoint we do not interpret), `SETTINGS_WT_INITIAL_MAX_DATA=8388608`, `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI` and `_BIDI=100`, GREASE; not draft-02's 0x2b603742. CONNECT `:protocol webtransport`; draft-14 selected. Its transport parameters on the WebTransport connection, from the server's qlog (`transport:parameters_set`, owner remote): `reset_stream_at`, `max_datagram_frame_size` 65535, `initial_max_data` 16777216, `initial_max_streams_bidi` and `_uni` 100, `max_idle_timeout` 30000, `active_connection_id_limit` 64, an empty `initial_source_connection_id` (zero-length connection IDs). Safari closes a session with WT_CLOSE_SESSION (the page's code 7 and "bye", a 10-byte capsule in a 12-byte DATA frame), the CONNECT stream's FIN and STOP_SENDING (H3_NO_ERROR) in one packet (server qlog, 2026-11-25); the server then reported the close as code 0 until the STOP_SENDING stopped counting as an abandoned request. Its initial limits declare WebTransport flow control, so the draft-14 zero-credit case ([compat shim 1](compat-shims.md#1-webtransport-draft-02-and-draft-14)) does not arise with it |

webtransport-go's client requires `reset_stream_at`, which the Ktor server now advertises with `webTransport`; neither
direction against webtransport-go is run here (it belongs to the gate's interop image). webtransport-go (2a2b547,
2026-11-09) and picoquic (f506de8, 2026-11-19) speak draft-15/-16 (`SETTINGS_WT_ENABLED` 0x2c7cf000), which we announce
next to draft-17; no public source found on 2026-11-24 says a browser ships draft-15 or later.

