# realtime-telemetry

A small application built on `kuicksilver-quic` the way an outside project would use it: a separate Gradle build that
depends on `io.kuicksilver:kuicksilver-quic` by coordinates (the composite build in `settings.gradle.kts` substitutes
this repository's modules; with published artifacts you would drop `includeBuild`). It is not published.

It is the real-time shape the library was designed for:

- a **control stream** (bidirectional, `StreamPriority(urgency = 0)`) carrying text lines: `HELLO <name>` → `WELCOME <name>`,
  `BYE` → `BYE`; both sides read lines with `readLineStrict(Protocol.MAX_LINE)` (1024 bytes), and the server closes a
  connection whose control line runs past it with application code 2;
- **sensor readings as QUIC datagrams** (RFC 9221) under `DatagramPolicy.LatestWins(key)`: a reading still queued is
  replaced by a newer one of the same key, so a congested network never delivers stale values;
- **media on unidirectional streams** at a lower, incremental priority;
- a **network switch** mid-session (`migrate` to a second socket, Wi-Fi to LTE) without a new handshake;
- TLS from **PEM files** (`Certificate.parsePem`, `TlsIdentity.fromPem`) against a private CA.

| File | What it shows |
|---|---|
| `src/commonMain/.../Protocol.kt` | ALPN, message formats, TLS configs from PEM |
| `src/commonMain/.../TelemetryServer.kt` | `incomingConnections()`, `incomingStreams()`, `datagrams`, `pathEvents` |
| `src/commonMain/.../TelemetryClient.kt` | stream priorities, `trySendDatagram`, `migrate`, `close(code)` |
| `src/jvmMain/.../Main.kt` | a command line server and client |
| `src/commonTest/.../TelemetryMemoryTest.kt` | the whole session over `MemoryNetwork` (no sockets), JVM and macOS |
| `src/jvmTest`, `src/macosArm64Test` | the same session over real UDP on loopback |
| `certs/gen.sh` | regenerates `SampleCerts.kt` (test-only CA and server key) |

## Build and test

From the repository root:

```
./gradlew --max-workers=2 -p samples/realtime-telemetry jvmTest macosArm64Test
```

Run it by hand (two terminals):

```
./gradlew -p samples/realtime-telemetry jvmRun --args="server 4433"
./gradlew -p samples/realtime-telemetry jvmRun --args="client 127.0.0.1 4433 probe-1"
```

## Limits worth knowing

- A QUIC server on Kotlin/Native (macOS, iOS, Linux, Windows) runs on the accelerated `ksl` socket, which
  `QuicEndpoint.bind` picks by default; on Apple with one endpoint loop per port (`loops = 1`). The macOS test runs the
  server that way. Clients work on every platform.
- The certificates in `SampleCerts.kt` are public test material; never ship them.
