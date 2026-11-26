# kq-cli

`kq`, a small curl-like command line on the Kuicksilver Ktor client engine (`HttpClient(Kuicksilver)`), built as a
native executable for macOS arm64, Linux x64 and arm64, and Windows x64. It is a separate Gradle build that depends on
`io.kuicksilver:kuicksilver-ktor-client` by coordinates (the composite build in `settings.gradle.kts` substitutes this
repository's modules; with published artifacts you would drop `includeBuild`). It uses public API only. It is not
published.

```
$ kq get -v --http3-only --0rtt --repeat 2 --cacert build/dev-ca.pem https://127.0.0.1:4433/
hello over HTTP/3
* GET https://127.0.0.1:4433/ (1 of 2)
* HTTP/3 over QUIC v1, ALPN h3, new connection to 127.0.0.1:4433
* QUIC handshake 2.0ms; RTT 1.2ms smoothed, 0.6ms min; 0-RTT not used (no session ticket for this server yet)
* chosen because: Configuration (HTTP/3 alternative 127.0.0.1:4433 from H3Only)
* 200, head after 29.1ms, 18 body bytes in 31.4ms
hello over HTTP/3
* GET https://127.0.0.1:4433/ (2 of 2)
* HTTP/3 over QUIC v1, ALPN h3, new connection to 127.0.0.1:4433
* QUIC handshake 2.4ms; RTT 1.9ms smoothed, 0.9ms min; 0-RTT accepted
* chosen because: Configuration (HTTP/3 alternative 127.0.0.1:4433 from H3Only)
* 200, head after 6.5ms, 18 body bytes in 7.1ms
```

What it shows:

- the **discovery modes**: no flag is `Http3Discovery.Auto` (HTTP/2 or HTTP/1.1 first, HTTP/3 once the server sends
  `Alt-Svc`), `--http3` is `Preferred` (HTTP/3 raced against TCP), `--http3-only` is `H3Only`, `--http2` and `--http1.1`
  stay on TCP;
- **why a request took the protocol it did** (`-v`): `ProtocolDiagnostics` of each response (`kuicksilverDiagnostics`):
  the reason, the HTTP/3 alternative and where it came from, the fallback reason, the race, connect failures; for a failed
  call the same from its exception;
- the **QUIC connection** behind a response: `QuicConnectionSnapshot` (RTT, reuse, address) joined by connection ID with
  what `http3 { connectionListener }` heard (handshake time, ALPN, the 0-RTT outcome);
- the **`Alt-Svc` fields received** (an alternative, `clear`); `--alt-svc <file>` keeps what the engine learned in a
  `FileAltSvcStore`, so the next run can start on HTTP/3;
- **0-RTT** (`--0rtt`, `http3 { earlyData = true }`): with `--repeat` each repeat closes the HTTP/3 connections first
  (`closeHttp3Connections()`), so the next one resumes the session and sends the GET in 0-RTT if the server allows it;
- **qlog** (`--qlog <dir>`): `AsyncQlogSink(DirectoryQlogSink(dir))`, one `.sqlog` file per QUIC connection, complete
  when kq exits: a counting `QlogSink` in front of it sees the endpoints close every trace, then kq flushes the sink
  (`-v` reports records it dropped or failed to write).

`kq --help` lists every option. Exit codes: 0 when every request got a response (whatever its status), 1 when a
request failed or writing the body failed (stdout or `-o`, which is truncated first and keeps what arrived before a
failure), 2 for a usage error, an invalid `-H` or an unreadable `--cacert`.

| File | What it shows |
|---|---|
| `src/commonMain/.../Kq.kt` | the client configuration, the request loop, the body streamed to stdout or `-o` |
| `src/commonMain/.../Report.kt` | the `-v` lines from `ProtocolDiagnostics` and the connection snapshot |
| `src/commonMain/.../Observe.kt` | the `ConnectionListener`, a `QlogSink` wrapper that counts open traces |
| `src/commonMain/.../Args.kt` | the command line |
| `src/nativeMain`, `src/jvmMain` | `main` on Kotlin/Native and on the JVM; `src/mingwMain`: stdout in binary mode on Windows |
| `src/commonTest/.../KqTest.kt` | kq against an in-process Kuicksilver server over real TCP and UDP on loopback, JVM and macOS |
| `src/jvmTest/.../DevServer.kt` | a local server to point kq at by hand |
| `certs/gen.sh` | regenerates the tests' `SampleCerts.kt` (a test-only CA and server key) |

## Build and test

From the repository root:

```
./gradlew --max-workers=2 -p samples/kq-cli jvmTest macosArm64Test
./gradlew --max-workers=2 -p samples/kq-cli linkReleaseExecutableMacosArm64   # build/bin/macosArm64/releaseExecutable/kq.kexe
```

`linkReleaseExecutableLinuxX64`, `linkReleaseExecutableLinuxArm64` and `linkReleaseExecutableMingwX64` (`kq.exe`) cross-build
the other executables from a Mac; they need the OpenSSL builds of those targets, which the build makes as for the
repository's own Kotlin/Native tests. On the JVM, `jvmRun --args="get -v https://..."` runs the same code.

Try it against a local server (two terminals):

```
./gradlew -p samples/kq-cli devServer --args=4433          # HTTP/1.1, HTTP/2 and HTTP/3 on 127.0.0.1:4433; writes build/dev-ca.pem
cd samples/kq-cli
build/bin/macosArm64/releaseExecutable/kq.kexe get -v --cacert build/dev-ca.pem --alt-svc build/alt-svc.txt https://127.0.0.1:4433/
```

The first run goes over HTTP/2 and learns `h3=":4433"`; run it again and the request races HTTP/3 against TCP from the
start.

## Limits worth knowing

- The QUIC version shown is the one kq offers (`KuicksilverEngineConfig.quic.versions`, QUIC v1 by default): the version
  a connection negotiated is not in the public API. With more than one offered, kq says so instead of guessing.
- In `Auto` mode a request right after the one that learned `Alt-Svc` usually still goes over the open HTTP/2
  connection (`not HTTP/3: H3NotReady`): the QUIC setup races in the background and serves later requests once it is up
  ([Racing and fallback](../../docs/guide/ktor.md#racing-and-fallback)).
- Session tickets live as long as the client: 0-RTT works between repeats of one run, never across runs.
- Redirects are not followed (as curl without `-L`); there is no option to skip certificate verification.
- `-H` with an empty value sends the field empty (curl removes the header instead); Ktor refuses `Transfer-Encoding`
  and `Upgrade` from the application, since the engine frames the message itself.
- URLs are printed without their userinfo (`user:password@`).
- The certificates in the tests' `SampleCerts.kt` are public test material; never ship them. The `kq` executable does not
  contain them.
