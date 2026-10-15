<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Reproducer: a socket closed while its `SelectorManager` is idle is never released (ktor-network, JVM)

Standalone: depends on `io.ktor:ktor-network` only (Maven Central; EAP builds from the Ktor EAP repository). It belongs to
the report draft [`../ktor-selector-close.md`](../ktor-selector-close.md).

```sh
gradle run                                  # Ktor 3.6.0 (tested with Gradle 9.7.1; JDK 21 toolchain)
gradle run -PktorVersion=2.3.13             # another version, e.g. 3.0.3 or the EAP build 3.6.0-eap-1684
gradle run --args=--control                 # the same with a second socket keeping the selector busy
```

Inside this repository, `../../../gradlew -g <empty dir> run` does the same without Kuicksilver's Gradle cache (the
reproducer is its own Gradle build and has no dependency verification metadata).

What it does: a client socket on its own `SelectorManager` connects to a server on another one. The client calls
`openReadChannel()` and never reads; the server writes 64 KiB chunks until its writes stop (the client's channel and both
kernel buffers are full: the client's reader coroutine waits for room in its channel, the client's manager has no
interest pending). Then the client calls `close()`. It prints `PASS` when the JVM's count of open file descriptors drops
within 5 s (the descriptor was closed), `FAIL` otherwise, and exits with 0 or 1. It also prints whether the server's
blocked write ended. `--control` adds a second client connection on the same manager that waits to read, so the manager
keeps selecting: the same `close()` then releases the descriptor at once.

Results (2026-10-15, JDK 21: Zulu 21.0.5 on macOS, Temurin 21 in Docker):

| Ktor | macOS 26 (arm64) | Linux (arm64, Docker) | `--control`, both |
|---|---|---|---|
| 2.3.13 | FAIL: descriptor kept, server write fails (broken pipe) | FAIL: descriptor kept, server write blocked | PASS |
| 3.0.3 | FAIL: same | FAIL: same | PASS |
| 3.6.0 | FAIL: same | FAIL: same | PASS |
| 3.6.0-eap-1684 (EAP, published 2026-10-11) | FAIL: same | FAIL: same | PASS |

Output with Ktor 3.6.0 on Linux:

```
server: wrote 6553600 bytes, then stalled
client: close() (open descriptors: 22)
client: descriptor released within 5 s: false (open descriptors: 22)
server: write ended within 5 s: false
FAIL
```

and with `--control`:

```
server: wrote 5505024 bytes, then stalled
client: close() (open descriptors: 24)
server: write failed: io.ktor.utils.io.ClosedByteChannelException: Broken pipe
client: descriptor released within 5 s: true (open descriptors: 23)
server: write ended within 5 s: true
PASS
```
