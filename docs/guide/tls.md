# TLS with Kuicksilver

Kuicksilver's TLS layer (`io.kuicksilver:kuicksilver-tls`) runs TLS 1.3 (and, when asked, the RFC 9325 profile of
TLS 1.2) over OpenSSL 3.5 on every Kotlin Multiplatform target. The same configuration object drives QUIC handshakes,
TLS over TCP and the `ktor-network` socket wrapper. The code blocks below compile and run as `GuideSamplesTest`.

## Native library availability

The TLS layer runs on the native library `libksl`, shipped for the platforms listed in the README. An application that
must also run elsewhere (another OS or CPU architecture) checks once at startup and keeps another transport, instead of
catching `KslException` from the first connection:

```kotlin
if (!KslLoader.isAvailable()) fallBackToTcp()   // never throws; the outcome is cached for the process
```

`KslLoader.availability()` (`@ExperimentalKuicksilverApi`) says why: `NativeAvailability.Unavailable.reason` is
`NoLibraryForPlatform`, `LoadFailed`, `IntegrityMismatch` (the SHA-256 manifest check refused the library) or
`AbiMismatch`, with the original exception as `cause`. The check makes the same single load attempt as
`KslLoader.ensureLoaded()`; after a failure, `ensureLoaded()` throws that same exception without retrying.

On the JVM the library is extracted once into `<java.io.tmpdir>/kuicksilver-native-<user>` (or
`-Dkuicksilver.native.workdir=<dir>`, for a `noexec` temp directory) and verified against the jar's SHA-256 manifest on
every start. The directory must be a real directory that you own and that nobody else can write (the loader applies
`rwx------`); a symbolic link, another owner or permissions that cannot be removed give `IntegrityMismatch`. The file is
kept between runs and shared between JVMs of the same user: its name carries the `ksl` ABI version.

## Configuration

A `TlsConfig` is immutable; build it with the `tlsConfig` DSL. A client needs a server name (its reference identifier)
and a trust configuration; a server needs an identity or an SNI selector.

```kotlin
// guide:tls:client-config
val client = tlsConfig(TlsRole.Client) {
    serverName = "server.test"          // SNI and the name the certificate must match
    alpn = listOf("h2", "http/1.1")
    trust = TrustConfig.Platform        // the OS trust store (JDK, Android NSC, SecTrust, Windows)
}
```

```kotlin
// guide:tls:server-config
val identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())   // the key array is zeroed after import
val server = tlsConfig(TlsRole.Server) {
    alpn = listOf("http/1.1")
    this.identity = identity
}
```

## Trust

Host names are always checked (RFC 9525) and the check cannot be disabled; it can be redirected with `ExpectedName`
for proxies (`ExpectedName` wraps `Platform`, `AnchoredCa` or `Custom`; to pin as well, put it inside `Pinned`:
`Pinned(pins, base = ExpectedName(name, base))`). Pins are an additional check against the validated chain, never a
replacement for it.

```kotlin
// guide:tls:trust
val pinned = TrustConfig.Pinned(
    pins = setOf(SpkiSha256.parse("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")),
    scope = PinScope.Leaf,
    base = TrustConfig.AnchoredCa(listOf(rootCertificate)),   // or Platform
)
```

Private CAs usually arrive as PEM files. `Certificate.parsePem` returns every `CERTIFICATE` block of a file in order
(a bundle, a chain), skips other blocks such as keys, and parses each certificate on the spot, so a damaged file fails
at startup with `TlsException.Config` rather than at the first handshake:

```kotlin
// guide:tls:pem-roots
val roots = Certificate.parsePem(caPem)   // every CERTIFICATE block, in order; TlsException.Config if none
val trust = TrustConfig.AnchoredCa(roots)
```

`TrustConfig.Tofu` stores the first key seen for a name; `TrustConfig.Custom` hands trust to your verifier and still
runs the shared name check afterwards (it is marked `@DelicateKuicksilverApi` for that reason).

## TLS over a socket

```kotlin
// guide:tls:socket
val selector = SelectorManager(Dispatchers.IO)
val socket = aSocket(selector).tcp().connect("server.test", 443).tls(client)
val write = socket.openWriteChannel(autoFlush = true)
val read = socket.openReadChannel()
write.writeStringUtf8("GET / HTTP/1.1\r\nHost: server.test\r\n\r\n")
val status = withTimeout(10.seconds) { read.readUTF8Line() }   // the status line
socket.close()   // sends close_notify, then closes the TCP socket
```

The same works on the server side with `Socket.tlsServer(config)` after `ServerSocket.accept()`.

## TLS over any channel

`TlsConnection.client(transportIn, transportOut, config)` and `TlsConnection.server(...)` run TLS over any pair of
ktor-io channels, so a TLS session can live inside a QUIC stream or a test harness. `input` and `output` carry
plaintext; `shutdown()` sends `close_notify`.

## Key logging

Secrets never leave native memory unless you ask. That includes the TCP client's session cache: a ticket kept for
resumption is a handle to a native OpenSSL session, never its serialized bytes, and the secret is wiped when the
entry is used, replaced, evicted or expires, or when the engine that owns the cache closes. Each Ktor client engine
keeps its own cache of at most 256 sessions (the least recently stored one is evicted first); `Socket.tls` and
`TlsConnection.client` share one process-wide cache with the same bound (the cache itself is internal API). `TlsConfig.keylog` accepts a `KeylogSink` (RFC 9850 lines); the
`SSLKEYLOGFILE` variable is ignored by the library and by the bundled OpenSSL. `keylogFile(path)` creates the file
with mode 0600 and checks it before the first line: a symlink at the path, a file that is not a regular file or belongs to
another user, or a file system without POSIX permissions is refused with an `IllegalArgumentException`, and an existing
file that is readable by the group or others is tightened to 0600 (on the JVM, Linux and Apple; on Windows the file is
only created, so keep it in a directory that only you can write). Every line reopens the file without following links.
`keylogFromEnvironment()` reads the variable explicitly.

```kotlin
val path = "/tmp/kuicksilver-keys.txt"
// guide:tls:keylog
val debugClient = tlsConfig(TlsRole.Client) {
    serverName = "server.test"
    keylog = keylogFile(path)   // @DelicateKuicksilverApi
}
```

## Key exchange groups

Both roles negotiate TLS 1.3 key exchange from one list: `X25519MLKEM768`, `X25519`, `secp256r1`, `X448`, `secp384r1`,
`secp521r1`. A client sends key shares for the post-quantum hybrid and for X25519, so a server of either kind picks its
group in one flight. A server takes the client's X25519 share when that is all the client sent, even if the client also
lists the hybrid as supported: OpenSSL's default would answer with a HelloRetryRequest for `X25519MLKEM768`, and that
extra round trip doubled the handshake under loss against ngtcp2, picoquic and quiche (interop `handshakeloss`). The
list is not configurable in v1.

