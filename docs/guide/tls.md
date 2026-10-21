# TLS with Kuicksilver

Kuicksilver's TLS layer (`io.kuicksilver:kuicksilver-tls`) runs TLS 1.3 (and, when asked, the RFC 9325 profile of
TLS 1.2) over OpenSSL 3.5 on every Kotlin Multiplatform target. The same configuration object drives QUIC handshakes,
TLS over TCP and the `ktor-network` socket wrapper. The code blocks below compile and run as `GuideSamplesTest`.

## Native library availability

The TLS layer runs on the native library `libksl`, shipped for the platforms listed in the README. An application that
must also run elsewhere (another OS or CPU architecture) checks once at startup and keeps another transport, instead of
catching `KslException` from the first connection:

```kotlin
// guide:tls:availability
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
if (!KslLoader.isAvailable()) fallBackToTcp()   // never throws; the outcome is cached for the process
```

`KslLoader.isAvailable()` and `KslLoader.availability()` are experimental (`@ExperimentalKuicksilverApi`); the latter says why: `NativeAvailability.Unavailable.reason` is
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
val identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())   // the key array is zeroed; the key now lives in OpenSSL only
val server = tlsConfig(TlsRole.Server) {
    alpn = listOf("http/1.1")
    this.identity = identity
}
```

## Trust

Host names are always checked (RFC 9525) and the check cannot be disabled; it can be redirected with `ExpectedName`
for proxies (`ExpectedName` wraps `Platform`, `AnchoredCa` or `Custom`; to pin as well, put it inside `Pinned` — except
around `Custom`, which `Pinned` refuses directly and through `ExpectedName`:
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

Every certificate given to `AnchoredCa` is a trust anchor, also one that is not self-signed: anchoring at an
intermediate CA accepts the chains that reach it, without its issuers (OpenSSL `X509_V_FLAG_PARTIAL_CHAIN`, as JDK
`TrustAnchor`s, Apple anchor certificates and Go's root pools behave).

### Platform trust

`TrustConfig.Platform` hands the chain to the platform's own verifier. `ksl` checks the reference identifier with the
shared RFC 9525 matcher afterwards on every platform, so a platform matcher can only make the decision stricter; pins
(`Pinned`) are compared against the chain the platform built, never against certificates the peer merely sent.

| Platform | Verifier and store | Revocation |
|---|---|---|
| JVM | the default `X509TrustManager`: the JDK's `cacerts` or `javax.net.ssl.trustStore`, not the OS store | as the JDK is configured (off by default) |
| Android | the platform `TrustManager`, including the app's Network Security Config (whose `cleartextTrafficPermitted` the Ktor client also honours for `http://`) | the platform's policy |
| Apple (macOS, iOS) | `SecTrust` with the SSL policy for the host name: the keychain and the system roots | the platform's policy; an incomplete required check is `UnknownRevocationStatus` |
| Windows (mingwX64) | CryptoAPI: `CertGetCertificateChain` for the `serverAuth` (or, for a client certificate, `clientAuth`) usage with the presented intermediates, then `CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL)` with the host name: the Windows root store, missing intermediates fetched through AIA | the leaf's status is checked; a revoked leaf is `Revoked`, an unknown status is ignored (soft fail, as browsers); network fetches share a 10 s budget and run off the handshake's thread |
| Linux (Native) | OpenSSL inside `ksl` with the system CA bundle (below) | none |

Windows errors map to `VerifyReason`: `CERT_E_UNTRUSTEDROOT` and chaining failures to `UnknownIssuer`, `CERT_E_EXPIRED` to
`Expired` or `NotYetValid`, `CERT_E_CN_NO_MATCH` to `HostnameMismatch`, `CRYPT_E_REVOKED` and `CERT_E_REVOKED` to `Revoked`,
`CRYPT_E_NO_REVOCATION_CHECK`, `CRYPT_E_REVOCATION_OFFLINE` and `CERT_E_REVOCATION_FAILURE` to `UnknownRevocationStatus`,
`CERT_E_WRONG_USAGE` and `CERT_E_PURPOSE` to `InvalidPurpose`, `TRUST_E_CERT_SIGNATURE` to `BadSignature`,
`CERT_E_MALFORMED` to `BadEncoding`; anything else is `UnknownIssuer`.

### Linux trust store

On Linux Native the bundled OpenSSL has no built-in certificate directory, so `ksl` looks for the system store when a
client context with `TrustConfig.Platform` is built, in this order:

1. `SSL_CERT_FILE` (a PEM bundle) and `SSL_CERT_DIR` (a directory of PEM certificates, hashed with `c_rehash` or not). When
   either variable is set, only these are used, as in Go's `crypto/x509`: a configured store never silently becomes another
   one.
2. Otherwise the first bundle that loads, from Go's list: `/etc/ssl/certs/ca-certificates.crt` (Debian, Ubuntu, Gentoo),
   `/etc/pki/tls/certs/ca-bundle.crt` (Fedora, RHEL 6), `/etc/ssl/ca-bundle.pem` (openSUSE), `/etc/pki/tls/cacert.pem`,
   `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` (CentOS, RHEL 7 and later), `/etc/ssl/cert.pem` (Alpine), and
   `/usr/local/etc/openssl/cert.pem`.
3. Otherwise the first of `/etc/ssl/certs` and `/etc/pki/tls/certs` that holds certificates. A directory with `c_rehash`
   links is searched by OpenSSL's hash lookup; any other directory is read like Go reads it: every PEM file in it loads.
   A directory without either does not count.

When nothing is found (a distroless or `scratch` image without `ca-certificates`), building the configuration fails with
`TlsException.Config` naming every path searched:

```text
invalid TLS configuration: ksl: no CA certificates for TrustConfig.Platform; searched /etc/ssl/certs/ca-certificates.crt, ...,
/etc/pki/tls/certs/; install ca-certificates, set SSL_CERT_FILE or SSL_CERT_DIR, or use AnchoredCa
```

Install the distribution's `ca-certificates` package, copy a bundle into the image and point `SSL_CERT_FILE` at it, or
ship your roots with `TrustConfig.AnchoredCa`.

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

`close()` returns at once and finishes in the background: it sends what is queued and `close_notify`, then closes the
TCP socket. On a client (`Socket.tls`) it drops what is left after 3 s in all (a peer that stopped reading) and closes the
socket anyway; on a server (`Socket.tlsServer`) it waits for the client to take everything, however slowly it reads, so
bound the connection yourself (an idle or stall timeout) where a client may never read.

The same works on the server side with `Socket.tlsServer(config)` after `ServerSocket.accept()`.

### Resumption and trust

A resumed handshake carries no certificates, so the client checks the chain it cached from the full handshake again
before it offers the ticket (ADR-0011): under `AnchoredCa` and the Linux `Platform` store `ksl` verifies it again
against the trust store, the current time, the name and the purpose; under the other platform verifiers and `Custom`
the verifier runs again on it. Pins are then checked against the cached validated chain. A chain that no longer passes
(an expired leaf, for example) means a full handshake, not a failure. A server holds only the client's leaf of a
resumed session: its verdict travels with the ticket, which resumes only under the same trust configuration and lives
at most `SessionTicketConfig.ticketLifetime`.

## TLS over any channel

`TlsConnection.client(transportIn, transportOut, config)` and `TlsConnection.server(...)` run TLS over any pair of
ktor-io channels, so a TLS session can live inside a QUIC stream or a test harness. `input` and `output` carry
plaintext; `shutdown()` sends what is still queued and `close_notify`, waits for the peer's, and closes after 3 s in
all at the latest, also when the peer stopped reading.

## Key logging

Secrets never leave native memory unless you ask. That includes the TCP client's session cache: a ticket kept for
resumption is a handle to a native OpenSSL session, never its serialized bytes, and the secret is wiped when the
entry is used, replaced, evicted or expires, or when the engine that owns the cache closes. Each Ktor client engine
keeps its own cache of at most 256 sessions (the least recently stored one is evicted first); `Socket.tls` and
`TlsConnection.client` share one process-wide cache with the same bound (the cache itself is internal API). `TlsConfig.keylog` accepts a `KeylogSink` (RFC 9850 lines); the
`SSLKEYLOGFILE` variable is not read on the library's own and is ignored by the bundled OpenSSL; only
`keylogFromEnvironment()`, called by the application, turns it into a sink. A `libksl` built against the system
OpenSSL (Linux only, loaded with `-Dkuicksilver.native.path` or `-Dkuicksilver.native.system=true`) refuses to load while
it is set, since that libssl might honour it (`KslException.NativeLoad` "SSLKEYLOGFILE is set and the system libssl may honour it; unset it (keylog)"). `keylogFile(path)` creates the file
with mode 0600 and checks it before the first line: a symlink at the path, a file that is not a regular file, has more than one
hard link or belongs to another user, or a file system without POSIX permissions is refused with an `IllegalArgumentException`, and an existing
file that is readable by the group or others is tightened to 0600 (on the JVM, Linux and Apple). The JVM on Windows has
no POSIX permission view and refuses the file; on Kotlin/Native Windows the file is only created, so keep it in a
directory that only you can write. On the JVM the file is opened once, when the sink is
created, and every line goes through that descriptor, so a file removed and recreated at the path later receives nothing;
the JVM sink is also `java.io.Closeable` (close it when you are done, otherwise the descriptor stays open until the
channel is collected or the process exits). Kotlin/Native reopens the file without following links for every line and
repeats the checks on the new descriptor. A FIFO at the path is refused without waiting for a reader (Native opens with
`O_NONBLOCK`; the JVM checks the path before it opens it), so a planted FIFO cannot stall `keylogFile` or the endpoint loop.

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

