<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# TLS with Kuicksilver

**What this page is for.** It explains the TLS layer on its own: building a `TlsConfig`, trust and certificate checks, TLS
over a socket or any channel, session resumption, key logging and key exchange groups. QUIC, Ktor and the socket wrapper all
use the same configuration object.

**Before you start**

- Dependency: `io.kuicksilver:kuicksilver-tls:0.3.0` or newer (the socket wrapper is `io.kuicksilver:kuicksilver-ktor-network`).
  Built with Kotlin 2.4.20: JVM and Android need Kotlin 2.3 or newer, Kotlin/Native 2.4.x
  ([Kotlin version](../stability.md#kotlin-version)).
- Platforms: JVM 17 or newer, Android `minSdk` 24, iOS 15, macOS 12 (macOS 11 on the JVM), Linux, Windows
  ([Platforms](../stability.md#platforms)).
- A client needs the server's name and a trust configuration; a server needs a `TlsIdentity` (certificate chain and
  private key).

**Minimal example.** [Configuration](#configuration) builds a client and a server `TlsConfig`; [TLS over a socket](#tls-over-a-socket)
runs a handshake over TCP.

<a id="imports"></a>
**Imports.** The code blocks on this page start after their imports; these are the imports they use, and the test that
compiles them fails when a name moves. `Dispatchers.IO` needs `kotlinx.coroutines.IO` in common and Native code.
Experimental and delicate API needs `@file:OptIn(...)` or the module-wide opt-in ([stability](../stability.md#stability-levels)).

```kotlin
// guide:tls:imports
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.ktor.network.tls
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.PinScope
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.keylogFile
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withTimeout
import kotlin.time.Duration.Companion.seconds
```

Kuicksilver's TLS layer (`io.kuicksilver:kuicksilver-tls`) runs TLS 1.3 (RFC 9846; the default, as RFC 9852 asks) and,
when asked, TLS 1.2 under the RFC 9325 profile as narrowed by RFC 10015 (ECDHE and AEAD only) over OpenSSL 3.5 on every Kotlin Multiplatform target. The same configuration object drives QUIC handshakes,
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
every start. The loader creates the directory, and any missing parent, owner-only (`rwx------`, or on Windows an ACL with
one entry for you) and checks it: it must be a real directory that you own and that nobody else can write. A
`-Dkuicksilver.native.workdir` that fails the check gives `IntegrityMismatch`; when the default directory fails it
(another user created it first, or it is a link), the process uses a new private directory next to it and prints a
warning. An elevated Windows process uses `kuicksilver-native-<user>-admin`. When a directory above the default one lets
another user rename it (writable by others without the sticky bit `/tmp` has, or owned by another user), the library
goes to `$XDG_RUNTIME_DIR/kuicksilver-native` or the user's cache directory instead, and when neither can be used it
stays in the temporary directory with a warning ([troubleshooting](troubleshooting.md#kslexceptionnativeload-or-kslloaderavailability-is-unavailable)).
The library is written owner-only (`rw-------`) through a new file and an atomic rename; a copy that another user owns or
may write is replaced, not reused, and one that cannot be replaced (Windows, another process has it loaded) is written
next to it under a name with its hash. The file is kept between runs and shared between JVMs of the same user: its name
carries the `ksl` ABI version.

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

### Rotating the server certificate

A server identity can be replaced while the server runs (experimental, 0.3.0): wrap it with
`TlsIdentity.reloadable(identity)`, use the result as the `identity`, and call `reload(TlsIdentity.fromPem(...))` when a
renewed certificate arrives. Every handshake whose ClientHello arrives afterwards, over TCP and QUIC alike, presents the new
chain and key, also on a TCP connection accepted before the reload; handshakes in progress and established connections
keep the identity they started with, and nothing they hold is freed under them.

- **Bad input never replaces the identity in use.** A key that does not match the leaf already fails in `fromPem` or
  `fromDer`; `reload` refuses a closed identity, a leaf certificate that has expired, and one that is not valid yet
  (notBefore more than 5 minutes ahead: a certificate staged for later is never served early), all with
  `TlsException.Config`, and the old identity goes on serving.
- **Ownership.** The reloadable identity owns what it serves: `reload` closes the identity it replaces, `close()` the
  current one. An identity `reload` refused is still yours to close.
- **Resumption.** Every server binds its session tickets to the leaf certificate they were issued under, so after a
  reload to another certificate a ticket from before it resumes nothing: the client runs a full handshake and sees the new
  certificate, and that ticket's 0-RTT is refused. A resumed connection carries no certificate (RFC 9846 section 2.2) and
  keeps the identity of its session, which is therefore the current one. After a key compromise, a reload stops both new
  handshakes and resumptions with the old key; connections already established run until they close.

Independently of reloads, resumption is bounded on every server (RFC 9846 section 4.7.1 recommends limiting the total
lifetime of resumption keying material and taking the certificate's lifetime into account): each resumption renews the
ticket, but a chain of renewals ends 7 days after the full handshake that authenticated it (BoringSSL's
`SSL_DEFAULT_SESSION_AUTH_TIMEOUT`) and at the leaf's notAfter; then the client runs a full handshake.

The Ktor server engine can also watch the PEM files itself; see [Certificate rotation](ktor.md#certificate-rotation).

### Rotating the client CA

The CA bundle a server verifies client certificates with (`clientAuth` `Optional` or `Required`) can also be replaced
while the server runs (experimental, 0.3.0). Wrap the bundle with `TrustConfig.reloadable(TrustConfig.AnchoredCa(roots))`
and use the result as the server's `trust`, alone or as the `base` of `Pinned`. Call `reload(TrustConfig.AnchoredCa(newRoots))`
when the bundle changes. It follows the rules of the identity above:

- **The rule.** After `reload` returns, no handshake accepts a client certificate that only a removed CA vouches for,
  over TCP and QUIC alike, however the client times its flights. A handshake takes the bundle current when its ClientHello
  arrives (over TCP when its first bytes are there, not at the accept) and OpenSSL verifies against it; if a reload replaced
  that bundle with other certificates before the handshake completes, the certificate is verified again against the bundle
  current then, as a fresh handshake would (OpenSSL's security level, and the pins of a `Pinned` around the bundle on the
  path built under it), and the handshake fails unless it passes. A reload to the same certificates changes nothing. One
  case is refused that a fresh handshake would accept: a session resumed across a reload that changed the certificates
  holds only the client's leaf, so it passes only if that leaf chains to the new bundle without intermediates (the client
  then runs a full handshake on its next connection). Connections established before the reload are not affected: a client of a CA you
  dropped that is already connected stays connected until its connection closes. Close such connections yourself if the
  CA was compromised.
- **Shared contexts.** The first handshake under the new bundle replaces the old bundle's shared OpenSSL context, which is
  freed with its last connection. With `clientAuth` `None` the bundle plays no part, and a reload changes nothing.
- **Non-CA certificates.** Every certificate of the bundle is a trust anchor, also a leaf: a client presenting exactly that
  certificate is accepted. `EngineMain` warns about such certificates in its CA file.
- **Bad input never replaces the bundle in use.** `reload` refuses a bundle in which no certificate is valid now (each
  expired, or not valid yet beyond 5 minutes of clock skew) with `TlsException.Config`, and the old bundle stays.
- **Resumption.** A session resumes only under the bundle it was authenticated with. After a reload, a ticket from before
  it resumes nothing (RFC 9846 section 4.7.1: "A server MAY treat a ticket as valid for a shorter period"). The client
  runs a full handshake and its certificate is verified against the new bundle, so a ticket never lets a client of a
  dropped CA back in.
- **What the client sees.** The server sends no `certificate_authorities` extension in its CertificateRequest (RFC 9846
  section 4.3.4: "The server MAY send it in the CertificateRequest message"), so clients pick their certificate without a
  CA list from the server, before and after a reload.
- **Servers only.** A client configuration with a `ReloadableCa` throws `TlsException.Config`; a client trusts its server
  through `AnchoredCa`.

```kotlin
// guide:tls:client-ca-rotation
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val clientCa = TrustConfig.reloadable(TrustConfig.AnchoredCa(Certificate.parsePem(caBundlePem)))
val mtlsServer = tlsConfig(TlsRole.Server) {
    alpn = listOf("h3")
    identity = serverIdentity
    clientAuth = ClientAuth.Required
    trust = clientCa
}
// later, when the bundle changes:
clientCa.reload(TrustConfig.AnchoredCa(Certificate.parsePem(renewedBundlePem)))
```

The Ktor server engine can watch the CA file too: `EngineMain`'s `kuicksilver.tls.clientCa` with
`kuicksilver.tls.reloadInterval` ([Certificate rotation](ktor.md#certificate-rotation)).

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

Every peer chain is held to OpenSSL's security level 2 (RFC 9325 section 4.5): every key needs 112 security bits (RSA
2048 bits, an elliptic curve 224 bits), and every certificate signature too, except the trust anchor's: no SHA-1 or MD5
(RFC 9846 section 4.5.1.3). A weaker chain ends the handshake with `bad_certificate` and `TlsException.Verify` with
`VerifyReason.WeakKey` or `VerifyReason.WeakSignature`; there is no switch to turn it off. The JDK, Android and Windows
verifiers would accept 1024-bit RSA on their own. Which certificates count depends on the trust:

- **`Platform`** (also under `Pinned` and `ExpectedName`): the platform is asked first, and after its yes `ksl` checks the
  path the platform built, leaf first and its trust anchor last (Android's `X509TrustManagerExtensions`, Apple's
  `SecTrustCopyCertificateChain`, Windows' chain, and on the JVM the path rebuilt with the JDK's PKIX builder to the trust
  manager's roots), as OpenSSL checks its own path: every key, the anchor's included, and every signature but the
  anchor's. A certificate the server sends that the platform does not use, such as an extra cross-certificate above the
  root the platform trusts (signed with SHA-1 by an old root, say), does not count, as with OpenSSL. If the platform does
  not say which path it took, the certificates the server sent are checked as for `Custom`. When the platform itself
  refuses a chain with an MD5, SHA-1 or small-key certificate in it (the JDK, Apple and Windows do), the refusal is still
  reported as `WeakSignature` or `WeakKey` with `bad_certificate`. This holds even when the chain is not trusted at all
  (RFC 9846 section 4.5.1.3 does not depend on trust; OpenSSL would send `unknown_ca`), and it takes precedence over the
  platform's own reason: an expired or revoked chain that also has a weak certificate among those sent is reported as
  `WeakKey` or `WeakSignature`. The chain is refused either way. On Linux Native `Platform` is
  OpenSSL's own verifier with the system store, which checks its own path the same way.
- **`AnchoredCa`**: OpenSSL checks the path it builds to your roots.
- **`Custom` and `Tofu`**: the certificates the peer sent are checked before your verifier or the TOFU store is asked:
  every presented certificate reachable from the leaf through issuers whose key verifies the signature (each such issuer
  is followed, so cross-certificates are all checked), only a really self-signed certificate's own signature exempt. This
  is stricter than OpenSSL for an extra cross-certificate the server sends above the anchor your verifier trusts: it is
  checked and refuses the chain. A certificate on no verified path from the leaf is not looked at.

The endpoint's own chain is held to the same rules when the identity is made (`TlsIdentity.fromDer`, `fromPem` and the
JVM key store factories throw `TlsException.Config` for a SHA-1- or MD5-signed certificate or a key under 112 bits), for
a server and for a client certificate alike.

| Platform | Verifier and store | Revocation |
|---|---|---|
| JVM | the default `X509TrustManager`: the JDK's `cacerts` or `javax.net.ssl.trustStore`, not the OS store | as the JDK is configured (off by default) |
| Android | the platform `TrustManager`, including the app's Network Security Config (whose `cleartextTrafficPermitted` the Ktor client also honours for `http://`) | the platform's policy |
| Apple (macOS, iOS) | `SecTrust` with the SSL policy for the host name: the keychain and the system roots | the platform's policy; an incomplete required check is `UnknownRevocationStatus` |
| Windows (mingwX64) | CryptoAPI: `CertGetCertificateChain` for the `serverAuth` (or, for a client certificate, `clientAuth`) usage with the presented intermediates, then `CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL)` with the host name: the Windows root store, missing intermediates fetched through AIA | the leaf's status is checked; a revoked leaf is `Revoked`, an unknown status is ignored (soft fail, as browsers); network fetches share a 10 s budget and run off the handshake's thread |
| Linux (Native) | OpenSSL inside `ksl` with the system CA bundle ([Linux trust store](#linux-trust-store)) | none |

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

### Certificate revocation

RFC 9325 section 7.5 requires "a strategy to distrust revoked certificates". Kuicksilver has three parts, all
experimental in 0.3.0:

- **Stapled OCSP (clients).** `TlsConfig.revocation` (`RevocationPolicy`, default `StapledIfPresent`) asks the server
  for a stapled OCSP response (`status_request`, RFC 6066 section 8) and checks it as RFC 6960 section 3.2 says: it must
  name the server's certificate and the issuer the verifier trusted, be signed by that issuer or by a responder the
  issuer delegated (id-kp-OCSPSigning), and be inside its validity interval (5 minutes of clock skew). A response saying
  revoked fails with `VerifyReason.Revoked`; one that fails a check fails with `VerifyReason.InvalidStatusResponse`; both
  send `bad_certificate_status_response` (113), also with `genericAlerts` (OpenSSL chooses that alert). A delegated
  responder must also carry no unknown critical extension, meet the security level, and not be listed on a configured CRL
  of the issuer. A server that staples nothing, or a response saying "unknown", passes under
  `StapledIfPresent` (OCSP clients "typically 'soft-fail'", RFC 9325 section 7.5) and fails under `RequireStapled`
  (`VerifyReason.UnknownRevocationStatus`, alert 113); a certificate marked must-staple (RFC 7633) fails without one
  under every policy but `Off`, and so does a required staple for a leaf that is itself the trust anchor (no issuer to
  check a response against). The check runs where `ksl` verifies the chain: `AnchoredCa`, and `Platform` on Linux Native, also
  inside `Pinned` and `ExpectedName`. Elsewhere under `Platform` the OS verifier decides: Apple and Windows apply their
  own revocation policy, while on Android (its blocklist only) and the JVM (off unless the application enables it, e.g.
  `com.sun.net.ssl.checkRevocation`) nothing checks revocation; use `AnchoredCa` where that matters. A `Custom` or `Tofu`
  verifier decides alone; `RequireStapled` with them is refused (`TlsException.Config`). A
  session resumes only while the response its full handshake checked is fresh.
- **CRLs (clients and servers).** `TrustConfig.AnchoredCa(roots, crls)` checks every certificate on the verified path
  against its issuer's CRL when one of `crls` is from that issuer (`CertificateRevocationList.parsePem` reads
  `X509 CRL` blocks). Revoked fails with `VerifyReason.Revoked` (alert 44); a CRL that expired fails with
  `VerifyReason.UnknownRevocationStatus` (alert 45), so replace CRLs before their nextUpdate; a CRL whose signature does
  not verify (alert 51), a configured CRL of the issuer that OpenSSL cannot use for the certificate (alert 48) or that does
  not cover it (a distribution point it does not name, alert 46) fails with `VerifyReason.UnknownRevocationStatus` as
  well. So does a configured CRL whose issuer is neither among the roots nor on the path: with
  `AnchoredCa(roots = [intermediate], crls = [the root's CRL, ...])` the intermediate's own status cannot be verified,
  and its certificates fail (fail closed; leave that CRL out, or anchor at the root). A certificate whose issuer has none
  of the configured CRLs is not checked. Only complete, direct CRLs are supported: delta CRLs,
  indirect CRLs and CRLs limited to some revocation reasons are refused when the trust is made (`TlsException.Config`). On a server, a
  `TrustConfig.ReloadableCa` reload to the same roots with new CRLs applies them to the next handshakes, as a CA reload
  does (tickets authenticated under the old CRLs resume nothing).
- **Stapling (servers).** `TlsConfig.ocspStapling` (or `ocspStapling` of the Ktor TLS connector) holds the OCSP
  response for the server's certificate, fetched by the application from its CA's responder. It is stapled over TCP and
  QUIC only to clients that ask, and only when it is for the leaf the handshake presents (the chain must include the
  issuer) and fresh at that moment; a stale response is silently not sent. A response is at most 2^24-5 bytes, and
  TLS 1.3 and QUIC staple one only up to 65527 bytes (it must fit the certificate's extensions, RFC 8446 section 4.4.2);
  a larger one is not sent there and the handshake goes on (RFC 6066 section 8: a server may send none). Call `update` with a fresh response before
  the current one's nextUpdate; `isUsableFor(chain)` says whether the current one would be stapled. An identity chosen
  by `sniSelector` staples the response of its own `ServerTlsOverride(identity, alpn, clientAuth, trust, ocspStapling)`,
  and never the default identity's (TCP; QUIC has no `sniSelector`).

```kotlin
// guide:tls:revocation
val crls = CertificateRevocationList.parsePem(crlPem)
val client = tlsConfig(TlsRole.Client) {
    serverName = "api.example.com"
    trust = TrustConfig.AnchoredCa(roots, crls)
    revocation = RevocationPolicy.StapledIfPresent   // the default
}
val stapling = OcspStapling(ocspResponseDer)      // later: stapling.update(fresher)
val server = tlsConfig(TlsRole.Server) {
    identity = serverIdentity                       // leaf and its issuer
    ocspStapling = stapling
}
```

Not offered: OCSP requests from the client itself, OCSP for intermediate certificates, fetching CRLs from their
distribution points.

## TLS over a socket

```kotlin
// guide:tls:socket
val selector = SelectorManager(Dispatchers.IO)
val socket = aSocket(selector).tcp().connect("server.test", 443).tls(client)
val write = socket.openWriteChannel(autoFlush = true)
val read = socket.openReadChannel()
write.writeStringUtf8("GET / HTTP/1.1\r\nHost: server.test\r\n\r\n")
val status = withTimeout(10.seconds) { read.readLine(LineEnding.Lenient) }   // the status line
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
all at the latest, also when the peer stopped reading. `close()` ends the connection at once. Cancelling the job of the
`context` passed to `client`/`server` ends it the same way: `input` and `output` fail and the native session is freed,
without a `close()`. When the transport fails (a reset), the `TlsException.Protocol` of the handshake or of the input
carries the transport's failure as its cause.

## Key logging

Secrets never leave native memory unless you ask. That includes the TCP client's session cache: a ticket kept for
resumption is a handle to a native OpenSSL session, never its serialized bytes, and the secret is wiped when the
entry is used, replaced, evicted or expires, or when the engine that owns the cache closes. Each Ktor client engine
keeps its own cache of at most 384 sessions, six tickets for each of 64 origins (the least recently stored one is
evicted first); `Socket.tls` and
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
list is not configurable.

