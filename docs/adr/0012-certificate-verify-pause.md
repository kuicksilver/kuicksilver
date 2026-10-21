# ADR-0012. Certificate verification with a handshake pause, without upcalls from C

Date: 2026-10-02. Status: accepted (approved by the owner 2026-10-02; server option (a) chosen by the owner after the 2026-10-02 spike).

## Context

Platform verifiers (Android `TrustManager`, `SecTrust`, Windows, JDK) live in Kotlin and can be slow (OCSP, network). Calling them from an OpenSSL callback is an upcall from C that blocks the thread and is complicated on JNI/cinterop.

## Decision

Client: in `KSL_VERIFY_PAUSE` mode the `ksl` verify callback calls `SSL_set_retry_verify`, `ksl_*_drive` returns `KSL_WANT_VERIFY`; Kotlin receives the chain, verifies it in a coroutine and resumes through `ksl_ssl_verify_resume(accept, alert)`. This also works in QUIC mode (checked in the 2026-10-02 spike).

Server: `SSL_set_retry_verify` is handled only in the client state machine of OpenSSL 3.5 (checked against `ssl/statem/statem_srvr.c`), so the pause is unavailable for client certificates on the server. The owner decided (2026-10-02) to choose the option after measuring the server path in the spike. Working assumption until then: synchronous OpenSSL verification against `AnchoredCa` inside `ksl`; `Pinned` in Kotlin right after the handshake, before the connection is handed to the application.

Cross-check 2026-10-02: neither the JDK (`NEED_TASK` — offloading work under `engineLock`, not a pause), nor Conscrypt (synchronous upcall `SSL_set_custom_verify`), nor kwik, rustls or Go offers an asynchronous pause; nobody has asynchronous verification on the server. Platform verifiers on JVM/Android do not check the hostname, so after the pause the name is always checked by the single matcher from `ksl`. The `ksl_ssl_verify_resume` continuation is called from the connection loop through the command queue, not from the verifier's thread.

Spike (2026-10-02): the pause works on the client with the contract "return 1 + `SSL_set_retry_verify`"; on the server OpenSSL ignores the retry and treats 1 as "accept" — pause mode is forbidden for server contexts in `ksl`. Owner decision (2026-10-02): option (a) — synchronous OpenSSL verification in `ksl` before the handshake completes, the pin after the handshake with `num_tickets=0` and an explicit ticket after the verdict; `Platform`/`Tofu`/`Custom` for client certificates are not supported in v1.

## Consequences

- Asynchronous verification on the client without blocking and without upcalls.
- On the server, trust modes for client certificates are restricted (`AnchoredCa`, optionally under `Pinned`).

## Implementation (2026-10-02)

The pause is implemented in `ksl_verify.c` (the callback returns 1 and sets `SSL_set_retry_verify`; `ksl_ssl_verify_resume` is accepted only in the paused state); on the server, pause mode is rejected by the context (`KSL_E_SERVER_PAUSE_FORBIDDEN`). The same "pause + resume" scheme is applied to ClientHello (`KSL_WANT_SNI` → `sniSelector`). Platform verifiers: JDK `TrustManager`, Android `X509TrustManagerExtensions` with the host, Apple `SecTrust` with `SecPolicyCreateSSL(host)`; Linux Native uses the OpenSSL system store without a pause. Windows (0.2.0): CryptoAPI (`CertGetCertificateChain`), run on `Dispatchers.IO` (`PlatformVerifier.mingw.kt`, see docs/guide/tls.md).
