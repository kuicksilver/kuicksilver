# ADR-0019. OpenSSL 4.x and Encrypted Client Hello

Date: 2026-11-18. Status: accepted (owner decision 2026-11-18); implementation pending. Supersedes in part
[ADR-0002](0002-openssl-first-backend.md): its pin of the OpenSSL 3.5 LTS branch. The rest of ADR-0002 (OpenSSL as the
first backend, linked statically; the transport behind the `QuicCrypto` interface; BoringSSL as a possible fallback)
stands.

## Context

The owner took TLS Encrypted Client Hello (RFC 9849, with the `ech` parameter of HTTPS records, RFC 9848) into 0.3.0:
the peers that browsers and mobile platforms use ship it (Chrome over BoringSSL, Go's `crypto/tls` and through it
quic-go, Android's platform TLS), and without it the server name of every connection is visible on the path.

- **OpenSSL 3.5 has no ECH.** The pinned 3.5.9 has HPKE but no ECH API (no `ech.h`). ECH arrived in OpenSSL 4.0.0
  (2026-04-14) and is in 4.1.0: `SSL_set1_ech_config_list`, the `OSSL_ECHSTORE_*` functions, `SSL_CTX_set1_echstore`,
  `SSL_ech_get1_status`, `SSL_ech_get1_retry_config`, `SSL_OP_ECH_GREASE`. OpenSSL supports shared mode only, not split
  mode.
- **Support windows** (OpenSSL's release strategy): 3.5 LTS until 2030-04-08; 4.0 until 2027-05-14; 4.1 until
  2027-11-23; the next LTS, 4.2, is planned for April 2027.
- **What a move costs.** The QUIC TLS interface `ksl` uses (`SSL_set_quic_tls_cbs`) is the same in 4.x. `ksl` already
  builds against 4.1.0 after a two-line change around `X509_check_host`, its C tests pass under ASan and UBSan, and the
  hosted CI builds 4.x weekly beside the pin (`gradle/openssl-next.toml`, the `openssl-next` job). The JNI library grew by
  about 10 % in that measurement. `tools/openssl/configure-flags.txt` loses options 4.x removed and must not add
  `no-ech`.
- **What the spike found** (2026-11-18): OpenSSL 4.1.0 fails a handshake with ECH after a HelloRetryRequest when the
  client sends any custom extension of its own (an internal error on the second ClientHello). QUIC always sends one, the
  transport parameters, so every ECH handshake over QUIC that meets a HelloRetryRequest fails, and `ksl` cannot work
  around it. A fix of about 30 lines in two OpenSSL files makes every check of the spike pass. OpenSSL's own QUIC ECH
  test has no HelloRetryRequest.

## Decision

- **Kuicksilver moves from OpenSSL 3.5 LTS to 4.1.x for 0.3.0, and to 4.2 LTS once it is released.** The pin in
  `gradle/openssl.toml` keeps its form: version, tarball SHA-256, signing key fingerprint; every target is built from
  the signature-checked tarball as before.
- **ECH in 0.3.0**: a client that takes the ECH configuration list from the origin's HTTPS record or from the application,
  retries once with the server's retry configurations, and sends GREASE ECH by default where it has none; a server in
  shared mode with key rotation and retry configurations. No split mode.
- **One carried OpenSSL patch, as an exception** (owner decision 2026-11-18). Until now the bundled OpenSSL has been the
  upstream release tarball exactly, checked by its signature and SHA-256 and nothing else. For the bug above the build
  carries one minimal patch, under these rules:
  - the bug is reported to OpenSSL with a minimal reproducer, and the patch is dropped in the first 4.1.x or 4.2
    release that fixes it;
  - the patch lives in the repository and is pinned by its SHA-256 next to the tarball's pin; `tools/openssl/build.sh`
    applies it to the verified tarball and refuses a patch whose hash differs;
  - the patch and its hash are listed in the build's provenance (`provenance.txt`, the release provenance and the SBOM)
    and are part of the build cache's key and of `configure-target.txt`;
  - the reproducibility checks (the double build, `tools/verify/verify-release.sh`) rebuild with the same patch;
  - no other patch is carried without a new decision.
  The implementation comes with the move to 4.1.x, not with this ADR.

## Consequences

- **A non-LTS window.** From 0.3.0 until 4.2 LTS ships, the bundled OpenSSL is a release with a short support window
  (4.1 until 2027-11-23). The move to 4.2 is a planned patch release; until then the commitments of SECURITY.md for
  OpenSSL advisories apply to 4.1.x unchanged.
- **Binary size** grows (about 10 % for the JNI library in the measurement above); the size gates of the AAR, the iOS
  framework and the JNI libraries are measured again and their limits changed only by decision.
- **Reproducibility**: a new pin (tarball, signature, SHA-256), a reviewed `configure-flags.txt`, and new baselines for
  the double build and for `tools/verify/verify-release.sh`; releases before 0.3.0 keep verifying against their own pin.
- **Documents and checks that name 3.5** change with the move: SECURITY.md (OpenSSL), docs/stability.md, the README,
  the troubleshooting text of `KslException.Version`, and the system-OpenSSL build mode on Linux, which today refuses
  4.x and will then need 4.x for ECH.
- **A patched OpenSSL until upstream fixes the bug.** A user who verifies a release no longer gets the upstream tarball
  alone: the published OpenSSL is that tarball plus one patch whose hash is pinned and listed in the provenance, and
  `verify-release.sh` applies it before comparing. The patch is reviewed like our own code, and every OpenSSL update
  checks whether it is still needed.

## Alternatives rejected

- **Two builds, 3.5 by default and 4.1 for ECH.** Every native target built twice, two reproducibility baselines, and a
  feature that silently depends on which artifact a user picked.
- **Backporting ECH to 3.5.** About 4000 lines in `ssl/ech` plus state-machine changes, carried as our own patch for
  years: far beyond the one bug fix of about 30 lines that this ADR allows, temporarily.
- **BoringSSL or AWS-LC.** Mature ECH, but the QUIC glue of `ksl` would be rewritten (`SSL_set_quic_method` instead of
  `SSL_set_quic_tls_cbs`) together with the ticket, 0-RTT and verification-pause code; BoringSSL has no versions. Not for
  0.3.0; ADR-0002's fallback stays a possibility.
- **Waiting for 4.2 LTS.** No non-LTS window, but no ECH in 0.3.0, against the owner's decision.
- **Shipping 4.1.x unpatched and documenting the failure after a HelloRetryRequest.** ECH over QUIC would fail whenever
  a server answers with a HelloRetryRequest (another key exchange group), and retrying without ECH would reveal the
  server name; the owner chose the patch.
