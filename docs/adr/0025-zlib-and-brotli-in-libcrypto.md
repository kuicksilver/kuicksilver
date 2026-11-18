<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0025. zlib and brotli in libcrypto, for TLS certificate compression

Date: 2026-11-18. Status: accepted (owner decision 2026-11-18).

## Context

TLS certificate compression ([RFC 8879](../spec/rfc/8879.md#certificate-compression)) is in 0.3.0: a compressed
certificate chain keeps a server's first flight within QUIC's amplification limit (RFC 9000 section 8.1) for longer
chains. OpenSSL 3.5 implements RFC 8879 (`SSL_CTX_set1_cert_comp_preference`, `SSL_CTX_compress_certs`, the
`compress_certificate` extension and the `CompressedCertificate` message), but only with its built-in codecs: there is no
hook for an algorithm of the application's (BoringSSL has `SSL_CTX_add_cert_compression_alg`, OpenSSL has none). The
bundled OpenSSL was built `no-comp`, without zlib, brotli or zstd, so every certificate compression function returned 0.
Their `-dynamic` variants load the library at run time through OpenSSL's DSO loader, which the build turns off
(`no-dso`).

The platforms' own zlib is no answer: there is none on Windows; the Kotlin/Native Linux sysroots and the mingw toolchain
ship zlib 1.2.11 (CVE-2018-25032), which a static link would freeze into our archives; a dynamic link would add a
dependency of the Linux libraries on the host's `libz.so.1`; and no platform ships brotli, the one algorithm ngtcp2's
BoringSSL examples register (`examples/tls_shared_boringssl.h`).

## Decision

- zlib and brotli are built from pinned release tarballs (`gradle/compression-libs.toml`, zlib 1.4 and brotli 1.2.1
  today) on every target, statically. zstd is not built (`no-zstd`): the owner chose brotli and zlib, and zstd would be a
third upstream to watch.
- **Verification** as for OpenSSL, by `tools/openssl/fetch.sh`: zlib's tarball by its SHA-256 and the PGP signature of
  its release key (`tools/openssl/zlib-release-key.asc`, fingerprint pinned). brotli signs no release: its tarball is
  GitHub's archive of the tag, pinned by its SHA-256 and by the tag's commit, which `git archive` writes into the
  tarball's pax header and `fetch.sh` checks. Both are in the SBOM, the provenance statement, `provenance.txt` of every
  OpenSSL build (which `-Pkuicksilver.openssl.prebuilt` checks) and Renovate.
- **Built into libcrypto.** `tools/openssl/compression.mk` compiles them with the compiler and flags of libcrypto's own
  objects (OpenSSL's Makefile variables: the target's flags and the project's `-Os -ffunction-sections -fdata-sections
  -fvisibility=hidden -fno-common`) and appends them to `libcrypto.a`. Every link line, the `ksl_ossl_` symbol prefix of
  [ADR-0007](0007-symbol-prefixing.md) (a second zlib in the application does not clash) and the export checks then cover
  them as part of OpenSSL. Only what OpenSSL calls is compiled: zlib without its `gz*` file API and `infback`.
- **Android and iOS ship brotli's decoder only.** Their libraries are clients almost always, and a client compresses only its
  own certificate, when a server asks for one. The encoder's entry points OpenSSL calls are stubs that fail
  (`tools/openssl/brotli/ksl_encoder_stub.c`), so OpenSSL still offers and decompresses brotli and zlib there. OpenSSL keeps
  one list for what an endpoint decompresses and what it compresses with (`cert_comp_prefs`), picks the first of the
  peer's algorithms for a client certificate without falling back, and ends the handshake when that compression fails; it
  cannot advertise brotli for receiving only. So `ksl` probes once whether brotli compresses: where it does not, a client
  with a certificate sends it uncompressed (`SSL_OP_NO_TX_CERTIFICATE_COMPRESSION`) and a server compresses its chain with
  zlib alone. Every other target (the JVM and Kotlin/Native libraries of macOS, Linux and Windows) has the full encoder.
- **The encoder's static tables are computed on first use** (`BROTLI_STATIC_INIT_LAZY`), not shipped: about 290 KB less.
  brotli leaves the call of that computation to the embedder (a C++11 function-local static, `static_init_lazy.cc`), which
  OpenSSL never makes; `tools/openssl/brotli/ksl_static_init.c` replaces brotli's `enc/static_init.c` and runs it once, under
  `CRYPTO_THREAD_run_once`, from the check every encoder instance makes when it is created, so concurrent first encoders wait
  for one computation and then see the tables. The decoder keeps its small static tables.
- OpenSSL is configured `enable-zlib enable-brotli` (not `-dynamic`), and `no-comp` is dropped. TLS record compression
  stays off (`SSL_OP_NO_COMPRESSION` on every `ksl` context, RFC 9325 section 3.3).

## Consequences

- **Size**, measured on the stripped Android arm64 library and the macOS arm64 JNI library (bytes):

  | Configuration | Android arm64 `libksl.so` | delta | macOS arm64 JNI | delta |
  |---|---|---|---|---|
  | no compression (before) | 2,898,576 | | 2,544,056 | |
  | zlib + brotli with the encoder's static tables | 3,704,880 | +806,304 | 3,337,496 | +793,440 |
  | zlib + brotli, encoder tables computed lazily | 3,420,688 | +522,112 | 3,056,792 | +512,736 |
  | zlib + brotli decoder only | 3,127,568 | +228,992 | 2,759,096 | +215,040 |

  Taken: decoder only on Android and iOS, the lazy encoder elsewhere (the macOS JNI library: +512,736). What is left on
  Android is brotli's RFC 7932 dictionary (122 KB, which a decoder needs), its decoder and zlib. The Android size gate
  (`tools/check/size.sh`) is 3,200,000 with a target of 2,900,000, 200,000 above where it was. Other per-target deltas
  (Android x86_64 and armeabi-v7a, iOS, Linux, mingw) were not measured.
- **What a decoder-only build gives up.** Its servers send zlib, not brotli (the 13.7 KB test chain: 3,681 bytes of first
  flight instead of 2,689); its clients send their certificates uncompressed. Receiving is the same as everywhere.
- **libm.** brotli's encoder calls `log2`, the decoder does not: the Android library needs no `libm` (none is linked).
  The Linux libraries with the encoder link `libm.so.6`, which the release's import whitelist names; `libm` is part of
  glibc, and a library built against the glibc 2.17 of the build images binds `log2` at the oldest symbol version
  (GLIBC_2.2.5 on x86_64, GLIBC_2.17 on aarch64), so the glibc floor of 2.17 (`tools/check/glibc-floor.sh`) does not move.
- **Supply chain.** Two more upstreams to watch: a zlib or brotli advisory is handled like an OpenSSL one (SECURITY.md).
  brotli's releases are unsigned, so its pin rests on the SHA-256 and the commit, cross-checked against a second source
  when they change.
