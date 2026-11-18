<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0020. zlib and brotli in libcrypto, for TLS certificate compression

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
- **brotli's static tables** stay compiled in (brotli's default, `BROTLI_STATIC_INIT_NONE`).
- OpenSSL is configured `enable-zlib enable-brotli` (not `-dynamic`), and `no-comp` is dropped. TLS record compression
  stays off (`SSL_OP_NO_COMPRESSION` on every `ksl` context, RFC 9325 section 3.3).

## Consequences

- **Size.** The libraries grow by about 0.8 MB per target, almost all of it brotli's encoder:

  | Library | before | after | delta |
  |---|---|---|---|
  | Android arm64-v8a `libksl.so` | 2,898,576 | 3,704,880 | +806,304 |
  | Android x86_64 `libksl.so` | 3,743,904 | 4,593,232 | +849,328 |
  | Android armeabi-v7a `libksl.so` | 2,222,824 | 3,012,880 | +790,056 |
  | macOS arm64 JNI `libksl_7_osx_aarch_64.dylib` | 2,544,056 | 3,337,496 | +793,440 |

  Of the 775 KB the two libraries add to the Android arm64 `libcrypto.a` in code and data: brotli's encoder 576 KB (its
  static dictionary lookup tables 290 KB of that), brotli's common part (the RFC 7932 dictionary) 127 KB, its decoder
  32 KB, zlib 40 KB. The Android size gate (`tools/check/size.sh`) moves up by 800,000 bytes, to a limit of 3,800,000
  and a target of 3,500,000.
- **Not taken, with their numbers.** brotli's `BROTLI_STATIC_INIT_LAZY` computes the encoder's lookup tables on first use
  instead of shipping them (about 290 KB less per target, the same in memory once a server compresses), but needs the
  embedder to call brotli's internal initialisation before OpenSSL creates an encoder; it can be taken later without
  changing the decision. A decoder-only brotli would leave servers sending brotli-compressed chains out.
- **libm.** brotli's encoder calls `log2`: the Linux and Android libraries now also need `libm` (`libm.so.6`, part of
  glibc and inside the glibc floor of 2.17; Android's `libm.so`). The Linux import whitelist of
  `tools/release/local-release.sh` names it.
- **Supply chain.** Two more upstreams to watch: a zlib or brotli advisory is handled like an OpenSSL one (SECURITY.md).
  brotli's releases are unsigned, so its pin rests on the SHA-256 and the commit, cross-checked against a second source
  when they change.
