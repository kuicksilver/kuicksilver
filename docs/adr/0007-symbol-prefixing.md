# ADR-0007. Symbol isolation: a version script for JNI, OpenSSL symbol prefixing for Kotlin/Native

Date: 2026-10-02. Status: accepted (approved by the owner 2026-10-02; the details are fixed by the K0(c) spike).

## Context

An application may contain a second copy of OpenSSL: the system one, one from another library, and in KMP already today one from `ktor-client-curl` 3.6.0, which embeds an unprefixed OpenSSL 3.6.2 in its klib. Two copies with identical symbols, linked statically, give, depending on the linker, either `duplicate symbol` (ld.lld) or a **silent mix of objects from two versions** (Xcode ld — verified by an experiment on 2026-10-02); the shim may then silently bind to the other copy; on Linux K/N links executables with `-export-dynamic`, and our OpenSSL would override the symbols of the system `libcrypto.so`. OpenSSL has no built-in symbol prefix (unlike `BORINGSSL_PREFIX`). Incidents: psycopg2#543, themis#657, tensorflow#43878, msquic#6031, webrtc-build-scripts#134 (iOS).

## Decision

- JNI (JVM, Android): OpenSSL is static inside `libksl`; only `ksl_*` and `JNI_*`/`Java_*` are exported (version script / `-exported_symbols_list` / `.def`). Checked in CI with `nm`/`dumpbin`.
- Kotlin/Native: the static library goes into the klib and into the final binary, where all symbols are shared → the symbols of our OpenSSL build are prefixed (`ksl_ossl_`): `llvm-objcopy --redefine-syms` of a fixed version (from the NDK or Homebrew — K/N and Xcode do not ship it) works the same for ELF, Mach-O (names with `_`) and COFF; the map is built with `nm -g --defined-only` over `libcrypto.a` + `libssl.a` separately for each format and is also applied to `libksl.a`, so the shim's references are renamed together with the definitions (the technique of msquic PR #6031 and skiko `PatchSkiaSymbolsTask`); OpenSSL is built with `-fvisibility=hidden`, `ksl_*` are `visibility("default")`; LTO is not used. The fallback is `ld -r` + localising everything except `ksl_*` (`ld -r -exported_symbols_list` on Apple, `ld.lld -r` + `--keep-global-symbols` on ELF; unavailable on mingw). A header with `#define`/`#pragma redefine_extname` for OpenSSL is **incomplete**: perlasm on x86_64 emits `.s` files that do not go through the preprocessor, so it only works with `no-asm`.

K0(c) 2026-10-02: confirmed on linuxX64, linuxArm64, macosArm64 (run) and mingwX64 (link); the negative control with `ktor-client-curl` 3.6.0 showed silent merging of the copies on both linkers; with the prefix both copies work in one process. OpenSSL is built with `-fvisibility=hidden -fno-common`.

## Consequences

- A second copy of OpenSSL in the process is safe.
- A symbol list generator is needed, plus a CI check that no unprefixed `SSL_*`/`EVP_*`/`CRYPTO_*` remain.
- The suitability of `llvm-objcopy --redefine-syms` for Mach-O and COFF is confirmed by the LLVM code and by link experiments on 2026-10-02; `--prefix-symbols` is ELF only, `--keep-global-symbols` is unavailable for COFF and for Mach-O in LLVM 18. K0(c) fixes this on linuxX64, linuxArm64, macosArm64, mingwX64 with a negative control against `ktor-client-curl` 3.6.0 and an `nm`/`.dynsym` check.
- Delivery risk: `staticLibraries`/`-include-binary` in cinterop are marked Experimental, and JetBrains plans to deprecate them (KT-70946, KT-70211); the fallback is a `.a` as a separate artifact + `linkerOpts`/a Gradle plugin.

## Implementation in K1 (2026-10-02)

`tools/prefix/prefix.sh` renames the OpenSSL globals and `libksl.a` for all K/N targets (7148–7452 symbols on macOS/iOS/Linux/mingw), `check-no-unprefixed.sh` checks with an allow list that "all globals start with `ksl_`". The JNI libraries export only `JNI_OnLoad*` (`tools/check/exports.sh` on dylib/.so/AAR). OpenSSL is built with `-fvisibility=hidden -fno-common`.
