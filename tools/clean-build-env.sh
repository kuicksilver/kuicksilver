#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Sourced, never run. Where a native build must be the project's own, byte for byte: the release
# (tools/release/local-release.sh), the double build (tools/check/double-build.sh), the rebuild of
# tools/verify/verify-release.sh and the hosted jobs that build the libraries a release reuses. ksl_clean_build_env unsets
# the environment variables we know of that change what a compiler, the linker, an archiver, the dynamic loader, Perl
# (which runs OpenSSL's Configure and code generators), OpenSSL's Configure, make or the build scripts produce;
# "ksl_clean_build_env note" also names each one it unsets (never its value). The list cannot be complete: a variable
# found to reach a build goes into ksl_build_env_vars below (and its group in this comment), and
# tools/check/native-flags-test.sh then checks that it is unset and that the double build ignores it.
#   compilers and tools:  CC CXX CPP AS LD AR RANLIB NM STRIP OBJCOPY CROSS_COMPILE RC WINDRES PERL HASHBANGPERL and the
#                         LLVM_* tools of tools/check/llvm-tool.sh
#   flags:                CPPFLAGS CFLAGS CXXFLAGS LDFLAGS LDLIBS ASFLAGS ARFLAGS RCFLAGS, OPT (tools/openssl/build.sh)
#   clang and gcc:        CCC_OVERRIDE_OPTIONS (edits every clang command line), CPATH, C_INCLUDE_PATH,
#                         CPLUS_INCLUDE_PATH, OBJC_INCLUDE_PATH, LIBRARY_PATH, COMPILER_PATH, GCC_EXEC_PREFIX, SDKROOT,
#                         MACOSX_DEPLOYMENT_TARGET, IPHONEOS_DEPLOYMENT_TARGET, RC_DEBUG_OPTIONS, SOURCE_DATE_EPOCH,
#                         TOOLCHAINS (xcrun's toolchain choice)
#   linkers and loaders:  LD_RUN_PATH (an rpath ld records), LD_PRELOAD, DYLD_INSERT_LIBRARIES (code loaded into every tool)
#   Perl:                 PERL5OPT, PERL5LIB, PERLLIB
#   OpenSSL's Configure:  CROSS_SYSROOT, __CNF_CPPDEFINES __CNF_CPPINCLUDES __CNF_CPPFLAGS __CNF_CFLAGS __CNF_CXXFLAGS __CNF_LDFLAGS
#                         __CNF_LDLIBS OPENSSL_LOCAL_CONFIG_DIR BUILDFILE
#   make:                 MAKEFLAGS MFLAGS GNUMAKEFLAGS MAKEFILES
#   the build scripts:    KSL_OPENSSL_PIN KSL_OPENSSL_OUT KSL_OPENSSL_PREFIXED KSL_OPENSSL_WORK KSL_KEEP_DEBUG
#                         KSL_OPENSSL_BUILD_IMAGE (set by build-docker.sh inside the container only)
# What selects a toolchain is left alone, as the release checks it against the pins: PATH, DEVELOPER_DIR, ANDROID_NDK_ROOT,
# KONAN_DEPS, JAVA_HOME. ksl_clean_build_env also exports KSL_PINNED_NDK=1, so tools/check/llvm-tool.sh takes the LLVM
# tools (llvm-ar, llvm-objcopy, ...) from the pinned NDK only, never from another NDK, PATH or Homebrew, and fails
# without it; and it unsets an ANDROID_NDK_HOME that is not the pinned NDK (Gradle and the NDK's own scripts read it).
# A caller that accepts toolchain drift (--allow-toolchain-drift) calls ksl_allow_toolchain_drift afterwards, which undoes both. tools/check/native-flags-test.sh checks that a release-like build ignores the variables above.
ksl_build_env_vars=(
  CC CXX CPP AS LD AR RANLIB NM STRIP OBJCOPY CROSS_COMPILE RC WINDRES PERL HASHBANGPERL
  LLVM_OBJCOPY LLVM_NM LLVM_OBJDUMP LLVM_READELF LLVM_AR
  CPPFLAGS CFLAGS CXXFLAGS LDFLAGS LDLIBS ASFLAGS ARFLAGS RCFLAGS OPT
  CCC_OVERRIDE_OPTIONS CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH LIBRARY_PATH COMPILER_PATH GCC_EXEC_PREFIX
  SDKROOT MACOSX_DEPLOYMENT_TARGET IPHONEOS_DEPLOYMENT_TARGET RC_DEBUG_OPTIONS SOURCE_DATE_EPOCH TOOLCHAINS
  LD_RUN_PATH LD_PRELOAD DYLD_INSERT_LIBRARIES
  PERL5OPT PERL5LIB PERLLIB CROSS_SYSROOT
  __CNF_CPPDEFINES __CNF_CPPINCLUDES __CNF_CPPFLAGS __CNF_CFLAGS __CNF_CXXFLAGS __CNF_LDFLAGS __CNF_LDLIBS
  OPENSSL_LOCAL_CONFIG_DIR BUILDFILE
  MAKEFLAGS MFLAGS GNUMAKEFLAGS MAKEFILES
  KSL_OPENSSL_PIN KSL_OPENSSL_OUT KSL_OPENSSL_PREFIXED KSL_OPENSSL_WORK KSL_KEEP_DEBUG KSL_OPENSSL_BUILD_IMAGE
)
ksl_clean_build_env() { # [note]
  local v pin
  for v in "${ksl_build_env_vars[@]}"; do
    if [ -n "${!v+x}" ]; then
      [ "${1:-}" != note ] || echo "     note: $v is ignored: the build uses the project's own compiler, flags and paths"
      unset "$v"
    fi
  done
  export KSL_PINNED_NDK=1
  pin=$(sed -n 's/^ndk = "\(.*\)".*/\1/p' "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/gradle/toolchains.toml" 2>/dev/null)
  if [ -n "${ANDROID_NDK_HOME:-}" ] && [ "$(sed -n 's/^Pkg.Revision *= *//p' "$ANDROID_NDK_HOME/source.properties" 2>/dev/null | tr -d '\r')" != "$pin" ]; then
    [ "${1:-}" != note ] || echo "     note: ANDROID_NDK_HOME is ignored: it is not the pinned NDK $pin"
    ksl_dropped_ndk_home="$ANDROID_NDK_HOME"; unset ANDROID_NDK_HOME
  fi
}
ksl_allow_toolchain_drift() { # after ksl_clean_build_env, for a caller run with --allow-toolchain-drift (local-release.sh,
  # verify-release.sh): the pinned-NDK mode is left again, so the LLVM tools come from whichever NDK is there (a
  # difference is then expected, and the caller says so), and an ANDROID_NDK_HOME it dropped is back
  unset KSL_PINNED_NDK
  if [ -n "${ksl_dropped_ndk_home:-}" ]; then export ANDROID_NDK_HOME="$ksl_dropped_ndk_home"; unset ksl_dropped_ndk_home; fi
}
ksl_build_env_guard() { # the hosted jobs' guard: the names of the variables above that are set, on one line (empty: none),
  # leaving out the values the workflow sets on purpose, which a build gives the same result with as without:
  #   LLVM_NM, LLVM_OBJCOPY, LLVM_OBJDUMP, LLVM_READELF, LLVM_AR naming the pinned NDK's own tool (.github/actions/setup writes them
  #   to GITHUB_ENV; tools/check/llvm-tool.sh takes that tool from the NDK anyway), and an SDKROOT that is the selected
  #   Xcode's macOS SDK (the one clang uses without it). The runner images set none of the others.
  local v t ok out=""
  for v in "${ksl_build_env_vars[@]}"; do
    [ -n "${!v+x}" ] || continue
    ok=0
    case "$v" in
      LLVM_NM|LLVM_OBJCOPY|LLVM_OBJDUMP|LLVM_READELF|LLVM_AR)
        t=$(printf '%s' "${v#LLVM_}" | tr '[:upper:]' '[:lower:]')
        if [ -n "${ANDROID_NDK_ROOT:-}" ]; then
          for c in "$ANDROID_NDK_ROOT"/toolchains/llvm/prebuilt/*/bin/llvm-"$t"; do [ "${!v}" = "$c" ] && ok=1; done
        fi ;;
      SDKROOT) [ -n "${!v}" ] && [ "${!v}" = "$(xcrun --sdk macosx --show-sdk-path 2>/dev/null)" ] && ok=1 ;;
    esac
    [ "$ok" = 1 ] || out="$out $v"
  done
  echo "${out# }"
}
