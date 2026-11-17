#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Sourced, never run. Where a native build must be the project's own, byte for byte: the release
# (tools/release/local-release.sh), the double build (tools/check/double-build.sh), the rebuild of
# tools/verify/verify-release.sh and the hosted jobs that build the libraries a release reuses. ksl_clean_build_env unsets
# every environment variable known to change what a compiler, the linker, an archiver, OpenSSL's Configure, make or the
# build scripts produce; "ksl_clean_build_env note" also names each one it unsets (never its value).
#   compilers and tools:  CC CXX CPP AS LD AR RANLIB NM STRIP OBJCOPY CROSS_COMPILE RC WINDRES PERL HASHBANGPERL and the
#                         LLVM_* tools of tools/check/llvm-tool.sh
#   flags:                CPPFLAGS CFLAGS CXXFLAGS LDFLAGS LDLIBS ASFLAGS ARFLAGS RCFLAGS, OPT (tools/openssl/build.sh)
#   clang and gcc:        CCC_OVERRIDE_OPTIONS (edits every clang command line), CPATH, C_INCLUDE_PATH,
#                         CPLUS_INCLUDE_PATH, OBJC_INCLUDE_PATH, LIBRARY_PATH, COMPILER_PATH, GCC_EXEC_PREFIX, SDKROOT,
#                         MACOSX_DEPLOYMENT_TARGET, IPHONEOS_DEPLOYMENT_TARGET, RC_DEBUG_OPTIONS, SOURCE_DATE_EPOCH
#   OpenSSL's Configure:  __CNF_CPPDEFINES __CNF_CPPINCLUDES __CNF_CPPFLAGS __CNF_CFLAGS __CNF_CXXFLAGS __CNF_LDFLAGS
#                         __CNF_LDLIBS OPENSSL_LOCAL_CONFIG_DIR BUILDFILE
#   make:                 MAKEFLAGS MFLAGS GNUMAKEFLAGS MAKEFILES
#   the build scripts:    KSL_OPENSSL_PIN KSL_OPENSSL_OUT KSL_OPENSSL_PREFIXED KSL_OPENSSL_WORK KSL_KEEP_DEBUG
# What selects a toolchain is left alone, as the release checks it against the pins: PATH, DEVELOPER_DIR, ANDROID_NDK_ROOT,
# KONAN_DEPS, JAVA_HOME. tools/check/native-flags-test.sh checks that a release-like build ignores the variables above.
ksl_build_env_vars=(
  CC CXX CPP AS LD AR RANLIB NM STRIP OBJCOPY CROSS_COMPILE RC WINDRES PERL HASHBANGPERL
  LLVM_OBJCOPY LLVM_NM LLVM_OBJDUMP LLVM_READELF
  CPPFLAGS CFLAGS CXXFLAGS LDFLAGS LDLIBS ASFLAGS ARFLAGS RCFLAGS OPT
  CCC_OVERRIDE_OPTIONS CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH LIBRARY_PATH COMPILER_PATH GCC_EXEC_PREFIX
  SDKROOT MACOSX_DEPLOYMENT_TARGET IPHONEOS_DEPLOYMENT_TARGET RC_DEBUG_OPTIONS SOURCE_DATE_EPOCH
  __CNF_CPPDEFINES __CNF_CPPINCLUDES __CNF_CPPFLAGS __CNF_CFLAGS __CNF_CXXFLAGS __CNF_LDFLAGS __CNF_LDLIBS
  OPENSSL_LOCAL_CONFIG_DIR BUILDFILE
  MAKEFLAGS MFLAGS GNUMAKEFLAGS MAKEFILES
  KSL_OPENSSL_PIN KSL_OPENSSL_OUT KSL_OPENSSL_PREFIXED KSL_OPENSSL_WORK KSL_KEEP_DEBUG
)
ksl_clean_build_env() { # [note]
  local v
  for v in "${ksl_build_env_vars[@]}"; do
    if [ -n "${!v+x}" ]; then
      [ "${1:-}" != note ] || echo "     note: $v is ignored: the build uses the project's own compiler, flags and paths"
      unset "$v"
    fi
  done
}
ksl_build_env_set() { # [prefix to leave out]: the names of the variables above that are set, one line; for the hosted jobs'
  # guard (their setup sets the LLVM_* tools on purpose)
  local v out=""
  for v in "${ksl_build_env_vars[@]}"; do
    if [ -n "${!v+x}" ] && { [ -z "${1:-}" ] || [ "${v#"$1"}" = "$v" ]; }; then out="$out $v"; fi
  done
  echo "${out# }"
}
