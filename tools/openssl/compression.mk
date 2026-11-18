# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Compiles the pinned zlib and brotli (gradle/compression-libs.toml) with the compiler and flags of OpenSSL's own libcrypto
# objects and appends them to libcrypto.a, so every link line, the ksl_ossl_ symbol prefix (ADR-0007) and the export
# checks cover them as part of OpenSSL. Run by tools/openssl/build.sh in the configured OpenSSL tree, after build_libs:
#   make -f Makefile -f compression.mk ksl-compression
# The sources are copies under ksl-zlib/ and ksl-brotli/ in that tree (relative paths: no machine path reaches an object).
# Only what OpenSSL's c_zlib.c and c_brotli.c call is compiled: zlib without its gz* file API and infback, brotli's
# common, decoder and encoder.

KSL_ZLIB_SRCS := adler32 compress crc32 deflate inffast inflate inftrees trees uncompr zutil
KSL_BROTLI_COMMON_SRCS := constants context dictionary platform shared_dictionary transform
KSL_BROTLI_DEC_SRCS := bit_reader decode huffman prefix state static_init
KSL_BROTLI_ENC_SRCS := backward_references backward_references_hq bit_cost block_splitter brotli_bit_stream cluster command \
  compound_dictionary compress_fragment compress_fragment_two_pass dictionary_hash encode encoder_dict entropy_encode \
  fast_log histogram literal_cost memory metablock static_dict static_dict_lut static_init utf8_util

KSL_COMPRESSION_OBJS := $(KSL_ZLIB_SRCS:%=ksl-compression/zlib-%.o) \
  $(KSL_BROTLI_COMMON_SRCS:%=ksl-compression/brotli-common-%.o) \
  $(KSL_BROTLI_DEC_SRCS:%=ksl-compression/brotli-dec-%.o) \
  $(KSL_BROTLI_ENC_SRCS:%=ksl-compression/brotli-enc-%.o)

# libcrypto's flags (LIB_CFLAGS: -fPIC, the target's and the project's -Os -ffunction-sections -fdata-sections
# -fvisibility=hidden -fno-common ...; LIB_CPPFLAGS: -DNDEBUG and the rest) plus the library's own include directory
KSL_COMPRESSION_CFLAGS = $(LIB_CFLAGS) $(LIB_CPPFLAGS)

ksl-compression/zlib-%.o: ksl-zlib/%.c
	@mkdir -p ksl-compression
	$(CC) $(KSL_COMPRESSION_CFLAGS) -Iksl-zlib -c -o $@ $<
ksl-compression/brotli-common-%.o: ksl-brotli/c/common/%.c
	@mkdir -p ksl-compression
	$(CC) $(KSL_COMPRESSION_CFLAGS) -Iksl-brotli/c/include -c -o $@ $<
ksl-compression/brotli-dec-%.o: ksl-brotli/c/dec/%.c
	@mkdir -p ksl-compression
	$(CC) $(KSL_COMPRESSION_CFLAGS) -Iksl-brotli/c/include -c -o $@ $<
ksl-compression/brotli-enc-%.o: ksl-brotli/c/enc/%.c
	@mkdir -p ksl-compression
	$(CC) $(KSL_COMPRESSION_CFLAGS) -Iksl-brotli/c/include -c -o $@ $<

# appended in a fixed order (reproducible archives); the archive's index is rebuilt after
.PHONY: ksl-compression
ksl-compression: $(KSL_COMPRESSION_OBJS) libcrypto.a
	$(AR) $(ARFLAGS) libcrypto.a $(KSL_COMPRESSION_OBJS)
	$(RANLIB) libcrypto.a
