# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Compiles the pinned zlib and brotli (gradle/compression-libs.toml) with the compiler and flags of OpenSSL's own libcrypto
# objects and appends them to libcrypto.a, so every link line, the ksl_ossl_ symbol prefix (ADR-0007) and the export
# checks cover them as part of OpenSSL. Run by tools/openssl/build.sh in the configured OpenSSL tree, after build_libs:
#   make -f Makefile -f compression.mk ksl-compression
# The sources are copies under ksl-zlib/ and ksl-brotli/ in that tree (relative paths: no machine path reaches an object).
# Only what OpenSSL's c_zlib.c and c_brotli.c call is compiled: zlib without its gz* file API and infback, brotli's
# common, decoder and encoder (ADR-0025):
#   KSL_BROTLI_ENCODER=1 (build.sh's default): the encoder, built with BROTLI_STATIC_INIT_LAZY (its static dictionary lookup
#     tables are computed on first use, not shipped) and with ksl's static_init (ksl_static_init.c) in place of brotli's, which
#     runs that computation once when the first encoder is created;
#   KSL_BROTLI_ENCODER=0 (Android and iOS): no encoder; the entry points OpenSSL calls fail (ksl_encoder_stub.c), so brotli is
#     decompressed but never compressed there.
#   ksl_compress.c (with the encoder): brotli's one-shot encoder, which OpenSSL uses for certificates, at quality 9 at most;
#   ksl_decompress.c (all targets): brotli's one-shot decoder, which OpenSSL uses for certificates, with its allocations bounded
#     by the output size.
# build.sh copies the ksl files next to brotli's encoder and decoder sources (ksl-brotli/c/enc/, c/dec/).
KSL_BROTLI_ENCODER ?= 1

KSL_ZLIB_SRCS := adler32 compress crc32 deflate inffast inflate inftrees trees uncompr zutil
KSL_BROTLI_COMMON_SRCS := constants context dictionary platform shared_dictionary transform
KSL_BROTLI_DEC_SRCS := bit_reader decode huffman prefix state static_init ksl_decompress
ifeq ($(KSL_BROTLI_ENCODER),1)
KSL_BROTLI_ENC_SRCS := backward_references backward_references_hq bit_cost block_splitter brotli_bit_stream cluster command \
  compound_dictionary compress_fragment compress_fragment_two_pass dictionary_hash encode encoder_dict entropy_encode \
  fast_log histogram literal_cost memory metablock static_dict static_dict_lut utf8_util ksl_static_init ksl_compress
else
KSL_BROTLI_ENC_SRCS := ksl_encoder_stub
endif

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
# dec/decode.c's one-shot BrotliDecoderDecompress gives way to ksl_decompress.c's, which bounds its allocations (RFC 8879
# section 5); the streaming decoder it calls is upstream's
ksl-compression/brotli-dec-decode.o: KSL_BROTLI_DEC_DEFS = -DBrotliDecoderDecompress=ksl_brotli_decompress_upstream
ksl-compression/brotli-dec-%.o: ksl-brotli/c/dec/%.c
	@mkdir -p ksl-compression
	$(CC) $(KSL_COMPRESSION_CFLAGS) $(KSL_BROTLI_DEC_DEFS) -Iksl-brotli/c/include -c -o $@ $<
# enc/encode.c's one-shot BrotliEncoderCompress gives way to ksl_compress.c's, which caps the quality at 9 (threat model 3.30)
ksl-compression/brotli-enc-encode.o: KSL_BROTLI_ENC_DEFS = -DBrotliEncoderCompress=ksl_brotli_compress_upstream
ksl-compression/brotli-enc-%.o: ksl-brotli/c/enc/%.c
	@mkdir -p ksl-compression
	$(CC) $(KSL_COMPRESSION_CFLAGS) $(KSL_BROTLI_ENC_DEFS) -DBROTLI_STATIC_INIT=BROTLI_STATIC_INIT_LAZY -Iksl-brotli/c/include -Iinclude -c -o $@ $<

# appended in a fixed order (reproducible archives); the archive's index is rebuilt after
.PHONY: ksl-compression
ksl-compression: $(KSL_COMPRESSION_OBJS) libcrypto.a
	$(AR) $(ARFLAGS) libcrypto.a $(KSL_COMPRESSION_OBJS)
	$(RANLIB) libcrypto.a
