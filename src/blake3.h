/*
 * BLAKE3 reference implementation, portable C version
 *
 * Based on the BLAKE3 specification and the public-domain reference
 * implementation by Jack O'Connor and Samuel Neves
 * (https://github.com/BLAKE3-team/BLAKE3). This file is released into the
 * public domain (CC0 1.0), like the original.
 *
 * Only the unkeyed, default 32-byte output length is exposed here, which is
 * everything the raw hashing format needs.
 */

#ifndef BLAKE3_H
#define BLAKE3_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BLAKE3_BLOCK_SIZE 64
#define BLAKE3_HASH_LENGTH 32
#define BLAKE3_CHUNK_SIZE 1024

/* algorithm context */
typedef struct blake3_chunk_state {
	uint32_t cv[8];
	uint64_t chunk_counter;
	uint8_t block[BLAKE3_BLOCK_SIZE];
	uint8_t block_len;
	uint8_t blocks_compressed;
} blake3_chunk_state;

typedef struct blake3_ctx {
	blake3_chunk_state chunk;
	uint32_t key_words[8];
	uint8_t cv_stack[54 * BLAKE3_HASH_LENGTH];
	uint8_t cv_stack_len;
} blake3_ctx;

/* hash functions */

void blake3_init(blake3_ctx *ctx);
void blake3_update(blake3_ctx *ctx, const unsigned char *data, size_t size);
void blake3_final(blake3_ctx *ctx, unsigned char *result);

#ifdef __cplusplus
}
#endif

#endif
