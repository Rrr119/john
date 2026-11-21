/*
 * BLAKE3 reference implementation, portable C version
 *
 * Based on the BLAKE3 specification and the public-domain reference
 * implementation by Jack O'Connor and Samuel Neves
 * (https://github.com/BLAKE3-team/BLAKE3). Released into the public domain
 * (CC0 1.0), like the original.
 *
 * This is the simple, portable variant: no SIMD, no keyed hashing, fixed
 * 32-byte output. It keeps the streaming init/update/final interface used by
 * John's raw hash formats and supports input of any length through the
 * chunk/tree logic.
 */

#include <string.h>

#include "blake3.h"

#define CHUNK_START 1
#define CHUNK_END 2
#define PARENT 4
#define ROOT 8

static const uint32_t IV[8] = {
	0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
	0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const uint8_t MSG_PERMUTATION[16] = {
	2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
};

static uint32_t load32_le(const uint8_t src[4])
{
	return (uint32_t) src[0] | ((uint32_t) src[1] << 8) |
	    ((uint32_t) src[2] << 16) | ((uint32_t) src[3] << 24);
}

static void store32_le(uint8_t dst[4], uint32_t w)
{
	dst[0] = (uint8_t) w;
	dst[1] = (uint8_t) (w >> 8);
	dst[2] = (uint8_t) (w >> 16);
	dst[3] = (uint8_t) (w >> 24);
}

static void store_cv_words(uint8_t bytes[32], const uint32_t words[8])
{
	int i;

	for (i = 0; i < 8; i++)
		store32_le(&bytes[i * 4], words[i]);
}

static uint32_t rotr32(uint32_t w, uint32_t n)
{
	return (w >> n) | (w << (32 - n));
}

#define G(a, b, c, d, mx, my) \
	do { \
		a = a + b + mx; \
		d = rotr32(d ^ a, 16); \
		c = c + d; \
		b = rotr32(b ^ c, 12); \
		a = a + b + my; \
		d = rotr32(d ^ a, 8); \
		c = c + d; \
		b = rotr32(b ^ c, 7); \
	} while (0)

#define ROUND(state, m) \
	do { \
		G(state[0], state[4], state[8], state[12], m[0], m[1]); \
		G(state[1], state[5], state[9], state[13], m[2], m[3]); \
		G(state[2], state[6], state[10], state[14], m[4], m[5]); \
		G(state[3], state[7], state[11], state[15], m[6], m[7]); \
		G(state[0], state[5], state[10], state[15], m[8], m[9]); \
		G(state[1], state[6], state[11], state[12], m[10], m[11]); \
		G(state[2], state[7], state[8], state[13], m[12], m[13]); \
		G(state[3], state[4], state[9], state[14], m[14], m[15]); \
	} while (0)

static void permute(uint32_t m[16])
{
	uint32_t permuted[16];
	int i;

	for (i = 0; i < 16; i++)
		permuted[i] = m[MSG_PERMUTATION[i]];
	memcpy(m, permuted, sizeof(permuted));
}

static void compress(const uint32_t key[8], const uint8_t block[64],
    uint8_t block_len, uint8_t flags,
    uint64_t chunk_counter, uint32_t out[16])
{
	uint32_t state[16];
	uint32_t m[16];
	int i;

	for (i = 0; i < 8; i++)
		state[i] = key[i];
	state[8] = IV[0];
	state[9] = IV[1];
	state[10] = IV[2];
	state[11] = IV[3];
	state[12] = (uint32_t) chunk_counter;
	state[13] = (uint32_t) (chunk_counter >> 32);
	state[14] = block_len;
	state[15] = flags;

	for (i = 0; i < 16; i++)
		m[i] = load32_le(&block[i * 4]);

	ROUND(state, m);
	permute(m);
	ROUND(state, m);
	permute(m);
	ROUND(state, m);
	permute(m);
	ROUND(state, m);
	permute(m);
	ROUND(state, m);
	permute(m);
	ROUND(state, m);
	permute(m);
	ROUND(state, m);

	for (i = 0; i < 8; i++) {
		state[i] ^= state[i + 8];
		state[i + 8] ^= key[i];
	}

	for (i = 0; i < 16; i++)
		out[i] = state[i];
}

static void chunk_state_init(blake3_chunk_state *self,
    const uint32_t key_words[8], uint64_t chunk_counter)
{
	memcpy(self->cv, key_words, sizeof(self->cv));
	self->chunk_counter = chunk_counter;
	self->block_len = 0;
	self->blocks_compressed = 0;
}

static size_t chunk_state_len(const blake3_chunk_state *self)
{
	return (size_t) BLAKE3_BLOCK_SIZE * self->blocks_compressed +
	    self->block_len;
}

static int chunk_state_start_flag(const blake3_chunk_state *self)
{
	return self->blocks_compressed == 0;
}

static void chunk_state_update(blake3_chunk_state *self,
    const uint8_t *input, size_t input_len)
{
	while (input_len > 0) {
		if (self->block_len == BLAKE3_BLOCK_SIZE) {
			uint32_t out[16];
			uint8_t flags =
			    (chunk_state_start_flag(self) ? CHUNK_START : 0);

			compress(self->cv, self->block,
			    BLAKE3_BLOCK_SIZE, flags, self->chunk_counter, out);
			memcpy(self->cv, out, sizeof(self->cv));
			self->blocks_compressed++;
			self->block_len = 0;
		}

		{
			size_t want = BLAKE3_BLOCK_SIZE - self->block_len;
			size_t take = input_len < want ? input_len : want;

			memcpy(&self->block[self->block_len], input, take);
			self->block_len += (uint8_t) take;
			input += take;
			input_len -= take;
		}
	}
}

static void chunk_state_final(const blake3_chunk_state *self, uint8_t out[32])
{
	uint8_t block[BLAKE3_BLOCK_SIZE];
	uint32_t wide[16];
	uint8_t flags =
	    (chunk_state_start_flag(self) ? CHUNK_START : 0) | CHUNK_END;

	memcpy(block, self->block, self->block_len);
	memset(block + self->block_len, 0,
	    BLAKE3_BLOCK_SIZE - self->block_len);
	compress(self->cv, block, self->block_len, flags,
	    self->chunk_counter, wide);
	store_cv_words(out, wide);
}

static void parent_output(const uint32_t key_words[8],
    const uint8_t left[32], const uint8_t right[32], uint8_t out[64])
{
	uint8_t block[BLAKE3_BLOCK_SIZE];
	uint32_t wide[16];

	memcpy(block, left, 32);
	memcpy(block + 32, right, 32);
	compress(key_words, block, BLAKE3_BLOCK_SIZE, PARENT, 0, wide);
	store_cv_words(out, wide);
	store_cv_words(out + 32, wide + 8);
}

static void parent_cv(const uint32_t key_words[8],
    const uint8_t left[32], const uint8_t right[32], uint8_t cv[32])
{
	uint8_t wide[64];

	parent_output(key_words, left, right, wide);
	memcpy(cv, wide, 32);
}

static int haschunks_merged(uint64_t total_chunks)
{
	return total_chunks > 1 && (total_chunks & 1) == 0;
}

static void push_cv(blake3_ctx *self, const uint8_t cv[32])
{
	memcpy(&self->cv_stack[self->cv_stack_len * BLAKE3_HASH_LENGTH],
	    cv, BLAKE3_HASH_LENGTH);
	self->cv_stack_len++;
}

static void pop_cv(blake3_ctx *self, uint8_t cv[32])
{
	self->cv_stack_len--;
	memcpy(cv, &self->cv_stack[self->cv_stack_len * BLAKE3_HASH_LENGTH],
	    BLAKE3_HASH_LENGTH);
}

static void add_chunk_cv(blake3_ctx *self, const uint8_t cv[32])
{
	uint64_t total_chunks = self->chunk.chunk_counter + 1;
	uint8_t new_cv[32];

	memcpy(new_cv, cv, 32);
	while (haschunks_merged(total_chunks)) {
		uint8_t left[32];
		uint8_t merged[32];

		pop_cv(self, left);
		parent_cv(self->key_words, left, new_cv, merged);
		memcpy(new_cv, merged, 32);
		total_chunks >>= 1;
	}
	push_cv(self, new_cv);
}

void blake3_init(blake3_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	memcpy(ctx->key_words, IV, sizeof(IV));
	chunk_state_init(&ctx->chunk, ctx->key_words, 0);
}

void blake3_update(blake3_ctx *ctx, const unsigned char *data, size_t size)
{
	while (size > 0) {
		size_t take = BLAKE3_CHUNK_SIZE -
		    chunk_state_len(&ctx->chunk);

		if (size > take) {
			uint8_t cv[32];

			chunk_state_update(&ctx->chunk, data, take);
			chunk_state_final(&ctx->chunk, cv);
			add_chunk_cv(ctx, cv);
			chunk_state_init(&ctx->chunk, ctx->key_words,
			    ctx->chunk.chunk_counter + 1);
			data += take;
			size -= take;
		} else {
			chunk_state_update(&ctx->chunk, data, size);
			break;
		}
	}
}

static void root_output(blake3_ctx *ctx, uint8_t out[64])
{
	uint8_t cv[32];

	chunk_state_final(&ctx->chunk, cv);

	if (ctx->cv_stack_len == 0) {
		uint8_t block[BLAKE3_BLOCK_SIZE];
		uint32_t wide[16];
		uint8_t flags =
		    (chunk_state_start_flag(&ctx->chunk) ? CHUNK_START : 0) |
		    CHUNK_END | ROOT;

		memcpy(block, ctx->chunk.block, ctx->chunk.block_len);
		memset(block + ctx->chunk.block_len, 0,
		    BLAKE3_BLOCK_SIZE - ctx->chunk.block_len);
		compress(ctx->chunk.cv, block,
		    ctx->chunk.block_len, flags, 0, wide);
		store_cv_words(out, wide);
		store_cv_words(out + 32, wide + 8);
		return;
	}

	{
		uint8_t current[32];
		uint8_t left[32];
		uint8_t count = ctx->cv_stack_len;

		memcpy(current, cv, 32);
		while (count > 0) {
			count--;
			memcpy(left,
			    &ctx->cv_stack[count * BLAKE3_HASH_LENGTH], 32);
			if (count == 0) {
				uint8_t block[BLAKE3_BLOCK_SIZE];
				uint32_t wide[16];

				memcpy(block, left, 32);
				memcpy(block + 32, current, 32);
				compress(ctx->key_words, block,
				    BLAKE3_BLOCK_SIZE, PARENT | ROOT, 0, wide);
				store_cv_words(out, wide);
				store_cv_words(out + 32, wide + 8);
				return;
			}

			{
				uint8_t merged[32];

				parent_cv(ctx->key_words, left, current,
				    merged);
				memcpy(current, merged, 32);
			}
		}
	}
}

void blake3_final(blake3_ctx *ctx, unsigned char *result)
{
	uint8_t wide[64];

	root_output(ctx, wide);
	memcpy(result, wide, BLAKE3_HASH_LENGTH);
}
