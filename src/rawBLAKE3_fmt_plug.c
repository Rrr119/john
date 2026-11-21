/*
 * Raw BLAKE3 format plugin
 *
 * Copyright (c) 2026
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rawBLAKE3;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawBLAKE3);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"

#include "blake3.h"

#define FORMAT_LABEL       "Raw-BLAKE3"
#define FORMAT_NAME        "BLAKE3"
#define FORMAT_TAG         "$raw-blake3$"
#define TAG_LENGTH         (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME     "BLAKE3 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT  ""
#define BENCHMARK_LENGTH   0x107
#define PLAINTEXT_LENGTH   MAX_PLAINTEXT_LENGTH
#define BINARY_SIZE        BLAKE3_HASH_LENGTH
#define BINARY_ALIGN       4
#define SALT_SIZE          0
#define SALT_ALIGN         1
#define MIN_KEYS_PER_CRYPT 1
#define MAX_KEYS_PER_CRYPT 64

#ifndef OMP_SCALE
#define OMP_SCALE          32
#endif

static struct fmt_tests blake3_tests[] = {
	/* official BLAKE3 empty-input vector */
	{ "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "" },
	/* short inputs, untagged hex */
	{ "17762fddd969a453925d65717ac3eea21320b66b54342fde15128d6caf21215f", "a" },
	{ "2dc99999a6aaef3f20349d2ed4057a2b54419545dabb809e6381de1bad8337e2", "ab" },
	/* canonical tagged form */
	{ FORMAT_TAG "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85", "abc" },
	{ "7f2611ba158b6dcea4a69c229c303358c5e04493abeadee106a4bfa464d55787", "password" },
	{ "7adb787627ad5ee341fa0ba46a956e78fd85c39e195119bb260d5181b4f1e4ba", "123456" },
	{ "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24", "hello world" },
	{ "2f1514181aadccd913abd94cfa592701a5686ab23f8df1dff1b74710febc6d4a",
	  "The quick brown fox jumps over the lazy dog" },
	{ "6c75c6903d9e1ce1836807e2390f5abd0cd6ca35420c983bdb14d24111301888", "qwerty123" },
	{ "4837a67745e98a945a80def6b5bfcf47032682246e4213e0c4c7d66279c511c9", "P@ssw0rd!" },
	{ FORMAT_TAG "d5f27fda50bfb4761d07c249ea25f4f9c41855002cc2f64a8b0e88fb721872b8",
	  "john the ripper" },
	/* mixed punctuation */
	{ "d12125241c81a05128e6a8bd57c2120f1d45c63a7d80f5379b42b54c1f460260",
	  "a]K5D{#}" },
	/* 8-bit (non-ASCII) password */
	{ "cda81315f35aa69f1a2b2316419f794287008cfe2ec6d5166a6edde17a2c7cb3",
	  "\xff\xfe\x80\x01\x7f" },
	/* 64-byte block boundary: 63, 64 and 65 bytes */
	{ "f9bdf438afe7a18d10d7910069110e1caa278d640f1b06740f8316487e15c35e",
	  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
	{ FORMAT_TAG "84421676fe0d5a2229f1e3bbf7b84cf541c8a3bad9f0606a96ecbcba941c2380",
	  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
	{ "a32b4a703f5d61b2df5bfbf5a5e7af5f8818b4c52489214e76704330024fe067",
	  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
	/* two-block boundary: 127 and 128 bytes */
	{ "709248006a1e769cc9fb8031299dffd49c73fd348ded69396d7e0fcc5075351b",
	  "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy" },
	{ "73ad54eb6b6b523c30dd8e2a56216b3e49d602c879d1a02d7bfd8d909fe404b3",
	  "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy" },
	/* maximum supported plaintext length: 318 and 319 bytes */
	{ "8ac7f73e4fc1cd3e7ccf1e61457057e4cd20d8bab873fbe8d0c93d37eb60bc12",
	  "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	  "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	  "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	  "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	  "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" },
	{ FORMAT_TAG "9ccca8d881b6a3f40ff50673d54ac0778e424a853238e05d466e0f30d2572ef4",
	  "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	  "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	  "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	  "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	  "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" },
	{ NULL }
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	if (!saved_key) {
		saved_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_key));
		crypt_out = mem_calloc(self->params.max_keys_per_crypt, sizeof(*crypt_out));
	}
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;
	int extra;

	p = ciphertext;

	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;
	if (hexlenl(p, &extra) != (2 * BLAKE3_HASH_LENGTH) || extra)
		return 0;

	return 1;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + BINARY_SIZE * 2 + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	strnzcpy(out + TAG_LENGTH, ciphertext, BINARY_SIZE * 2 + 1);
	return out;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p = strrchr(ciphertext, '$') + 1;
	else
		p = ciphertext;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;

#ifdef _OPENMP
	#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		blake3_ctx ctx;

		blake3_init(&ctx);
		blake3_update(&ctx, (unsigned char *)saved_key[index],
		    strlen(saved_key[index]));
		blake3_final(&ctx, (unsigned char *)crypt_out[index]);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (*(uint32_t *)binary == crypt_out[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_rawBLAKE3 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD,
		{ NULL},
		{ FORMAT_TAG},
		blake3_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
		{ NULL},
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif                          /* plugin stanza */
