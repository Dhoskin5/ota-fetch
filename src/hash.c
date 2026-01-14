#include "hash.h"

#include <openssl/sha.h>
#include <stdio.h>

/* ------------------------------------------------------------------------ */
int sha256sum_file(const char *path, uint8_t *digest_out) {
	if (!path || !digest_out)
		return SHA256SUM_EINVAL;

	FILE *fp = fopen(path, "rb");
	if (!fp)
		return SHA256SUM_EOPEN;

	SHA256_CTX ctx;
	if (SHA256_Init(&ctx) != 1) {
		fclose(fp);
		return SHA256SUM_EINIT;
	}

	unsigned char buf[4096];
	size_t n;
	while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
		if (SHA256_Update(&ctx, buf, n) != 1) {
			fclose(fp);
			return SHA256SUM_EUPDATE;
		}
	}

	if (ferror(fp)) {
		fclose(fp);
		return SHA256SUM_EREAD;
	}

	fclose(fp);

	if (SHA256_Final(digest_out, &ctx) != 1)
		return SHA256SUM_EFINAL;

	return SHA256SUM_OK;
}

/* ------------------------------------------------------------------------ */
int hex_encode(char *out, size_t out_sz, const uint8_t *in, size_t len) {
	if (!out || !in)
		return -1;
	if (out_sz < (len * 2 + 1))
		return -2;

	static const char hexd[16] = "0123456789abcdef";
	for (size_t i = 0; i < len; ++i) {
		out[i * 2 + 0] = hexd[(in[i] >> 4) & 0xF];
		out[i * 2 + 1] = hexd[in[i] & 0xF];
	}
	out[len * 2] = '\0';
	return 0;
}

/* ------------------------------------------------------------------------ */
const char *sha256_hex(const uint8_t digest[SHA256_DIGEST_LEN]) {
	if (!digest)
		return "(null)";

		/* Use Thread local storage when available;
		 * Fall back to a single static* buffer. */
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
	enum { RING_SLOTS = 4 };
	static _Thread_local char ring[RING_SLOTS][SHA256_DIGEST_LEN * 2 + 1];
	static _Thread_local unsigned idx;
	char *out = ring[idx++ % RING_SLOTS];
#else
	static char out[SHA256_DIGEST_LEN * 2 + 1];
#endif

	(void)hex_encode(out, SHA256_DIGEST_LEN * 2 + 1, digest,
			 SHA256_DIGEST_LEN);
	return out;
}
