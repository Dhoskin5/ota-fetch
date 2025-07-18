#include "hash.h"
#include <openssl/sha.h>
#include <stdio.h>

int sha256sum_file(const char *path, uint8_t *digest_out) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    unsigned char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        SHA256_Update(&ctx, buf, n);
    }
    fclose(fp);

    if (ferror(fp)) return -2;

    SHA256_Final(digest_out, &ctx);
    return 0;
}
