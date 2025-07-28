#ifndef HASH_H
#define HASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// SHA256 output is 32 bytes
#define SHA256_DIGEST_LEN 32

// Returns 0 on success, nonzero on error
int sha256sum_file(const char *path, uint8_t *digest_out);
void print_sha256sum(const char *label, const uint8_t *hash, size_t len);
#ifdef __cplusplus
}
#endif

#endif // HASH_H
