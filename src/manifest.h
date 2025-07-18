#ifndef OTA_FETCH_MANIFEST_H
#define OTA_FETCH_MANIFEST_H

#include <stdbool.h>

typedef struct {
	char *version;
	char *created;
	char *update_type;
	char *target;
	char *filename;
	char *sha256;
	char *url;
	long size;
} manifest_t;

manifest_t *manifest_load(const char *path);
void manifest_free(manifest_t *manifest);
void manifest_print(const manifest_t *m);

#endif // OTA_FETCH_MANIFEST_H
