#include "manifest.h"
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DUP(s) ((s) ? strdup(s) : NULL)

/* ------------------------------------------------------------------------ */
manifest_t *manifest_load(const char *path) {
	FILE *fp = fopen(path, "r");
	if (!fp)
		return NULL;

	fseek(fp, 0, SEEK_END);
	long len = ftell(fp);
	rewind(fp);

	char *data = malloc(len + 1);
	if (!data) {
		fclose(fp);
		return NULL;
	}
	fread(data, 1, len, fp);
	data[len] = '\0';
	fclose(fp);

	cJSON *root = cJSON_Parse(data);
	free(data);
	if (!root)
		return NULL;

	manifest_t *m = calloc(1, sizeof(manifest_t));
	if (!m) {
		cJSON_Delete(root);
		return NULL;
	}

	m->version = DUP(cJSON_GetObjectItem(root, "version")->valuestring);
	m->created = DUP(cJSON_GetObjectItem(root, "created")->valuestring);
	m->target = DUP(cJSON_GetObjectItem(root, "target")->valuestring);
	m->update_type = DUP(cJSON_GetObjectItem(root, "update_type")->valuestring);

	

	cJSON *files = cJSON_GetObjectItem(root, "files");
	if (files && cJSON_GetArraySize(files) > 0) {
		cJSON *file = cJSON_GetArrayItem(files, 0);
		m->filename = DUP(
		    cJSON_GetObjectItem(file, "filename")->valuestring);
		m->sha256 = DUP(
		    cJSON_GetObjectItem(file, "sha256")->valuestring);
		m->url = DUP(cJSON_GetObjectItem(file, "url")->valuestring);
		m->size = cJSON_GetObjectItem(file, "size")->valuedouble;
	}

	cJSON_Delete(root);
	return m;
}

/* ------------------------------------------------------------------------ */
void manifest_free(manifest_t *m) {
	if (!m)
		return;
	free(m->version);
	free(m->created);
	free(m->target);
	free(m->update_type);
	free(m->filename);
	free(m->sha256);
	free(m->url);
	free(m);
}

/* ------------------------------------------------------------------------ */
void manifest_print(const manifest_t *m) {
	if (!m)
		return;
	printf("Manifest:\n");
	printf("  version:  %s\n", m->version);
	printf("  created:  %s\n", m->created);
	printf("  target:   %s\n", m->target);
	printf("  type:	    %s\n", m->update_type);
	printf("  file:     %s\n", m->filename);
	printf("  url:      %s\n", m->url);
	printf("  sha256:   %s\n", m->sha256);
	printf("  size:     %ld\n", m->size);
}
