#include "ota_fetch.h"
#include "manifest.h"
#include <curl/curl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FETCH_INTERVAL_SEC 3600 // 1 hour loop in daemon mode

struct memory_buffer {
	char *data;
	size_t size;
};

/* ------------------------------------------------------------------------ */
int mkdir_p(const char *path, mode_t mode) {
	char tmp[512];
	char *p = NULL;
	size_t len;

	snprintf(tmp, sizeof(tmp), "%s", path);
	len = strlen(tmp);
	if (tmp[len - 1] == '/')
		tmp[len - 1] = 0;

	for (p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			mkdir(tmp, mode);
			*p = '/';
		}
	}
	return mkdir(tmp, mode);
}

/* ------------------------------------------------------------------------ */
static size_t write_callback(void *contents, size_t size, size_t nmemb,
			     void *userp) {
	size_t total_size = size * nmemb;
	struct memory_buffer *mem = (struct memory_buffer *)userp;

	char *ptr = realloc(mem->data, mem->size + total_size + 1);
	if (!ptr)
		return 0;

	mem->data = ptr;
	memcpy(&(mem->data[mem->size]), contents, total_size);
	mem->size += total_size;
	mem->data[mem->size] = 0;
	return total_size;
}

/* ------------------------------------------------------------------------ */
static int perform_fetch(const struct ota_config *cfg) {
	CURL *curl = curl_easy_init();
	if (!curl) {
		fprintf(stderr, "Failed to initialize libcurl\n");
		return 1;
	}

	struct memory_buffer buf = {0};

	curl_easy_setopt(curl, CURLOPT_URL, cfg->server_url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, cfg->connect_timeout);

	// mTLS setup
	curl_easy_setopt(curl, CURLOPT_SSLCERT, cfg->client_cert);
	curl_easy_setopt(curl, CURLOPT_SSLKEY, cfg->client_key);
	curl_easy_setopt(curl, CURLOPT_CAINFO, cfg->ca_cert);

	CURLcode res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "curl error: %s\n", curl_easy_strerror(res));
		curl_easy_cleanup(curl);
		free(buf.data);
		return 2;
	}

	curl_easy_cleanup(curl);

	// Ensure inbox dir exists
	mkdir_p(cfg->inbox_manfiest_dir, 0755);

	// Write manifest file
	char manifest_path[512];
	snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json",
		 cfg->inbox_manfiest_dir);

	FILE *fp = fopen(manifest_path, "w");
	if (!fp) {
		fprintf(stderr, "Failed to write manifest: %s\n",
			strerror(errno));
		free(buf.data);
		return 3;
	}
	fwrite(buf.data, 1, buf.size, fp);
	fclose(fp);
	free(buf.data);

	printf("Manifest saved to: %s\n", manifest_path);

	return 0;
}

/* ------------------------------------------------------------------------ */
static int perform_compare(const struct ota_config *cfg) {
	char inbox_path[512], current_path[512];
	snprintf(inbox_path, sizeof(inbox_path), "%s/manifest.json",
		 cfg->inbox_manfiest_dir);
	snprintf(current_path, sizeof(current_path), "%s/manifest.json",
		 cfg->current_manifest_dir);

	manifest_t *inbox = manifest_load(inbox_path);
	if (!inbox) {
		fprintf(stderr, "Failed to load inbox manifest\n");
		return -1;
	}

	manifest_t *current = manifest_load(current_path);

	int result = 0;
	if (!current) {
		printf("No current manifest found. Update required.\n");
		result = 1;
	} else if (!manifest_equal(current, inbox)) {
		printf("Manifest differs. Update required.\n");
		result = 1;
	} else {
		printf("Manifest matches. No update needed.\n");
		result = 0;
	}

	manifest_free(inbox);
	manifest_free(current);
	return result;
}

/* ------------------------------------------------------------------------ */
int ota_fetch_run(bool daemon_mode, const struct ota_config *cfg) {
	int attempt = 0;

	do {
		int rc = perform_fetch(cfg);
		if (rc == 0) {
			int cmp = perform_compare(cfg);

			if (cmp < 0) {
				fprintf(stderr, "Error comparing manifests\n");
				return cmp;
			} else if (cmp > 0) {
				printf("Update available. Proceeding with "
				       "update...\n");
				// Here you would trigger the update process
			} else {
				printf("System is up to date.\n");
			}

			attempt = 0;
		} else {
			attempt++;
		}

		if (!daemon_mode) {
			return rc;
		}

		sleep(FETCH_INTERVAL_SEC);
	} while (daemon_mode && attempt < cfg->retry_attempts);

	return 0;
}
