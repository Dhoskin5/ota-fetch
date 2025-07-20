#include "ota_fetch.h"
#include "manifest.h"
#include "verify_libcrypto.h"
#include "hash.h"
#include <curl/curl.h>
#include <errno.h>
#include <openssl/sha.h>
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
static int fetch_file(const char *url, const char *dest_path,
		      const struct ota_config *cfg) {
	CURL *curl = curl_easy_init();
	if (!curl) {
		fprintf(stderr, "Failed to initialize libcurl\n");
		return 1;
	}

	struct memory_buffer buf = {0};

	curl_easy_setopt(curl, CURLOPT_URL, url);
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
		fprintf(stderr, "curl error fetching %s: %s\n", url,
			curl_easy_strerror(res));

		long verify_result = 0;
		curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &verify_result);
		fprintf(stderr, "SSL verify result: %ld\n", verify_result);

		curl_easy_cleanup(curl);
		free(buf.data);
		return 2;
	}

	curl_easy_cleanup(curl);

	// Ensure directory exists
	char dir[512];
	strncpy(dir, dest_path, sizeof(dir));
	char *slash = strrchr(dir, '/');
	if (slash) {
		*slash = '\0';
		mkdir_p(dir, 0755);
	}

	FILE *fp = fopen(dest_path, "wb");
	if (!fp) {
		fprintf(stderr, "Failed to write %s: %s\n", dest_path,
			strerror(errno));
		free(buf.data);
		return 3;
	}
	fwrite(buf.data, 1, buf.size, fp);
	fclose(fp);
	free(buf.data);

	printf("%s saved to: %s\n", url, dest_path);
	return 0;
}

/* ------------------------------------------------------------------------ */
static int fetch_manifest(const struct ota_config *cfg) {
	char manifest_url[512], sig_url[512], cert_url[512];
	char manifest_path[512], sig_path[512], cert_path[512];

	snprintf(manifest_url, sizeof(manifest_url), "%s/manifest.json",
		 cfg->server_url);
	snprintf(sig_url, sizeof(sig_url), "%s/manifest.json.sig",
		 cfg->server_url);
	snprintf(cert_url, sizeof(cert_url), "%s/signer.crt",
		 cfg->server_url);

	snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json",
		 cfg->inbox_manifest_dir);
	snprintf(sig_path, sizeof(sig_path), "%s/manifest.json.sig",
		 cfg->inbox_manifest_dir);
	snprintf(cert_path, sizeof(cert_path), "%s/signer.crt",
		 cfg->inbox_manifest_dir);

	int rc1 = fetch_file(manifest_url, manifest_path, cfg);
	int rc2 = fetch_file(sig_url, sig_path, cfg);
	int rc3 = fetch_file(cert_url, cert_path, cfg);

	if (rc1)
		fprintf(stderr, "Failed to fetch manifest.json\n");
	if (rc2)
		fprintf(stderr, "Failed to fetch manifest.json.sig\n");
	if (rc3)
		fprintf(stderr, "Failed to fetch signer.crt\n");

	return rc1 || rc2 || rc3;
}

/* ------------------------------------------------------------------------ */
bool manifests_equal(const char *path1, const char *path2) {
    // Use your existing SHA256 hashing function
    uint8_t hash1[32], hash2[32];
    if (sha256sum_file(path1, hash1) != 0 || sha256sum_file(path2, hash2) != 0)
        return false; // One missing? Not equal!
    return memcmp(hash1, hash2, 32) == 0;
}

/* ------------------------------------------------------------------------ */
static int compare_manifest(const struct ota_config *cfg) {
	char inbox_path[512], current_path[512];
	snprintf(inbox_path, sizeof(inbox_path), "%s/manifest.json",
		 cfg->inbox_manifest_dir);
	snprintf(current_path, sizeof(current_path), "%s/manifest.json",
		 cfg->current_manifest_dir);

	int result = 0;
	if (!manifests_equal(current_path, inbox_path)) {
		printf("No current manifest found. Update required.\n");
		result = 1;
	} else {
		printf("Manifest matches. No update needed.\n");
		result = 0;
	}

	return result;
}

/* ------------------------------------------------------------------------ */
static int move_completed_manifest(const struct ota_config *cfg) {
    char inbox_path[512], current_path[512];

    // Source: inbox manifest
    snprintf(inbox_path, sizeof(inbox_path), "%s/manifest.json", cfg->inbox_manifest_dir);

    // Destination: current manifest
    snprintf(current_path, sizeof(current_path), "%s/manifest.json", cfg->current_manifest_dir);

    // Ensure destination directory exists
    mkdir_p(cfg->current_manifest_dir, 0755);

    // Remove existing destination file, if any
    unlink(current_path);

    // Move (rename) the file
    if (rename(inbox_path, current_path) != 0) {
        fprintf(stderr, "Failed to move manifest from %s to %s: %s\n",
            inbox_path, current_path, strerror(errno));
        return -1;
    }

    printf("Moved manifest: %s → %s\n", inbox_path, current_path);
    return 0;
}

/* ------------------------------------------------------------------------ */
static int fetch_payload(const struct ota_config *cfg) {
	char inbox_path[512];
	snprintf(inbox_path, sizeof(inbox_path), "%s/manifest.json",
		 cfg->inbox_manifest_dir);

	manifest_t *inbox = manifest_load(inbox_path);
	if (!inbox) {
		fprintf(stderr, "Failed to load inbox manifest\n");
		return -1;
	}

	CURL *curl = curl_easy_init();
	if (!curl) {
		fprintf(stderr, "Failed to initialize libcurl\n");
		return -2;
	}

	struct memory_buffer buf = {0};

	curl_easy_setopt(curl, CURLOPT_URL, inbox->url);
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
		return -3;
	}

	curl_easy_cleanup(curl);

	// Ensure inbox dir exists
	mkdir_p(cfg->inbox_manifest_dir, 0755);

	// Write payload file
	char payload_path[512];
	snprintf(payload_path, sizeof(payload_path), "%s/%s",
		 cfg->inbox_manifest_dir, inbox->filename);

	FILE *fp = fopen(payload_path, "wb");
	if (!fp) {
		fprintf(stderr, "Failed to write payload: %s\n",
			strerror(errno));
		free(buf.data);
		return -4;
	}

	fwrite(buf.data, 1, buf.size, fp);
	fclose(fp);
	free(buf.data);

	printf("Payload saved to: %s\n", payload_path);

	return 0;
}

/* ------------------------------------------------------------------------ */
static int validate_payload(const struct ota_config *cfg) {
	char manifest_path[512], payload_path[512];
	snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json",
		 cfg->inbox_manifest_dir);
	snprintf(payload_path, sizeof(payload_path), "%s/%s",
		 cfg->inbox_manifest_dir, ""); // Will append actual filename

	manifest_t *m = manifest_load(manifest_path);
	if (!m) {
		fprintf(stderr, "Failed to load manifest for validation\n");
		return -1;
	}

	snprintf(payload_path, sizeof(payload_path), "%s/%s",
		 cfg->inbox_manifest_dir, m->filename);

	FILE *fp = fopen(payload_path, "rb");
	if (!fp) {
		fprintf(stderr, "Failed to open payload for hashing: %s\n",
			payload_path);
		manifest_free(m);
		return -2;
	}

	unsigned char hash[SHA256_DIGEST_LENGTH];
	char hash_string[SHA256_DIGEST_LENGTH * 2 + 1];
	hash_string[sizeof(hash_string) - 1] = '\0';

	SHA256_CTX sha256;
	SHA256_Init(&sha256);

	unsigned char buf[4096];
	size_t read_len;
	while ((read_len = fread(buf, 1, sizeof(buf), fp)) > 0) {
		SHA256_Update(&sha256, buf, read_len);
	}
	fclose(fp);
	SHA256_Final(hash, &sha256);

	for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
		snprintf(&hash_string[i * 2], 3, "%02x", hash[i]);
	}

	if (strcmp(hash_string, m->sha256) != 0) {
		fprintf(stderr, "SHA256 mismatch\n");
		fprintf(stderr, "Expected: %s\n", m->sha256);
		fprintf(stderr, "Actual:   %s\n", hash_string);
		manifest_free(m);
		return 1;
	}

	printf("Payload SHA256 validated successfully.\n");
	manifest_free(m);
	return 0;
}

/* ------------------------------------------------------------------------ */
static int apply_payload(const struct ota_config *cfg) {

	char manifest_path[512], payload_path[512];
	snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json",
		 cfg->inbox_manifest_dir);
	snprintf(payload_path, sizeof(payload_path), "%s/%s",
		 cfg->inbox_manifest_dir, ""); // Will append actual filename

	manifest_t *m = manifest_load(manifest_path);
	if (!m) {
		fprintf(stderr, "Failed to load manifest for validation\n");
		return -1;
	}

	if (strcmp(m->update_type, "rauc_bundle_test") == 0) {
		printf("[TEST] Simulating RAUC bundle update for testing.\n");

		move_completed_manifest(cfg);
		return 0;
	} else if (strcmp(m->update_type, "rauc_bundle") == 0) {
		// Real RAUC integration (e.g. call rauc CLI)
	}
	// ... handle other types as needed

	return 0;
}



/* ------------------------------------------------------------------------ */
int ota_fetch_run(bool daemon_mode, const struct ota_config *cfg) {
	int attempt = 0;

	do {
		int rc = fetch_manifest(cfg);
		if (rc == 0) {
			// --------- New: Manifest Signature Verification
			// -------------
			char manifest_path[512], sig_path[512], cert_path[512];
			snprintf(manifest_path, sizeof(manifest_path),
				 "%s/manifest.json", cfg->inbox_manifest_dir);
			snprintf(sig_path, sizeof(sig_path),
				 "%s/manifest.json.sig",
				 cfg->inbox_manifest_dir);
			snprintf(cert_path, sizeof(cert_path),
				 "%s/signer.crt", cfg->inbox_manifest_dir);

			char errbuf[VERIFY_ERRBUF_LEN] = {0};
			verify_result_t vres = verify_signature_with_cert(
			    manifest_path, sig_path, cert_path,
			    cfg->root_ca_path, errbuf, sizeof(errbuf));

			if (vres != VERIFY_OK) {
				fprintf(stderr,
					"[OTA] Manifest signature validation "
					"failed: %s\n",
					errbuf);
				return 10;
			}
			printf("[OTA] Manifest signature validation OK.\n");

			// -----------------------------------------------------------

			int cmp = compare_manifest(cfg);

			if (cmp < 0) {
				fprintf(stderr, "Error comparing manifests\n");
				return cmp;
			} else if (cmp > 0) {
				printf("Update available. Proceeding with "
				       "update...\n");

				if (fetch_payload(cfg) != 0)
					return 3;
				if (validate_payload(cfg) != 0)
					return 4;
				if (apply_payload(cfg) != 0)
					return 5;
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
