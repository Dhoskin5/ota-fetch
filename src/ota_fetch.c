/**
 * @file ota_fetch.c
 * @brief OTA Fetcher core logic for secure embedded update downloads.
 *
 * This file implements the main OTA fetch and update loop for embedded Linux.
 * Features:
 *   - Secure HTTPS/mTLS downloads via libcurl
 *   - Manifest signature verification (OpenSSL)
 *   - Payload integrity validation (SHA-256)
 *   - Integration with RAUC and other update frameworks
 *   - One-shot and daemon (periodic) modes
 *
 * Designed for embedded edge systems and modularity.
 *
 * @author Dustin Hoskins
 * @date 2025
 */

#include "ota_fetch.h"
#include "hash.h"
#include "logging.h"
#include "manifest.h"
#include "verify_libcrypto.h"
#include <curl/curl.h>
#include <errno.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/**
 * @def FETCH_INTERVAL_SEC
 * @brief Number of seconds between update checks in daemon mode.
 */
#define FETCH_INTERVAL_SEC 3600

/**
 * @def RETRY_DELAY
 * @brief Number of seconds to wait before retrying a failed fetch.
 */
#define RETRY_DELAY 5

/**
 * @brief OTA context state.
 *
 * Holds paths, manifests, and configuration for a single OTA operation.
 */
typedef struct ota_ctx {
	struct ota_config config;
	manifest_t *current_manifest;
	manifest_t *inbox_manifest;
	char *current_manifest_path;
	char *inbox_manifest_path;
	char *inbox_sig_path;
	char *inbox_cert_path;
	char *payload_path;
} ota_ctx_t;

/**
 * @brief In-memory data buffer for HTTP(S) downloads.
 */
struct memory_buffer {
	char *data;
	size_t size;
};

/**
 * @brief Result codes for file equality checks.
 */
typedef enum {
	FILES_EQ = 0,  /**< Files are equal */
	FILES_NEQ = 1, /**< Files are not equal */
	FILES_ERR = -1 /**< Error occurred */
} files_equal_result_t;

/**
 * @brief libcurl write callback for in-memory downloads.
 *
 * @param contents Data pointer from libcurl.
 * @param size     Size of each item.
 * @param nmemb    Number of items.
 * @param userp    User data pointer (memory_buffer).
 * @return Number of bytes written.
 */
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

/**
 * @brief Build a path by joining a directory and a filename.
 *
 * @param dir  Directory path.
 * @param file Filename.
 * @return Newly allocated path string (must be freed), or NULL on error.
 */
static char *build_path(const char *dir, const char *file) {
	if (!dir || !file) {
		return NULL; // Prevent undefined behavior
	}

	size_t len = strlen(dir) + strlen(file) + 2; // '/' + '\0'
	char *result = malloc(len);
	if (!result) {
		return NULL; // Allocation failed
	}

	snprintf(result, len, "%s/%s", dir, file);
	return result;
}

/**
 * mkdir_p - Recursively create directories like "mkdir -p".
 * @path: Directory path to create.
 * @mode: Permissions to use for any newly created directories.
 *
 * Returns 0 on success, or 1 on error (sets errno).
 *
 * Notes:
 *   - This function handles absolute and relative paths.
 *   - Intermediate directories are created as needed.
 *   - Returns 0 if the path already exists as a directory.
 */
static int mkdir_p(const char *path, mode_t mode) {
	char temp[PATH_MAX];
	size_t len;
	char *p = NULL;

	if (!path || !*path) {
		errno = EINVAL;
		return -1;
	}

	len = strnlen(path, PATH_MAX);
	if (len == 0 || len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		return -1;
	}

	strncpy(temp, path, sizeof(temp));
	temp[len] = '\0';

	// Remove trailing slash (except root)
	if (len > 1 && temp[len - 1] == '/')
		temp[len - 1] = '\0';

	for (p = temp + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(temp, mode) != 0) {
				if (errno != EEXIST) {
					return -1;
				}
			}
			*p = '/';
		}
	}
	if (mkdir(temp, mode) != 0) {
		if (errno != EEXIST) {
			return -1;
		}
	}
	return 0;
}

/**
 * @brief Compare two files by SHA256 hash.
 *
 * @param path1 First file path.
 * @param path2 Second file path.
 * @return FILES_EQ if equal, FILES_NEQ if not, FILES_ERR on error.
 */
static int files_equal(const char *path1, const char *path2) {
	uint8_t hash1[32], hash2[32];
	int irethash1;
	int irethash2;

	irethash1 = sha256sum_file(path1, hash1);
	irethash2 = sha256sum_file(path2, hash2);

	LOG_INFO("ihash1ret =%d", irethash1);
	LOG_INFO("ihash2ret =%d", irethash2);

	if ((irethash1 != 0) || (irethash2 != 0)) {
		return FILES_ERR;
	}

	print_sha256sum("Hash1", hash1, 32);
	print_sha256sum("Hash2", hash2, 32);

	return (memcmp(hash1, hash2, 32) == 0) ? FILES_EQ : FILES_NEQ;
}

/**
 * @brief Check if a file exists.
 *
 * @param path File path.
 * @return 1 if file exists, 0 otherwise.
 */
static int file_exists(const char *path) {
	struct stat st;
	return (path && stat(path, &st) == 0);
}

/**
 * @brief Download a file from a URL to a local path using HTTPS/mTLS.
 *
 * @param url       Remote file URL.
 * @param dest_path Local destination path.
 * @param cfg       OTA config (includes certs/keys).
 * @return 0 on success, -1 on error.
 */
static int fetch_file(const char *url, const char *dest_path,
		      const struct ota_config *cfg) {
	CURL *curl = curl_easy_init();
	if (!curl) {
		LOG_ERROR("Failed to initialize libcurl");
		return -1;
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
		LOG_ERROR("curl error fetching %s: %s", url,
			  curl_easy_strerror(res));

		long verify_result = 0;
		curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT,
				  &verify_result);
		LOG_ERROR("SSL verify result: %ld", verify_result);

		curl_easy_cleanup(curl);
		free(buf.data);
		return -1;
	}

	curl_easy_cleanup(curl);

	// Ensure directory exists
	char dir[PATH_MAX];
	strncpy(dir, dest_path, sizeof(dir));
	char *slash = strrchr(dir, '/');
	if (slash) {
		*slash = '\0';
		if (mkdir_p(dir, 0755) != 0) {
			LOG_ERROR("Failed to create directory: %s",
				  strerror(errno));
		}
	}

	FILE *fp = fopen(dest_path, "wb");
	if (!fp) {
		LOG_ERROR("Failed to write %s: %s", dest_path, strerror(errno));
		free(buf.data);
		return -1;
	}
	fwrite(buf.data, 1, buf.size, fp);
	fclose(fp);
	free(buf.data);

	LOG_INFO("%s saved to: %s", url, dest_path);
	return 0;
}

/**
 * @brief Initialize OTA context (paths, config, manifests).
 *
 * @param ctx OTA context struct to initialize.
 * @param cfg OTA configuration.
 * @note ctx->payload_path is allocated in this function and freed by
 * ota_ctx_free().
 * @return 0 on success, -1 on error.
 */
static int ota_ctx_init(ota_ctx_t *ctx, const struct ota_config *cfg) {
	int iRet = 0;
	memset(ctx, 0, sizeof(*ctx));
	memcpy(&ctx->config, cfg, sizeof(*cfg));

	// Current Manifest Path
	ctx->current_manifest_path = build_path(cfg->current_manifest_dir,
						"manifest.json");
	if (ctx->current_manifest_path == NULL) {
		LOG_ERROR("Failed to create current manifest path");
		iRet = -1;
	}

	// Inbox Manifest Path
	ctx->inbox_manifest_path = build_path(cfg->inbox_manifest_dir,
					      "manifest.json");
	if (ctx->inbox_manifest_path == NULL) {
		LOG_ERROR("Failed to create inbox manifest path");
		iRet = -1;
	}

	// Inbox Manifest Sig Path
	ctx->inbox_sig_path = build_path(cfg->inbox_manifest_dir,
					 "manifest.json.sig");
	if (ctx->inbox_sig_path == NULL) {
		LOG_ERROR("Failed to create inbox manifest sig path");
		iRet = -1;
	}

	// Inbox Signer Cert Path
	ctx->inbox_cert_path = build_path(cfg->inbox_manifest_dir,
					  "signer.crt");
	if (ctx->inbox_cert_path == NULL) {
		LOG_ERROR("Failed to create inbox cert path");
		iRet = -1;
	}

	// Clean inbox

	return iRet;
}

/**
 * @brief Free all memory/resources in OTA context.
 *
 * @param ctx OTA context to clean up.
 */
static void ota_ctx_free(ota_ctx_t *ctx) {

	if (ctx->inbox_manifest != NULL) {
		manifest_free(ctx->inbox_manifest);
		ctx->inbox_manifest = NULL;
	}

	if (ctx->current_manifest != NULL) {
		manifest_free(ctx->current_manifest);
		ctx->current_manifest = NULL;
	}

	if (ctx->current_manifest_path != NULL) {
		free(ctx->current_manifest_path);
		ctx->current_manifest_path = NULL;
	}

	if (ctx->inbox_manifest_path != NULL) {
		free(ctx->inbox_manifest_path);
		ctx->inbox_manifest_path = NULL;
	}

	if (ctx->inbox_sig_path != NULL) {
		free(ctx->inbox_sig_path);
		ctx->inbox_sig_path = NULL;
	}

	if (ctx->inbox_cert_path != NULL) {
		free(ctx->inbox_cert_path);
		ctx->inbox_cert_path = NULL;
	}

	if (ctx->payload_path != NULL) {
		free(ctx->payload_path);
		ctx->payload_path = NULL;
	}
}

/**
 * @brief Download new manifest, signature, and signer cert from server.
 *
 * @param ctx OTA context.
 * @return 0 on success, non-zero on error.
 */
static int fetch_new_manifest(ota_ctx_t *ctx) {

	char *manifest_url = NULL;
	char *sig_url = NULL;
	char *cert_url = NULL;

	manifest_url = build_path(ctx->config.server_url, "manifest.json");
	sig_url = build_path(ctx->config.server_url, "manifest.json.sig");
	cert_url = build_path(ctx->config.server_url, "signer.crt");

	int rc1 = fetch_file(manifest_url, ctx->inbox_manifest_path,
			     &ctx->config);
	int rc2 = fetch_file(sig_url, ctx->inbox_sig_path, &ctx->config);
	int rc3 = fetch_file(cert_url, ctx->inbox_cert_path, &ctx->config);

	if (rc1)
		LOG_ERROR("Failed to fetch manifest.json");
	if (rc2)
		LOG_ERROR("Failed to fetch manifest.json.sig");
	if (rc3)
		LOG_ERROR("Failed to fetch signer.crt");

	if (manifest_url != NULL) {
		free(manifest_url);
	}
	if (sig_url != NULL) {
		free(sig_url);
	}
	if (cert_url != NULL) {
		free(cert_url);
	}

	return rc1 || rc2 || rc3;
}

/**
 * @brief Verify new manifest signature with OpenSSL and provided certs.
 *
 * @param ctx OTA context.
 * @return 0 if valid, -1 on error.
 */
static int validate_new_manifest(ota_ctx_t *ctx) {
	char errbuf[VERIFY_ERRBUF_LEN] = {0};
	verify_result_t vres = verify_signature_with_cert(
	    ctx->inbox_manifest_path, ctx->inbox_sig_path, ctx->inbox_cert_path,
	    ctx->config.root_ca_path, errbuf, sizeof(errbuf));

	if (vres != VERIFY_OK) {
		LOG_ERROR("Manifest signature validation "
			  "failed: %s",
			  errbuf);
		return -1;
	}
	LOG_INFO("Manifest signature validation OK.");
	return 0;
}

/**
 * @brief Compare new and current manifests for changes.
 *
 * @param ctx OTA context.
 * @return 0 if same, 1 if update required, -1 on error.
 */
static int compare_manifests(ota_ctx_t *ctx) {

	if (!file_exists(ctx->current_manifest_path)) {
		LOG_WARN("No current manifest found: Update required");
		return 1; // Update required
	}
	if (!file_exists(ctx->inbox_manifest_path)) {
		LOG_ERROR("No inbox manifest to compare: Aborting");
		return -1; // Could not compare
	}

	int ret = files_equal(ctx->current_manifest_path,
			      ctx->inbox_manifest_path);
	if (ret == 0) {
		LOG_INFO("Manifest matches: System up to date");
	} else if (ret == 1) {
		LOG_INFO("Manifest mismatch: Update required");
	} else {
		LOG_ERROR("Error comparing manifests");
	}

	return ret;
}

/**
 * @brief Move new inbox manifest into place as current manifest.
 *
 * @param ctx OTA context.
 * @return 0 on success, -1 on error.
 */
static int make_new_manifest_current(ota_ctx_t *ctx) {

	// Ensure destination directory exists
	if (mkdir_p(ctx->config.current_manifest_dir, 0755) != 0) {
		LOG_ERROR("Failed to create directory: %s", strerror(errno));
	}

	// Remove existing destination file, if any
	unlink(ctx->current_manifest_path);

	// Move (rename) the file
	if (rename(ctx->inbox_manifest_path, ctx->current_manifest_path) != 0) {
		LOG_ERROR("Failed to move manifest from %s to %s: %s",
			  ctx->inbox_manifest_path, ctx->current_manifest_path,
			  strerror(errno));
		return -1;
	}

	LOG_INFO("Moved manifest: %s → %s", ctx->inbox_manifest_path,
		 ctx->current_manifest_path);
	return 0;
}

/**
 * @brief Download OTA payload file specified in the manifest.
 *
 * @param ctx OTA context.
 * @return 0 on success, -1 on error.
 */
static int fetch_payload(ota_ctx_t *ctx) {
	int ret;

	// Assemble path where payload will be downloaded
	// Note: ctx->payload_path is freed in ota_ctx_free. Do not call
	// fetch_payload() multiple times per ctx lifecycle.
	ctx->payload_path = build_path(ctx->config.inbox_manifest_dir,
				       ctx->inbox_manifest->filename);

	// Fetch payload from URL provided in manifest
	ret = fetch_file(ctx->inbox_manifest->url, ctx->payload_path,
			 &ctx->config);

	if (ret == 0) {
		LOG_INFO("Payload downloaded successful: %s",
			 ctx->payload_path);
	} else {
		LOG_ERROR("Payload downloaded failed");
	}

	return ret;
}

/**
 * @brief Validate downloaded payload by SHA256 hash.
 *
 * @param ctx OTA context.
 * @return 0 if valid, -1 on mismatch or error.
 */
static int validate_payload(ota_ctx_t *ctx) {

	FILE *fp = fopen(ctx->payload_path, "rb");
	if (!fp) {
		LOG_ERROR("Failed to open payload for hashing: %s",
			  ctx->payload_path);
		return -1;
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

	if (strcmp(hash_string, ctx->inbox_manifest->sha256) != 0) {
		LOG_ERROR("SHA256 mismatch");
		LOG_ERROR("Expected: %s", ctx->inbox_manifest->sha256);
		LOG_ERROR("Actual:   %s", hash_string);
		return -1;
	}

	LOG_INFO("Payload SHA256 validated successfully.");
	return 0;
}

/**
 * @brief Apply the OTA update payload.
 *
 * Integrates with RAUC or simulates update for testing.
 *
 * @param ctx OTA context.
 * @return 0 on success, non-zero on error.
 */
static int apply_payload(ota_ctx_t *ctx) {

	LOG_INFO("Applying payload");

	if (strcmp(ctx->inbox_manifest->update_type, "rauc_bundle_test") == 0) {

		LOG_INFO("Simulating RAUC bundle update for testing");
		make_new_manifest_current(ctx);

	} else if (strcmp(ctx->inbox_manifest->update_type, "rauc_bundle") ==
		   0) {

		// Real RAUC integration (e.g. call rauc CLI)
		// TODO

	} else {
		// ... handle other types as needed
	}

	return 0;
}

/* ------------------------------------------------------------------------ */
int ota_fetch_run(bool daemon_mode, const struct ota_config *cfg) {
	int attempt = 0;
	int rc = 0;
	ota_ctx_t ctx;

	while (1) {
		rc = ota_ctx_init(&ctx, cfg);
		if (rc != 0)
			goto attempt_end;

		rc = fetch_new_manifest(&ctx);
		if (rc != 0)
			goto attempt_end;

		rc = validate_new_manifest(&ctx);
		if (rc != 0)
			goto attempt_end;

		rc = compare_manifests(&ctx);
		if ((rc == 0) && (!daemon_mode)) {
			// System up to data + one-shot, return
			ota_ctx_free(&ctx);
			return rc;
		}

		ctx.inbox_manifest = manifest_load(ctx.inbox_manifest_path);
		if (ctx.inbox_manifest == NULL) {
			LOG_ERROR("Failed to load new manifest");
			goto attempt_end;
		}

		rc = fetch_payload(&ctx);
		if (rc != 0)
			goto attempt_end;

		rc = validate_payload(&ctx);
		if (rc != 0)
			goto attempt_end;

		rc = apply_payload(&ctx);
		if ((rc == 0) && (!daemon_mode)) {
			// System up to data + one-shot, return
			ota_ctx_free(&ctx);
			return rc;
		}

	attempt_end:
		attempt++;
		ota_ctx_free(&ctx);

		if (daemon_mode) {
			// daemon mode
			sleep(FETCH_INTERVAL_SEC);
		} else {
			// one-shot mode
			if (attempt < cfg->retry_attempts) {
				sleep(RETRY_DELAY);
			} else {
				return rc;
			}
		}

		// TODO SIGTERM/SIGINT
	};

	return 0;
}
