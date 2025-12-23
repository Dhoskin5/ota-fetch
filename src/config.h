/**
 * @file config.h
 * @brief OTA Fetcher configuration structure and helpers.
 *
 * Defines the OTA config structure and functions for loading, freeing,
 * and printing OTA update client configuration. Configuration includes
 * network credentials, system paths, and update policies.
 *
 * @author Dustin Hoskins
 * @date 2025
 */

#ifndef OTA_FETCH_CONFIG_H
#define OTA_FETCH_CONFIG_H

#include <stdbool.h>

/**
 * @brief OTA Fetcher configuration settings.
 *
 * Holds server URLs, certificates, credentials, timeouts, and paths
 * used for OTA update fetching and validation.
 */
struct ota_config {
	/**< OTA server base URL (e.g., "https://updates.example.com") */
	char *server_url;
	/**< Path to CA certificate for TLS validation */
	char *ca_cert;
	/**< Path to client certificate for mTLS (or NULL) */
	char *client_cert;
	/**< Path to client private key for mTLS (or NULL) */
	char *client_key;
	/**< HTTP(S) connect timeout, in seconds */
	int connect_timeout;
	/**< Number of download retry attempts on failure */
	int retry_attempts;
	/**< Directory to store inbox (pending) manifests and payloads */
	char *inbox_manifest_dir;
	/**< Directory for current/active manifest and state */
	char *current_manifest_dir;
	/**< Path to root CA cert for manifest signature validation */
	char *root_ca_path;
	/**< Path to log file (or NULL for stderr) */
	char *log_file;
	/**< Device ID for release */
	char *device_id;
};

/**
 * @brief Load OTA config from file.
 *
 * Loads OTA configuration from a file (default: /etc/ota-fetch/ota-fetch.conf).
 *
 * @param filename Path to config file.
 * @param config   Pointer to ota_config struct to populate.
 * @return 0 on success, nonzero on error.
 *
 * @note Dynamically allocates strings in @p config; must call config_free().
 */
int config_load(const char *filename, struct ota_config *config);

/**
 * @brief Free all dynamically allocated strings in OTA config.
 *
 * @param config Pointer to ota_config struct to free.
 */
void config_free(struct ota_config *config);

/**
 * @brief Print OTA config for debugging/logging.
 *
 * Outputs all fields and values to stderr for human inspection.
 *
 * @param config Pointer to ota_config struct to print.
 */
void config_print(const struct ota_config *config);

#endif // OTA_FETCH_CONFIG_H
