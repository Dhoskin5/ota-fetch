#ifndef OTA_FETCH_CONFIG_H
#define OTA_FETCH_CONFIG_H

#include <stdbool.h>

struct ota_config {
	// Network settings
	char *server_url;
	char *ca_cert;
	char *client_cert;
	char *client_key;
	int connect_timeout;
	int retry_attempts;

	// System paths
	char *inbox_manfiest_dir;
	char *current_manifest_dir;
	char *log_file;
};

// Load config from file (default: /etc/ota-fetch/ota-fetch.conf)
int config_load(const char *filename, struct ota_config *config);

// Free all dynamically allocated strings
void config_free(struct ota_config *config);

// Optionally print config (for debug)
void config_print(const struct ota_config *config);

#endif // OTA_FETCH_CONFIG_H
