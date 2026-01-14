#include "config.h"
#include "ini.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DUP(s) ((s) ? strdup(s) : NULL)

/* ------------------------------------------------------------------------ */
int config_handler(void *user, const char *section, const char *name,
		   const char *value) {
	struct ota_config *cfg = (struct ota_config *)user;

#define MATCH(sec, key) strcmp(section, sec) == 0 && strcmp(name, key) == 0

	if (MATCH("network", "server_url")) {
		cfg->server_url = DUP(value);
	} else if (MATCH("network", "ca_cert")) {
		cfg->ca_cert = DUP(value);
	} else if (MATCH("network", "client_cert")) {
		cfg->client_cert = DUP(value);
	} else if (MATCH("network", "client_key")) {
		cfg->client_key = DUP(value);
	} else if (MATCH("network", "connect_timeout")) {
		cfg->connect_timeout = atoi(value);
	} else if (MATCH("network", "transfer_timeout")) {
		cfg->transfer_timeout = atoi(value);
	} else if (MATCH("network", "retry_attempts")) {
		cfg->retry_attempts = atoi(value);
	} else if (MATCH("system", "update_interval_sec")) {
		cfg->update_interval_sec = atoi(value);
	} else if (MATCH("system", "inbox_manifest_dir")) {
		cfg->inbox_manifest_dir = DUP(value);
	} else if (MATCH("system", "current_manifest_dir")) {
		cfg->current_manifest_dir = DUP(value);
	} else if (MATCH("system", "root_ca_path")) {
		cfg->root_ca_path = DUP(value);
	} else if (MATCH("system", "log_file")) {
		cfg->log_file = DUP(value);
	} else if (MATCH("system", "device_id")) {
		cfg->device_id = DUP(value);
	}

	return 1; // success
}

/* ------------------------------------------------------------------------ */
int config_load(const char *filename, struct ota_config *config) {
	memset(config, 0, sizeof(*config));
	return ini_parse(filename, config_handler, config);
}

/* ------------------------------------------------------------------------ */
void config_free(struct ota_config *config) {
	free(config->server_url);
	free(config->ca_cert);
	free(config->client_cert);
	free(config->client_key);
	free(config->inbox_manifest_dir);
	free(config->current_manifest_dir);
	free(config->root_ca_path);
	free(config->log_file);
	free(config->device_id);
}

/* ------------------------------------------------------------------------ */
void config_print(const struct ota_config *config) {
	printf("Config:\n");
	printf("server_url          = %s\n", config->server_url);
	printf("ca_cert             = %s\n", config->ca_cert);
	printf("client_cert         = %s\n", config->client_cert);
	printf("client_key          = %s\n", config->client_key);
	printf("connect_timeout     = %d\n", config->connect_timeout);
	printf("transfer_timeout    = %d\n", config->transfer_timeout);
	printf("retry_attempts      = %d\n", config->retry_attempts);
	printf("update_interval_sec = %d\n", config->update_interval_sec);
	printf("inbox_manifest_dir  = %s\n", config->inbox_manifest_dir);
	printf("current_manfiest_dir= %s\n", config->current_manifest_dir);
	printf("root_ca_path	    = %s\n", config->root_ca_path);
	printf("log_file            = %s\n", config->log_file);
	printf("device_id           = %s\n", config->device_id);
}
