/**
 * @file main.c
 * @brief OTA Fetcher CLI entry point.
 *
 * Parses command-line arguments, loads configuration, and invokes
 * the main OTA fetch/update logic. Supports one-shot and periodic
 * (daemon_mode) operation without backgrounding the process.
 *
 * @author Dustin Hoskins
 * @date 2025
 */

#include "config.h"
#include "manifest.h"
#include "ota_fetch.h"
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * @brief Supported run modes for OTA fetcher.
 */
enum run_mode {
	MODE_ONESHOT, /**< Run once and exit */
	MODE_DAEMON   /**< Run periodically as a daemon */
};

/**
 * @brief Print usage/help text to stdout.
 *
 * @param progname Name of the executable (argv[0]).
 */
void print_usage(const char *progname) {
	printf("Usage: %s [--daemon] [--oneshot] [--config=PATH]\n", progname);
}

static int redirect_stderr_to_log(const char *path) {
	if (!path || path[0] == '\0')
		return 0;

	FILE *fp = fopen(path, "a");
	if (!fp) {
		fprintf(stderr, "Warning: Failed to open log_file %s: %s\n",
			path, strerror(errno));
		return -1;
	}

	if (dup2(fileno(fp), STDERR_FILENO) < 0) {
		fprintf(stderr,
			"Warning: Failed to redirect stderr to %s: %s\n",
			path, strerror(errno));
		fclose(fp);
		return -1;
	}
	fclose(fp);
	setvbuf(stderr, NULL, _IOLBF, 0);
	return 0;
}

/**
 * @brief Main entry point for OTA fetcher CLI.
 *
 * Parses CLI arguments, loads the OTA configuration, prints config,
 * and runs the main OTA fetch loop in the selected mode.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Exit code (0 on success, nonzero on error).
 */
int main(int argc, char *argv[]) {
	const char *config_path = "/etc/ota_fetch/ota_fetch.conf";
	enum run_mode mode = MODE_ONESHOT;

	static struct option long_opts[] = {{"daemon", no_argument, 0, 'd'},
					    {"oneshot", no_argument, 0, 'o'},
					    {"config", required_argument, 0,
					     'c'},
					    {"help", no_argument, 0, 'h'},
					    {0, 0, 0, 0}};

	int opt;
	while ((opt = getopt_long(argc, argv, "doc:th", long_opts, NULL)) !=
	       -1) {
		switch (opt) {
		case 'd':
			mode = MODE_DAEMON;
			break;
		case 'o':
			mode = MODE_ONESHOT;
			break;
		case 'c':
			config_path = optarg;
			break;
		case 'h':
		default:
			print_usage(argv[0]);
			return 0;
		}
	}

	struct ota_config config;
	int config_rc = config_load(config_path, &config);
	if (config_rc != 0) {
		if (config_rc > 0) {
			fprintf(stderr,
				"Error: Failed to load config %s (parse error near line %d)\n",
				config_path, config_rc);
		} else {
			fprintf(stderr, "Error: Failed to load config: %s\n",
				config_path);
		}
		return 1;
	}

	redirect_stderr_to_log(config.log_file);
	config_print(&config);

	int rc = ota_fetch_run(mode == MODE_DAEMON, &config);

	config_free(&config);
	return rc;
}
