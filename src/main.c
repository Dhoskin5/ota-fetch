#include "config.h"
#include "manifest.h"
#include "ota_fetch.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum run_mode { MODE_ONESHOT, MODE_DAEMON };

void print_usage(const char *progname) {
	printf("Usage: %s [--daemon] [--oneshot] [--config=PATH]\n", progname);
}

int main(int argc, char *argv[]) {
	const char *config_path = "/etc/ota-fetch/ota-fetch.conf";
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
	if (config_load(config_path, &config) < 0) {
		fprintf(stderr, "Error: Failed to load config: %s\n",
			config_path);
		return 1;
	}

	config_print(&config);

	int rc = ota_fetch_run(mode == MODE_DAEMON, &config);

	config_free(&config);
	return rc;
}
