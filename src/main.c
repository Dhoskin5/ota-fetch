#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include "config.h"
#include "ota_fetch.h"
#include "manifest.h"

enum run_mode {
    MODE_ONESHOT,
    MODE_DAEMON,
    MODE_TEST
};

void print_usage(const char *progname) {
    printf("Usage: %s [--daemon] [--oneshot] [--config=PATH] [--test]\n", progname);
}

int main(int argc, char *argv[]) {
    const char *config_path = "/etc/ota-fetch/ota-fetch.conf";
    enum run_mode mode = MODE_ONESHOT;

    static struct option long_opts[] = {
        {"daemon",  no_argument,       0, 'd'},
        {"oneshot", no_argument,       0, 'o'},
        {"config",  required_argument, 0, 'c'},
        {"test",    no_argument,       0, 't'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "doc:th", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'd': mode = MODE_DAEMON; break;
            case 'o': mode = MODE_ONESHOT; break;
            case 't': mode = MODE_TEST; break;
            case 'c': config_path = optarg; break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }

    if (mode == MODE_TEST) {
        printf("Running in TEST mode (no network)...\n\n");

        const char *current_path = "var/lib/ota_fetch/current/manifest.json";
        const char *inbox_path   = "var/lib/ota_fetch/inbox/manifest.json";

        manifest_t *cur = manifest_load(current_path);
        manifest_t *new = manifest_load(inbox_path);

        if (!new) {
            fprintf(stderr, "Error loading inbox manifest: %s\n", inbox_path);
            manifest_free(cur);
            return 2;
        }

        manifest_print(new);

        if (!cur) {
            printf("No current manifest. Update required.\n");
        } else if (!manifest_equal(cur, new)) {
            printf("Manifest differs. Update available.\n");
        } else {
            printf("Manifest matches. System is up to date.\n");
        }

        manifest_free(cur);
        manifest_free(new);

	printf("\n");

	struct ota_config ota_fetch_config = {0};
	const char * test_config_path = "etc/ota_fetch/ota_fetch.conf";
	config_load(test_config_path, &ota_fetch_config);
	config_print(&ota_fetch_config);
	config_free(&ota_fetch_config);

        return 0;
    }

    struct ota_config config;
    if (config_load(config_path, &config) < 0) {
        fprintf(stderr, "Error: Failed to load config: %s\n", config_path);
        return 1;
    }

    config_print(&config);

    int rc = ota_fetch_run(mode == MODE_DAEMON, &config);

    config_free(&config);
    return rc;
}
