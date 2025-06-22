#ifndef OTA_FETCH_H
#define OTA_FETCH_H

#include <stdbool.h>
#include "config.h"

// Entry point from main.c
int ota_fetch_run(bool daemon_mode, const struct ota_config *cfg);

#endif // OTA_FETCH_H
