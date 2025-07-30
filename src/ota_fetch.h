/**
 * @file ota_fetch.h
 * @brief OTA Fetcher API for secure embedded update downloads.
 *
 * Declares the OTA fetch and update entry point for embedded Linux systems.
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

#ifndef OTA_FETCH_H
#define OTA_FETCH_H

#include "config.h"
#include <stdbool.h>

/**
 * @brief Run OTA fetch and update loop (main entry point).
 *
 * Checks for new updates, verifies, downloads, validates, and applies them.
 * Supports one-shot and daemon mode.
 *
 * @param daemon_mode If true, run periodically; else, exit after one update
 * check.
 * @param cfg         OTA configuration (server URL, certs, etc.).
 * @return 0 on success, non-zero on failure.
 */
int ota_fetch_run(bool daemon_mode, const struct ota_config *cfg);

#endif // OTA_FETCH_H
