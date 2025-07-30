/**
 * @file manifest.h
 * @brief OTA update manifest API.
 *
 * Defines the manifest structure and helper functions for parsing,
 * freeing, and printing OTA update manifests. Each manifest describes
 * a single update payload and its cryptographic metadata.
 *
 * @author Dustin Hoskins
 * @date 2025
 */

#ifndef OTA_FETCH_MANIFEST_H
#define OTA_FETCH_MANIFEST_H

#include <stdbool.h>

/**
 * @brief OTA update manifest structure.
 *
 * Represents metadata describing a single OTA update payload.
 */
typedef struct {
	char *version; /**< Semantic version or unique ID of the update. */
	char *created; /**< ISO8601 timestamp when manifest was generated. */
	char *update_type; /**< Type of update (e.g., "rauc_bundle"). */
	char *target;	   /**< Target device or system for this update. */
	char *filename;	   /**< Filename of the update payload. */
	char *sha256;	   /**< SHA-256 hash of the payload, as hex string. */
	char *url;	   /**< URL to fetch the payload from. */
	long size;	   /**< Payload size in bytes. */
} manifest_t;

/**
 * @brief Parse a manifest JSON file from disk.
 *
 * Loads and parses a manifest from the specified file.
 *
 * @param path Path to manifest JSON file.
 * @return Pointer to allocated manifest_t on success, NULL on error.
 *
 * @note The returned manifest_t must be freed with manifest_free().
 */
manifest_t *manifest_load(const char *path);

/**
 * @brief Free a manifest structure and all its fields.
 *
 * Frees all dynamically allocated fields in the manifest, then the manifest
 * itself.
 *
 * @param manifest Pointer to manifest_t to free (may be NULL).
 */
void manifest_free(manifest_t *manifest);

/**
 * @brief Print manifest fields and values for debugging/logging.
 *
 * Prints all manifest fields in a human-readable format.
 *
 * @param m Pointer to manifest_t to print.
 */
void manifest_print(const manifest_t *m);

#endif // OTA_FETCH_MANIFEST_H
