// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef NET_API_KEY_H
#define NET_API_KEY_H

#define ELA_API_KEY_MAX_LEN 1024

/*
 * Initialise the API key candidate list from up to three sources, in
 * priority order:
 *   1. cli_key  — value of --api-key (may be NULL)
 *   2. ELA_API_KEY environment variable
 *   3. /tmp/ela.key file  (newline-delimited; each line is one candidate)
 * Duplicates are removed while preserving order.
 */
void ela_api_key_init(const char *cli_key);

/*
 * Return the currently-active API key, or NULL if none is configured
 * or all candidates have been exhausted.
 */
const char *ela_api_key_get(void);

/*
 * Advance to the next candidate after a 401 response.
 * Returns the next key, or NULL if all candidates are exhausted.
 */
const char *ela_api_key_next(void);

/*
 * Lock the current key as confirmed-working.  Subsequent calls to
 * ela_api_key_get() always return this key; ela_api_key_next() returns NULL.
 */
void ela_api_key_confirm(void);

#endif /* NET_API_KEY_H */
