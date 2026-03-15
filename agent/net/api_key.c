// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "api_key.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_KEYS  64
#define KEY_FILE  "/tmp/ela.key"

static char keys[MAX_KEYS][ELA_API_KEY_MAX_LEN + 1];
static int  key_count     = 0;
static int  key_current   = 0;
static int  key_confirmed = 0;

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

static int key_already_added(const char *k)
{
	int i;
	for (i = 0; i < key_count; i++) {
		if (!strcmp(keys[i], k))
			return 1;
	}
	return 0;
}

static void add_key(const char *k)
{
	if (!k || !*k)
		return;
	if (strlen(k) > ELA_API_KEY_MAX_LEN)
		return;
	if (key_count >= MAX_KEYS)
		return;
	if (key_already_added(k))
		return;
	strncpy(keys[key_count], k, ELA_API_KEY_MAX_LEN);
	keys[key_count][ELA_API_KEY_MAX_LEN] = '\0';
	key_count++;
}

static void load_key_file(const char *path)
{
	FILE *f = fopen(path, "r");
	char line[ELA_API_KEY_MAX_LEN + 2];
	size_t len;

	if (!f)
		return;
	while (fgets(line, (int)sizeof(line), f)) {
		len = strlen(line);
		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
			line[--len] = '\0';
		if (len > 0)
			add_key(line);
	}
	fclose(f);
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

void ela_api_key_init(const char *cli_key)
{
	key_count     = 0;
	key_current   = 0;
	key_confirmed = 0;

	add_key(cli_key);
	add_key(getenv("ELA_API_KEY"));
	load_key_file(KEY_FILE);
}

const char *ela_api_key_get(void)
{
	if (key_count == 0 || key_current >= key_count)
		return NULL;
	return keys[key_current];
}

const char *ela_api_key_next(void)
{
	if (key_confirmed)
		return NULL;
	key_current++;
	return ela_api_key_get();
}

void ela_api_key_confirm(void)
{
	key_confirmed = 1;
}
