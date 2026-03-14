// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "str_util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int append_text(char **buf, size_t *len, size_t *cap, const char *text)
{
	char *tmp;
	size_t text_len;
	size_t need;
	size_t new_cap;

	if (!buf || !len || !cap || !text)
		return -1;

	text_len = strlen(text);
	need = *len + text_len + 1;
	if (need > *cap) {
		new_cap = *cap ? *cap : 256;
		while (new_cap < need)
			new_cap *= 2;
		tmp = realloc(*buf, new_cap);
		if (!tmp)
			return -1;
		*buf = tmp;
		*cap = new_cap;
	}

	memcpy(*buf + *len, text, text_len);
	*len += text_len;
	(*buf)[*len] = '\0';
	return 0;
}

int append_bytes(char **buf, size_t *len, size_t *cap, const char *data, size_t data_len)
{
	char *tmp;
	size_t need;
	size_t new_cap;

	if (!buf || !len || !cap || (!data && data_len))
		return -1;

	need = *len + data_len + 1;
	if (need > *cap) {
		new_cap = *cap ? *cap : 256;
		while (new_cap < need)
			new_cap *= 2;
		tmp = realloc(*buf, new_cap);
		if (!tmp)
			return -1;
		*buf = tmp;
		*cap = new_cap;
	}

	if (data_len)
		memcpy(*buf + *len, data, data_len);
	*len += data_len;
	(*buf)[*len] = '\0';
	return 0;
}

char *url_percent_encode(const char *text)
{
	static const char hex[] = "0123456789ABCDEF";
	char *out = NULL;
	size_t len = 0;
	size_t cap = 0;
	const unsigned char *p = (const unsigned char *)text;

	if (!text)
		return NULL;

	while (*p) {
		if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~') {
			if (append_bytes(&out, &len, &cap, (const char *)p, 1) != 0)
				goto fail;
		} else {
			char esc[3];
			esc[0] = '%';
			esc[1] = hex[*p >> 4];
			esc[2] = hex[*p & 0x0F];
			if (append_bytes(&out, &len, &cap, esc, sizeof(esc)) != 0)
				goto fail;
		}
		p++;
	}

	return out;

fail:
	free(out);
	return NULL;
}

