// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_STR_UTIL_H
#define UTIL_STR_UTIL_H

#include <stddef.h>

int append_text(char **buf, size_t *len, size_t *cap, const char *text);
int append_bytes(char **buf, size_t *len, size_t *cap, const char *data, size_t data_len);
char *url_percent_encode(const char *text);
int append_json_escaped(char **buf, size_t *len, size_t *cap, const char *text);
int append_csv_field(char **buf, size_t *len, size_t *cap, const char *text);

#endif /* UTIL_STR_UTIL_H */
