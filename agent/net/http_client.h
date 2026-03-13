// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#ifndef NET_HTTP_CLIENT_H
#define NET_HTTP_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct parsed_http_uri {
	bool https;
	char host[256];
	uint16_t port;
	char path[PATH_MAX];
};

int parse_http_uri(const char *uri, struct parsed_http_uri *parsed);

#endif /* NET_HTTP_CLIENT_H */
