// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "tcp_util.h"
#include "../embedded_linux_audit_cmd.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int connect_tcp_host_port(const char *host, uint16_t port)
{
	struct in_addr addr;
	struct sockaddr_in sa;
	int sock = -1;

	if (!host || !*host || !port)
		return -1;

	if (inet_pton(AF_INET, host, &addr) != 1)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr = addr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(sock);
		return -1;
	}

	return sock;
}

int connect_tcp_host_port_any(const char *host, uint16_t port)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *ai;
	char portbuf[8];
	int sock = -1;
	int rc;

	if (!host || !*host || !port)
		return -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(portbuf, sizeof(portbuf), "%u", (unsigned int)port);
	rc = getaddrinfo(host, portbuf, &hints, &res);
	if (rc != 0 || !res)
		return -1;

	for (ai = res; ai; ai = ai->ai_next) {
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock < 0)
			continue;
		if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		close(sock);
		sock = -1;
	}

	freeaddrinfo(res);
	return sock;
}

int ela_connect_tcp_ipv4(const char *spec)
{
	char host[64];
	char *colon;
	char *end;
	unsigned long port_ul;
	int sock;
	struct sockaddr_in sa;

	if (!spec || !*spec)
		return -1;

	strncpy(host, spec, sizeof(host) - 1);
	host[sizeof(host) - 1] = '\0';
	colon = strrchr(host, ':');
	if (!colon || colon == host || *(colon + 1) == '\0')
		return -1;

	*colon = '\0';
	errno = 0;
	port_ul = strtoul(colon + 1, &end, 10);
	if (errno || *end || port_ul == 0 || port_ul > 65535)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)port_ul);
	if (inet_pton(AF_INET, host, &sa.sin_addr) != 1)
		return -1;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(sock);
		return -1;
	}

	return sock;
}

bool ela_is_valid_tcp_output_target(const char *spec)
{
	char host[64];
	char *colon;
	char *end;
	unsigned long port_ul;
	struct in_addr addr;

	if (!spec || !*spec)
		return false;

	strncpy(host, spec, sizeof(host) - 1);
	host[sizeof(host) - 1] = '\0';
	colon = strrchr(host, ':');
	if (!colon || colon == host || *(colon + 1) == '\0')
		return false;

	*colon = '\0';
	errno = 0;
	port_ul = strtoul(colon + 1, &end, 10);
	if (errno || *end || port_ul == 0 || port_ul > 65535)
		return false;

	return inet_pton(AF_INET, host, &addr) == 1;
}

int ela_send_all(int sock, const uint8_t *buf, size_t len)
{
	while (len) {
		ssize_t n = send(sock, buf, len, 0);
		if (n <= 0)
			return -1;
		buf += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
}
