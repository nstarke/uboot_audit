// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../embedded_linux_audit_cmd.h"
#include "../shell/interactive.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <host:port>\n"
		"  Transfer (send) this binary to a receiver listening at host:port,\n"
		"  then daemonize and serve an interactive session over the same connection.\n"
		"  The receiver may be started with:\n"
		"    nc -l -p <port> > embedded_linux_audit && chmod +x embedded_linux_audit\n",
		prog);
}

int transfer_main(int argc, char **argv)
{
	const char *target;
	int sock;
	int fd;
	char buf[65536];
	ssize_t n;
	pid_t pid;

	if (argc < 2) {
		usage(argv[0]);
		return 2;
	}

	if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
		usage(argv[0]);
		return 0;
	}

	if (argc > 2) {
		fprintf(stderr, "transfer: unexpected argument: %s\n", argv[2]);
		usage(argv[0]);
		return 2;
	}

	target = argv[1];

	fd = open("/proc/self/exe", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "transfer: failed to open binary: %s\n", strerror(errno));
		return 1;
	}

	sock = ela_connect_tcp_any(target);
	if (sock < 0) {
		fprintf(stderr, "transfer: failed to connect to %s\n", target);
		close(fd);
		return 1;
	}

	/* Daemonize: parent reports and exits, child handles transfer + interactive session */
	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "transfer: fork failed: %s\n", strerror(errno));
		close(fd);
		close(sock);
		return 1;
	}

	if (pid > 0) {
		/* Parent */
		close(fd);
		close(sock);
		fprintf(stdout, "Transfer started (pid=%ld)\n", (long)pid);
		return 0;
	}

	/* Daemon child */
	setsid();

	/* Send the binary over the socket */
	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		if (ela_send_all(sock, (const uint8_t *)buf, (size_t)n) < 0) {
			close(fd);
			close(sock);
			exit(1);
		}
	}
	close(fd);

	if (n < 0) {
		close(sock);
		exit(1);
	}

	/* Switch stdin/stdout/stderr to the socket and serve an interactive session */
	dup2(sock, STDIN_FILENO);
	dup2(sock, STDOUT_FILENO);
	dup2(sock, STDERR_FILENO);
	close(sock);

	exit(interactive_loop(argv[0]));
}
