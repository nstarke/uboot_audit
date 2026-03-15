// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../embedded_linux_audit_cmd.h"
#include "../net/ws_client.h"
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
		"Usage: %s [--insecure] <host:port|ws://...|wss://...>\n"
		"  Transfer (send) this binary to a receiver listening at host:port,\n"
		"  then daemonize and serve an interactive session over the same connection.\n"
		"  For ws:// or wss:// targets, an interactive session is established over\n"
		"  WebSocket without transferring the binary.\n"
		"  --insecure  Disable TLS certificate verification (for self-signed certs)\n"
		"  The receiver for raw TCP may be started with:\n"
		"    nc -l <port> > embedded_linux_audit && chmod +x embedded_linux_audit\n",
		prog);
}

int transfer_main(int argc, char **argv)
{
	const char *target;
	int insecure = 0;
	int sock;
	int fd;
	char buf[65536];
	ssize_t n;
	pid_t pid;
	int i;

	if (argc < 2) {
		usage(argv[0]);
		return 2;
	}

	if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
		usage(argv[0]);
		return 0;
	}

	/* Parse optional flags before the target */
	target = NULL;
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--insecure")) {
			insecure = 1;
		} else if (argv[i][0] == '-') {
			fprintf(stderr, "transfer: unknown option: %s\n", argv[i]);
			usage(argv[0]);
			return 2;
		} else if (!target) {
			target = argv[i];
		} else {
			fprintf(stderr, "transfer: unexpected argument: %s\n", argv[i]);
			usage(argv[0]);
			return 2;
		}
	}

	if (!target) {
		usage(argv[0]);
		return 2;
	}

	if (ela_is_ws_url(target)) {
		struct ela_ws_conn ws;

		if (ela_ws_connect(target, insecure, &ws) != 0) {
			fprintf(stderr, "transfer: failed to connect to %s\n", target);
			return 1;
		}

		pid = fork();
		if (pid < 0) {
			fprintf(stderr, "transfer: fork failed: %s\n", strerror(errno));
			ela_ws_close_parent_fd(&ws);
			return 1;
		}

		if (pid > 0) {
			ela_ws_close_parent_fd(&ws);
			fprintf(stdout, "Transfer started (pid=%ld)\n", (long)pid);
			return 0;
		}

		setsid();
		exit(ela_ws_run_interactive(&ws, argv[0]));
	}

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
