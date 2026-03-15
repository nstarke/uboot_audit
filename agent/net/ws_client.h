// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef WS_CLIENT_H
#define WS_CLIENT_H

#include <curl/curl.h>

struct ela_ws_conn {
	CURL              *curl;
	curl_socket_t      sock;
	struct curl_slist *auth_headers; /* freed by ela_ws_run_interactive / ela_ws_close_parent_fd */
};

/* Returns 1 if the URL begins with ws:// or wss://, 0 otherwise. */
int ela_is_ws_url(const char *url);

/*
 * Connect to a WebSocket server.  If the URL has no path component the
 * local primary MAC address is discovered and "/terminal/<mac>" is
 * appended automatically.  insecure=1 disables TLS peer/host verification.
 * Returns 0 on success, -1 on error.
 */
int ela_ws_connect(const char *base_url, int insecure,
		   struct ela_ws_conn *ws_out);

/*
 * Close the parent's copy of the socket after fork() without sending a
 * WebSocket CLOSE frame, which would disrupt the child's session.
 */
void ela_ws_close_parent_fd(const struct ela_ws_conn *ws);

/*
 * Run an interactive REPL session over the established WebSocket connection.
 * interactive_loop() runs in a forked child process bridged via pipes.
 * Received frames whose text content contains "_type":"heartbeat" are
 * answered with the current system date and are not forwarded to the REPL.
 * Returns the exit code of the interactive session.
 */
int ela_ws_run_interactive(struct ela_ws_conn *ws, const char *prog);

#endif /* WS_CLIENT_H */
