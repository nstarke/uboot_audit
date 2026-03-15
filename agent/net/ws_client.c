// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "ws_client.h"
#include "api_key.h"
#include "../embedded_linux_audit_cmd.h"
#include "../shell/interactive.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef __linux__
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#endif

/* -------------------------------------------------------------------------
 * Primary MAC address discovery
 * ---------------------------------------------------------------------- */

static void get_primary_mac(char *buf, size_t buf_sz)
{
#ifdef __linux__
	struct ifaddrs *ifap, *ifa;
	unsigned char *m;

	if (getifaddrs(&ifap) == 0) {
		for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
			struct sockaddr_ll *sll;

			if (!ifa->ifa_addr ||
			    ifa->ifa_addr->sa_family != AF_PACKET)
				continue;
			if (ifa->ifa_flags & IFF_LOOPBACK)
				continue;

			sll = (struct sockaddr_ll *)ifa->ifa_addr;
			if (sll->sll_halen != 6)
				continue;

			m = sll->sll_addr;
			if (!m[0] && !m[1] && !m[2] && !m[3] && !m[4] && !m[5])
				continue;

			snprintf(buf, buf_sz,
				 "%02x-%02x-%02x-%02x-%02x-%02x",
				 m[0], m[1], m[2], m[3], m[4], m[5]);
			freeifaddrs(ifap);
			return;
		}
		freeifaddrs(ifap);
	}
#endif
	snprintf(buf, buf_sz, "unknown");
}

/* -------------------------------------------------------------------------
 * URL helpers
 * ---------------------------------------------------------------------- */

int ela_is_ws_url(const char *url)
{
	if (!url)
		return 0;
	return strncmp(url, "ws://", 5) == 0 ||
	       strncmp(url, "wss://", 6) == 0;
}

/*
 * Build the full WebSocket URL with MAC address:
 *   ws://host:port              ->  ws://host:port/terminal/<mac>
 *   ws://host:port/terminal     ->  ws://host:port/terminal/<mac>
 *   ws://host:port/other/path   ->  ws://host:port/other/path/<mac>
 */
static int build_ws_url(const char *base_url, const char *mac,
			 char *out, size_t out_sz)
{
	size_t scheme_len;
	const char *after_scheme;
	const char *path_sep;
	char stripped[512];
	size_t slen;
	int n;

	scheme_len = strncmp(base_url, "wss://", 6) == 0 ? 6 : 5;

	/* Copy and strip any trailing slashes */
	strncpy(stripped, base_url, sizeof(stripped) - 1);
	stripped[sizeof(stripped) - 1] = '\0';
	slen = strlen(stripped);
	while (slen > scheme_len && stripped[slen - 1] == '/')
		stripped[--slen] = '\0';

	after_scheme = stripped + scheme_len;
	path_sep     = strchr(after_scheme, '/');

	if (path_sep)
		n = snprintf(out, out_sz, "%s/%s", stripped, mac);
	else
		n = snprintf(out, out_sz, "%s/terminal/%s", stripped, mac);

	return (n > 0 && (size_t)n < out_sz) ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * Connection
 * ---------------------------------------------------------------------- */

int ela_ws_connect(const char *base_url, int insecure,
		   struct ela_ws_conn *ws_out)
{
	char mac[32];
	char full_url[512];
	CURL *curl;
	CURLcode rc;
	curl_socket_t sock = CURL_SOCKET_BAD;
	struct curl_blob ca_blob;

	if (!base_url || !ws_out)
		return -1;

	get_primary_mac(mac, sizeof(mac));

	if (build_ws_url(base_url, mac, full_url, sizeof(full_url)) != 0) {
		fprintf(stderr, "ws: URL too long: %s\n", base_url);
		return -1;
	}

	curl = curl_easy_init();
	if (!curl)
		return -1;

	curl_easy_setopt(curl, CURLOPT_URL, full_url);
	/* CONNECT_ONLY=1 performs the HTTP WebSocket upgrade then returns,
	 * leaving the socket ready for curl_ws_recv / curl_ws_send. */
	curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);

	{
		const char *key = ela_api_key_get();
		if (key && *key) {
			char auth_header[64 + ELA_API_KEY_MAX_LEN];
			struct curl_slist *hdrs = NULL;
			snprintf(auth_header, sizeof(auth_header),
				 "Authorization: Bearer %s", key);
			hdrs = curl_slist_append(NULL, auth_header);
			if (hdrs)
				curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
			/* hdrs intentionally not freed: curl holds a reference
			 * until curl_easy_cleanup().  We store it in ws_out. */
			ws_out->auth_headers = hdrs;
		} else {
			ws_out->auth_headers = NULL;
		}
	}

	if (insecure) {
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	}

	/* Use the embedded CA bundle for wss:// certificate verification */
	memset(&ca_blob, 0, sizeof(ca_blob));
	ca_blob.data  = (void *)ela_default_ca_bundle_pem;
	ca_blob.len   = ela_default_ca_bundle_pem_len;
	ca_blob.flags = CURL_BLOB_NOCOPY;
	curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &ca_blob);

	rc = curl_easy_perform(curl);
	if (rc != CURLE_OK) {
		long http_code = 0;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		if (http_code == 401)
			fprintf(stderr,
				"ws: server returned 401 Unauthorized\n"
				"  Set a bearer token via --api-key, ELA_API_KEY, or /tmp/ela.key\n");
		else
			fprintf(stderr, "ws: connect to %s failed: %s\n",
				full_url, curl_easy_strerror(rc));
		curl_easy_cleanup(curl);
		return -1;
	}

	rc = curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sock);
	if (rc != CURLE_OK || sock == CURL_SOCKET_BAD) {
		fprintf(stderr, "ws: failed to obtain active socket\n");
		curl_easy_cleanup(curl);
		return -1;
	}

	ws_out->curl = curl;
	ws_out->sock = sock;
	return 0;
}

void ela_ws_close_parent_fd(const struct ela_ws_conn *ws)
{
	if (!ws)
		return;
	if (ws->sock != CURL_SOCKET_BAD)
		close((int)ws->sock);
	if (ws->auth_headers)
		curl_slist_free_all(ws->auth_headers);
	/* Intentionally do NOT call curl_easy_cleanup: that might send a
	 * WebSocket CLOSE frame and disrupt the child's session. */
}

/* -------------------------------------------------------------------------
 * Heartbeat response
 * ---------------------------------------------------------------------- */

static void send_heartbeat_ack(CURL *curl)
{
	char msg[160];
	char date_str[64];
	time_t t = time(NULL);
	struct tm *tm_info;
	size_t sent = 0;

	tm_info = localtime(&t);
	if (tm_info)
		strftime(date_str, sizeof(date_str),
			 "%a %b %d %H:%M:%S %Z %Y", tm_info);
	else
		snprintf(date_str, sizeof(date_str), "unknown");

	snprintf(msg, sizeof(msg),
		 "{\"_type\":\"heartbeat_ack\",\"date\":\"%s\"}", date_str);
	curl_ws_send(curl, msg, strlen(msg), &sent, 0, CURLWS_TEXT);
}

/* -------------------------------------------------------------------------
 * Interactive session bridge
 * ---------------------------------------------------------------------- */

int ela_ws_run_interactive(struct ela_ws_conn *ws, const char *prog)
{
	int    pipe_to_loop[2];   /* parent → interactive_loop stdin  */
	int    pipe_from_loop[2]; /* interactive_loop stdout → parent */
	pid_t  child;
	char   recv_buf[65536];
	char   frame_buf[65536];
	size_t frame_len = 0;

	if (pipe(pipe_to_loop) != 0 || pipe(pipe_from_loop) != 0) {
		fprintf(stderr, "ws: pipe: %s\n", strerror(errno));
		return 1;
	}

	child = fork();
	if (child < 0) {
		fprintf(stderr, "ws: fork: %s\n", strerror(errno));
		return 1;
	}

	if (child == 0) {
		/* Child: run interactive_loop with pipes as stdio */
		dup2(pipe_to_loop[0],   STDIN_FILENO);
		dup2(pipe_from_loop[1], STDOUT_FILENO);
		dup2(pipe_from_loop[1], STDERR_FILENO);
		close(pipe_to_loop[0]);
		close(pipe_to_loop[1]);
		close(pipe_from_loop[0]);
		close(pipe_from_loop[1]);
		setvbuf(stdout, NULL, _IONBF, 0);
		setvbuf(stderr, NULL, _IONBF, 0);
		exit(interactive_loop(prog));
	}

	/* Parent: bridge WebSocket ↔ pipes */
	close(pipe_to_loop[0]);
	close(pipe_from_loop[1]);

	for (;;) {
		fd_set         rfds;
		struct timeval tv;
		int            maxfd;
		int            sel;
		int            child_status;

		if (waitpid(child, &child_status, WNOHANG) > 0)
			break;

		FD_ZERO(&rfds);
		FD_SET(ws->sock,        &rfds);
		FD_SET(pipe_from_loop[0], &rfds);
		maxfd = (int)ws->sock > pipe_from_loop[0]
			? (int)ws->sock : pipe_from_loop[0];

		tv.tv_sec  = 1;
		tv.tv_usec = 0;
		sel = select(maxfd + 1, &rfds, NULL, NULL, &tv);
		if (sel < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		/* WebSocket frame → interactive_loop */
		if (FD_ISSET(ws->sock, &rfds)) {
			const struct curl_ws_frame *meta = NULL;
			size_t nread = 0;
			CURLcode rc;

			rc = curl_ws_recv(ws->curl, recv_buf,
					  sizeof(recv_buf) - 1,
					  &nread, &meta);

			if (rc == CURLE_OK && meta) {
				if (meta->flags & CURLWS_CLOSE)
					break;

				if (nread > 0 &&
				    frame_len + nread < sizeof(frame_buf)) {
					memcpy(frame_buf + frame_len,
					       recv_buf, nread);
					frame_len += nread;
				}

				if (meta->bytesleft == 0 && frame_len > 0) {
					frame_buf[frame_len] = '\0';

					if (strstr(frame_buf,
						   "\"_type\":\"heartbeat\"")) {
						send_heartbeat_ack(ws->curl);
					} else if (meta->flags & CURLWS_TEXT) {
						if (write(pipe_to_loop[1],
							  frame_buf,
							  frame_len) < 0)
							break;
					}
					frame_len = 0;
				}
			} else if (rc != CURLE_AGAIN) {
				break;
			}
		}

		/* interactive_loop output → WebSocket */
		if (FD_ISSET(pipe_from_loop[0], &rfds)) {
			ssize_t n = read(pipe_from_loop[0],
					 recv_buf, sizeof(recv_buf));
			if (n <= 0)
				break;
			size_t sent = 0;
			curl_ws_send(ws->curl, recv_buf, (size_t)n,
				     &sent, 0, CURLWS_TEXT);
		}
	}

	close(pipe_to_loop[1]);
	close(pipe_from_loop[0]);
	waitpid(child, NULL, 0);
	if (ws->auth_headers) {
		curl_slist_free_all(ws->auth_headers);
		ws->auth_headers = NULL;
	}
	curl_easy_cleanup(ws->curl);
	ws->curl = NULL;
	return 0;
}
