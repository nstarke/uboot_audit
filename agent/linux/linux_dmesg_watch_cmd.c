// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "net/http_client.h"
#include "net/tcp_util.h"

#include <csv.h>
#include <errno.h>
#include <json.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define WATCH_PID_FILE      "/tmp/ela-dmesg-watch.pid"
#define WATCH_POLL_SECS     5

/* Daemon-side state (only meaningful after fork) */
static int g_watch_sock = -1;
static const char *g_watch_http_uri = NULL;
static bool g_watch_insecure = false;
static volatile sig_atomic_t g_watch_stop = 0;

static void watch_signal_handler(int sig)
{
	(void)sig;
	g_watch_stop = 1;
}

/* Returns true if dmesg supports -w / --follow */
static bool dmesg_follow_supported(void)
{
	FILE *fp = popen("dmesg --help 2>&1", "r");
	char line[256];
	bool found = false;

	if (!fp)
		return false;
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "-w") || strstr(line, "--follow")) {
			found = true;
			break;
		}
	}
	pclose(fp);
	return found;
}

static const char *watch_content_type(const char *fmt)
{
	if (!strcmp(fmt, "json"))
		return "application/json; charset=utf-8";
	if (!strcmp(fmt, "csv"))
		return "text/csv; charset=utf-8";
	return "text/plain; charset=utf-8";
}

/*
 * Format one dmesg line per output format and emit it to all configured
 * destinations (stdout, TCP socket, HTTP).  In txt mode the line is passed
 * through unchanged; csv and json wrap the message in the appropriate
 * envelope.
 */
static void emit_watch_line(const char *line, const char *fmt)
{
	char *buf = NULL;
	size_t len = 0;
	char errbuf[256];
	size_t line_len = strlen(line);
	char *stripped = NULL;
	const char *msg;

	/* Strip trailing newline for embedded formats */
	if (line_len > 0 && line[line_len - 1] == '\n') {
		stripped = malloc(line_len);
		if (stripped) {
			memcpy(stripped, line, line_len - 1);
			stripped[line_len - 1] = '\0';
		}
	}
	msg = stripped ? stripped : line;

	if (!strcmp(fmt, "json")) {
		json_object *obj;
		const char *js;
		size_t js_len;

		obj = json_object_new_object();
		if (!obj)
			goto done;
		json_object_object_add(obj, "record",  json_object_new_string("dmesg"));
		json_object_object_add(obj, "message", json_object_new_string(msg));
		js = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
		js_len = strlen(js);
		buf = malloc(js_len + 2U);
		if (buf) {
			memcpy(buf, js, js_len);
			buf[js_len] = '\n';
			buf[js_len + 1] = '\0';
			len = js_len + 1U;
		}
		json_object_put(obj);
	} else if (!strcmp(fmt, "csv")) {
		size_t msg_len = strlen(msg);
		size_t field_sz = (msg_len * 2U) + 3U;
		char *field = malloc(field_sz);
		size_t written;

		if (!field)
			goto done;
		written = csv_write(field, field_sz, msg, msg_len);
		/* "dmesg," + escaped field + "\n\0" */
		buf = malloc(6U + written + 2U);
		if (!buf) {
			free(field);
			goto done;
		}
		memcpy(buf, "dmesg,", 6);
		memcpy(buf + 6, field, written);
		buf[6 + written] = '\n';
		buf[6 + written + 1] = '\0';
		len = 6U + written + 1U;
		free(field);
	} else {
		/* txt: pass through with guaranteed newline */
		bool need_nl = line_len == 0 || line[line_len - 1] != '\n';

		buf = malloc(line_len + (need_nl ? 2U : 1U));
		if (!buf)
			goto done;
		memcpy(buf, line, line_len);
		if (need_nl)
			buf[line_len] = '\n';
		buf[line_len + (need_nl ? 1U : 0U)] = '\0';
		len = line_len + (need_nl ? 1U : 0U);
	}

	if (!buf || len == 0)
		goto done;

	/* Console: write when no remote transport is configured */
	if (g_watch_sock < 0 && !g_watch_http_uri)
		fwrite(buf, 1, len, stdout);

	/* TCP */
	if (g_watch_sock >= 0)
		(void)ela_send_all(g_watch_sock, (const uint8_t *)buf, len);

	/* HTTP: one POST per line for real-time delivery */
	if (g_watch_http_uri) {
		char *upload_uri = ela_http_build_upload_uri(g_watch_http_uri, "dmesg", NULL);
		if (upload_uri) {
			(void)ela_http_post(upload_uri,
					    (const uint8_t *)buf,
					    len,
					    watch_content_type(fmt),
					    g_watch_insecure,
					    false,
					    errbuf,
					    sizeof(errbuf));
			free(upload_uri);
		}
	}

done:
	free(buf);
	free(stripped);
}

/* Stream dmesg -w output, emitting each line as it arrives */
static void watch_loop_follow(const char *fmt)
{
	FILE *fp;
	char line[4096];

	fp = popen("dmesg -w", "r");
	if (!fp)
		return;
	while (!g_watch_stop && fgets(line, sizeof(line), fp))
		emit_watch_line(line, fmt);
	pclose(fp);
}

/*
 * Parse the monotonic timestamp from a standard dmesg line:
 *   "[  123.456789] message"
 * Returns true and sets *ts_out on success.
 */
static bool parse_dmesg_ts(const char *line, double *ts_out)
{
	const char *p = line;
	double ts;

	while (*p == ' ' || *p == '[')
		p++;
	if (sscanf(p, "%lf", &ts) != 1)
		return false;
	*ts_out = ts;
	return true;
}

/*
 * Poll dmesg every WATCH_POLL_SECS seconds, emitting only lines whose
 * monotonic timestamp is strictly greater than the last seen value.
 * Lines with no parseable timestamp are always emitted.
 */
static void watch_loop_poll(const char *fmt)
{
	double last_ts = -1.0;
	char line[4096];
	FILE *fp;
	double ts;
	int i;

	while (!g_watch_stop) {
		fp = popen("dmesg", "r");
		if (fp) {
			while (fgets(line, sizeof(line), fp)) {
				if (!parse_dmesg_ts(line, &ts)) {
					/* No timestamp: always emit to avoid dropping logs */
					emit_watch_line(line, fmt);
					continue;
				}
				if (ts > last_ts) {
					emit_watch_line(line, fmt);
					last_ts = ts;
				}
			}
			pclose(fp);
		}

		/* Sleep in 1-second chunks so SIGTERM is noticed promptly */
		for (i = 0; i < WATCH_POLL_SECS && !g_watch_stop; i++)
			sleep(1);
	}
}

static int write_pid_file(pid_t pid)
{
	FILE *fp = fopen(WATCH_PID_FILE, "w");

	if (!fp)
		return -1;
	fprintf(fp, "%ld\n", (long)pid);
	fclose(fp);
	return 0;
}

static pid_t read_pid_file(void)
{
	FILE *fp;
	long pid = -1;

	fp = fopen(WATCH_PID_FILE, "r");
	if (!fp)
		return -1;
	if (fscanf(fp, "%ld", &pid) != 1)
		pid = -1;
	fclose(fp);
	return (pid > 0) ? (pid_t)pid : -1;
}

/*
 * Fork a daemon child that runs the watch loop.  Returns 0 in the parent
 * (success), -1 on fork error.  The child never returns from this function.
 */
static int daemonize_and_watch(const char *fmt,
				const char *tcp_target,
				const char *http_uri,
				bool insecure)
{
	pid_t pid = fork();

	if (pid < 0)
		return -1;

	if (pid > 0) {
		/* Parent: record the child's PID and return */
		if (write_pid_file(pid) != 0)
			fprintf(stderr, "dmesg watch: warning: failed to write PID file %s\n",
				WATCH_PID_FILE);
		return 0;
	}

	/* Daemon child */
	setsid();

	signal(SIGTERM, watch_signal_handler);
	signal(SIGINT,  watch_signal_handler);

	if (tcp_target && *tcp_target)
		g_watch_sock = ela_connect_tcp_ipv4(tcp_target);

	g_watch_http_uri = http_uri;
	g_watch_insecure = insecure;

	if (dmesg_follow_supported())
		watch_loop_follow(fmt);
	else
		watch_loop_poll(fmt);

	if (g_watch_sock >= 0)
		close(g_watch_sock);

	unlink(WATCH_PID_FILE);
	exit(0);
}

static int watch_stop(void)
{
	pid_t pid = read_pid_file();

	if (pid < 0) {
		fprintf(stderr, "dmesg watch: not running (no PID file at %s)\n",
			WATCH_PID_FILE);
		return 1;
	}

	if (kill(pid, SIGTERM) != 0) {
		if (errno == ESRCH) {
			fprintf(stderr,
				"dmesg watch: process %ld no longer exists; cleaning up\n",
				(long)pid);
			unlink(WATCH_PID_FILE);
			return 0;
		}
		fprintf(stderr, "dmesg watch: failed to stop process %ld: %s\n",
			(long)pid, strerror(errno));
		return 1;
	}

	unlink(WATCH_PID_FILE);
	fprintf(stdout, "dmesg watch stopped (pid=%ld)\n", (long)pid);
	return 0;
}

static void usage_watch(const char *prog)
{
	fprintf(stderr,
		"Usage: %s watch <on|off>\n"
		"  on:  start a background dmesg watch process\n"
		"       uses 'dmesg -w' if supported, otherwise polls every %ds\n"
		"  off: stop the running background dmesg watch process\n"
		"  Output is routed via global --output-tcp or --output-http when set.\n"
		"  Respects global --output-format (txt, csv, json).\n",
		prog, WATCH_POLL_SECS);
}

/*
 * Entry point: argv[0] = "watch", argv[1] = "on" | "off" | "--help"
 */
int linux_dmesg_watch_main(int argc, char **argv)
{
	const char *output_tcp  = getenv("ELA_OUTPUT_TCP");
	const char *output_http = getenv("ELA_OUTPUT_HTTP");
	const char *output_https = getenv("ELA_OUTPUT_HTTPS");
	const char *fmt = getenv("ELA_OUTPUT_FORMAT");
	bool insecure = getenv("ELA_OUTPUT_INSECURE") &&
			!strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	const char *http_uri = NULL;
	const char *action;
	pid_t existing_pid;

	if (!fmt || !*fmt)
		fmt = "txt";

	if (argc < 2) {
		usage_watch(argv[0]);
		return 2;
	}

	if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
		usage_watch(argv[0]);
		return 0;
	}

	if (argc > 2) {
		fprintf(stderr, "dmesg watch: unexpected argument: %s\n", argv[2]);
		usage_watch(argv[0]);
		return 2;
	}

	action = argv[1];

	if (strcmp(action, "on") && strcmp(action, "off")) {
		fprintf(stderr, "dmesg watch: expected 'on' or 'off', got: %s\n", action);
		usage_watch(argv[0]);
		return 2;
	}

	if (!strcmp(action, "off"))
		return watch_stop();

	/* action == "on" */
	existing_pid = read_pid_file();
	if (existing_pid > 0 && kill(existing_pid, 0) == 0) {
		fprintf(stderr, "dmesg watch: already running (pid=%ld)\n",
			(long)existing_pid);
		return 1;
	}
	if (existing_pid > 0)
		unlink(WATCH_PID_FILE); /* stale PID file */

	if (output_http && *output_http)
		http_uri = output_http;
	else if (output_https && *output_https)
		http_uri = output_https;

	if (daemonize_and_watch(fmt, output_tcp, http_uri, insecure) != 0) {
		fprintf(stderr, "dmesg watch: failed to start daemon: %s\n",
			strerror(errno));
		return 1;
	}

	fprintf(stdout, "dmesg watch started\n");
	return 0;
}
