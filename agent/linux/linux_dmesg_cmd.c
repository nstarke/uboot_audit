// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static bool g_verbose;
static bool g_insecure;
static int g_output_sock = -1;
static const char *g_output_http_uri = NULL;
static char *g_output_http_buf = NULL;
static size_t g_output_http_len;
static size_t g_output_http_cap;

struct line_buffer {
	char *text;
	size_t len;
};

static int parse_positive_line_count(const char *spec, size_t *count_out)
{
	char *end = NULL;
	unsigned long value;

	if (!spec || !*spec || !count_out)
		return -1;
	if (spec[0] == '-')
		return -1;

	errno = 0;
	value = strtoul(spec, &end, 10);
	if (errno != 0 || !end || *end != '\0' || value == 0 || (unsigned long)(size_t)value != value)
		return -1;

	*count_out = (size_t)value;
	return 0;
}

static void send_to_output_socket(const char *buf, size_t len)
{
	while (g_output_sock >= 0 && len) {
		ssize_t n = send(g_output_sock, buf, len, 0);
		if (n <= 0) {
			close(g_output_sock);
			g_output_sock = -1;
			return;
		}
		buf += n;
		len -= (size_t)n;
	}
}

static void append_output_http_buffer(const char *buf, size_t len)
{
	char *tmp;
	size_t need;
	size_t new_cap;

	if (!g_output_http_uri || !buf || !len)
		return;

	need = g_output_http_len + len + 1;
	if (need > g_output_http_cap) {
		new_cap = g_output_http_cap ? g_output_http_cap : 1024;
		while (new_cap < need)
			new_cap *= 2;

		tmp = realloc(g_output_http_buf, new_cap);
		if (!tmp)
			return;
		g_output_http_buf = tmp;
		g_output_http_cap = new_cap;
	}

	memcpy(g_output_http_buf + g_output_http_len, buf, len);
	g_output_http_len += len;
	g_output_http_buf[g_output_http_len] = '\0';
}

static void emit_v(FILE *stream, const char *fmt, va_list ap)
{
	va_list aq;
	char stack[1024];
	char *dyn = NULL;
	int needed;
	bool mirror_to_remote;

	mirror_to_remote = (stream == stdout);

	va_copy(aq, ap);
	vfprintf(stream, fmt, ap);
	fflush(stream);

	needed = vsnprintf(stack, sizeof(stack), fmt, aq);
	va_end(aq);

	if (needed < 0)
		return;

	if ((size_t)needed < sizeof(stack)) {
		if (mirror_to_remote) {
			send_to_output_socket(stack, (size_t)needed);
			append_output_http_buffer(stack, (size_t)needed);
		}
		return;
	}

	dyn = malloc((size_t)needed + 1);
	if (!dyn)
		return;

	va_copy(aq, ap);
	vsnprintf(dyn, (size_t)needed + 1, fmt, aq);
	va_end(aq);
	if (mirror_to_remote) {
		send_to_output_socket(dyn, (size_t)needed);
		append_output_http_buffer(dyn, (size_t)needed);
	}
	free(dyn);
}

static void out_printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	emit_v(stdout, fmt, ap);
	va_end(ap);
}

static void err_printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	emit_v(stderr, fmt, ap);
	va_end(ap);
}

static int flush_output_http_buffer(void)
{
	char errbuf[256];
	char *upload_uri;

	if (!g_output_http_uri)
		return 0;

	if (g_output_http_len == 0)
		return 0;

	upload_uri = ela_http_build_upload_uri(g_output_http_uri, "dmesg", NULL);
	if (!upload_uri)
		return -1;

	if (ela_http_post(upload_uri,
			 (const uint8_t *)(g_output_http_buf ? g_output_http_buf : ""),
			 g_output_http_len,
			 "text/plain; charset=utf-8",
			 g_insecure,
			 g_verbose,
			 errbuf,
			 sizeof(errbuf)) < 0) {
		err_printf("Failed to POST dmesg output to %s: %s\n", upload_uri,
			   errbuf[0] ? errbuf : "unknown error");
		free(upload_uri);
		return -1;
	}

	free(upload_uri);

	g_output_http_len = 0;
	if (g_output_http_buf)
		g_output_http_buf[0] = '\0';

	return 0;
}

static void free_tail_lines(struct line_buffer *lines, size_t count)
{
	size_t i;

	if (!lines)
		return;

	for (i = 0; i < count; i++)
		free(lines[i].text);
	free(lines);
}

static void usage(const char *prog)
{
	err_printf("Usage: %s\n"
		   "  [--head <positive-lines> | --tail <positive-lines>]\n"
		   "  --head N emits only the first N dmesg lines\n"
		   "  --tail N emits only the last N dmesg lines\n"
		   "  watch on   start a background dmesg watch daemon\n"
		   "  watch off  stop the running background dmesg watch daemon\n"
		   "  Remote output is configured via global --output-tcp or --output-http\n",
		prog);
}

int linux_dmesg_scan_main(int argc, char **argv)
{
	if (argc >= 2 && !strcmp(argv[1], "watch"))
		return linux_dmesg_watch_main(argc - 1, argv + 1);

	const char *output_tcp_target = getenv("ELA_OUTPUT_TCP");
	const char *output_http_target = getenv("ELA_OUTPUT_HTTP");
	const char *output_https_target = getenv("ELA_OUTPUT_HTTPS");
	const char *parsed_output_http = NULL;
	const char *parsed_output_https = NULL;
	FILE *fp = NULL;
	char line[4096];
	struct line_buffer *tail_lines = NULL;
	size_t tail_count = 0;
	size_t tail_seen = 0;
	size_t head_count = 0;
	size_t head_seen = 0;
	int ret = 0;
	int opt;

	optind = 1;
	g_verbose = getenv("ELA_VERBOSE") && !strcmp(getenv("ELA_VERBOSE"), "1");
	g_insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	if (g_output_sock >= 0) {
		close(g_output_sock);
		g_output_sock = -1;
	}

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "head", required_argument, NULL, 'H' },
		{ "tail", required_argument, NULL, 'T' },
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "hH:T:", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'H':
			if (parse_positive_line_count(optarg, &head_count) != 0) {
				err_printf("Invalid --head value (expected positive integer): %s\n", optarg);
				return 2;
			}
			break;
		case 'T':
			if (parse_positive_line_count(optarg, &tail_count) != 0) {
				err_printf("Invalid --tail value (expected positive integer): %s\n", optarg);
				return 2;
			}
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	if (head_count && tail_count) {
		err_printf("Use only one of --head or --tail\n");
		return 2;
	}

	if (optind < argc) {
		usage(argv[0]);
		return 2;
	}

	if (output_tcp_target && *output_tcp_target) {
		g_output_sock = ela_connect_tcp_ipv4(output_tcp_target);
		if (g_output_sock < 0) {
			err_printf("Invalid/failed output target (expected IPv4:port): %s\n", output_tcp_target);
			ret = 2;
			goto out;
		}
	}

	if (output_http_target && *output_http_target) {
		if (ela_parse_http_output_uri(output_http_target,
						  &parsed_output_http,
						  &parsed_output_https,
						  line,
						  sizeof(line)) < 0) {
			err_printf("%s\n", line);
			ret = 2;
			goto out;
		}
		g_output_http_uri = parsed_output_http ? parsed_output_http : parsed_output_https;
	}

	if (output_https_target && *output_https_target) {
		if (strncmp(output_https_target, "https://", 8)) {
			err_printf("Invalid --output-https URI (expected https://host:port/...): %s\n", output_https_target);
			ret = 2;
			goto out;
		}
		if (g_output_http_uri) {
			err_printf("Use only one of --output-http or --output-https\n");
			ret = 2;
			goto out;
		}
		g_output_http_uri = output_https_target;
	}

	if (g_verbose)
		err_printf("Collecting dmesg output\n");

	if (tail_count) {
		tail_lines = calloc(tail_count, sizeof(*tail_lines));
		if (!tail_lines) {
			err_printf("Out of memory while preparing tail buffer\n");
			ret = 1;
			goto out;
		}
	}

	fp = popen("dmesg", "r");
	if (!fp) {
		err_printf("Failed to execute dmesg: %s\n", strerror(errno));
		ret = 1;
		goto out;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (head_count) {
			if (head_seen < head_count)
				out_printf("%s", line);
			head_seen++;
			if (head_seen >= head_count)
				break;
			continue;
		}

		if (tail_count) {
			size_t slot = tail_seen % tail_count;
			char *copy = strdup(line);

			if (!copy) {
				err_printf("Out of memory while storing tail output\n");
				ret = 1;
				goto out;
			}

			free(tail_lines[slot].text);
			tail_lines[slot].text = copy;
			tail_lines[slot].len = strlen(copy);
			tail_seen++;
			continue;
		}

		out_printf("%s", line);
	}

	if (pclose(fp) != 0 && ret == 0)
		ret = 1;
	fp = NULL;

	if (ret == 0 && tail_count) {
		size_t start;
		size_t emit_count;
		size_t i;

		emit_count = tail_seen < tail_count ? tail_seen : tail_count;
		start = tail_seen < tail_count ? 0 : (tail_seen % tail_count);
		for (i = 0; i < emit_count; i++) {
			size_t slot = (start + i) % tail_count;
			if (tail_lines[slot].text)
				out_printf("%s", tail_lines[slot].text);
		}
	}

out:
	if (fp)
		(void)pclose(fp);
	if (g_output_sock >= 0)
		close(g_output_sock);
	if (flush_output_http_buffer() < 0 && ret == 0)
		ret = 1;
	free(g_output_http_buf);
	free_tail_lines(tail_lines, tail_count);
	g_output_http_buf = NULL;
	g_output_http_len = 0;
	g_output_http_cap = 0;
	g_output_http_uri = NULL;
	return ret;
}