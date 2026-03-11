// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

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

	upload_uri = uboot_http_build_upload_uri(g_output_http_uri, "dmesg", NULL);
	if (!upload_uri)
		return -1;

	if (uboot_http_post(upload_uri,
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

static void usage(const char *prog)
{
	err_printf("Usage: %s\n"
		   "  Remote output is configured via global --output-tcp or --output-http\n",
		prog);
}

int linux_dmesg_scan_main(int argc, char **argv)
{
	const char *output_tcp_target = getenv("FW_AUDIT_OUTPUT_TCP");
	const char *output_http_target = getenv("FW_AUDIT_OUTPUT_HTTP");
	const char *output_https_target = getenv("FW_AUDIT_OUTPUT_HTTPS");
	const char *parsed_output_http = NULL;
	const char *parsed_output_https = NULL;
	FILE *fp = NULL;
	char line[4096];
	int ret = 0;
	int opt;

	optind = 1;
	g_verbose = getenv("FW_AUDIT_VERBOSE") && !strcmp(getenv("FW_AUDIT_VERBOSE"), "1");
	g_insecure = getenv("FW_AUDIT_OUTPUT_INSECURE") && !strcmp(getenv("FW_AUDIT_OUTPUT_INSECURE"), "1");
	if (g_output_sock >= 0) {
		close(g_output_sock);
		g_output_sock = -1;
	}

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	if (optind < argc) {
		usage(argv[0]);
		return 2;
	}

	if (output_tcp_target && *output_tcp_target) {
		g_output_sock = uboot_connect_tcp_ipv4(output_tcp_target);
		if (g_output_sock < 0) {
			err_printf("Invalid/failed output target (expected IPv4:port): %s\n", output_tcp_target);
			ret = 2;
			goto out;
		}
	}

	if (output_http_target && *output_http_target) {
		if (fw_audit_parse_http_output_uri(output_http_target,
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

	fp = popen("dmesg", "r");
	if (!fp) {
		err_printf("Failed to execute dmesg: %s\n", strerror(errno));
		ret = 1;
		goto out;
	}

	while (fgets(line, sizeof(line), fp))
		out_printf("%s", line);

	if (pclose(fp) != 0 && ret == 0)
		ret = 1;
	fp = NULL;

out:
	if (fp)
		(void)pclose(fp);
	if (g_output_sock >= 0)
		close(g_output_sock);
	if (flush_output_http_buffer() < 0 && ret == 0)
		ret = 1;
	free(g_output_http_buf);
	g_output_http_buf = NULL;
	g_output_http_len = 0;
	g_output_http_cap = 0;
	g_output_http_uri = NULL;
	return ret;
}