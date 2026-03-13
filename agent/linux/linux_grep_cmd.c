// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct output_buffer {
	char *data;
	size_t len;
	size_t cap;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --search <string> --path <absolute-directory> [--recursive]\n"
		"  Search all files in the given absolute directory for the provided string\n"
		"  When --recursive is set, recurse into subdirectories\n"
		"  Output format is always text/plain as: path:line-number:line\n"
		"  When global --output-http is configured, POST matches to /:mac/upload/grep\n",
		prog);
}

static int output_buffer_append_len(struct output_buffer *buf, const char *text, size_t text_len)
{
	size_t need;
	char *tmp;
	size_t new_cap;

	if (!buf || (!text && text_len != 0))
		return -1;

	need = buf->len + text_len + 1;
	if (need > buf->cap) {
		new_cap = buf->cap ? buf->cap : 1024;
		while (new_cap < need)
			new_cap *= 2;
		tmp = realloc(buf->data, new_cap);
		if (!tmp)
			return -1;
		buf->data = tmp;
		buf->cap = new_cap;
	}

	if (text_len > 0)
		memcpy(buf->data + buf->len, text, text_len);
	buf->len += text_len;
	buf->data[buf->len] = '\0';
	return 0;
}

static int output_buffer_append(struct output_buffer *buf, const char *text)
{
	if (!text)
		return -1;
	return output_buffer_append_len(buf, text, strlen(text));
}

static int emit_match(const char *path,
			     unsigned long line_no,
			     const char *line,
			     int output_sock,
			     bool capture,
			     struct output_buffer *buf)
{
	struct output_buffer out = {0};
	char prefix[PATH_MAX + 64];
	int n;
	int ret = -1;

	if (!path || !line)
		return -1;

	n = snprintf(prefix, sizeof(prefix), "%s:%lu:", path, line_no);
	if (n < 0 || (size_t)n >= sizeof(prefix))
		goto out;

	if (output_buffer_append(&out, prefix) != 0 || output_buffer_append(&out, line) != 0)
		goto out;
	if (out.len == 0 || out.data[out.len - 1] != '\n') {
		if (output_buffer_append(&out, "\n") != 0)
			goto out;
	}

	if (output_sock >= 0 && ela_send_all(output_sock, (const uint8_t *)out.data, out.len) < 0)
		goto out;

	if (capture) {
		if (output_buffer_append_len(buf, out.data, out.len) != 0)
			goto out;
	} else if (fwrite(out.data, 1, out.len, stdout) != out.len) {
		goto out;
	}

	ret = 0;
out:
	free(out.data);
	return ret;
}

static void report_grep_error(const char *output_uri,
			      bool insecure,
			      const char *fmt,
			      const char *path)
{
	char msg[PATH_MAX + 128];
	char errbuf[256];
	int n;

	if (!fmt || !path)
		return;

	n = snprintf(msg, sizeof(msg), fmt, path, strerror(errno));
	if (n < 0)
		return;

	fputs(msg, stderr);
	if (!output_uri)
		return;

	if (ela_http_post_log_message(output_uri, msg, insecure, false, errbuf, sizeof(errbuf)) < 0)
		fprintf(stderr, "Failed HTTP(S) POST log to %s: %s\n", output_uri, errbuf[0] ? errbuf : "unknown error");
}

static int grep_file(const char *file_path,
		    const char *needle,
		    int output_sock,
		    bool capture,
		    struct output_buffer *buf)
{
	FILE *fp;
	char *line = NULL;
	size_t line_cap = 0;
	unsigned long line_no = 0;
	int ret = 0;

	if (!file_path || !needle)
		return -1;

	fp = fopen(file_path, "r");
	if (!fp)
		return -1;

	while (getline(&line, &line_cap, fp) >= 0) {
		line_no++;
		if (!strstr(line, needle))
			continue;
		if (emit_match(file_path, line_no, line, output_sock, capture, buf) != 0) {
			ret = -1;
			break;
		}
	}

	free(line);
	fclose(fp);
	return ret;
}

static int grep_directory(const char *dir_path,
			 const char *needle,
			 const char *output_uri,
			 bool insecure,
			 int output_sock,
			 bool capture,
			 struct output_buffer *buf,
			 bool recursive)
{
	DIR *dir;
	struct dirent *de;

	dir = opendir(dir_path);
	if (!dir) {
		report_grep_error(output_uri, insecure, "Cannot open directory %s: %s\n", dir_path);
		return -1;
	}

	while ((de = readdir(dir)) != NULL) {
		char child[PATH_MAX];
		struct stat st;
		int n;

		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;

		if (!strcmp(dir_path, "/"))
			n = snprintf(child, sizeof(child), "/%s", de->d_name);
		else
			n = snprintf(child, sizeof(child), "%s/%s", dir_path, de->d_name);
		if (n < 0 || (size_t)n >= sizeof(child)) {
			closedir(dir);
			return -1;
		}

		if (lstat(child, &st) != 0) {
			report_grep_error(output_uri, insecure, "Cannot stat %s: %s\n", child);
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			if (recursive && grep_directory(child, needle, output_uri, insecure, output_sock, capture, buf, recursive) != 0) {
				closedir(dir);
				return -1;
			}
			continue;
		}

		if (!S_ISREG(st.st_mode))
			continue;

		if (grep_file(child, needle, output_sock, capture, buf) != 0)
			report_grep_error(output_uri, insecure, "Cannot read file %s: %s\n", child);
	}

	closedir(dir);
	return 0;
}

int linux_grep_scan_main(int argc, char **argv)
{
	const char *output_tcp = getenv("ELA_OUTPUT_TCP");
	const char *output_http = getenv("ELA_OUTPUT_HTTP");
	const char *output_https = getenv("ELA_OUTPUT_HTTPS");
	const char *parsed_output_http = NULL;
	const char *parsed_output_https = NULL;
	const char *output_uri = NULL;
	const char *dir_path = NULL;
	const char *search = NULL;
	bool insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	bool recursive = false;
	int output_sock = -1;
	struct stat st;
	struct output_buffer buf = {0};
	char *upload_uri = NULL;
	char errbuf[256];
	int ret = 0;
	int opt;

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "search", required_argument, NULL, 's' },
		{ "path", required_argument, NULL, 'p' },
		{ "recursive", no_argument, NULL, 'r' },
		{ 0, 0, 0, 0 }
	};

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hs:p:r", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 's':
			search = optarg;
			break;
		case 'p':
			dir_path = optarg;
			break;
		case 'r':
			recursive = true;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
		usage(argv[0]);
		return 2;
	}

	if (!search || !*search) {
		fprintf(stderr, "grep requires --search\n");
		return 2;
	}

	if (!dir_path || !*dir_path) {
		fprintf(stderr, "grep requires --path\n");
		return 2;
	}

	if (dir_path[0] != '/') {
		fprintf(stderr, "grep requires an absolute directory path\n");
		return 2;
	}

	if (output_http && *output_http &&
	    ela_parse_http_output_uri(output_http,
					    &parsed_output_http,
					    &parsed_output_https,
					    NULL,
					    0) < 0) {
		fprintf(stderr, "Invalid --output-http URI (expected http://host:port/... or https://host:port/...): %s\n", output_http);
		return 2;
	}

	if (output_http && output_https) {
		fprintf(stderr, "Use only one of --output-http or --output-https\n");
		return 2;
	}

	if (parsed_output_http)
		output_uri = parsed_output_http;
	if (output_https)
		output_uri = output_https;

	if (lstat(dir_path, &st) != 0) {
		fprintf(stderr, "Cannot stat %s: %s\n", dir_path, strerror(errno));
		return 1;
	}

	if (!S_ISDIR(st.st_mode)) {
		fprintf(stderr, "grep requires a directory path: %s\n", dir_path);
		return 2;
	}

	if (output_tcp && *output_tcp) {
		output_sock = ela_connect_tcp_ipv4(output_tcp);
		if (output_sock < 0) {
			fprintf(stderr, "Invalid/failed output target (expected IPv4:port): %s\n", output_tcp);
			return 2;
		}
	}

	if (grep_directory(dir_path, search, output_uri, insecure, output_sock, output_uri != NULL, &buf, recursive) != 0) {
		ret = 1;
		goto out;
	}

	if (output_uri) {
		upload_uri = ela_http_build_upload_uri(output_uri, "grep", dir_path);
		if (!upload_uri) {
			fprintf(stderr, "Unable to build upload URI for %s\n", dir_path);
			ret = 1;
			goto out;
		}

		if (ela_http_post(upload_uri,
				   (const uint8_t *)(buf.data ? buf.data : ""),
				   buf.len,
				   "text/plain; charset=utf-8",
				   insecure,
				   false,
				   errbuf,
				   sizeof(errbuf)) < 0) {
			fprintf(stderr, "Failed HTTP(S) POST to %s: %s\n", upload_uri, errbuf[0] ? errbuf : "unknown error");
			ret = 1;
			goto out;
		}
	}

out:
	if (output_sock >= 0)
		close(output_sock);
	free(upload_uri);
	free(buf.data);
	return ret;
}