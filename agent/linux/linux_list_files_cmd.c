// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
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

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

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
		"Usage: %s [absolute-directory] [--insecure] [--suid-only]\n"
		"  Recursively list files under the given absolute directory (default: /)\n"
		"  When --suid-only is set, only files with the SUID bit set are returned\n"
		"  When --output-http or --output-https is configured, POST the list to /:mac/upload/file-list\n",
		prog);
}

static int output_buffer_append(struct output_buffer *buf, const char *text)
{
	size_t need;
	char *tmp;
	size_t new_cap;
	size_t text_len;

	if (!buf || !text)
		return -1;

	text_len = strlen(text);
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

	memcpy(buf->data + buf->len, text, text_len);
	buf->len += text_len;
	buf->data[buf->len] = '\0';
	return 0;
}

static int emit_path(const char *path,
			     int output_sock,
			     bool capture,
			     struct output_buffer *buf)
{
	char line[PATH_MAX + 2];
	int line_len;

	if (!path)
		return -1;

	line_len = snprintf(line, sizeof(line), "%s\n", path);
	if (line_len < 0 || (size_t)line_len >= sizeof(line))
		return -1;

	if (output_sock >= 0 && uboot_send_all(output_sock, (const uint8_t *)line, (size_t)line_len) < 0)
		return -1;

	if (capture)
		return output_buffer_append(buf, line);

	fputs(line, stdout);
	return 0;
}

static int list_files_recursive(const char *dir_path,
				int output_sock,
				bool capture,
				struct output_buffer *buf,
				bool suid_only)
{
	DIR *dir;
	struct dirent *de;

	dir = opendir(dir_path);
	if (!dir) {
		fprintf(stderr, "Cannot open directory %s: %s\n", dir_path, strerror(errno));
		return -1;
	}

	while ((de = readdir(dir)) != NULL) {
		char child[PATH_MAX];
		struct stat st;
		int n;

		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;

		n = snprintf(child, sizeof(child),
			     !strcmp(dir_path, "/") ? "/%s" : "%s/%s",
			     dir_path,
			     de->d_name);
		if (n < 0 || (size_t)n >= sizeof(child)) {
			closedir(dir);
			return -1;
		}

		if (lstat(child, &st) != 0) {
			fprintf(stderr, "Cannot stat %s: %s\n", child, strerror(errno));
			closedir(dir);
			return -1;
		}

		if (S_ISDIR(st.st_mode)) {
			if (list_files_recursive(child, output_sock, capture, buf, suid_only) != 0) {
				closedir(dir);
				return -1;
			}
			continue;
		}

		if (suid_only && !(st.st_mode & S_ISUID))
			continue;

		if (emit_path(child, output_sock, capture, buf) != 0) {
			closedir(dir);
			return -1;
		}
	}

	closedir(dir);
	return 0;
}

int linux_list_files_scan_main(int argc, char **argv)
{
	const char *output_tcp = getenv("FW_AUDIT_OUTPUT_TCP");
	const char *output_http = getenv("FW_AUDIT_OUTPUT_HTTP");
	const char *output_https = getenv("FW_AUDIT_OUTPUT_HTTPS");
	const char *output_uri = NULL;
	const char *dir_path = "/";
	bool insecure = false;
	bool suid_only = false;
	int output_sock = -1;
	struct stat st;
	struct output_buffer buf = {0};
	char *upload_uri = NULL;
	char errbuf[256];
	int ret = 0;
	int opt;

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "output-tcp", required_argument, NULL, 'o' },
		{ "output-http", required_argument, NULL, 'O' },
		{ "output-https", required_argument, NULL, 'T' },
		{ "insecure", no_argument, NULL, 'k' },
		{ "suid-only", no_argument, NULL, 's' },
		{ 0, 0, 0, 0 }
	};

	optind = 1;
	while ((opt = getopt_long(argc, argv, "ho:O:T:ks", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'o':
			output_tcp = optarg;
			break;
		case 'O':
			output_http = optarg;
			break;
		case 'T':
			output_https = optarg;
			break;
		case 'k':
			insecure = true;
			break;
		case 's':
			suid_only = true;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	if (optind < argc) {
		dir_path = argv[optind++];
	}

	if (optind < argc) {
		fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
		usage(argv[0]);
		return 2;
	}

	if (!dir_path || dir_path[0] != '/') {
		fprintf(stderr, "list-files requires an absolute directory path\n");
		return 2;
	}

	if (output_http && strncmp(output_http, "http://", 7)) {
		fprintf(stderr, "Invalid --output-http URI (expected http://host:port/...): %s\n", output_http);
		return 2;
	}

	if (output_https && strncmp(output_https, "https://", 8)) {
		fprintf(stderr, "Invalid --output-https URI (expected https://host:port/...): %s\n", output_https);
		return 2;
	}

	if (output_http && output_https) {
		fprintf(stderr, "Use only one of --output-http or --output-https\n");
		return 2;
	}

	if (output_http)
		output_uri = output_http;
	if (output_https)
		output_uri = output_https;

	if (lstat(dir_path, &st) != 0) {
		fprintf(stderr, "Cannot stat %s: %s\n", dir_path, strerror(errno));
		return 1;
	}

	if (!S_ISDIR(st.st_mode)) {
		fprintf(stderr, "list-files requires a directory path: %s\n", dir_path);
		return 2;
	}

	if (output_tcp && *output_tcp) {
		output_sock = uboot_connect_tcp_ipv4(output_tcp);
		if (output_sock < 0) {
			fprintf(stderr, "Invalid/failed output target (expected IPv4:port): %s\n", output_tcp);
			return 2;
		}
	}

	if (list_files_recursive(dir_path, output_sock, output_uri != NULL, &buf, suid_only) != 0) {
		ret = 1;
		goto out;
	}

	if (output_uri) {
		upload_uri = uboot_http_build_upload_uri(output_uri, "file-list", dir_path);
		if (!upload_uri) {
			fprintf(stderr, "Unable to build upload URI for %s\n", dir_path);
			ret = 1;
			goto out;
		}

		if (uboot_http_post(upload_uri,
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