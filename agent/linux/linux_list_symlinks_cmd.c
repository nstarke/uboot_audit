// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include "util/output_buffer.h"

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <json.h>
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

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [absolute-directory] [--recursive]\n"
		"  List symlinks under the given absolute directory (default: /)\n"
		"  When --recursive is set, recurse into subdirectories\n"
		"  Output honors --output-format as txt, csv, or json\n"
		"  When global --output-http is configured, POST the list to /:mac/upload/symlink-list\n",
		prog);
}

static int emit_symlink(const char *link_path,
				const char *target_path,
				const char *output_format,
				int output_sock,
				bool capture,
				struct output_buffer *buf)
{
	struct output_buffer line = {0};
	int ret = -1;

	if (!link_path || !target_path || !output_format)
		return -1;

	if (!strcmp(output_format, "txt")) {
		if (output_buffer_append(&line, link_path) != 0 ||
		    output_buffer_append(&line, " -> ") != 0 ||
		    output_buffer_append(&line, target_path) != 0 ||
		    output_buffer_append(&line, "\n") != 0)
			goto out;
	} else if (!strcmp(output_format, "csv")) {
		if (csv_write_to_buf(&line, link_path) != 0 ||
		    output_buffer_append(&line, ",") != 0 ||
		    csv_write_to_buf(&line, target_path) != 0 ||
		    output_buffer_append(&line, "\n") != 0)
			goto out;
	} else if (!strcmp(output_format, "json")) {
		json_object *obj;
		const char *js;

		obj = json_object_new_object();
		if (!obj)
			goto out;
		json_object_object_add(obj, "link_path",     json_object_new_string(link_path));
		json_object_object_add(obj, "location_path", json_object_new_string(target_path));
		js = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
		if (output_buffer_append(&line, js) != 0 ||
		    output_buffer_append(&line, "\n") != 0) {
			json_object_put(obj);
			goto out;
		}
		json_object_put(obj);
	} else {
		goto out;
	}

	if (output_sock >= 0 && ela_send_all(output_sock, (const uint8_t *)line.data, line.len) < 0)
		goto out;

	if (capture) {
		if (output_buffer_append_len(buf, line.data, line.len) != 0)
			goto out;
	} else {
		if (fwrite(line.data, 1, line.len, stdout) != line.len)
			goto out;
	}

	ret = 0;
out:
	free(line.data);
	return ret;
}

static void report_symlink_error(const char *output_uri,
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

static int list_symlinks_recursive(const char *dir_path,
				   const char *output_uri,
				   bool insecure,
				   const char *output_format,
				   int output_sock,
				   bool capture,
				   struct output_buffer *buf,
				   bool recursive)
{
	DIR *dir;
	struct dirent *de;

	dir = opendir(dir_path);
	if (!dir) {
		report_symlink_error(output_uri, insecure, "Cannot open directory %s: %s\n", dir_path);
		return -1;
	}

	while ((de = readdir(dir)) != NULL) {
		char child[PATH_MAX];
		char target[PATH_MAX];
		struct stat st;
		ssize_t target_len;
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
			report_symlink_error(output_uri, insecure, "Cannot stat %s: %s\n", child);
			continue;
		}

		if (S_ISLNK(st.st_mode)) {
			target_len = readlink(child, target, sizeof(target) - 1);
			if (target_len < 0) {
				report_symlink_error(output_uri, insecure, "Cannot read symlink %s: %s\n", child);
				continue;
			}
			target[target_len] = '\0';

			if (emit_symlink(child, target, output_format, output_sock, capture, buf) != 0) {
				closedir(dir);
				return -1;
			}
			continue;
		}

		if (S_ISDIR(st.st_mode) && recursive) {
			if (list_symlinks_recursive(child, output_uri, insecure, output_format, output_sock, capture, buf, recursive) != 0)
				return -1;
		}
	}

	closedir(dir);
	return 0;
}

int linux_list_symlinks_scan_main(int argc, char **argv)
{
	const char *output_format = getenv("ELA_OUTPUT_FORMAT");
	const char *output_tcp = getenv("ELA_OUTPUT_TCP");
	const char *output_http = getenv("ELA_OUTPUT_HTTP");
	const char *output_https = getenv("ELA_OUTPUT_HTTPS");
	const char *parsed_output_http = NULL;
	const char *parsed_output_https = NULL;
	const char *output_uri = NULL;
	const char *dir_path = "/";
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
		{ "recursive", no_argument, NULL, 'r' },
		{ 0, 0, 0, 0 }
	};

	if (!output_format || !*output_format)
		output_format = "txt";

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hr", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'r':
			recursive = true;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	if (optind < argc)
		dir_path = argv[optind++];

	if (optind < argc) {
		fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
		usage(argv[0]);
		return 2;
	}

	if (!dir_path || dir_path[0] != '/') {
		fprintf(stderr, "list-symlinks requires an absolute directory path\n");
		return 2;
	}

	if (strcmp(output_format, "txt") && strcmp(output_format, "csv") && strcmp(output_format, "json")) {
		fprintf(stderr, "Invalid output format for list-symlinks: %s\n", output_format);
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
		fprintf(stderr, "list-symlinks requires a directory path: %s\n", dir_path);
		return 2;
	}

	if (output_tcp && *output_tcp) {
		output_sock = ela_connect_tcp_ipv4(output_tcp);
		if (output_sock < 0) {
			fprintf(stderr, "Invalid/failed output target (expected IPv4:port): %s\n", output_tcp);
			return 2;
		}
	}

	if (list_symlinks_recursive(dir_path, output_uri, insecure, output_format, output_sock, output_uri != NULL, &buf, recursive) != 0) {
		ret = 1;
		goto out;
	}

	if (output_uri) {
		upload_uri = ela_http_build_upload_uri(output_uri, "symlink-list", dir_path);
		if (!upload_uri) {
			fprintf(stderr, "Unable to build upload URI for %s\n", dir_path);
			ret = 1;
			goto out;
		}

		if (ela_http_post(upload_uri,
				   (const uint8_t *)(buf.data ? buf.data : ""),
				   buf.len,
				   !strcmp(output_format, "csv") ? "text/csv; charset=utf-8" :
				   (!strcmp(output_format, "json") ? "application/x-ndjson; charset=utf-8" : "text/plain; charset=utf-8"),
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