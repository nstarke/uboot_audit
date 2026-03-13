// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <dirent.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <curl/curl.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <absolute-path> [--recursive] [--allow-dev] [--allow-sysfs] [--allow-proc] [--allow-symlinks]\n"
		"  Copy one local file to remote destination, or upload directory contents over HTTP(S)\n"
		"  --recursive                    Recurse into subdirectories when source is a directory\n"
		"  --allow-dev                    Allow copying paths under /dev\n"
		"  --allow-sysfs                  Allow copying paths under /sys\n"
		"  --allow-proc                   Allow copying paths under /proc\n"
		"  --allow-symlinks               Upload symlinks as symlinks over HTTP(S)\n",
		prog);
}

static bool has_path_prefix(const char *path, const char *prefix)
{
	size_t prefix_len;

	if (!path || !prefix)
		return false;

	prefix_len = strlen(prefix);
	if (strncmp(path, prefix, prefix_len))
		return false;

	return path[prefix_len] == '\0' || path[prefix_len] == '/';
}

static bool path_is_allowed(const char *path, bool allow_dev, bool allow_sysfs, bool allow_proc)
{
	if (has_path_prefix(path, "/dev"))
		return allow_dev;
	if (has_path_prefix(path, "/sys"))
		return allow_sysfs;
	if (has_path_prefix(path, "/proc"))
		return allow_proc;
	return true;
}

static bool stat_is_copyable_file(const struct stat *st)
{
	if (!st)
		return false;

	return S_ISREG(st->st_mode) || S_ISCHR(st->st_mode) || S_ISBLK(st->st_mode);
}

static void print_verbose_copy_summary(const char *path, uint64_t copied_files)
{
	if (!path)
		return;

	fprintf(stderr,
		"remote-copy copied path %s (%" PRIu64 " file%s copied)\n",
		path,
		copied_files,
		copied_files == 1 ? "" : "s");
}

static void report_remote_copy_http_error(const char *output_uri,
					 bool insecure,
					 bool verbose,
					 const char *message)
{
	char errbuf[256];

	if (!message || !*message) {
		return;
	}

	fputs(message, stderr);
	if (!output_uri || !*output_uri) {
		return;
	}

	if (ela_http_post_log_message(output_uri, message, insecure, verbose, errbuf, sizeof(errbuf)) < 0) {
		fprintf(stderr, "Failed HTTP(S) POST log to %s: %s\n", output_uri,
			errbuf[0] ? errbuf : "unknown error");
	}
}

static void report_remote_copy_errno(const char *output_uri,
				     bool insecure,
				     bool verbose,
				     const char *fmt,
				     const char *path)
{
	char message[PATH_MAX + 128];
	int saved_errno = errno;
	int n;

	if (!fmt || !path) {
		return;
	}

	n = snprintf(message, sizeof(message), fmt, path, strerror(saved_errno));
	if (n < 0) {
		return;
	}

	report_remote_copy_http_error(output_uri, insecure, verbose, message);
}

static int send_symlink_to_http(const char *path, const char *output_uri, bool insecure, bool verbose)
{
	char errbuf[256];
	char target[PATH_MAX];
	char *upload_uri = NULL;
	ssize_t target_len;

	target_len = readlink(path, target, sizeof(target) - 1);
	if (target_len < 0) {
		report_remote_copy_errno(output_uri, insecure, verbose,
			"Cannot read symlink %s: %s\n", path);
		return -1;
	}
	target[target_len] = '\0';

	upload_uri = ela_http_build_upload_uri(output_uri, "file", path);
	if (!upload_uri) {
		char message[PATH_MAX + 64];
		snprintf(message, sizeof(message), "Unable to build upload URI for symlink %s\n", path);
		report_remote_copy_http_error(output_uri, insecure, verbose, message);
		return -1;
	}

	{
		char *final_uri;
		size_t final_len = strlen(upload_uri) + strlen("&symlink=true&symlinkPath=") + (size_t)target_len * 3U + 1U;
		CURL *curl = curl_easy_init();
		char *escaped_target;
		if (!curl) {
			report_remote_copy_http_error(output_uri, insecure, verbose,
				"Unable to initialize curl for symlink upload\n");
			free(upload_uri);
			return -1;
		}
		escaped_target = curl_easy_escape(curl, target, 0);
		curl_easy_cleanup(curl);
		if (!escaped_target) {
			report_remote_copy_http_error(output_uri, insecure, verbose,
				"Unable to escape symlink target for upload\n");
			free(upload_uri);
			return -1;
		}
		final_len = strlen(upload_uri) + strlen("&symlink=true&symlinkPath=") + strlen(escaped_target) + 1U;
		final_uri = malloc(final_len);
		if (!final_uri) {
			report_remote_copy_http_error(output_uri, insecure, verbose,
				"Unable to allocate upload URI for symlink\n");
			curl_free(escaped_target);
			free(upload_uri);
			return -1;
		}
		snprintf(final_uri, final_len, "%s&symlink=true&symlinkPath=%s", upload_uri, escaped_target);
		curl_free(escaped_target);
		free(upload_uri);
		upload_uri = final_uri;
	}

	if (ela_http_post(upload_uri,
			   (const uint8_t *)"",
			   0,
			   "application/octet-stream",
			   insecure,
			   verbose,
			   errbuf,
			   sizeof(errbuf)) < 0) {
		char message[PATH_MAX + 384];
		snprintf(message, sizeof(message), "Failed HTTP(S) POST symlink %s to %s: %s\n",
			path, upload_uri, errbuf[0] ? errbuf : "unknown error");
		report_remote_copy_http_error(output_uri, insecure, verbose, message);
		free(upload_uri);
		return -1;
	}

	free(upload_uri);
	return 0;
}

static int send_file_to_tcp(const char *path, const char *output_tcp, bool verbose)
{
	uint8_t buf[4096];
	int fd;
	int sock;
	(void)verbose;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
		return -1;
	}

	sock = ela_connect_tcp_ipv4(output_tcp);
	if (sock < 0) {
		fprintf(stderr, "Invalid/failed output target (expected IPv4:port): %s\n", output_tcp);
		close(fd);
		return -1;
	}

	for (;;) {
		ssize_t n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			fprintf(stderr, "Read failure on %s: %s\n", path, strerror(errno));
			close(sock);
			close(fd);
			return -1;
		}
		if (n == 0)
			break;
		if (ela_send_all(sock, buf, (size_t)n) < 0) {
			fprintf(stderr, "Failed sending bytes to %s\n", output_tcp);
			close(sock);
			close(fd);
			return -1;
		}
	}

	close(sock);
	close(fd);
	return 0;
}

static int send_file_to_http(const char *path, const char *output_uri, bool insecure, bool verbose)
{
	char errbuf[256];
	char *upload_uri = NULL;
	uint8_t *data = NULL;
	size_t data_len = 0;
	size_t data_cap = 0;
	int fd = -1;
	int rc = -1;
	(void)verbose;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		report_remote_copy_errno(output_uri, insecure, verbose,
			"Cannot open %s: %s\n", path);
		return -1;
	}

	for (;;) {
		uint8_t chunk[4096];
		ssize_t got = read(fd, chunk, sizeof(chunk));
		if (got < 0) {
			report_remote_copy_errno(output_uri, insecure, verbose,
				"Read failure on %s: %s\n", path);
			goto out;
		}
		if (got == 0)
			break;

		if (data_len + (size_t)got > data_cap) {
			size_t new_cap = data_cap ? data_cap : 4096;
			uint8_t *tmp;

			while (new_cap < data_len + (size_t)got)
				new_cap *= 2;

			tmp = realloc(data, new_cap);
			if (!tmp) {
				char message[PATH_MAX + 64];
				snprintf(message, sizeof(message), "Unable to grow upload buffer for %s\n", path);
				report_remote_copy_http_error(output_uri, insecure, verbose, message);
				goto out;
			}
			data = tmp;
			data_cap = new_cap;
		}

		memcpy(data + data_len, chunk, (size_t)got);
		data_len += (size_t)got;
	}

	upload_uri = ela_http_build_upload_uri(output_uri, "file", path);
	if (!upload_uri) {
		char message[PATH_MAX + 64];
		snprintf(message, sizeof(message), "Unable to build upload URI for %s\n", path);
		report_remote_copy_http_error(output_uri, insecure, verbose, message);
		goto out;
	}

	if (ela_http_post(upload_uri,
			   data,
			   data_len,
			   "application/octet-stream",
			   insecure,
			   verbose,
			   errbuf,
			   sizeof(errbuf)) < 0) {
		char message[PATH_MAX + 384];
		snprintf(message, sizeof(message), "Failed HTTP(S) POST file %s to %s: %s\n",
			path, upload_uri, errbuf[0] ? errbuf : "unknown error");
		report_remote_copy_http_error(output_uri, insecure, verbose, message);
		goto out;
	}

	rc = 0;

out:
	free(upload_uri);
	free(data);
	if (fd >= 0)
		close(fd);
	return rc;
}

static int upload_path_http(const char *path,
			    const char *output_uri,
			    bool insecure,
			    bool verbose,
			    bool recursive,
			    bool allow_dev,
			    bool allow_sysfs,
			    bool allow_proc,
			    bool allow_symlinks,
			    uint64_t *copied_files)
{
	struct stat st;

	if (!path_is_allowed(path, allow_dev, allow_sysfs, allow_proc)) {
		char message[PATH_MAX + 96];
		snprintf(message, sizeof(message), "Refusing to copy restricted path without allow flag: %s\n", path);
		report_remote_copy_http_error(output_uri, insecure, verbose, message);
		return -1;
	}

	if (lstat(path, &st) != 0) {
		report_remote_copy_errno(output_uri, insecure, verbose,
			"Cannot stat %s: %s\n", path);
		return -1;
	}

	if (S_ISLNK(st.st_mode)) {
		if (!allow_symlinks) {
			if (verbose)
				fprintf(stderr, "Skipping symlink without --allow-symlinks: %s\n", path);
			return 0;
		}
		if (send_symlink_to_http(path, output_uri, insecure, verbose) == 0) {
			if (copied_files)
				(*copied_files)++;
			return 0;
		}
		return -1;
	}

	if (S_ISDIR(st.st_mode)) {
		DIR *dir;
		struct dirent *de;
		int rc = 0;

		dir = opendir(path);
		if (!dir) {
			report_remote_copy_errno(output_uri, insecure, verbose,
				"Cannot open directory %s: %s\n", path);
			return -1;
		}

		while ((de = readdir(dir)) != NULL) {
			char *child;
			size_t child_len;
			int child_rc;
			struct stat child_st;

			if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
				continue;

			child_len = strlen(path) + 1 + strlen(de->d_name) + 1;
			child = malloc(child_len);
			if (!child) {
				report_remote_copy_http_error(output_uri, insecure, verbose,
					"Unable to allocate path buffer during recursive remote-copy\n");
				rc = -1;
				break;
			}
			snprintf(child, child_len, "%s/%s", path, de->d_name);

			if (lstat(child, &child_st) != 0) {
				report_remote_copy_errno(output_uri, insecure, verbose,
					"Cannot stat %s: %s\n", child);
				free(child);
				rc = -1;
				continue;
			}

			if (S_ISDIR(child_st.st_mode) && !recursive) {
				free(child);
				continue;
			}

			child_rc = upload_path_http(child, output_uri, insecure, verbose,
				recursive, allow_dev, allow_sysfs, allow_proc, allow_symlinks,
				copied_files);
			free(child);
			if (child_rc != 0) {
				rc = -1;
				continue;
			}
		}

		closedir(dir);
		return rc;
	}

	if (!stat_is_copyable_file(&st)) {
		if (verbose)
			fprintf(stderr, "Skipping unsupported file type: %s\n", path);
		return 0;
	}

	if (send_file_to_http(path, output_uri, insecure, verbose) == 0) {
		if (copied_files)
			(*copied_files)++;
		return 0;
	}

	return -1;
}

int linux_remote_copy_scan_main(int argc, char **argv)
{
	const char *output_tcp = getenv("ELA_OUTPUT_TCP");
	const char *output_http = getenv("ELA_OUTPUT_HTTP");
	const char *output_https = getenv("ELA_OUTPUT_HTTPS");
	const char *output_uri = NULL;
	const char *path = NULL;
	struct stat st;
	bool recursive = false;
	bool allow_dev = false;
	bool allow_sysfs = false;
	bool allow_proc = false;
	bool allow_symlinks = false;
	bool insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	bool verbose = getenv("ELA_VERBOSE") && !strcmp(getenv("ELA_VERBOSE"), "1");
	uint64_t copied_files = 0;
	int opt;

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "recursive", no_argument, NULL, 'r' },
		{ "allow-dev", no_argument, NULL, 'D' },
		{ "allow-sysfs", no_argument, NULL, 'S' },
		{ "allow-proc", no_argument, NULL, 'P' },
		{ "allow-symlinks", no_argument, NULL, 'L' },
		{ 0, 0, 0, 0 }
	};

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hrDSPL", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'r':
			recursive = true;
			break;
		case 'D':
			allow_dev = true;
			break;
		case 'S':
			allow_sysfs = true;
			break;
		case 'P':
			allow_proc = true;
			break;
		case 'L':
			allow_symlinks = true;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "remote-copy requires an absolute file path\n");
		usage(argv[0]);
		return 2;
	}

	path = argv[optind];
	if (!path || path[0] != '/') {
		fprintf(stderr, "remote-copy requires an absolute file path: %s\n", path ? path : "(null)");
		return 2;
	}

	if (optind + 1 < argc) {
		fprintf(stderr, "Unexpected argument: %s\n", argv[optind + 1]);
		usage(argv[0]);
		return 2;
	}

	if (getenv("ELA_OUTPUT_HTTP") && getenv("ELA_OUTPUT_HTTPS")) {
		fprintf(stderr, "Use only one of --output-http or --output-https\n");
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

	if ((!output_tcp || !*output_tcp) && (!output_uri || !*output_uri)) {
		fprintf(stderr, "remote-copy requires one of --output-tcp or --output-http\n");
		return 2;
	}

	if (output_tcp && output_uri) {
		fprintf(stderr, "remote-copy accepts only one remote target at a time\n");
		return 2;
	}

	if (stat(path, &st) != 0) {
		fprintf(stderr, "Cannot stat %s: %s\n", path, strerror(errno));
		return 1;
	}

	if (!path_is_allowed(path, allow_dev, allow_sysfs, allow_proc)) {
		fprintf(stderr, "Refusing to copy restricted path without allow flag: %s\n", path);
		return 2;
	}

	if (output_tcp) {
		if (S_ISDIR(st.st_mode)) {
			fprintf(stderr, "Directory uploads require --output-http\n");
			return 2;
		}
		if (S_ISLNK(st.st_mode)) {
			fprintf(stderr, "Symlink uploads require --output-http\n");
			return 2;
		}
		if (!stat_is_copyable_file(&st)) {
			fprintf(stderr, "Path is not a supported file for TCP transfer: %s\n", path);
			return 1;
		}
		if (send_file_to_tcp(path, output_tcp, verbose) != 0)
			return 1;
		copied_files = 1;
		if (verbose)
			print_verbose_copy_summary(path, copied_files);
		return 0;
	}

	if (upload_path_http(path, output_uri, insecure, verbose,
			recursive, allow_dev, allow_sysfs, allow_proc, allow_symlinks,
			&copied_files) != 0)
		return 1;

	if (verbose)
		print_verbose_copy_summary(path, copied_files);

	return 0;
}