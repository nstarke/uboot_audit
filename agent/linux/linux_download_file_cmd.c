// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <http(s)-url> <output-path>\n"
		"  Download a file from HTTP(S) to a local path\n",
		prog);
}

int linux_download_file_scan_main(int argc, char **argv)
{
	const char *url = NULL;
	const char *output_path = NULL;
	bool insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	bool verbose = getenv("ELA_VERBOSE") && !strcmp(getenv("ELA_VERBOSE"), "1");
	char errbuf[256];
	struct stat st;
	uint64_t downloaded_bytes = 0;
	bool success = false;
	int opt;
	int ret = 0;

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};

	optind = 1;
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

	if (optind >= argc) {
		fprintf(stderr, "download-file requires a URL beginning with http:// or https://\n");
		usage(argv[0]);
		return 2;
	}

	url = argv[optind++];
	if (strncmp(url, "http://", 7) && strncmp(url, "https://", 8)) {
		fprintf(stderr, "download-file requires a URL beginning with http:// or https://: %s\n", url);
		return 2;
	}

	if (optind >= argc) {
		fprintf(stderr, "download-file requires an output path\n");
		usage(argv[0]);
		return 2;
	}

	output_path = argv[optind++];
	if (!output_path || !*output_path) {
		fprintf(stderr, "download-file requires a non-empty output path\n");
		return 2;
	}

	if (optind < argc) {
		fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
		usage(argv[0]);
		return 2;
	}

	if (ela_http_get_to_file(url, output_path, insecure, verbose, errbuf, sizeof(errbuf)) < 0) {
		fprintf(stderr, "Failed to download %s to %s: %s\n",
			url,
			output_path,
			errbuf[0] ? errbuf : "unknown error");
		ret = 1;
	} else if (stat(output_path, &st) != 0) {
		fprintf(stderr, "Downloaded %s but failed to stat %s: %s\n",
			url,
			output_path,
			strerror(errno));
		ret = 1;
	} else {
		downloaded_bytes = (uint64_t)st.st_size;
		success = true;
	}

	fprintf(stderr,
		"download-file downloaded %" PRIu64 " bytes success=%s url=%s output=%s\n",
		downloaded_bytes,
		success ? "true" : "false",
		url,
		output_path);

	return ret;
}