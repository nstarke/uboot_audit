// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "uboot/image/uboot_image_cmd.h"

#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --dev <device> --offset <bytes>\n",
		prog);
}

int uboot_image_pull_main(int argc, char **argv)
{
	const char *dev = NULL;
	const char *output_tcp = getenv("ELA_OUTPUT_TCP");
	const char *output_http = getenv("ELA_OUTPUT_HTTP");
	const char *output_https = getenv("ELA_OUTPUT_HTTPS");
	const char *parsed_output_http = NULL;
	const char *parsed_output_https = NULL;
	const char *output_uri = NULL;
	uint64_t offset = 0;
	bool have_offset = false;
	bool verbose = getenv("ELA_VERBOSE") && !strcmp(getenv("ELA_VERBOSE"), "1");
	bool insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	int opt;
	int rc;

	optind = 1;

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "dev", required_argument, NULL, 'd' },
		{ "offset", required_argument, NULL, 'o' },
		{ "output-tcp", required_argument, NULL, 't' },
		{ "output-http", required_argument, NULL, 'O' },
		{ "send-logs", no_argument, NULL, 'L' },
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "hd:o:t:O:L", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'd':
			dev = optarg;
			break;
		case 'o':
			offset = uboot_image_parse_u64(optarg);
			have_offset = true;
			break;
		case 't':
			output_tcp = optarg;
			break;
		case 'O':
			if (ela_parse_http_output_uri(optarg,
						  &parsed_output_http,
						  &parsed_output_https,
						  NULL,
						  0) < 0) {
				fprintf(stderr, "Invalid --output-http URI (expected http://host:port/... or https://host:port/...): %s\n", optarg);
				return 2;
			}
			output_http = parsed_output_http;
			output_https = parsed_output_https;
			break;
		case 'L':
			fprintf(stderr, "--send-logs is not valid with image pull\n");
			return 2;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	if (!dev || !have_offset) {
		usage(argv[0]);
		return 2;
	}

	if (optind < argc) {
		usage(argv[0]);
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
		fprintf(stderr, "image pull requires one of --output-tcp or --output-http\n");
		return 2;
	}

	if (output_tcp && output_uri) {
		fprintf(stderr, "image pull accepts only one remote target at a time\n");
		return 2;
	}

	rc = uboot_image_prepare(verbose, insecure, false, output_tcp, output_http, output_https);
	if (rc)
		return rc;

	rc = uboot_image_pull_execute(dev, offset, output_tcp, output_uri);
	return uboot_image_finish(rc);
}
