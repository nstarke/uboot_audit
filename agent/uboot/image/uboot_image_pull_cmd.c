// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "uboot/image/uboot_image_cmd.h"
#include "uboot/image/uboot_image_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

static int pull_image_to_output_tcp(const char *dev, uint64_t offset, const char *output_tcp_target)
{
	uint8_t hdr[UIMAGE_HDR_SIZE];
	uint64_t dev_size = uboot_guess_size_any(dev);
	uint64_t total_size = 0;
	int fd, sock;

	fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		uboot_img_err_printf("Cannot open %s: %s\n", dev, strerror(errno));
		return 1;
	}

	if (pread(fd, hdr, sizeof(hdr), (off_t)offset) != (ssize_t)sizeof(hdr)) {
		uboot_img_err_printf("Unable to read image header from %s @ 0x%jx\n", dev, (uintmax_t)offset);
		close(fd);
		return 1;
	}

	if (!memcmp(hdr, "\x27\x05\x19\x56", 4)) {
		if (!validate_uimage_header(hdr, offset, dev_size ? dev_size : UINT64_MAX)) {
			uboot_img_err_printf("uImage header validation failed at offset 0x%jx\n", (uintmax_t)offset);
			close(fd);
			return 1;
		}
		total_size = UIMAGE_HDR_SIZE + ela_read_be32(hdr + 12);
	} else if (!memcmp(hdr, "\xD0\x0D\xFE\xED", 4)) {
		if (!validate_fit_header(hdr, offset, dev_size ? dev_size : UINT64_MAX)) {
			uboot_img_err_printf("FIT header validation failed at offset 0x%jx\n", (uintmax_t)offset);
			close(fd);
			return 1;
		}
		total_size = ela_read_be32(hdr + 4);
	} else {
		uboot_img_err_printf("Unknown image format at offset 0x%jx\n", (uintmax_t)offset);
		close(fd);
		return 1;
	}

	sock = ela_connect_tcp_ipv4(output_tcp_target);
	if (sock < 0) {
		uboot_img_err_printf("Unable to connect to output target %s\n", output_tcp_target);
		close(fd);
		return 1;
	}

	{
		uint8_t buf[4096];
		uint64_t sent = 0;
		while (sent < total_size) {
			size_t want = (size_t)((total_size - sent) > sizeof(buf) ? sizeof(buf) : (total_size - sent));
			ssize_t n = pread(fd, buf, want, (off_t)(offset + sent));
			if (n <= 0 || ela_send_all(sock, buf, (size_t)n) < 0) {
				uboot_img_err_printf("Pull failed while sending image bytes\n");
				close(sock);
				close(fd);
				return 1;
			}
			sent += (uint64_t)n;
		}
		if (g_verbose) {
			char msg[256];
			snprintf(msg, sizeof(msg), "Pulled %ju bytes from %s @ 0x%jx to %s",
				(uintmax_t)total_size, dev, (uintmax_t)offset, output_tcp_target);
			emit_image_verbose(dev, offset, msg);
		}
	}

	close(sock);
	close(fd);
	return 0;
}

static int pull_image_to_output_http(const char *dev, uint64_t offset, const char *output_http_uri)
{
	uint8_t hdr[UIMAGE_HDR_SIZE];
	uint64_t dev_size = uboot_guess_size_any(dev);
	uint64_t total_size = 0;
	uint8_t *img = NULL;
	int fd;
	char errbuf[256];
	char file_path[512];
	char *upload_uri = NULL;

	fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		uboot_img_err_printf("Cannot open %s: %s\n", dev, strerror(errno));
		return 1;
	}

	if (pread(fd, hdr, sizeof(hdr), (off_t)offset) != (ssize_t)sizeof(hdr)) {
		uboot_img_err_printf("Unable to read image header from %s @ 0x%jx\n", dev, (uintmax_t)offset);
		close(fd);
		return 1;
	}

	if (!memcmp(hdr, "\x27\x05\x19\x56", 4)) {
		if (!validate_uimage_header(hdr, offset, dev_size ? dev_size : UINT64_MAX)) {
			uboot_img_err_printf("uImage header validation failed at offset 0x%jx\n", (uintmax_t)offset);
			close(fd);
			return 1;
		}
		total_size = UIMAGE_HDR_SIZE + ela_read_be32(hdr + 12);
	} else if (!memcmp(hdr, "\xD0\x0D\xFE\xED", 4)) {
		if (!validate_fit_header(hdr, offset, dev_size ? dev_size : UINT64_MAX)) {
			uboot_img_err_printf("FIT header validation failed at offset 0x%jx\n", (uintmax_t)offset);
			close(fd);
			return 1;
		}
		total_size = ela_read_be32(hdr + 4);
	} else {
		uboot_img_err_printf("Unknown image format at offset 0x%jx\n", (uintmax_t)offset);
		close(fd);
		return 1;
	}

	img = malloc((size_t)total_size);
	if (!img) {
		uboot_img_err_printf("Unable to allocate image buffer (%ju bytes)\n", (uintmax_t)total_size);
		close(fd);
		return 1;
	}

	if (pread(fd, img, (size_t)total_size, (off_t)offset) != (ssize_t)total_size) {
		uboot_img_err_printf("Pull failed while reading image bytes\n");
		free(img);
		close(fd);
		return 1;
	}

	snprintf(file_path, sizeof(file_path), "%s@0x%jx.bin", dev, (uintmax_t)offset);
	upload_uri = ela_http_build_upload_uri(output_http_uri, "uboot-image", file_path);
	if (!upload_uri) {
		uboot_img_err_printf("Failed to build upload URI for %s\n", dev);
		free(img);
		close(fd);
		return 1;
	}

	if (ela_http_post(upload_uri, img, (size_t)total_size,
			 g_pull_binary_content_type, g_insecure,
			 g_verbose,
			 errbuf, sizeof(errbuf)) < 0) {
		uboot_img_err_printf("Failed HTTP POST to %s: %s\n", upload_uri, errbuf[0] ? errbuf : "unknown error");
		free(upload_uri);
		free(img);
		close(fd);
		return 1;
	}

	if (g_verbose) {
		char msg[256];
		snprintf(msg, sizeof(msg), "Pulled %ju bytes from %s @ 0x%jx to %s",
			(uintmax_t)total_size, dev, (uintmax_t)offset, upload_uri);
		emit_image_verbose(dev, offset, msg);
	}

	free(upload_uri);
	free(img);
	close(fd);
	return 0;
}

int uboot_image_pull_execute(const char *dev,
			     uint64_t offset,
			     const char *output_tcp_target,
			     const char *output_http_uri)
{
	if (output_http_uri)
		return pull_image_to_output_http(dev, offset, output_http_uri);

	return pull_image_to_output_tcp(dev, offset, output_tcp_target);
}
