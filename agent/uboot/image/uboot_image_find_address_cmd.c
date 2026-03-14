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
		"Usage: %s --dev <device> --offset <bytes> [--send-logs --output-tcp <IPv4:port>]\n",
		prog);
}

int uboot_image_find_address_main(int argc, char **argv)
{
	const char *dev = NULL;
	const char *output_tcp = getenv("ELA_OUTPUT_TCP");
	const char *output_http = getenv("ELA_OUTPUT_HTTP");
	const char *output_https = getenv("ELA_OUTPUT_HTTPS");
	const char *parsed_output_http = NULL;
	const char *parsed_output_https = NULL;
	uint64_t offset = 0;
	bool have_offset = false;
	bool verbose = getenv("ELA_VERBOSE") && !strcmp(getenv("ELA_VERBOSE"), "1");
	bool insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	bool send_logs = false;
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
			send_logs = true;
			break;
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

	if (!send_logs && output_tcp) {
		fprintf(stderr, "--output-tcp requires --send-logs for find-address\n");
		return 2;
	}

	rc = uboot_image_prepare(verbose, insecure, send_logs, output_tcp, output_http, output_https);
	if (rc)
		return rc;

	rc = uboot_image_find_address_execute(dev, offset);
	return uboot_image_finish(rc);
}

int uboot_image_find_address_execute(const char *dev, uint64_t offset)
{
	uint8_t hdr[UIMAGE_HDR_SIZE];
	uint64_t dev_size = uboot_guess_size_any(dev);
	int fd;

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
		if (g_output_format == FW_OUTPUT_TXT) {
			uboot_img_out_printf("uImage load address: 0x%08x\n", ela_read_be32(hdr + 16));
		} else {
			char value[32];
			snprintf(value, sizeof(value), "0x%08x", ela_read_be32(hdr + 16));
			emit_image_record("image_load_address", dev, offset, "uImage", value);
		}
		close(fd);
		return 0;
	}

	if (!memcmp(hdr, "\xD0\x0D\xFE\xED", 4)) {
		uint32_t total_size;
		uint8_t *fit_blob;
		uint32_t load_addr;
		uint64_t uboot_off = 0;
		bool uboot_off_found = false;

		if (!validate_fit_header(hdr, offset, dev_size ? dev_size : UINT64_MAX)) {
			uboot_img_err_printf("FIT header validation failed at offset 0x%jx\n", (uintmax_t)offset);
			close(fd);
			return 1;
		}

		total_size = ela_read_be32(hdr + 4);
		fit_blob = malloc((size_t)total_size);
		if (!fit_blob) {
			uboot_img_err_printf("Unable to allocate memory to inspect FIT image\n");
			close(fd);
			return 1;
		}

		if (pread(fd, fit_blob, (size_t)total_size, (off_t)offset) != (ssize_t)total_size) {
			uboot_img_err_printf("Unable to read full FIT image for address lookup\n");
			free(fit_blob);
			close(fd);
			return 1;
		}

		if (fit_find_load_address(fit_blob,
					  (size_t)total_size,
					  &load_addr,
					  &uboot_off,
					  &uboot_off_found)) {
			if (g_output_format == FW_OUTPUT_TXT) {
				uboot_img_out_printf("FIT load address: 0x%08x\n", load_addr);
			} else {
				char value[32];
				snprintf(value, sizeof(value), "0x%08x", load_addr);
				emit_image_record("image_load_address", dev, offset, "FIT", value);
			}
		}
		else
			uboot_img_err_printf("FIT load address not found\n");

		if (uboot_off_found) {
			if (g_output_format == FW_OUTPUT_TXT) {
				uboot_img_out_printf("FIT U-Boot code offset: 0x%jx\n", (uintmax_t)uboot_off);
			} else {
				char value[32];
				snprintf(value, sizeof(value), "0x%jx", (uintmax_t)uboot_off);
				emit_image_record("fit_uboot_offset", dev, offset, "FIT", value);
			}
		}
		else
			uboot_img_err_printf("FIT U-Boot code offset not found\n");

		free(fit_blob);
		close(fd);
		return 0;
	}

	uboot_img_err_printf("Unknown image format at offset 0x%jx\n", (uintmax_t)offset);
	close(fd);
	return 1;
}
