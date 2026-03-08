// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "uboot_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--output-format <csv|json|txt>] <subcommand> [options]\n"
		"\n"
		"Global options:\n"
		"  --output-format <csv|json|txt>  Set output format for subcommands\n"
		"\n"
		"Subcommands:\n"
		"  env     Scan for U-Boot environment candidates (uboot_env_scan behavior)\n"
		"  image   Scan or extract U-Boot images (uboot_image_scan behavior)\n"
		"  audit   Run audit rules against device data\n"
		"\n"
		"Examples:\n"
		"  %s env --verbose\n"
		"  %s image --dev /dev/mtdblock4 --step 0x1000\n"
		"  %s audit --dev /dev/mtdblock4 --offset 0x0 --size 0x10000\n",
		prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
	const char *output_format = "txt";
	int cmd_idx = 1;

	if (argc < 2) {
		usage(argv[0]);
		return 2;
	}

	while (cmd_idx < argc) {
		if (!strcmp(argv[cmd_idx], "--output-format")) {
			cmd_idx++;
			if (cmd_idx >= argc) {
				fprintf(stderr, "Missing value for --output-format\n\n");
				usage(argv[0]);
				return 2;
			}
			output_format = argv[cmd_idx++];
			continue;
		}

		if (!strncmp(argv[cmd_idx], "--output-format=", 16)) {
			output_format = argv[cmd_idx] + 16;
			cmd_idx++;
			continue;
		}

		if (!strcmp(argv[cmd_idx], "-h") || !strcmp(argv[cmd_idx], "--help") || !strcmp(argv[cmd_idx], "help")) {
			usage(argv[0]);
			return 0;
		}

		break;
	}

	if (strcmp(output_format, "txt") && strcmp(output_format, "csv") && strcmp(output_format, "json")) {
		fprintf(stderr, "Invalid --output-format: %s (expected: csv, json, txt)\n\n", output_format);
		usage(argv[0]);
		return 2;
	}

	if (cmd_idx >= argc) {
		usage(argv[0]);
		return 2;
	}

	if (setenv("FW_AUDIT_OUTPUT_FORMAT", output_format, 1) != 0) {
		fprintf(stderr, "Failed to set FW_AUDIT_OUTPUT_FORMAT\n");
		return 2;
	}

	if (!strcmp(argv[cmd_idx], "-h") || !strcmp(argv[cmd_idx], "--help") || !strcmp(argv[cmd_idx], "help")) {
		usage(argv[0]);
		return 0;
	}

	if (!strcmp(argv[cmd_idx], "env"))
		return uboot_env_scan_main(argc - cmd_idx, argv + cmd_idx);

	if (!strcmp(argv[cmd_idx], "image"))
		return uboot_image_scan_main(argc - cmd_idx, argv + cmd_idx);

	if (!strcmp(argv[cmd_idx], "audit"))
		return uboot_audit_scan_main(argc - cmd_idx, argv + cmd_idx);

	fprintf(stderr, "Unknown subcommand: %s\n\n", argv[cmd_idx]);
	usage(argv[0]);
	return 2;
}
