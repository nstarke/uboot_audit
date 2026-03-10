// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--output-format <csv|json|txt>] [--verbose] [--output-tcp <IPv4:port>] [--output-http <http://host:port/path>] [--output-https <https://host:port/path>] <group> <subcommand> [options]\n"
		"\n"
		"Global options:\n"
		"  --output-format <csv|json|txt>  Set output format for subcommands\n"
		"  --verbose                        Enable verbose mode for commands/subcommands\n"
		"  --output-tcp <IPv4:port>         Configure TCP remote output for commands/subcommands\n"
		"  --output-http <http://...>       Configure HTTP remote output for commands/subcommands\n"
		"  --output-https <https://...>     Configure HTTPS remote output for commands/subcommands\n"
		"\n"
		"Groups and subcommands:\n"
		"  uboot env          Scan for U-Boot environment candidates\n"
		"  uboot image        Scan or extract U-Boot images\n"
		"  uboot audit        Run U-Boot audit rules\n"
		"  linux dmesg        Dump kernel ring buffer output\n"
		"  linux list-files   List files under a directory (use --recursive to recurse)\n"
		"  linux remote-copy  Copy a local file to remote destination\n"
		"  efi orom           EFI option ROM utilities (pull/list)\n"
		"  bios orom          BIOS option ROM utilities (pull/list)\n"
		"\n"
		"Examples:\n"
		"  %s --verbose uboot env\n"
		"  %s uboot image --dev /dev/mtdblock4 --step 0x1000\n"
		"  %s uboot audit --dev /dev/mtdblock4 --offset 0x0 --size 0x10000\n"
		"  %s --verbose --output-http http://127.0.0.1:5000/dmesg linux dmesg\n"
		"  %s --output-http http://127.0.0.1:5000 linux list-files /etc\n"
		"  %s --output-https https://127.0.0.1:5443/upload linux remote-copy /tmp/fw.bin\n"
		"  %s --output-http http://127.0.0.1:5000/orom --verbose efi orom pull\n"
		"  %s --output-tcp 127.0.0.1:5001 --verbose bios orom list\n",
		prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
	const char *output_format = "txt";
	const char *output_tcp = NULL;
	const char *output_http = NULL;
	const char *output_https = NULL;
	bool verbose = false;
	bool output_format_explicit = false;
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
			output_format_explicit = true;
			continue;
		}

		if (!strncmp(argv[cmd_idx], "--output-format=", 16)) {
			output_format = argv[cmd_idx] + 16;
			output_format_explicit = true;
			cmd_idx++;
			continue;
		}

		if (!strcmp(argv[cmd_idx], "--verbose")) {
			verbose = true;
			cmd_idx++;
			continue;
		}

		if (!strcmp(argv[cmd_idx], "--output-tcp")) {
			cmd_idx++;
			if (cmd_idx >= argc) {
				fprintf(stderr, "Missing value for --output-tcp\n\n");
				usage(argv[0]);
				return 2;
			}
			output_tcp = argv[cmd_idx++];
			continue;
		}

		if (!strncmp(argv[cmd_idx], "--output-tcp=", 13)) {
			output_tcp = argv[cmd_idx] + 13;
			cmd_idx++;
			continue;
		}

		if (!strcmp(argv[cmd_idx], "--output-http")) {
			cmd_idx++;
			if (cmd_idx >= argc) {
				fprintf(stderr, "Missing value for --output-http\n\n");
				usage(argv[0]);
				return 2;
			}
			output_http = argv[cmd_idx++];
			continue;
		}

		if (!strncmp(argv[cmd_idx], "--output-http=", 14)) {
			output_http = argv[cmd_idx] + 14;
			cmd_idx++;
			continue;
		}

		if (!strcmp(argv[cmd_idx], "--output-https")) {
			cmd_idx++;
			if (cmd_idx >= argc) {
				fprintf(stderr, "Missing value for --output-https\n\n");
				usage(argv[0]);
				return 2;
			}
			output_https = argv[cmd_idx++];
			continue;
		}

		if (!strncmp(argv[cmd_idx], "--output-https=", 15)) {
			output_https = argv[cmd_idx] + 15;
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

	if (output_http && strncmp(output_http, "http://", 7)) {
		fprintf(stderr, "Invalid --output-http URI (expected http://host:port/...): %s\n\n", output_http);
		usage(argv[0]);
		return 2;
	}

	if (output_https && strncmp(output_https, "https://", 8)) {
		fprintf(stderr, "Invalid --output-https URI (expected https://host:port/...): %s\n\n", output_https);
		usage(argv[0]);
		return 2;
	}

	if (output_http && output_https) {
		fprintf(stderr, "Use only one of --output-http or --output-https\n\n");
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

	if (setenv("FW_AUDIT_VERBOSE", verbose ? "1" : "0", 1) != 0) {
		fprintf(stderr, "Failed to set FW_AUDIT_VERBOSE\n");
		return 2;
	}

	if (output_tcp && *output_tcp) {
		if (setenv("FW_AUDIT_OUTPUT_TCP", output_tcp, 1) != 0) {
			fprintf(stderr, "Failed to set FW_AUDIT_OUTPUT_TCP\n");
			return 2;
		}
	} else {
		unsetenv("FW_AUDIT_OUTPUT_TCP");
	}

	if (output_http && *output_http) {
		if (setenv("FW_AUDIT_OUTPUT_HTTP", output_http, 1) != 0) {
			fprintf(stderr, "Failed to set FW_AUDIT_OUTPUT_HTTP\n");
			return 2;
		}
	} else {
		unsetenv("FW_AUDIT_OUTPUT_HTTP");
	}

	if (output_https && *output_https) {
		if (setenv("FW_AUDIT_OUTPUT_HTTPS", output_https, 1) != 0) {
			fprintf(stderr, "Failed to set FW_AUDIT_OUTPUT_HTTPS\n");
			return 2;
		}
	} else {
		unsetenv("FW_AUDIT_OUTPUT_HTTPS");
	}

	if (!strcmp(argv[cmd_idx], "-h") || !strcmp(argv[cmd_idx], "--help") || !strcmp(argv[cmd_idx], "help")) {
		usage(argv[0]);
		return 0;
	}

	if (!strcmp(argv[cmd_idx], "uboot")) {
		int sub_idx = cmd_idx + 1;

		if (sub_idx >= argc || !strcmp(argv[sub_idx], "-h") ||
		    !strcmp(argv[sub_idx], "--help") || !strcmp(argv[sub_idx], "help")) {
			usage(argv[0]);
			return 0;
		}

		if (!strcmp(argv[sub_idx], "env"))
			return uboot_env_scan_main(argc - sub_idx, argv + sub_idx);

		if (!strcmp(argv[sub_idx], "image"))
			return uboot_image_scan_main(argc - sub_idx, argv + sub_idx);

		if (!strcmp(argv[sub_idx], "audit"))
			return embedded_linux_audit_scan_main(argc - sub_idx, argv + sub_idx);

		fprintf(stderr, "Unknown uboot subcommand: %s\n\n", argv[sub_idx]);
		usage(argv[0]);
		return 2;
	}

	if (!strcmp(argv[cmd_idx], "linux")) {
		int sub_idx = cmd_idx + 1;

		if (sub_idx >= argc || !strcmp(argv[sub_idx], "-h") ||
		    !strcmp(argv[sub_idx], "--help") || !strcmp(argv[sub_idx], "help")) {
			usage(argv[0]);
			return 0;
		}

		if (!strcmp(argv[sub_idx], "dmesg")) {
			if (output_format_explicit)
				fprintf(stderr,
					"Warning: --output-format has no effect for dmesg; remote output is always text/plain\n");
			return linux_dmesg_scan_main(argc - sub_idx, argv + sub_idx);
		}

		if (!strcmp(argv[sub_idx], "remote-copy")) {
			if (output_format_explicit)
				fprintf(stderr,
					"Warning: --output-format has no effect for remote-copy; file transfer is raw bytes\n");
			return linux_remote_copy_scan_main(argc - sub_idx, argv + sub_idx);
		}

		if (!strcmp(argv[sub_idx], "list-files")) {
			if (output_format_explicit)
				fprintf(stderr,
					"Warning: --output-format has no effect for list-files; output is always text/plain\n");
			return linux_list_files_scan_main(argc - sub_idx, argv + sub_idx);
		}

		fprintf(stderr, "Unknown linux subcommand: %s\n\n", argv[sub_idx]);
		usage(argv[0]);
		return 2;
	}

	if (!strcmp(argv[cmd_idx], "efi")) {
		int sub_idx = cmd_idx + 1;

		if (sub_idx >= argc || !strcmp(argv[sub_idx], "-h") ||
		    !strcmp(argv[sub_idx], "--help") || !strcmp(argv[sub_idx], "help")) {
			usage(argv[0]);
			return 0;
		}

		if (!strcmp(argv[sub_idx], "orom"))
			return efi_orom_main(argc - sub_idx, argv + sub_idx);

		fprintf(stderr, "Unknown efi subcommand: %s\n\n", argv[sub_idx]);
		usage(argv[0]);
		return 2;
	}

	if (!strcmp(argv[cmd_idx], "bios")) {
		int sub_idx = cmd_idx + 1;

		if (sub_idx >= argc || !strcmp(argv[sub_idx], "-h") ||
		    !strcmp(argv[sub_idx], "--help") || !strcmp(argv[sub_idx], "help")) {
			usage(argv[0]);
			return 0;
		}

		if (!strcmp(argv[sub_idx], "orom"))
			return bios_orom_main(argc - sub_idx, argv + sub_idx);

		fprintf(stderr, "Unknown bios subcommand: %s\n\n", argv[sub_idx]);
		usage(argv[0]);
		return 2;
	}

	fprintf(stderr, "Unknown command group: %s\n\n", argv[cmd_idx]);
	usage(argv[0]);
	return 2;
}