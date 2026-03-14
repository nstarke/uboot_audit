// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "uboot/image/uboot_image_cmd.h"
#include "uboot/image/uboot_image_internal.h"

#include <ctype.h>
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

int uboot_image_list_commands_main(int argc, char **argv)
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
		fprintf(stderr, "--output-tcp requires --send-logs for list-commands\n");
		return 2;
	}

	rc = uboot_image_prepare(verbose, insecure, send_logs, output_tcp, output_http, output_https);
	if (rc)
		return rc;

	rc = uboot_image_list_commands_execute(dev, offset);
	return uboot_image_finish(rc);
}

static bool is_printable_ascii(uint8_t c)
{
	return c >= 0x20 && c <= 0x7e;
}

static bool token_in_list_ci(const char *token, const char *const *list, size_t list_count)
{
	for (size_t i = 0; i < list_count; i++) {
		if (!strcasecmp(token, list[i]))
			return true;
	}
	return false;
}

static bool bytes_contains_token_ci(const uint8_t *buf, size_t len, const char *needle)
{
	size_t nlen;

	if (!buf || !needle)
		return false;

	nlen = strlen(needle);
	if (!nlen || len < nlen)
		return false;

	for (size_t i = 0; i + nlen <= len; i++) {
		size_t j = 0;
		for (; j < nlen; j++) {
			if (tolower((unsigned char)buf[i + j]) != tolower((unsigned char)needle[j]))
				break;
		}
		if (j == nlen)
			return true;
	}

	return false;
}

static bool token_has_command_context(const uint8_t *buf, size_t len, size_t start, size_t end)
{
	static const char *const ctx_needles[] = {
		"unknown command",
		"list of commands",
		"commands",
		"usage:",
		"help",
		"cmd"
	};
	size_t lo = (start > 96U) ? (start - 96U) : 0U;
	size_t hi = end + 96U;

	if (hi > len)
		hi = len;
	if (hi <= lo)
		return false;

	for (size_t i = 0; i < ARRAY_SIZE(ctx_needles); i++) {
		if (bytes_contains_token_ci(buf + lo, hi - lo, ctx_needles[i]))
			return true;
	}

	return false;
}

static bool token_looks_like_command_name(const char *s)
{
	size_t len;
	bool has_alpha = false;

	if (!s)
		return false;

	len = strlen(s);
	if (len < 2 || len > 32)
		return false;

	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)s[i];
		if (!(isalnum(c) || c == '_' || c == '-' || c == '.'))
			return false;
		if (isalpha(c))
			has_alpha = true;
	}

	if (!has_alpha)
		return false;
	if (!isalpha((unsigned char)s[0]))
		return false;

	return true;
}

static int find_extracted_command(struct extracted_command *cmds, size_t count, const char *name)
{
	for (size_t i = 0; i < count; i++) {
		if (!strcmp(cmds[i].name, name))
			return (int)i;
	}
	return -1;
}

static int add_extracted_command(struct extracted_command **cmds,
				 size_t *count,
				 const char *name,
				 int occ_score,
				 bool known,
				 bool context_seen)
{
	int idx = find_extracted_command(*cmds, *count, name);

	if (idx >= 0) {
		struct extracted_command *c = &(*cmds)[(size_t)idx];
		c->hits++;
		if (occ_score > c->best_occ_score)
			c->best_occ_score = occ_score;
		if (known)
			c->known = true;
		if (context_seen)
			c->context_seen = true;
		return 0;
	}

	struct extracted_command *tmp = realloc(*cmds, (*count + 1U) * sizeof(**cmds));
	if (!tmp)
		return -1;
	*cmds = tmp;

	tmp[*count].name = strdup(name);
	if (!tmp[*count].name)
		return -1;
	tmp[*count].hits = 1;
	tmp[*count].best_occ_score = occ_score;
	tmp[*count].known = known;
	tmp[*count].context_seen = context_seen;
	(*count)++;

	return 0;
}

static int extracted_command_final_score(const struct extracted_command *c)
{
	int score;

	if (!c)
		return 0;

	score = c->best_occ_score;
	if (c->known)
		score += 2;
	if (c->context_seen)
		score += 1;
	if (c->hits > 1) {
		unsigned int extra = c->hits - 1;
		if (extra > 3)
			extra = 3;
		score += (int)extra;
	}

	return score;
}

static const char *confidence_from_score(int score)
{
	if (score >= 10)
		return "high";
	if (score >= 7)
		return "medium";
	return "low";
}

static int extracted_command_cmp(const void *a, const void *b)
{
	const struct extracted_command *ca = (const struct extracted_command *)a;
	const struct extracted_command *cb = (const struct extracted_command *)b;
	int sa = extracted_command_final_score(ca);
	int sb = extracted_command_final_score(cb);

	if (sa != sb)
		return sb - sa;

	return strcmp(ca->name, cb->name);
}

static int extract_commands_from_blob(const uint8_t *blob,
				      size_t blob_len,
				      struct extracted_command **out_cmds,
				      size_t *out_count)
{
	static const char *const known_cmds[] = {
		"help", "printenv", "setenv", "env", "saveenv", "run", "echo", "version",
		"bdinfo", "boot", "bootm", "booti", "bootz", "bootd", "source", "reset",
		"mm", "mw", "md", "cmp", "cp", "go", "load", "loadb", "loadx", "loady",
		"fatload", "fatls", "ext4load", "ext4ls", "nand", "ubi", "ubifsmount",
		"ubifsls", "ubifsload", "sf", "mmc", "usb", "dhcp", "tftpboot", "ping",
		"crc32", "iminfo", "imls", "fdt", "itest", "true", "false", "sleep"
	};
	static const char *const stop_tokens[] = {
		"u-boot", "usage", "unknown", "command", "commands", "description",
		"firmware", "images", "image", "load", "data", "hash", "signature", "algo"
	};
	struct extracted_command *cmds = NULL;
	size_t count = 0;
	char token[64];

	if (!blob || !blob_len || !out_cmds || !out_count)
		return -1;

	for (size_t i = 0; i < blob_len;) {
		size_t start = i;
		size_t end;
		size_t len;
		bool known;
		bool context_seen;
		bool has_upper = false;
		bool has_sep = false;
		int occ_score = 0;

		if (!is_printable_ascii(blob[i])) {
			i++;
			continue;
		}

		while (i < blob_len && is_printable_ascii(blob[i]))
			i++;
		end = i;
		len = end - start;

		if (len >= sizeof(token))
			continue;

		memcpy(token, blob + start, len);
		token[len] = '\0';

		if (!token_looks_like_command_name(token))
			continue;

		for (size_t j = 0; j < len; j++) {
			if (isupper((unsigned char)token[j]))
				has_upper = true;
			if (token[j] == '-' || token[j] == '_')
				has_sep = true;
		}

		if (token_in_list_ci(token, stop_tokens, ARRAY_SIZE(stop_tokens)))
			continue;

		known = token_in_list_ci(token, known_cmds, ARRAY_SIZE(known_cmds));
		context_seen = token_has_command_context(blob, blob_len, start, end);

		if (known)
			occ_score += 3;
		if (context_seen)
			occ_score += 3;
		if (!has_upper)
			occ_score += 1;
		if (len >= 3 && len <= 12)
			occ_score += 1;
		if (has_sep)
			occ_score += 1;

		if (occ_score < 2)
			continue;

		if (add_extracted_command(&cmds, &count, token, occ_score, known, context_seen) < 0) {
			for (size_t k = 0; k < count; k++)
				free(cmds[k].name);
			free(cmds);
			return -1;
		}
	}

	if (count)
		qsort(cmds, count, sizeof(*cmds), extracted_command_cmp);

	*out_cmds = cmds;
	*out_count = count;
	return 0;
}

int list_image_commands(const char *dev, uint64_t offset)
{
	uint8_t hdr[UIMAGE_HDR_SIZE];
	uint64_t dev_size = uboot_guess_size_any(dev);
	uint8_t *image_blob = NULL;
	size_t image_len = 0;
	const uint8_t *payload = NULL;
	size_t payload_len = 0;
	struct extracted_command *cmds = NULL;
	size_t cmd_count = 0;
	int fd;
	int rc = 1;

	fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		uboot_img_err_printf("Cannot open %s: %s\n", dev, strerror(errno));
		return 1;
	}

	if (pread(fd, hdr, sizeof(hdr), (off_t)offset) != (ssize_t)sizeof(hdr)) {
		uboot_img_err_printf("Unable to read image header from %s @ 0x%jx\n", dev, (uintmax_t)offset);
		goto out;
	}

	if (!memcmp(hdr, "\x27\x05\x19\x56", 4)) {
		uint32_t total_size;
		uint32_t data_size;

		if (!validate_uimage_header(hdr, offset, dev_size ? dev_size : UINT64_MAX)) {
			uboot_img_err_printf("uImage header validation failed at offset 0x%jx\n", (uintmax_t)offset);
			goto out;
		}

		data_size = ela_read_be32(hdr + 12);
		total_size = UIMAGE_HDR_SIZE + data_size;
		image_len = (size_t)total_size;
		image_blob = malloc(image_len);
		if (!image_blob) {
			uboot_img_err_printf("Unable to allocate memory to inspect uImage\n");
			goto out;
		}

		if (pread(fd, image_blob, image_len, (off_t)offset) != (ssize_t)image_len) {
			uboot_img_err_printf("Unable to read full uImage for command extraction\n");
			goto out;
		}

		payload = image_blob + UIMAGE_HDR_SIZE;
		payload_len = data_size;
	} else if (!memcmp(hdr, "\xD0\x0D\xFE\xED", 4)) {
		uint32_t total_size;
		uint64_t uboot_off = 0;
		bool uboot_off_found = false;
		uint32_t unused_addr = 0;

		if (!validate_fit_header(hdr, offset, dev_size ? dev_size : UINT64_MAX)) {
			uboot_img_err_printf("FIT header validation failed at offset 0x%jx\n", (uintmax_t)offset);
			goto out;
		}

		total_size = ela_read_be32(hdr + 4);
		image_len = (size_t)total_size;
		image_blob = malloc(image_len);
		if (!image_blob) {
			uboot_img_err_printf("Unable to allocate memory to inspect FIT image\n");
			goto out;
		}

		if (pread(fd, image_blob, image_len, (off_t)offset) != (ssize_t)image_len) {
			uboot_img_err_printf("Unable to read full FIT image for command extraction\n");
			goto out;
		}

		(void)fit_find_load_address(image_blob,
					    image_len,
					    &unused_addr,
					    &uboot_off,
					    &uboot_off_found);

		if (uboot_off_found && uboot_off < image_len) {
			payload = image_blob + (size_t)uboot_off;
			payload_len = image_len - (size_t)uboot_off;
		} else {
			payload = image_blob;
			payload_len = image_len;
		}
	} else {
		uboot_img_err_printf("Unknown image format at offset 0x%jx\n", (uintmax_t)offset);
		goto out;
	}

	if (extract_commands_from_blob(payload, payload_len, &cmds, &cmd_count) < 0) {
		uboot_img_err_printf("Failed command extraction from image payload\n");
		goto out;
	}

	if (!cmd_count) {
		if (g_output_format == FW_OUTPUT_TXT)
			uboot_img_out_printf("No likely U-Boot commands extracted from image bytes.\n");
		else
			emit_image_record("image_command", dev, offset, "low", "none");
		rc = 0;
		goto out;
	}

	bool emitted_any = false;
	for (size_t i = 0; i < cmd_count; i++) {
		int score = extracted_command_final_score(&cmds[i]);
		const char *confidence = confidence_from_score(score);

		if (score < 5)
			continue;
		emitted_any = true;

		if (g_output_format == FW_OUTPUT_TXT) {
			uboot_img_out_printf("image command: %s offset=0x%jx command=%s confidence=%s score=%d hits=%u\n",
				dev, (uintmax_t)offset, cmds[i].name, confidence, score, cmds[i].hits);
		} else {
			emit_image_record("image_command", dev, offset, confidence, cmds[i].name);
		}
	}

	if (!emitted_any) {
		if (g_output_format == FW_OUTPUT_TXT)
			uboot_img_out_printf("No likely U-Boot commands extracted from image bytes.\n");
		else
			emit_image_record("image_command", dev, offset, "low", "none");
	}

	rc = 0;

out:
	for (size_t i = 0; i < cmd_count; i++)
		free(cmds[i].name);
	free(cmds);
	free(image_blob);
	close(fd);
	return rc;
}

int uboot_image_list_commands_execute(const char *dev, uint64_t offset)
{
	return list_image_commands(dev, offset);
}
