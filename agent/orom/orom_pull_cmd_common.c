// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "orom_pull_cmd_common.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <glob.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <json.h>
#include <csv.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static void usage(const char *prog, const char *fw_mode)
{
	fprintf(stderr,
		"Usage: %s <pull|list>\n"
		"  pull: read %s PCI option ROM payloads from sysfs and stream bytes to remote output\n"
		"  list: enumerate %s PCI option ROM candidates and emit formatted records\n",
		prog, fw_mode, fw_mode);
}

enum orom_output_format {
	OROM_FMT_TXT = 0,
	OROM_FMT_CSV,
	OROM_FMT_JSON,
};

struct orom_ctx {
	const char *fw_mode;
	bool verbose;
	bool insecure;
	const char *output_tcp;
	const char *output_http;
	const char *output_https;
	const char *output_uri;
	enum orom_output_format fmt;
	bool csv_header_emitted;
};

static void detect_output_format(struct orom_ctx *ctx)
{
	const char *fmt;

	ctx->fmt = OROM_FMT_TXT;
	fmt = getenv("ELA_OUTPUT_FORMAT");
	if (!fmt || !*fmt)
		return;
	if (!strcmp(fmt, "csv"))
		ctx->fmt = OROM_FMT_CSV;
	else if (!strcmp(fmt, "json"))
		ctx->fmt = OROM_FMT_JSON;
}

static void mirror_log_to_remote(struct orom_ctx *ctx, const char *line)
{
	char errbuf[256];
	char *upload_uri = NULL;

	if (!ctx || !line || !*line)
		return;

	if (ctx->output_uri) {
		upload_uri = ela_http_build_upload_uri(ctx->output_uri, "log", NULL);
		if (upload_uri) {
			(void)ela_http_post(upload_uri,
			(const uint8_t *)line,
			strlen(line),
			"text/plain; charset=utf-8",
			ctx->insecure,
			ctx->verbose,
			errbuf,
			sizeof(errbuf));
			free(upload_uri);
		}
	}

	if (ctx->output_tcp) {
		int sock = ela_connect_tcp_ipv4(ctx->output_tcp);
		if (sock >= 0) {
			(void)ela_send_all(sock, (const uint8_t *)line, strlen(line));
			close(sock);
		}
	}
}

static void log_line(struct orom_ctx *ctx, bool verbose_only, const char *fmt, ...)
{
	char line[1024];
	va_list ap;

	if (verbose_only && (!ctx || !ctx->verbose))
		return;

	va_start(ap, fmt);
	vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);

	fputs(line, stderr);
	mirror_log_to_remote(ctx, line);
}

static bool rom_matches_mode(const uint8_t *buf, size_t len, const char *fw_mode)
{
	bool want_efi = !strcmp(fw_mode, "efi");
	bool saw_any = false;

	if (!buf || len < 0x1c)
		return false;

	for (size_t i = 0; i + 0x18 < len; i++) {
		if (i + 4 > len)
			break;
		if (memcmp(buf + i, "PCIR", 4))
			continue;
		saw_any = true;
		if (i + 0x15 >= len)
			continue;
		if (want_efi && buf[i + 0x14] == 0x03)
			return true;
		if (!want_efi && buf[i + 0x14] == 0x00)
			return true;
	}

	/* fallback: if descriptor not found, include payload for both modes */
	return !saw_any;
}

static int read_rom_bytes(const char *rom_path, uint8_t **out, size_t *out_len)
{
	uint8_t *buf = NULL;
	size_t cap = 0;
	size_t len = 0;
	int fd;

	*out = NULL;
	*out_len = 0;

	fd = open(rom_path, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return -1;

	if (write(fd, "1", 1) < 0) {
		close(fd);
		return -1;
	}
	(void)lseek(fd, 0, SEEK_SET);

	for (;;) {
		uint8_t tmp[4096];
		ssize_t n = read(fd, tmp, sizeof(tmp));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			free(buf);
			(void)lseek(fd, 0, SEEK_SET);
			if (write(fd, "0", 1) < 0) {
				/* best effort disable */
			}
			close(fd);
			return -1;
		}
		if (n == 0)
			break;
		if (len + (size_t)n > cap) {
			size_t next = cap ? cap * 2U : 8192U;
			uint8_t *grown;
			while (next < len + (size_t)n)
				next *= 2U;
			grown = realloc(buf, next);
			if (!grown) {
				free(buf);
				(void)lseek(fd, 0, SEEK_SET);
				if (write(fd, "0", 1) < 0) {
					/* best effort disable */
				}
				close(fd);
				return -1;
			}
			buf = grown;
			cap = next;
		}
		memcpy(buf + len, tmp, (size_t)n);
		len += (size_t)n;
	}

	(void)lseek(fd, 0, SEEK_SET);
	if (write(fd, "0", 1) < 0) {
		/* best effort disable */
	}
	close(fd);

	*out = buf;
	*out_len = len;
	return 0;
}

static int send_rom_tcp(const char *output_tcp, const char *name, const uint8_t *data, size_t len)
{
	int sock;
	char hdr[512];
	int hlen;

	sock = ela_connect_tcp_ipv4(output_tcp);
	if (sock < 0)
		return -1;

	hlen = snprintf(hdr, sizeof(hdr), "OROM %s %zu\n", name, len);
	if (hlen < 0 || (size_t)hlen >= sizeof(hdr)) {
		close(sock);
		return -1;
	}

	if (ela_send_all(sock, (const uint8_t *)hdr, (size_t)hlen) < 0 ||
	    ela_send_all(sock, data, len) < 0) {
		close(sock);
		return -1;
	}

	close(sock);
	return 0;
}

static int send_rom_http(const char *output_uri,
			 bool insecure,
			 bool verbose,
			 const char *name,
			 const uint8_t *data,
			 size_t len)
{
	char errbuf[256];
	char *upload_uri;
	char *payload;
	size_t name_len = strlen(name);
	int rc;

	payload = malloc(name_len + 1 + len);
	if (!payload)
		return -1;

	memcpy(payload, name, name_len);
	payload[name_len] = '\n';
	memcpy(payload + name_len + 1, data, len);

	upload_uri = ela_http_build_upload_uri(output_uri, "orom", name);
	if (!upload_uri) {
		free(payload);
		return -1;
	}

	rc = ela_http_post(upload_uri,
		(const uint8_t *)payload,
		name_len + 1 + len,
		"application/octet-stream",
		insecure,
		verbose,
		errbuf,
		sizeof(errbuf));
	free(upload_uri);
	free(payload);
	return rc;
}

static void emit_csv_header(struct orom_ctx *ctx)
{
	if (!ctx || ctx->csv_header_emitted)
		return;
	printf("record,mode,rom_path,size,type,value\n");
	ctx->csv_header_emitted = true;
}

static void csv_out_field(const char *s)
{
	const char *in = s ? s : "";
	size_t in_len = strlen(in);
	size_t buf_len = (in_len * 2U) + 3U;
	char *buf = malloc(buf_len);
	size_t written;

	if (!buf)
		return;
	written = csv_write(buf, buf_len, in, in_len);
	printf("%.*s", (int)written, buf);
	free(buf);
}

static void emit_record(struct orom_ctx *ctx,
			const char *record,
			const char *rom_path,
			size_t size,
			const char *type,
			const char *value)
{
	char line[1024];

	if (!ctx)
		return;

	if (ctx->fmt == OROM_FMT_CSV) {
		char size_s[32];
		emit_csv_header(ctx);
		snprintf(size_s, sizeof(size_s), "%zu", size);
		csv_out_field(record); printf(",");
		csv_out_field(ctx->fw_mode); printf(",");
		csv_out_field(rom_path ? rom_path : ""); printf(",");
		csv_out_field(size_s); printf(",");
		csv_out_field(type ? type : ""); printf(",");
		csv_out_field(value ? value : ""); printf("\n");
		fflush(stdout);
		snprintf(line, sizeof(line), "%s,%s,%s,%s,%s,%s\n",
			record ? record : "",
			ctx->fw_mode ? ctx->fw_mode : "",
			rom_path ? rom_path : "",
			size_s,
			type ? type : "",
			value ? value : "");
		mirror_log_to_remote(ctx, line);
		return;
	}

	if (ctx->fmt == OROM_FMT_JSON) {
		json_object *obj = json_object_new_object();
		const char *js;
		if (!obj)
			return;
		json_object_object_add(obj, "record", json_object_new_string(record ? record : ""));
		json_object_object_add(obj, "mode", json_object_new_string(ctx->fw_mode ? ctx->fw_mode : ""));
		if (rom_path)
			json_object_object_add(obj, "rom_path", json_object_new_string(rom_path));
		json_object_object_add(obj, "size", json_object_new_uint64((uint64_t)size));
		if (type)
			json_object_object_add(obj, "type", json_object_new_string(type));
		if (value)
			json_object_object_add(obj, "value", json_object_new_string(value));
		js = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
		printf("%s\n", js);
		fflush(stdout);
		snprintf(line, sizeof(line), "%s\n", js);
		mirror_log_to_remote(ctx, line);
		json_object_put(obj);
		return;
	}

	snprintf(line, sizeof(line), "orom %s mode=%s rom=%s size=%zu %s=%s\n",
		record ? record : "record",
		ctx->fw_mode ? ctx->fw_mode : "",
		rom_path ? rom_path : "",
		size,
		type ? type : "type",
		value ? value : "");
	printf("%s", line);
	fflush(stdout);
	mirror_log_to_remote(ctx, line);
}

static int orom_execute_pull(struct orom_ctx *ctx)
{
	glob_t g;
	int pulled = 0;

	if ((!ctx->output_tcp || !*ctx->output_tcp) && (!ctx->output_uri || !*ctx->output_uri)) {
		log_line(ctx, false,
			"pull requires one of --output-tcp or --output-http\n");
		return 2;
	}

	if (glob("/sys/bus/pci/devices/*/rom", 0, NULL, &g) != 0) {
		log_line(ctx, false, "No PCI ROM sysfs nodes found\n");
		return 1;
	}

	for (size_t i = 0; i < g.gl_pathc; i++) {
		const char *rom_path = g.gl_pathv[i];
		uint8_t *rom = NULL;
		size_t rom_len = 0;

		log_line(ctx, true, "[orom %s pull] inspect %s\n", ctx->fw_mode, rom_path);

		if (read_rom_bytes(rom_path, &rom, &rom_len) < 0 || !rom || rom_len == 0) {
			free(rom);
			continue;
		}

		if (!rom_matches_mode(rom, rom_len, ctx->fw_mode)) {
			free(rom);
			continue;
		}

		log_line(ctx, true, "[orom %s pull] send %s bytes=%zu\n", ctx->fw_mode, rom_path, rom_len);

		if (ctx->output_tcp) {
			if (send_rom_tcp(ctx->output_tcp, rom_path, rom, rom_len) < 0) {
				free(rom);
				globfree(&g);
				log_line(ctx, false, "Failed to send ROM over TCP\n");
				return 1;
			}
		} else {
			if (send_rom_http(ctx->output_uri, ctx->insecure, ctx->verbose, rom_path, rom, rom_len) < 0) {
				free(rom);
				globfree(&g);
				log_line(ctx, false, "Failed to send ROM over HTTP(S)\n");
				return 1;
			}
		}

		emit_record(ctx, "orom_pull", rom_path, rom_len, "status", "sent");
		pulled++;
		free(rom);
	}

	globfree(&g);

	if (pulled == 0) {
		log_line(ctx, false, "No matching %s option ROM payloads found\n", ctx->fw_mode);
		return 1;
	}

	log_line(ctx, true, "[orom %s pull] sent %d ROM payload(s)\n", ctx->fw_mode, pulled);
	return 0;
}

static int orom_execute_list(struct orom_ctx *ctx)
{
	glob_t g;
	int listed = 0;

	if (glob("/sys/bus/pci/devices/*/rom", 0, NULL, &g) != 0) {
		log_line(ctx, false, "No PCI ROM sysfs nodes found\n");
		return 1;
	}

	for (size_t i = 0; i < g.gl_pathc; i++) {
		const char *rom_path = g.gl_pathv[i];
		uint8_t *rom = NULL;
		size_t rom_len = 0;

		log_line(ctx, true, "[orom %s list] inspect %s\n", ctx->fw_mode, rom_path);

		if (read_rom_bytes(rom_path, &rom, &rom_len) < 0 || !rom || rom_len == 0) {
			free(rom);
			continue;
		}

		if (!rom_matches_mode(rom, rom_len, ctx->fw_mode)) {
			free(rom);
			continue;
		}

		emit_record(ctx, "orom_list", rom_path, rom_len, "match", "true");
		listed++;
		free(rom);
	}

	globfree(&g);

	if (listed == 0) {
		log_line(ctx, false, "No matching %s option ROM payloads found\n", ctx->fw_mode);
		emit_record(ctx, "orom_list", "", 0, "match", "none");
		return 1;
	}

	return 0;
}

int orom_group_main(const char *fw_mode, int argc, char **argv)
{
	struct orom_ctx ctx;
	const char *action;
	int opt;

	optind = 1;
	memset(&ctx, 0, sizeof(ctx));
	ctx.fw_mode = fw_mode;
	ctx.verbose = getenv("ELA_VERBOSE") && !strcmp(getenv("ELA_VERBOSE"), "1");
	ctx.insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	ctx.output_tcp = getenv("ELA_OUTPUT_TCP");
	ctx.output_http = getenv("ELA_OUTPUT_HTTP");
	ctx.output_https = getenv("ELA_OUTPUT_HTTPS");
	detect_output_format(&ctx);

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "output-tcp", required_argument, NULL, 't' },
		{ "output-http", required_argument, NULL, 'O' },
		{ 0, 0, 0, 0 }
	};

	if (argc < 2) {
		usage(argv[0], fw_mode);
		return 2;
	}

	action = argv[1];
	if (!strcmp(action, "-h") || !strcmp(action, "--help") || !strcmp(action, "help")) {
		usage(argv[0], fw_mode);
		return 0;
	}
	if (strcmp(action, "pull") && strcmp(action, "list")) {
		usage(argv[0], fw_mode);
		return 2;
	}

	optind = 2;

	while ((opt = getopt_long(argc, argv, "ht:O:", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0], fw_mode);
			return 0;
		case 't':
			ctx.output_tcp = optarg;
			break;
		case 'O':
			{
				const char *new_output_http = NULL;
				const char *new_output_https = NULL;
				if (ela_parse_http_output_uri(optarg,
						      &new_output_http,
						      &new_output_https,
						      NULL,
						      0) < 0)
				ctx.output_http = optarg;
				else {
					if ((ctx.output_http && new_output_https) || (ctx.output_https && new_output_http)) {
						fprintf(stderr, "Use only one of --output-http or --output-https\n");
						return 2;
					}
					ctx.output_http = new_output_http;
					ctx.output_https = new_output_https;
				}
			}
			break;
		default:
			usage(argv[0], fw_mode);
			return 2;
		}
	}

	if (optind < argc) {
		usage(argv[0], fw_mode);
		return 2;
	}

	if (ctx.output_http &&
	    !ctx.output_https &&
	    strncmp(ctx.output_http, "http://", 7)) {
		fprintf(stderr, "Invalid --output-http URI (expected http://host:port/... or https://host:port/...): %s\n", ctx.output_http);
		return 2;
	}

	if (ctx.output_http && ctx.output_https) {
		fprintf(stderr, "Use only one of --output-http or --output-https\n");
		return 2;
	}

	ctx.output_uri = ctx.output_http ? ctx.output_http : ctx.output_https;

	/* Validate pull's required output target before the ISA check so that
	 * missing-argument errors correctly return rc=2 on all ISAs. */
	if (!strcmp(action, "pull") &&
	    (!ctx.output_tcp || !*ctx.output_tcp) &&
	    (!ctx.output_uri || !*ctx.output_uri)) {
		fprintf(stderr, "pull requires one of --output-tcp or --output-http\n");
		return 2;
	}

	{
		const char *isa = ela_detect_isa();

		if (!ela_isa_supported_for_efi_bios(isa)) {
			fprintf(stderr,
				"Unsupported ISA for %s group: %s (supported: x86, x86_64, aarch64-be, aarch64-le)\n",
				fw_mode, isa ? isa : "unknown");
			return 1;
		}
	}

	if (!strcmp(action, "pull"))
		return orom_execute_pull(&ctx);

	return orom_execute_list(&ctx);
}
