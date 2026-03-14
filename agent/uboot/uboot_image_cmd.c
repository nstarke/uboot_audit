// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "uboot/image/uboot_image_cmd.h"
#include "uboot/image/uboot_image_internal.h"

#include <errno.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <getopt.h>
#include <glob.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <json.h>
#include <csv.h>

/* Global state definitions (authoritative) */
bool g_verbose;
bool g_allow_text;
const char *g_allow_text_pattern = "U-Boot";
bool g_send_logs;
bool g_insecure;
uint32_t g_crc32_table[256];
int g_log_sock = -1;
const char *g_pull_binary_content_type = "application/octet-stream";
const char *g_output_http_uri = NULL;
char *g_output_http_buf = NULL;
size_t g_output_http_len;
size_t g_output_http_cap;
enum uboot_output_format g_output_format = FW_OUTPUT_TXT;
bool g_csv_header_emitted;

static const char *image_http_content_type(void);
static void err_printf(const char *fmt, ...);

int flush_output_http_buffer(void)
{
	char errbuf[256];
	char *upload_uri;

	if (!g_output_http_uri)
		return 0;

	if (g_output_http_len == 0)
		return 0;

	upload_uri = ela_http_build_upload_uri(g_output_http_uri, "log", NULL);
	if (!upload_uri)
		return -1;

	if (ela_http_post(upload_uri,
			 (const uint8_t *)(g_output_http_buf ? g_output_http_buf : ""),
			 g_output_http_len,
			 image_http_content_type(),
			 g_insecure,
			 g_verbose,
			 errbuf,
			 sizeof(errbuf)) < 0) {
		err_printf("Failed to POST output to %s: %s\n", upload_uri,
			errbuf[0] ? errbuf : "unknown error");
		free(upload_uri);
		return -1;
	}

	free(upload_uri);

	g_output_http_len = 0;
	if (g_output_http_buf)
		g_output_http_buf[0] = '\0';

	return 0;
}

static const char *image_http_content_type(void)
{
	switch (g_output_format) {
	case FW_OUTPUT_JSON:
		return "application/x-ndjson; charset=utf-8";
	case FW_OUTPUT_CSV:
		return "text/csv; charset=utf-8";
	case FW_OUTPUT_TXT:
	default:
		return "text/plain; charset=utf-8";
	}
}

static void emit_v(FILE *stream, const char *fmt, va_list ap)
{
	va_list aq;
	char stack[1024];
	char *dyn = NULL;
	int needed;
	bool mirror_to_remote;

	mirror_to_remote = (stream == stdout);

	va_copy(aq, ap);
	vfprintf(stream, fmt, ap);
	fflush(stream);

	needed = vsnprintf(stack, sizeof(stack), fmt, aq);
	va_end(aq);

	if (needed < 0)
		return;

	if ((size_t)needed < sizeof(stack)) {
		if (mirror_to_remote && g_log_sock >= 0)
			ela_send_all(g_log_sock, (const uint8_t *)stack, (size_t)needed);
		if (mirror_to_remote && g_output_http_uri) {
			size_t need = g_output_http_len + (size_t)needed + 1;
			if (need > g_output_http_cap) {
				size_t new_cap = g_output_http_cap ? g_output_http_cap : 1024;
				char *tmp;
				while (new_cap < need)
					new_cap *= 2;
				tmp = realloc(g_output_http_buf, new_cap);
				if (tmp) {
					g_output_http_buf = tmp;
					g_output_http_cap = new_cap;
					memcpy(g_output_http_buf + g_output_http_len, stack, (size_t)needed);
					g_output_http_len += (size_t)needed;
					g_output_http_buf[g_output_http_len] = '\0';
				}
			} else {
				memcpy(g_output_http_buf + g_output_http_len, stack, (size_t)needed);
				g_output_http_len += (size_t)needed;
				g_output_http_buf[g_output_http_len] = '\0';
			}
		}
		return;
	}

	dyn = malloc((size_t)needed + 1);
	if (!dyn)
		return;

	va_copy(aq, ap);
	vsnprintf(dyn, (size_t)needed + 1, fmt, aq);
	va_end(aq);
	if (mirror_to_remote && g_log_sock >= 0)
		ela_send_all(g_log_sock, (const uint8_t *)dyn, (size_t)needed);
	if (mirror_to_remote && g_output_http_uri) {
		size_t need = g_output_http_len + (size_t)needed + 1;
		if (need > g_output_http_cap) {
			size_t new_cap = g_output_http_cap ? g_output_http_cap : 1024;
			char *tmp;
			while (new_cap < need)
				new_cap *= 2;
			tmp = realloc(g_output_http_buf, new_cap);
			if (tmp) {
				g_output_http_buf = tmp;
				g_output_http_cap = new_cap;
				memcpy(g_output_http_buf + g_output_http_len, dyn, (size_t)needed);
				g_output_http_len += (size_t)needed;
				g_output_http_buf[g_output_http_len] = '\0';
			}
		} else {
			memcpy(g_output_http_buf + g_output_http_len, dyn, (size_t)needed);
			g_output_http_len += (size_t)needed;
			g_output_http_buf[g_output_http_len] = '\0';
		}
	}
	free(dyn);
}

static void out_printf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	emit_v(stdout, fmt, ap);
	va_end(ap);
}

static void err_printf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	emit_v(stderr, fmt, ap);
	va_end(ap);
}

void uboot_img_out_printf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	emit_v(stdout, fmt, ap);
	va_end(ap);
}

void uboot_img_err_printf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	emit_v(stderr, fmt, ap);
	va_end(ap);
}

static void detect_output_format(void)
{
	const char *fmt = getenv("ELA_OUTPUT_FORMAT");

	g_output_format = FW_OUTPUT_TXT;
	if (!fmt || !*fmt)
		return;

	if (!strcmp(fmt, "csv"))
		g_output_format = FW_OUTPUT_CSV;
	else if (!strcmp(fmt, "json"))
		g_output_format = FW_OUTPUT_JSON;
}

static void emit_image_csv_header(void)
{
	if (g_csv_header_emitted)
		return;
	out_printf("record,device,offset,type,value\n");
	g_csv_header_emitted = true;
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
	out_printf("%.*s", (int)written, buf);
	free(buf);
}

void emit_image_record(const char *record, const char *dev, uint64_t off,
		       const char *type, const char *value)
{
	if (g_output_format == FW_OUTPUT_CSV) {
		char off_s[32];

		snprintf(off_s, sizeof(off_s), "0x%jx", (uintmax_t)off);
		emit_image_csv_header();
		csv_out_field(record ? record : ""); out_printf(",");
		csv_out_field(dev ? dev : ""); out_printf(",");
		csv_out_field(off_s); out_printf(",");
		csv_out_field(type ? type : ""); out_printf(",");
		csv_out_field(value ? value : ""); out_printf("\n");
		return;
	}

	if (g_output_format == FW_OUTPUT_JSON) {
		json_object *obj = json_object_new_object();
		if (!obj)
			return;
		json_object_object_add(obj, "record", json_object_new_string(record ? record : ""));
		if (dev)
			json_object_object_add(obj, "device", json_object_new_string(dev));
		json_object_object_add(obj, "offset", json_object_new_uint64(off));
		json_object_object_add(obj, "type", json_object_new_string(type ? type : ""));
		if (value)
			json_object_object_add(obj, "value", json_object_new_string(value));
		out_printf("%s\n", json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN));
		json_object_put(obj);
	}
}

void emit_image_verbose(const char *dev, uint64_t off, const char *msg)
{
	bool emitted = false;

	if (!g_verbose || !msg)
		return;

	if (g_output_format == FW_OUTPUT_TXT) {
		out_printf("%s\n", msg);
		emitted = true;
	} else {
		emit_image_record("verbose", dev ? dev : "", off, "log", msg);
		emitted = true;
	}

	if (emitted && g_output_http_uri && g_output_http_len > 0)
		(void)flush_output_http_buffer();
}

static size_t align_up_4(size_t v)
{
	return (v + 3U) & ~((size_t)3U);
}

static bool str_contains_token_ci(const char *haystack, const char *needle)
{
	size_t needle_len;

	if (!haystack || !needle)
		return false;

	needle_len = strlen(needle);
	if (!needle_len)
		return true;

	for (const char *p = haystack; *p; p++) {
		if (!strncasecmp(p, needle, needle_len))
			return true;
	}

	return false;
}

bool validate_fit_header(const uint8_t *p, uint64_t abs_off, uint64_t dev_size)
{
	uint32_t totalsize = ela_read_be32(p + 4);
	uint32_t off_dt_struct = ela_read_be32(p + 8);
	uint32_t off_dt_strings = ela_read_be32(p + 12);
	uint32_t off_mem_rsvmap = ela_read_be32(p + 16);
	uint32_t version = ela_read_be32(p + 20);
	uint32_t last_comp_version = ela_read_be32(p + 24);
	uint32_t size_dt_strings = ela_read_be32(p + 32);
	uint32_t size_dt_struct = ela_read_be32(p + 36);

	if (totalsize < FIT_MIN_TOTAL_SIZE || totalsize > FIT_MAX_TOTAL_SIZE)
		return false;
	if (abs_off + totalsize > dev_size)
		return false;

	if (off_mem_rsvmap < 40 || off_mem_rsvmap >= totalsize)
		return false;
	if (off_dt_struct >= totalsize || off_dt_strings >= totalsize)
		return false;
	if (size_dt_struct == 0 || size_dt_strings == 0)
		return false;
	if ((uint64_t)off_dt_struct + size_dt_struct > totalsize)
		return false;
	if ((uint64_t)off_dt_strings + size_dt_strings > totalsize)
		return false;

	if (version < 16 || version > 17)
		return false;
	if (last_comp_version > version)
		return false;

	return true;
}

bool validate_uimage_header(const uint8_t *p, uint64_t abs_off, uint64_t dev_size)
{
	uint8_t hdr[UIMAGE_HDR_SIZE];
	uint32_t header_crc;
	uint32_t calc_crc;
	uint32_t data_size;

	memcpy(hdr, p, sizeof(hdr));
	header_crc = ela_read_be32(hdr + 4);
	hdr[4] = hdr[5] = hdr[6] = hdr[7] = 0;
	calc_crc = ela_crc32_calc(g_crc32_table, hdr, sizeof(hdr));
	if (calc_crc != header_crc)
		return false;

	data_size = ela_read_be32(p + 12);
	if (data_size == 0 || data_size > UIMAGE_MAX_DATA_SIZE)
		return false;
	if (abs_off + UIMAGE_HDR_SIZE + data_size > dev_size)
		return false;

	return true;
}

bool fit_find_load_address(const uint8_t *blob,
			   size_t blob_size,
			   uint32_t *addr_out,
			   uint64_t *uboot_off_out,
			   bool *uboot_off_found_out)
{
	const uint32_t FDT_BEGIN_NODE = 1;
	const uint32_t FDT_END_NODE = 2;
	const uint32_t FDT_PROP = 3;
	const uint32_t FDT_NOP = 4;
	const uint32_t FDT_END = 9;
	const int MAX_DEPTH = 64;
	uint32_t off_dt_struct;
	uint32_t off_dt_strings;
	uint32_t total_size;
	uint32_t size_dt_struct;
	uint32_t size_dt_strings;
	const uint8_t *p;
	const uint8_t *end;
	const char *strings;
	const char *node_stack[MAX_DEPTH];
	int depth = -1;
	bool load_found = false;
	uint32_t load_value = 0;
	bool in_image_node = false;
	int image_depth = -1;
	bool image_name_uboot = false;
	bool image_desc_uboot = false;
	bool image_type_firmware = false;
	bool image_payload_off_found = false;
	uint64_t image_payload_off = 0;
	bool chosen_uboot_off = false;
	uint64_t chosen_uboot_off_val = 0;

	if (uboot_off_found_out)
		*uboot_off_found_out = false;
	if (uboot_off_out)
		*uboot_off_out = 0;

	if (!blob || blob_size < 40 || !addr_out)
		return false;

	total_size = ela_read_be32(blob + 4);
	off_dt_struct = ela_read_be32(blob + 8);
	off_dt_strings = ela_read_be32(blob + 12);
	size_dt_strings = ela_read_be32(blob + 32);
	size_dt_struct = ela_read_be32(blob + 36);

	if ((uint64_t)off_dt_struct + size_dt_struct > blob_size)
		return false;
	if ((uint64_t)off_dt_strings + size_dt_strings > blob_size)
		return false;

	p = blob + off_dt_struct;
	end = p + size_dt_struct;
	strings = (const char *)blob + off_dt_strings;

	while (p + 4 <= end) {
		uint32_t token = ela_read_be32(p);
		p += 4;

		switch (token) {
		case FDT_BEGIN_NODE: {
			const uint8_t *name_start = p;
			const char *name;
			while (p < end && *p)
				p++;
			if (p >= end)
				return false;
			name = (const char *)name_start;
			p++;
			p = name_start + align_up_4((size_t)(p - name_start));

			if (depth + 1 >= MAX_DEPTH)
				return false;
			depth++;
			node_stack[depth] = name;

			if (depth == 2 && !strcmp(node_stack[1], "images")) {
				in_image_node = true;
				image_depth = depth;
				image_name_uboot = str_contains_token_ci(name, "u-boot");
				image_desc_uboot = false;
				image_type_firmware = false;
				image_payload_off_found = false;
				image_payload_off = 0;
			}
			break;
		}
		case FDT_END_NODE:
			if (depth < 0)
				return false;
			if (in_image_node && depth == image_depth) {
				bool is_uboot_candidate = image_name_uboot || image_desc_uboot || image_type_firmware;
				if (!chosen_uboot_off && is_uboot_candidate && image_payload_off_found) {
					chosen_uboot_off = true;
					chosen_uboot_off_val = image_payload_off;
				}
				in_image_node = false;
				image_depth = -1;
			}
			depth--;
			break;
		case FDT_NOP:
			break;
		case FDT_END:
			if (load_found)
				*addr_out = load_value;
			if (chosen_uboot_off && uboot_off_found_out)
				*uboot_off_found_out = true;
			if (chosen_uboot_off && uboot_off_out)
				*uboot_off_out = chosen_uboot_off_val;
			return load_found;
		case FDT_PROP: {
			uint32_t len;
			uint32_t nameoff;
			const char *name;
			const uint8_t *data;

			if (p + 8 > end)
				return false;
			len = ela_read_be32(p);
			nameoff = ela_read_be32(p + 4);
			p += 8;
			if (nameoff >= size_dt_strings)
				return false;
			if ((uint64_t)(end - p) < len)
				return false;

			name = strings + nameoff;
			data = p;
			if (!strcmp(name, "load") && len >= 4 && !load_found) {
				load_value = ela_read_be32(data);
				if (len >= 8 && load_value == 0)
					load_value = ela_read_be32(data + 4);
				load_found = true;
			}

			if (in_image_node) {
				if (!strcmp(name, "description") && len > 0)
					image_desc_uboot = str_contains_token_ci((const char *)data, "u-boot");

				if (!strcmp(name, "type") && len > 0 && !strcasecmp((const char *)data, "firmware"))
					image_type_firmware = true;

				if (!strcmp(name, "data") && len > 0) {
					image_payload_off_found = true;
					image_payload_off = (uint64_t)(data - blob);
				}

				if (!strcmp(name, "data-position") && len >= 4) {
					uint64_t pos = ela_read_be32(data);
					if (len >= 8 && pos == 0)
						pos = ela_read_be32(data + 4);
					image_payload_off_found = true;
					image_payload_off = pos;
				}

				if (!strcmp(name, "data-offset") && len >= 4) {
					uint64_t ext_off = ela_read_be32(data);
					if (len >= 8 && ext_off == 0)
						ext_off = ela_read_be32(data + 4);
					image_payload_off_found = true;
					image_payload_off = (uint64_t)total_size + ext_off;
				}
			}

			p += align_up_4((size_t)len);
			break;
		}
		default:
			return false;
		}
	}

	if (load_found)
		*addr_out = load_value;
	if (chosen_uboot_off && uboot_off_found_out)
		*uboot_off_found_out = true;
	if (chosen_uboot_off && uboot_off_out)
		*uboot_off_out = chosen_uboot_off_val;

	return load_found;
}

static void report_signature(const char *dev, uint64_t off, const char *kind)
{
	if (g_output_format == FW_OUTPUT_TXT) {
		out_printf("candidate image signature: %s offset=0x%jx type=%s\n",
		       dev, (uintmax_t)off, kind);
		return;
	}
	emit_image_record("image_signature", dev, off, kind, NULL);
}

static int scan_dev_for_image(const char *dev, uint64_t step)
{
	static const uint8_t uimage_magic[] = { 0x27, 0x05, 0x19, 0x56 };
	static const uint8_t fit_magic[] = { 0xD0, 0x0D, 0xFE, 0xED };
	const char *text_pattern = g_allow_text_pattern ? g_allow_text_pattern : "U-Boot";
	size_t text_pattern_len = strlen(text_pattern);
	int fd;
	struct stat st;
	uint64_t size = 0;
	uint64_t off;
	uint8_t *buf;
	int hits = 0;

	fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == EBUSY) {
			if (g_verbose) {
				char msg[256];
				snprintf(msg, sizeof(msg), "Skipping busy device %s: %s", dev, strerror(errno));
				emit_image_verbose(dev, 0, msg);
			}
			return 0;
		}
		err_printf("Cannot open %s: %s\n", dev, strerror(errno));
		return -1;
	}

	if (fstat(fd, &st) == 0)
		size = (uint64_t)st.st_size;
	if (!size)
		size = uboot_guess_size_any(dev);

	if (!size) {
		close(fd);
		return -1;
	}

	buf = malloc((size_t)step);
	if (!buf) {
		close(fd);
		return -1;
	}

	if (g_verbose) {
		char msg[256];
		snprintf(msg, sizeof(msg), "Scanning %s size=0x%jx step=0x%jx",
			dev, (uintmax_t)size, (uintmax_t)step);
		emit_image_verbose(dev, 0, msg);
	}

	for (off = 0; off < size; off += step) {
		size_t to_read = (size - off > step) ? (size_t)step : (size_t)(size - off);
		ssize_t n = pread(fd, buf, to_read, (off_t)off);
		if (n <= 0)
			break;

		for (size_t i = 0; i + UIMAGE_HDR_SIZE <= (size_t)n; i += 4) {
			if (!memcmp(buf + i, uimage_magic, sizeof(uimage_magic))) {
				if (validate_uimage_header(buf + i, off + i, size)) {
					report_signature(dev, off + i, "uImage");
					hits++;
				}
			}
			if (!memcmp(buf + i, fit_magic, sizeof(fit_magic))) {
				if (validate_fit_header(buf + i, off + i, size)) {
					report_signature(dev, off + i, "FIT");
					hits++;
				}
			}
		}

		if (g_allow_text && text_pattern_len > 0) {
			for (size_t i = 0; i + text_pattern_len <= (size_t)n; i++) {
				if (!memcmp(buf + i, text_pattern, text_pattern_len)) {
					report_signature(dev, off + i, "U-Boot-text");
					hits++;
				}
			}
		}
	}

	free(buf);
	close(fd);
	return hits;
}

uint64_t uboot_image_parse_u64(const char *s)
{
	uint64_t v;

	if (ela_parse_u64(s, &v)) {
		fprintf(stderr, "Invalid number: %s\n", s);
		exit(2);
	}
	return v;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--dev <device>] [--step <bytes>] [--allow-text]\n"
		"       %s [--skip-remove] [--skip-mtd] [--skip-ubi] [--skip-sd] [--skip-emmc]\n"
		"       %s pull --dev <device> --offset <bytes>\n"
		"       %s find-address --dev <device> --offset <bytes>\n"
		"       %s list-commands --dev <device> --offset <bytes>\n"
		"  no args: scan /dev/mtdblock*, /dev/ubi*_*, /dev/ubiblock*_*, /dev/mmcblk* and /dev/sd* for U-Boot image signatures\n"
		"  --dev: scan only a specific device\n"
		"  --step: step size when scanning (default: 0x1000)\n"
		"  --allow-text[=<text>]: also match plain text (default: 'U-Boot'; higher false-positive risk)\n"
		"  --skip-remove: keep any helper /dev nodes created during scan\n"
		"  --skip-mtd: skip mtdblock scan targets\n"
		"  --skip-ubi: skip UBI and ubiblock scan targets\n"
		"  --skip-sd: skip /dev/sd* scan targets\n"
		"  --skip-emmc: skip /dev/mmcblk* scan targets\n"
		"  pull: read image from --dev at --offset and stream bytes to a remote destination\n"
		"  find-address: print image load address from header/FIT data\n"
		"  list-commands: best-effort extraction of command names from image bytes\n",
		prog, prog, prog, prog, prog);
}

int uboot_image_scan_main(int argc, char **argv)
{
	const char *dev_override = NULL;
	const char *output_tcp_target = getenv("ELA_OUTPUT_TCP");
	const char *output_http_target = getenv("ELA_OUTPUT_HTTP");
	const char *output_https_target = getenv("ELA_OUTPUT_HTTPS");
	uint64_t step = 0x1000;
	bool skip_mtd = false;
	bool skip_ubi = false;
	bool skip_sd = false;
	bool skip_emmc = false;
	bool skip_remove = false;
	bool send_logs = false;
	bool helper_verbose = false;
	char **created_mtdblock_nodes = NULL;
	size_t created_mtdblock_count = 0;
	char **created_ubi_nodes = NULL;
	size_t created_ubi_count = 0;
	char **created_block_nodes = NULL;
	size_t created_block_count = 0;
	int opt;
	int total_hits = 0;

	optind = 1;
	detect_output_format();
	g_verbose = getenv("ELA_VERBOSE") && !strcmp(getenv("ELA_VERBOSE"), "1");
	g_allow_text = false;
	g_allow_text_pattern = "U-Boot";
	g_insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	if (argc > 1) {
		if (!strcmp(argv[1], "pull"))
			return uboot_image_pull_main(argc - 1, argv + 1);
		if (!strcmp(argv[1], "find-address"))
			return uboot_image_find_address_main(argc - 1, argv + 1);
		if (!strcmp(argv[1], "list-commands"))
			return uboot_image_list_commands_main(argc - 1, argv + 1);
	}

	static const struct option long_opts[] = {
		{ "dev", required_argument, NULL, 'd' },
		{ "step", required_argument, NULL, 's' },
		{ "send-logs", no_argument, NULL, 'L' },
		{ "allow-text", optional_argument, NULL, 't' },
		{ "skip-remove", no_argument, NULL, 'R' },
		{ "skip-mtd", no_argument, NULL, 'M' },
		{ "skip-ubi", no_argument, NULL, 'U' },
		{ "skip-sd", no_argument, NULL, 'S' },
		{ "skip-emmc", no_argument, NULL, 'E' },
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "hd:s:t::LRMUSE", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'd':
			dev_override = optarg;
			break;
		case 's':
			step = uboot_image_parse_u64(optarg);
			if (!step)
				step = 0x1000;
			break;
		case 'L':
			send_logs = true;
			break;
		case 't':
			g_allow_text = true;
			if (optarg && *optarg) {
				g_allow_text_pattern = optarg;
			} else if (optind < argc && argv[optind] && argv[optind][0] != '-') {
				g_allow_text_pattern = argv[optind];
				optind++;
			}
			break;
		case 'R':
			skip_remove = true;
			break;
		case 'M':
			skip_mtd = true;
			break;
		case 'U':
			skip_ubi = true;
			break;
		case 'S':
			skip_sd = true;
			break;
		case 'E':
			skip_emmc = true;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	helper_verbose = (g_output_format == FW_OUTPUT_TXT) && g_verbose;
	g_send_logs = send_logs;

	if (output_http_target && strncmp(output_http_target, "http://", 7)) {
		err_printf("Invalid --output-http URI (expected http://host:port/...): %s\n", output_http_target);
		return 2;
	}

	if (output_https_target && strncmp(output_https_target, "https://", 8)) {
		err_printf("Invalid --output-https URI (expected https://host:port/...): %s\n", output_https_target);
		return 2;
	}

	if (output_http_target && output_https_target) {
		err_printf("Use only one of --output-http or --output-https\n");
		return 2;
	}

	g_output_http_uri = output_http_target ? output_http_target : output_https_target;

	if (g_send_logs && !output_tcp_target) {
		err_printf("--send-logs requires --output-tcp\n");
		return 2;
	}

	if (g_send_logs) {
		g_log_sock = ela_connect_tcp_ipv4(output_tcp_target);
		if (g_log_sock < 0) {
			err_printf("Unable to connect to log output target %s\n", output_tcp_target);
			return 1;
		}
	}

	ela_crc32_init(g_crc32_table);

	if (geteuid() != 0) {
		err_printf("This program must be run as root.\n");
		return 1;
	}

	if (!skip_mtd)
		uboot_ensure_mtd_nodes_collect(helper_verbose, &created_mtdblock_nodes, &created_mtdblock_count);
	if (!skip_ubi)
		uboot_ensure_ubi_nodes_collect(helper_verbose, &created_ubi_nodes, &created_ubi_count);
	uboot_ensure_block_nodes_collect(helper_verbose, !skip_sd, !skip_emmc,
		&created_block_nodes, &created_block_count);

	if (dev_override) {
		int hits = scan_dev_for_image(dev_override, step);
		total_hits = (hits > 0) ? hits : 0;
		if (hits < 0)
			total_hits = -1;
		goto out;
	}

	glob_t g;
	unsigned int scan_flags = 0;

	if (!skip_mtd)
		scan_flags |= FW_SCAN_GLOB_MTDBLOCK;
	if (!skip_ubi)
		scan_flags |= (FW_SCAN_GLOB_UBI | FW_SCAN_GLOB_UBIBLOCK);
	if (!skip_emmc)
		scan_flags |= FW_SCAN_GLOB_MMCBLK;
	if (!skip_sd)
		scan_flags |= FW_SCAN_GLOB_SDBLK;

	if (uboot_glob_scan_devices(&g, scan_flags) < 0) {
		total_hits = -1;
		goto out;
	}

	for (size_t i = 0; i < g.gl_pathc; i++) {
		int hits = scan_dev_for_image(g.gl_pathv[i], step);
		if (hits < 0) {
			total_hits = -1;
			break;
		}
		if (hits > 0)
			total_hits += hits;
	}

	globfree(&g);

out:
	if (total_hits == 0 && g_verbose)
		emit_image_verbose(NULL, 0, "No image signatures found.");

	if (!skip_remove) {
		for (size_t i = 0; i < created_mtdblock_count; i++) {
			if (unlink(created_mtdblock_nodes[i]) < 0 && errno != ENOENT)
				err_printf("Warning: failed to remove created node %s: %s\n",
					created_mtdblock_nodes[i], strerror(errno));
		}
		for (size_t i = 0; i < created_ubi_count; i++) {
			if (unlink(created_ubi_nodes[i]) < 0 && errno != ENOENT)
				err_printf("Warning: failed to remove created node %s: %s\n",
					created_ubi_nodes[i], strerror(errno));
		}
		for (size_t i = 0; i < created_block_count; i++) {
			if (unlink(created_block_nodes[i]) < 0 && errno != ENOENT)
				err_printf("Warning: failed to remove created node %s: %s\n",
					created_block_nodes[i], strerror(errno));
		}
	}

	uboot_free_created_nodes(created_mtdblock_nodes, created_mtdblock_count);
	uboot_free_created_nodes(created_ubi_nodes, created_ubi_count);
	uboot_free_created_nodes(created_block_nodes, created_block_count);

	if (g_log_sock >= 0) {
		close(g_log_sock);
		g_log_sock = -1;
	}
	if (flush_output_http_buffer() < 0)
		total_hits = -1;
	free(g_output_http_buf);
	g_output_http_buf = NULL;
	g_output_http_len = 0;
	g_output_http_cap = 0;
	g_output_http_uri = NULL;

	return (total_hits < 0) ? 1 : 0;
}

int uboot_image_prepare(bool verbose,
			bool insecure,
			bool send_logs,
			const char *output_tcp_target,
			const char *output_http_target,
			const char *output_https_target)
{
	detect_output_format();
	g_verbose = verbose;
	g_allow_text = false;
	g_allow_text_pattern = "U-Boot";
	g_send_logs = send_logs;
	g_insecure = insecure;
	g_csv_header_emitted = false;
	g_output_http_uri = NULL;
	if (g_log_sock >= 0) {
		close(g_log_sock);
		g_log_sock = -1;
	}

	if (output_http_target && strncmp(output_http_target, "http://", 7)) {
		err_printf("Invalid --output-http URI (expected http://host:port/...): %s\n", output_http_target);
		return 2;
	}

	if (output_https_target && strncmp(output_https_target, "https://", 8)) {
		err_printf("Invalid --output-https URI (expected https://host:port/...): %s\n", output_https_target);
		return 2;
	}

	if (output_http_target && output_https_target) {
		err_printf("Use only one of --output-http or --output-https\n");
		return 2;
	}

	if (output_http_target)
		g_output_http_uri = output_http_target;
	if (output_https_target)
		g_output_http_uri = output_https_target;

	if (g_send_logs && !output_tcp_target) {
		err_printf("--send-logs requires --output-tcp\n");
		return 2;
	}

	if (g_send_logs) {
		g_log_sock = ela_connect_tcp_ipv4(output_tcp_target);
		if (g_log_sock < 0) {
			err_printf("Unable to connect to log output target %s\n", output_tcp_target);
			return 2;
		}
	}

	ela_crc32_init(g_crc32_table);
	return 0;
}

int uboot_image_finish(int rc)
{
	int ret = rc;

	if (g_log_sock >= 0) {
		close(g_log_sock);
		g_log_sock = -1;
	}

	if (flush_output_http_buffer() < 0)
		ret = 1;

	free(g_output_http_buf);
	g_output_http_buf = NULL;
	g_output_http_len = 0;
	g_output_http_cap = 0;
	g_output_http_uri = NULL;

	return ret;
}
