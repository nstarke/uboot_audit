// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "fw_scan.h"

#include <errno.h>
#include <arpa/inet.h>
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define UIMAGE_HDR_SIZE 64U
#define FIT_MIN_TOTAL_SIZE 0x100U
#define FIT_MAX_TOTAL_SIZE (64U * 1024U * 1024U)
#define UIMAGE_MAX_DATA_SIZE (256U * 1024U * 1024U)

static bool g_verbose;
static bool g_allow_text;
static bool g_send_logs;
static uint32_t g_crc32_table[256];
static int g_log_sock = -1;

static void emit_v(FILE *stream, const char *fmt, va_list ap)
{
	va_list aq;
	char stack[1024];
	char *dyn = NULL;
	int needed;

	va_copy(aq, ap);
	vfprintf(stream, fmt, ap);
	fflush(stream);

	needed = vsnprintf(stack, sizeof(stack), fmt, aq);
	va_end(aq);

	if (g_log_sock < 0 || needed < 0)
		return;

	if ((size_t)needed < sizeof(stack)) {
		fw_send_all(g_log_sock, (const uint8_t *)stack, (size_t)needed);
		return;
	}

	dyn = malloc((size_t)needed + 1);
	if (!dyn)
		return;

	va_copy(aq, ap);
	vsnprintf(dyn, (size_t)needed + 1, fmt, aq);
	va_end(aq);
	fw_send_all(g_log_sock, (const uint8_t *)dyn, (size_t)needed);
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

static size_t align_up_4(size_t v)
{
	return (v + 3U) & ~((size_t)3U);
}

static void crc32_init(void)
{
	const uint32_t poly = 0xEDB88320U;
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t c = i;
		for (int j = 0; j < 8; j++)
			c = (c & 1U) ? (poly ^ (c >> 1)) : (c >> 1);
		g_crc32_table[i] = c;
	}
}

static uint32_t crc32_calc(const uint8_t *buf, size_t len)
{
	uint32_t c = 0xFFFFFFFFU;
	for (size_t i = 0; i < len; i++)
		c = g_crc32_table[(c ^ buf[i]) & 0xFFU] ^ (c >> 8);
	return c ^ 0xFFFFFFFFU;
}

static bool validate_fit_header(const uint8_t *p, uint64_t abs_off, uint64_t dev_size)
{
	uint32_t totalsize = fw_read_be32(p + 4);
	uint32_t off_dt_struct = fw_read_be32(p + 8);
	uint32_t off_dt_strings = fw_read_be32(p + 12);
	uint32_t off_mem_rsvmap = fw_read_be32(p + 16);
	uint32_t version = fw_read_be32(p + 20);
	uint32_t last_comp_version = fw_read_be32(p + 24);
	uint32_t size_dt_strings = fw_read_be32(p + 32);
	uint32_t size_dt_struct = fw_read_be32(p + 36);

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

static bool validate_uimage_header(const uint8_t *p, uint64_t abs_off, uint64_t dev_size)
{
	uint8_t hdr[UIMAGE_HDR_SIZE];
	uint32_t header_crc;
	uint32_t calc_crc;
	uint32_t data_size;

	memcpy(hdr, p, sizeof(hdr));
	header_crc = fw_read_be32(hdr + 4);
	hdr[4] = hdr[5] = hdr[6] = hdr[7] = 0;
	calc_crc = crc32_calc(hdr, sizeof(hdr));
	if (calc_crc != header_crc)
		return false;

	data_size = fw_read_be32(p + 12);
	if (data_size == 0 || data_size > UIMAGE_MAX_DATA_SIZE)
		return false;
	if (abs_off + UIMAGE_HDR_SIZE + data_size > dev_size)
		return false;

	return true;
}

static bool fit_find_load_address(const uint8_t *blob, size_t blob_size, uint32_t *addr_out)
{
	const uint32_t FDT_BEGIN_NODE = 1;
	const uint32_t FDT_END_NODE = 2;
	const uint32_t FDT_PROP = 3;
	const uint32_t FDT_NOP = 4;
	const uint32_t FDT_END = 9;
	uint32_t off_dt_struct;
	uint32_t off_dt_strings;
	uint32_t size_dt_struct;
	uint32_t size_dt_strings;
	const uint8_t *p;
	const uint8_t *end;
	const char *strings;

	if (!blob || blob_size < 40 || !addr_out)
		return false;

	off_dt_struct = fw_read_be32(blob + 8);
	off_dt_strings = fw_read_be32(blob + 12);
	size_dt_strings = fw_read_be32(blob + 32);
	size_dt_struct = fw_read_be32(blob + 36);

	if ((uint64_t)off_dt_struct + size_dt_struct > blob_size)
		return false;
	if ((uint64_t)off_dt_strings + size_dt_strings > blob_size)
		return false;

	p = blob + off_dt_struct;
	end = p + size_dt_struct;
	strings = (const char *)blob + off_dt_strings;

	while (p + 4 <= end) {
		uint32_t token = fw_read_be32(p);
		p += 4;

		switch (token) {
		case FDT_BEGIN_NODE: {
			const uint8_t *name_start = p;
			while (p < end && *p)
				p++;
			if (p >= end)
				return false;
			p++;
			p = name_start + align_up_4((size_t)(p - name_start));
			break;
		}
		case FDT_END_NODE:
		case FDT_NOP:
			break;
		case FDT_END:
			return false;
		case FDT_PROP: {
			uint32_t len;
			uint32_t nameoff;
			const char *name;
			const uint8_t *data;

			if (p + 8 > end)
				return false;
			len = fw_read_be32(p);
			nameoff = fw_read_be32(p + 4);
			p += 8;
			if (nameoff >= size_dt_strings)
				return false;
			if ((uint64_t)(end - p) < len)
				return false;

			name = strings + nameoff;
			data = p;
			if (!strcmp(name, "load") && len >= 4) {
				uint32_t load = fw_read_be32(data);
				if (len >= 8 && load == 0)
					load = fw_read_be32(data + 4);
				*addr_out = load;
				return true;
			}

			p += align_up_4((size_t)len);
			break;
		}
		default:
			return false;
		}
	}

	return false;
}

static uint64_t parse_u64(const char *s)
{
	uint64_t v;

	if (fw_parse_u64(s, &v)) {
		fprintf(stderr, "Invalid number: %s\n", s);
		exit(2);
	}
	return v;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--verbose] [--dev <device>] [--step <bytes>] [--allow-text]\n"
		"       %s --pull --dev <device> --offset <bytes> --output <IPv4:port>\n"
		"       %s --find-address --dev <device> --offset <bytes>\n"
		"  no args: scan /dev/mtdblock* and /dev/mtd* for U-Boot image signatures\n"
		"  --verbose: print scan progress\n"
		"  --dev: scan only a specific device\n"
		"  --step: step size when scanning (default: 0x1000)\n"
		"  --allow-text: also match plain 'U-Boot' string (higher false-positive risk)\n"
		"  --send-logs: send tool log output to --output IPv4:port\n"
		"  --pull: read image from --dev at --offset and stream bytes to --output\n"
		"  --find-address: print image load address from header/FIT data\n"
		"  --offset: byte offset of image header for --pull\n"
		"  --output: IPv4:TCPPort destination for --pull\n",
		prog, prog, prog);
}

static int find_image_load_address(const char *dev, uint64_t offset)
{
	uint8_t hdr[UIMAGE_HDR_SIZE];
	uint64_t dev_size = fw_guess_size_from_sysfs(dev);
	int fd;

	if (!dev_size)
		dev_size = fw_guess_size_from_proc_mtd(dev);

	fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		err_printf("Cannot open %s: %s\n", dev, strerror(errno));
		return 1;
	}

	if (pread(fd, hdr, sizeof(hdr), (off_t)offset) != (ssize_t)sizeof(hdr)) {
		err_printf("Unable to read image header from %s @ 0x%jx\n", dev, (uintmax_t)offset);
		close(fd);
		return 1;
	}

	if (!memcmp(hdr, "\x27\x05\x19\x56", 4)) {
		if (!validate_uimage_header(hdr, offset, dev_size ? dev_size : UINT64_MAX)) {
			err_printf("uImage header validation failed at offset 0x%jx\n", (uintmax_t)offset);
			close(fd);
			return 1;
		}
		out_printf("uImage load address: 0x%08x\n", fw_read_be32(hdr + 16));
		close(fd);
		return 0;
	}

	if (!memcmp(hdr, "\xD0\x0D\xFE\xED", 4)) {
		uint32_t total_size;
		uint8_t *fit_blob;
		uint32_t load_addr;

		if (!validate_fit_header(hdr, offset, dev_size ? dev_size : UINT64_MAX)) {
			err_printf("FIT header validation failed at offset 0x%jx\n", (uintmax_t)offset);
			close(fd);
			return 1;
		}

		total_size = fw_read_be32(hdr + 4);
		fit_blob = malloc((size_t)total_size);
		if (!fit_blob) {
			err_printf("Unable to allocate memory to inspect FIT image\n");
			close(fd);
			return 1;
		}

		if (pread(fd, fit_blob, (size_t)total_size, (off_t)offset) != (ssize_t)total_size) {
			err_printf("Unable to read full FIT image for address lookup\n");
			free(fit_blob);
			close(fd);
			return 1;
		}

		if (fit_find_load_address(fit_blob, (size_t)total_size, &load_addr))
			out_printf("FIT load address: 0x%08x\n", load_addr);
		else
			err_printf("FIT load address not found\n");

		free(fit_blob);
		close(fd);
		return 0;
	}

	err_printf("Unknown image format at offset 0x%jx\n", (uintmax_t)offset);
	close(fd);
	return 1;
}

static int pull_image_to_output(const char *dev, uint64_t offset, const char *output)
{
	uint8_t hdr[UIMAGE_HDR_SIZE];
	uint64_t dev_size = fw_guess_size_from_sysfs(dev);
	uint64_t total_size = 0;
	int fd, sock;

	if (!dev_size)
		dev_size = fw_guess_size_from_proc_mtd(dev);

	fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		err_printf("Cannot open %s: %s\n", dev, strerror(errno));
		return 1;
	}

	if (pread(fd, hdr, sizeof(hdr), (off_t)offset) != (ssize_t)sizeof(hdr)) {
		err_printf("Unable to read image header from %s @ 0x%jx\n", dev, (uintmax_t)offset);
		close(fd);
		return 1;
	}

	if (!memcmp(hdr, "\x27\x05\x19\x56", 4)) {
		if (!validate_uimage_header(hdr, offset, dev_size ? dev_size : UINT64_MAX)) {
			err_printf("uImage header validation failed at offset 0x%jx\n", (uintmax_t)offset);
			close(fd);
			return 1;
		}
		total_size = UIMAGE_HDR_SIZE + fw_read_be32(hdr + 12);
	} else if (!memcmp(hdr, "\xD0\x0D\xFE\xED", 4)) {
		if (!validate_fit_header(hdr, offset, dev_size ? dev_size : UINT64_MAX)) {
			err_printf("FIT header validation failed at offset 0x%jx\n", (uintmax_t)offset);
			close(fd);
			return 1;
		}
		total_size = fw_read_be32(hdr + 4);
	} else {
		err_printf("Unknown image format at offset 0x%jx\n", (uintmax_t)offset);
		close(fd);
		return 1;
	}

	sock = fw_connect_tcp_ipv4(output);
	if (sock < 0) {
		err_printf("Unable to connect to output target %s\n", output);
		close(fd);
		return 1;
	}

	{
		uint8_t buf[4096];
		uint64_t sent = 0;
		while (sent < total_size) {
			size_t want = (size_t)((total_size - sent) > sizeof(buf) ? sizeof(buf) : (total_size - sent));
			ssize_t n = pread(fd, buf, want, (off_t)(offset + sent));
			if (n <= 0 || fw_send_all(sock, buf, (size_t)n) < 0) {
				err_printf("Pull failed while sending image bytes\n");
				close(sock);
				close(fd);
				return 1;
			}
			sent += (uint64_t)n;
		}
		if (g_verbose)
			out_printf("Pulled %ju bytes from %s @ 0x%jx to %s\n", (uintmax_t)total_size, dev, (uintmax_t)offset, output);
	}

	close(sock);
	close(fd);
	return 0;
}

static void report_signature(const char *dev, uint64_t off, const char *kind)
{
	out_printf("candidate image signature: %s offset=0x%jx type=%s\n",
	       dev, (uintmax_t)off, kind);
}

static int scan_dev_for_image(const char *dev, uint64_t step)
{
	static const uint8_t uimage_magic[] = { 0x27, 0x05, 0x19, 0x56 };
	static const uint8_t fit_magic[] = { 0xD0, 0x0D, 0xFE, 0xED };
	static const char uboot_text[] = "U-Boot";
	int fd;
	struct stat st;
	uint64_t size = 0;
	uint64_t off;
	uint8_t *buf;
	int hits = 0;

	fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == EBUSY) {
			if (g_verbose)
				err_printf("Skipping busy device %s: %s\n", dev, strerror(errno));
			return 0;
		}
		err_printf("Cannot open %s: %s\n", dev, strerror(errno));
		return -1;
	}

	if (fstat(fd, &st) == 0)
		size = (uint64_t)st.st_size;
	if (!size)
		size = fw_guess_size_from_sysfs(dev);
	if (!size)
		size = fw_guess_size_from_proc_mtd(dev);

	if (!size) {
		close(fd);
		return -1;
	}

	buf = malloc((size_t)step);
	if (!buf) {
		close(fd);
		return -1;
	}

	if (g_verbose)
		out_printf("Scanning %s size=0x%jx step=0x%jx\n", dev, (uintmax_t)size, (uintmax_t)step);

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

		if (g_allow_text) {
			for (size_t i = 0; i + sizeof(uboot_text) - 1 <= (size_t)n; i++) {
				if (!memcmp(buf + i, uboot_text, sizeof(uboot_text) - 1)) {
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

int main(int argc, char **argv)
{
	const char *dev_override = NULL;
	const char *output_target = NULL;
	uint64_t step = 0x1000;
	uint64_t pull_offset = 0;
	bool pull_mode = false;
	bool find_address = false;
	bool offset_set = false;
	int opt;
	int total_hits = 0;

	static const struct option long_opts[] = {
		{ "verbose", no_argument, NULL, 'v' },
		{ "dev", required_argument, NULL, 'd' },
		{ "step", required_argument, NULL, 's' },
		{ "offset", required_argument, NULL, 'o' },
		{ "output", required_argument, NULL, 'p' },
		{ "pull", no_argument, NULL, 'P' },
		{ "find-address", no_argument, NULL, 'a' },
		{ "send-logs", no_argument, NULL, 'L' },
		{ "allow-text", no_argument, NULL, 't' },
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "hvd:s:o:p:PtaL", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'v':
			g_verbose = true;
			break;
		case 'd':
			dev_override = optarg;
			break;
		case 's':
			step = parse_u64(optarg);
			if (!step)
				step = 0x1000;
			break;
		case 'o':
			pull_offset = parse_u64(optarg);
			offset_set = true;
			break;
		case 'p':
			output_target = optarg;
			break;
		case 'P':
			pull_mode = true;
			break;
		case 'a':
			find_address = true;
			break;
		case 'L':
			g_send_logs = true;
			break;
		case 't':
			g_allow_text = true;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	crc32_init();

	if (geteuid() != 0) {
		err_printf("This program must be run as root.\n");
		return 1;
	}

	if (g_send_logs && !output_target) {
		err_printf("--send-logs requires --output\n");
		return 2;
	}

	if (g_send_logs && pull_mode) {
		err_printf("--send-logs cannot be combined with --pull\n");
		return 2;
	}

	if (g_send_logs) {
		g_log_sock = fw_connect_tcp_ipv4(output_target);
		if (g_log_sock < 0) {
			err_printf("Unable to connect to log output target %s\n", output_target);
			return 2;
		}
	}

	if (pull_mode) {
		if (!dev_override || !offset_set || !output_target) {
			err_printf("--pull requires --dev, --offset, and --output\n");
			return 2;
		}
		if (find_address) {
			err_printf("--find-address cannot be combined with --pull\n");
			return 2;
		}
		return pull_image_to_output(dev_override, pull_offset, output_target);
	}

	if (find_address) {
		if (!dev_override || !offset_set) {
			err_printf("--find-address requires --dev and --offset\n");
			return 2;
		}
		if (output_target && !g_send_logs) {
			err_printf("--find-address cannot be combined with --output (unless --send-logs is set)\n");
			return 2;
		}
		return find_image_load_address(dev_override, pull_offset);
	}

	fw_ensure_mtd_nodes(g_verbose);

	if (dev_override) {
		int hits = scan_dev_for_image(dev_override, step);
		return (hits < 0) ? 1 : 0;
	}

	glob_t g;
	memset(&g, 0, sizeof(g));
	glob("/dev/mtdblock[0-9]*", 0, NULL, &g);
	glob("/dev/mtd[0-9]*", GLOB_APPEND, NULL, &g);

	for (size_t i = 0; i < g.gl_pathc; i++) {
		int hits = scan_dev_for_image(g.gl_pathv[i], step);
		if (hits > 0)
			total_hits += hits;
	}

	globfree(&g);

	if (!total_hits && g_verbose)
		out_printf("No image signatures found.\n");

	if (g_log_sock >= 0)
		close(g_log_sock);

	return 0;
}
