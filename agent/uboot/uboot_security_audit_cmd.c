// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "uboot/audit/uboot_audit_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define FIT_MIN_TOTAL_SIZE 0x100U
#define FIT_MAX_TOTAL_SIZE (64U * 1024U * 1024U)
#define AUTO_SCAN_STEP 0x1000ULL
#define DEFAULT_AUDIT_SIZE 0x10000ULL
#define AUTO_SCAN_MAX_BYTES (64ULL * 1024ULL * 1024ULL)

static uint32_t read_be32_local(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) |
		((uint32_t)p[1] << 16) |
		((uint32_t)p[2] << 8) |
		(uint32_t)p[3];
}

static enum uboot_output_format g_output_format = FW_OUTPUT_TXT;
static int g_output_sock = -1;
static const char *g_output_http_uri;
static char *g_output_http_buf;
static size_t g_output_http_len;
static size_t g_output_http_cap;
static bool g_http_insecure;
static bool g_http_verbose;

static bool buffer_has_newline(const char *buf, size_t len)
{
	if (!buf || !len)
		return false;

	return memchr(buf, '\n', len) != NULL;
}

static int flush_output_http_buffer(void);

static bool audit_rule_may_need_signature_artifacts(const char *rule_filter)
{
	if (!rule_filter || !*rule_filter)
		return true;

	return !strcmp(rule_filter, "uboot_validate_secureboot");
}

static enum uboot_output_format detect_output_format(void)
{
	const char *fmt = getenv("ELA_OUTPUT_FORMAT");

	if (!fmt || !*fmt || !strcmp(fmt, "txt"))
		return FW_OUTPUT_TXT;
	if (!strcmp(fmt, "csv"))
		return FW_OUTPUT_CSV;
	if (!strcmp(fmt, "json"))
		return FW_OUTPUT_JSON;

	return FW_OUTPUT_TXT;
}

static void send_to_output_socket(const char *buf, size_t len)
{
	while (g_output_sock >= 0 && len) {
		ssize_t n = send(g_output_sock, buf, len, 0);
		if (n <= 0) {
			close(g_output_sock);
			g_output_sock = -1;
			return;
		}
		buf += n;
		len -= (size_t)n;
	}
}

static void append_output_http_buffer(const char *buf, size_t len)
{
	char *tmp;
	size_t need;
	size_t new_cap;

	if (!g_output_http_uri || !buf || !len)
		return;

	need = g_output_http_len + len + 1;
	if (need > g_output_http_cap) {
		new_cap = g_output_http_cap ? g_output_http_cap : 1024;
		while (new_cap < need)
			new_cap *= 2;

		tmp = realloc(g_output_http_buf, new_cap);
		if (!tmp)
			return;
		g_output_http_buf = tmp;
		g_output_http_cap = new_cap;
	}

	memcpy(g_output_http_buf + g_output_http_len, buf, len);
	g_output_http_len += len;
	g_output_http_buf[g_output_http_len] = '\0';
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
		if (mirror_to_remote) {
			send_to_output_socket(stack, (size_t)needed);
			append_output_http_buffer(stack, (size_t)needed);
		}
		if (mirror_to_remote && g_http_verbose && g_output_http_uri && g_output_http_len > 0 &&
		    buffer_has_newline(stack, (size_t)needed))
			(void)flush_output_http_buffer();
		return;
	}

	dyn = malloc((size_t)needed + 1);
	if (!dyn)
		return;

	va_copy(aq, ap);
	vsnprintf(dyn, (size_t)needed + 1, fmt, aq);
	va_end(aq);
	if (mirror_to_remote) {
		send_to_output_socket(dyn, (size_t)needed);
		append_output_http_buffer(dyn, (size_t)needed);
	}
	if (mirror_to_remote && g_http_verbose && g_output_http_uri && g_output_http_len > 0 &&
	    buffer_has_newline(dyn, (size_t)needed))
		(void)flush_output_http_buffer();
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

void uboot_audit_out_printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	emit_v(stdout, fmt, ap);
	va_end(ap);
}

void uboot_audit_err_printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	emit_v(stderr, fmt, ap);
	va_end(ap);
}

void uboot_audit_out_json_escaped(const char *s)
{
	if (!s)
		return;

	for (const char *p = s; *p; p++) {
		if (*p == '\\' || *p == '"')
			out_printf("\\");
		out_printf("%c", *p);
	}
}

static int flush_output_http_buffer(void)
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
			 audit_http_content_type(g_output_format),
			 g_http_insecure,
			 g_http_verbose,
			 errbuf,
			 sizeof(errbuf)) < 0) {
		fprintf(stderr, "Failed to POST output to %s: %s\n", upload_uri,
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

static uint64_t parse_u64(const char *s)
{
	uint64_t v;

	if (ela_parse_u64(s, &v)) {
		err_printf("Invalid number: %s\n", s);
		exit(2);
	}

	return v;
}

static int copy_file_contents(const char *src_path, const char *dst_path)
{
	uint8_t buf[4096];
	int src_fd = -1;
	int dst_fd = -1;
	int rc = -1;

	if (!src_path || !*src_path || !dst_path || !*dst_path)
		return -1;

	src_fd = open(src_path, O_RDONLY | O_CLOEXEC);
	if (src_fd < 0)
		goto out;

	dst_fd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (dst_fd < 0)
		goto out;

	for (;;) {
		ssize_t n = read(src_fd, buf, sizeof(buf));
		if (n < 0)
			goto out;
		if (n == 0)
			break;
		if (write(dst_fd, buf, (size_t)n) != n)
			goto out;
	}

	rc = 0;

out:
	if (src_fd >= 0)
		close(src_fd);
	if (dst_fd >= 0)
		close(dst_fd);
	return rc;
}

static int ensure_fw_env_config_exists(bool force_scan, bool verbose)
{
	const char *output_tcp = getenv("ELA_OUTPUT_TCP");
	const char *output_http = getenv("ELA_OUTPUT_HTTP");
	const char *output_https = getenv("ELA_OUTPUT_HTTPS");
	char *env_argv[9];
	int env_argc = 0;

	(void)verbose;

	env_argv[env_argc++] = "env";
	env_argv[env_argc++] = "--output-config=fw_env.config";
	(void)output_tcp;
	(void)output_http;
	(void)output_https;
	env_argv[env_argc] = NULL;

	if (!force_scan && access("fw_env.config", F_OK) == 0)
		return 0;

	if (!force_scan && access("uboot_env.config", F_OK) == 0)
		return copy_file_contents("uboot_env.config", "fw_env.config");

	return uboot_env_scan_main(env_argc, env_argv);
}

static const char *resolve_first_readable_glob(const char *pattern, char **owned_path)
{
	glob_t g;
	int grc;

	if (!pattern || !*pattern || !owned_path)
		return NULL;

	grc = glob(pattern, 0, NULL, &g);
	if (grc != 0)
		return NULL;

	for (size_t i = 0; i < g.gl_pathc; i++) {
		if (access(g.gl_pathv[i], R_OK) != 0)
			continue;
		*owned_path = strdup(g.gl_pathv[i]);
		globfree(&g);
		return *owned_path;
	}

	globfree(&g);
	return NULL;
}

static bool fit_header_looks_valid(const uint8_t *p, uint64_t abs_off, uint64_t dev_size)
{
	uint32_t totalsize = read_be32_local(p + 4);
	uint32_t off_dt_struct = read_be32_local(p + 8);
	uint32_t off_dt_strings = read_be32_local(p + 12);
	uint32_t off_mem_rsvmap = read_be32_local(p + 16);
	uint32_t version = read_be32_local(p + 20);
	uint32_t last_comp_version = read_be32_local(p + 24);
	uint32_t size_dt_strings = read_be32_local(p + 32);
	uint32_t size_dt_struct = read_be32_local(p + 36);

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

static int find_fit_blob_in_device(const char *dev, uint64_t *off_out, uint32_t *size_out)
{
	uint8_t hdr[64];
	uint64_t dev_size;
	uint64_t scan_limit;
	uint64_t off;
	int fd;

	if (!dev || !off_out || !size_out)
		return -1;

	fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	dev_size = uboot_guess_size_any(dev);
	if (dev_size < sizeof(hdr)) {
		close(fd);
		return -1;
	}

	scan_limit = dev_size;
	if (scan_limit > AUTO_SCAN_MAX_BYTES)
		scan_limit = AUTO_SCAN_MAX_BYTES;

	for (off = 0; off + sizeof(hdr) <= scan_limit; off += AUTO_SCAN_STEP) {
		if (pread(fd, hdr, sizeof(hdr), (off_t)off) != (ssize_t)sizeof(hdr))
			break;
		if (memcmp(hdr, "\xD0\x0D\xFE\xED", 4))
			continue;
		if (!fit_header_looks_valid(hdr, off, dev_size))
			continue;
		*off_out = off;
		*size_out = read_be32_local(hdr + 4);
		close(fd);
		return 0;
	}

	close(fd);
	return -1;
}

static int extract_region_to_file(const char *dev, uint64_t off, uint32_t size, const char *path)
{
	uint8_t buf[4096];
	uint64_t done = 0;
	int in_fd;
	int out_fd;

	in_fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (in_fd < 0)
		return -1;

	out_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (out_fd < 0) {
		close(in_fd);
		return -1;
	}

	while (done < size) {
		size_t want = (size - done > sizeof(buf)) ? sizeof(buf) : (size_t)(size - done);
		ssize_t n = pread(in_fd, buf, want, (off_t)(off + done));
		if (n <= 0 || write(out_fd, buf, (size_t)n) != n) {
			close(in_fd);
			close(out_fd);
			return -1;
		}
		done += (uint64_t)n;
	}

	close(in_fd);
	close(out_fd);
	return 0;
}

static int find_pubkey_pem_in_device(const char *dev, char **pem_out)
{
	static const char begin_marker[] = "-----BEGIN PUBLIC KEY-----";
	static const char end_marker[] = "-----END PUBLIC KEY-----";
	uint8_t chunk[1024 * 1024];
	char *carry = NULL;
	size_t carry_len = 0;
	uint64_t dev_size;
	uint64_t scan_limit;
	uint64_t off;
	int fd;

	if (!dev || !pem_out)
		return -1;

	fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	dev_size = uboot_guess_size_any(dev);
	if (!dev_size) {
		close(fd);
		return -1;
	}

	scan_limit = dev_size;
	if (scan_limit > AUTO_SCAN_MAX_BYTES)
		scan_limit = AUTO_SCAN_MAX_BYTES;

	for (off = 0; off < scan_limit; off += sizeof(chunk)) {
		ssize_t n = pread(fd, chunk, sizeof(chunk), (off_t)off);
		char *combined;
		size_t combined_len;
		char *b;

		if (n <= 0)
			break;

		combined_len = carry_len + (size_t)n;
		combined = malloc(combined_len + 1);
		if (!combined)
			break;
		if (carry_len)
			memcpy(combined, carry, carry_len);
		memcpy(combined + carry_len, chunk, (size_t)n);
		combined[combined_len] = '\0';

		b = strstr(combined, begin_marker);
		if (b) {
			char *e = strstr(b, end_marker);
			if (e) {
				size_t pem_len = (size_t)(e - b) + strlen(end_marker);
				char *pem = malloc(pem_len + 2);
				if (!pem) {
					free(combined);
					break;
				}
				memcpy(pem, b, pem_len);
				if (pem_len == 0 || pem[pem_len - 1] != '\n')
					pem[pem_len++] = '\n';
				pem[pem_len] = '\0';
				*pem_out = pem;
				free(combined);
				free(carry);
				close(fd);
				return 0;
			}
		}

		free(carry);
		if (combined_len > 4096) {
			carry_len = 4096;
			carry = malloc(carry_len + 1);
			if (carry) {
				memcpy(carry, combined + combined_len - carry_len, carry_len);
				carry[carry_len] = '\0';
			}
		} else {
			carry_len = combined_len;
			carry = combined;
			combined = NULL;
		}

		free(combined);
	}

	free(carry);
	close(fd);
	return -1;
}

static char *create_auto_signature_dir(void)
{
	char root_template[] = "/tmp/embedded_linux_audit.XXXXXX";
	char *root;
	char *subdir;
	int n;

	root = mkdtemp(root_template);
	if (!root)
		return NULL;

	n = snprintf(NULL, 0, "%s/embedded_linux_audit", root);
	if (n <= 0)
		return NULL;

	subdir = malloc((size_t)n + 1);
	if (!subdir)
		return NULL;

	snprintf(subdir, (size_t)n + 1, "%s/embedded_linux_audit", root);
	if (mkdir(subdir, 0700) != 0 && errno != EEXIST) {
		free(subdir);
		return NULL;
	}

	return subdir;
}

static int auto_scan_signature_artifacts(char **blob_path_out, char **pubkey_path_out)
{
	glob_t g;
	unsigned int scan_flags = FW_SCAN_GLOB_MTDBLOCK | FW_SCAN_GLOB_UBI |
		FW_SCAN_GLOB_UBIBLOCK | FW_SCAN_GLOB_MMCBLK | FW_SCAN_GLOB_SDBLK;
	char *pem = NULL;
	char *auto_dir = NULL;
	char *blob_path = NULL;
	char *pubkey_path = NULL;

	if (!blob_path_out || !pubkey_path_out)
		return -1;

	auto_dir = create_auto_signature_dir();
	if (!auto_dir)
		return -1;

	if (uboot_glob_scan_devices(&g, scan_flags) < 0)
		return -1;

	for (size_t i = 0; i < g.gl_pathc && (!blob_path || !pubkey_path); i++) {
		const char *dev = g.gl_pathv[i];

		if (!blob_path) {
			uint64_t fit_off;
			uint32_t fit_size;
			if (find_fit_blob_in_device(dev, &fit_off, &fit_size) == 0) {
				int n = snprintf(NULL, 0, "%s/auto_signature_blob.fit", auto_dir);
				if (n > 0) {
					blob_path = malloc((size_t)n + 1);
					if (blob_path)
						snprintf(blob_path, (size_t)n + 1, "%s/auto_signature_blob.fit", auto_dir);
				}
				if (blob_path && extract_region_to_file(dev, fit_off, fit_size, blob_path) != 0) {
					free(blob_path);
					blob_path = NULL;
				}
			}
		}

		if (!pubkey_path) {
			if (find_pubkey_pem_in_device(dev, &pem) == 0) {
				int fd;
				int n = snprintf(NULL, 0, "%s/auto_signature_pubkey.pem", auto_dir);
				if (n > 0) {
					pubkey_path = malloc((size_t)n + 1);
					if (pubkey_path)
						snprintf(pubkey_path, (size_t)n + 1, "%s/auto_signature_pubkey.pem", auto_dir);
				}
				if (!pubkey_path)
					continue;
				fd = open(pubkey_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
				if (fd < 0 || write(fd, pem, strlen(pem)) < 0) {
					if (fd >= 0)
						close(fd);
					free(pubkey_path);
					pubkey_path = NULL;
				} else {
					close(fd);
				}
				free(pem);
				pem = NULL;
			}
		}
	}

	globfree(&g);
	free(auto_dir);

	*blob_path_out = blob_path;
	*pubkey_path_out = pubkey_path;

	return (blob_path ? 1 : 0) + (pubkey_path ? 1 : 0);
}

static void usage(const char *prog)
{
	err_printf(
		"Usage: %s [--list-rules] [--rule <name>] --dev <device> [--offset <bytes>] [--size <bytes>]\n"
		"  --list-rules    List compiled audit rules\n"
		"  --rule <name>   Run only one rule by name\n"
		"  --dev <device>  Input device/file to audit\n"
		"  --offset <n>    Read offset (default: 0)\n"
		"  --size <n>      Number of bytes to read for audit (default: 0x10000)\n"
		"  --signature-blob <path>   Blob file used for signature verification rules\n"
		"  --signature-pubkey <path> Public key PEM file for signature verification rules\n"
		"  --scan-signature-devices  Force device scan for FIT blob and PEM pubkey\n"
		"  --scan-signature-blob <glob>   Auto-select first readable blob path matching glob\n"
		"  --scan-signature-pubkey <glob> Auto-select first readable pubkey path matching glob\n"
		"  --signature-alg <name>    Digest algorithm (if omitted: tries sha256, sha384, sha512, sha1, sha224)\n",
		prog);
}

int embedded_linux_audit_scan_main(int argc, char **argv)
{
	const char *dev = NULL;
	const char *rule_filter = NULL;
	const char *signature_blob_path = NULL;
	const char *signature_pubkey_path = NULL;
	const char *signature_blob_scan = NULL;
	const char *signature_pubkey_scan = NULL;
	const char *signature_algorithm = NULL;
	const char *output_tcp_target = getenv("ELA_OUTPUT_TCP");
	const char *output_http_target = getenv("ELA_OUTPUT_HTTP");
	const char *output_https_target = getenv("ELA_OUTPUT_HTTPS");
	const char *output_http_uri = NULL;
	bool scan_signature_devices = false;
	bool insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	uint64_t offset = 0;
	uint64_t size = DEFAULT_AUDIT_SIZE;
	bool size_explicit = false;
	bool verbose = getenv("ELA_VERBOSE") && !strcmp(getenv("ELA_VERBOSE"), "1");
	bool list_rules = false;
	uint32_t crc32_table[256];
	const struct embedded_linux_audit_rule * const *rulep;
	const struct embedded_linux_audit_rule * const *start = __start_embedded_linux_audit_rules;
	const struct embedded_linux_audit_rule * const *stop = __stop_embedded_linux_audit_rules;
	enum uboot_output_format fmt;
	int opt;
	int ret = 0;
	int fd = -1;
	uint8_t *buf = NULL;
	size_t read_len;
	ssize_t got;
	bool ran_any = false;
	char *scanned_blob_path = NULL;
	char *scanned_pubkey_path = NULL;

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "dev", required_argument, NULL, 'd' },
		{ "offset", required_argument, NULL, 'o' },
		{ "size", required_argument, NULL, 's' },
		{ "signature-blob", required_argument, NULL, 'B' },
		{ "signature-pubkey", required_argument, NULL, 'K' },
		{ "scan-signature-blob", required_argument, NULL, 'X' },
		{ "scan-signature-pubkey", required_argument, NULL, 'Y' },
		{ "scan-signature-devices", no_argument, NULL, 'Z' },
		{ "output-tcp", required_argument, NULL, 'p' },
		{ "output-http", required_argument, NULL, 'O' },
		{ "output-https", required_argument, NULL, 'T' },
		{ "signature-alg", required_argument, NULL, 'A' },
		{ "rule", required_argument, NULL, 'r' },
		{ "list-rules", no_argument, NULL, 'l' },
		{ 0, 0, 0, 0 }
	};

	optind = 1;
	fmt = detect_output_format();
	g_output_format = fmt;
	g_output_http_uri = NULL;
	g_output_sock = -1;
	g_output_http_buf = NULL;
	g_output_http_len = 0;
	g_output_http_cap = 0;
	g_http_insecure = false;
	g_http_verbose = false;

	while ((opt = getopt_long(argc, argv, "hd:o:s:B:K:X:Y:Zp:O:T:A:r:l", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'd':
			dev = optarg;
			break;
		case 'o':
			offset = parse_u64(optarg);
			break;
		case 's':
			size = parse_u64(optarg);
			size_explicit = true;
			break;
		case 'B':
			signature_blob_path = optarg;
			break;
		case 'K':
			signature_pubkey_path = optarg;
			break;
		case 'X':
			signature_blob_scan = optarg;
			break;
		case 'Y':
			signature_pubkey_scan = optarg;
			break;
		case 'Z':
			scan_signature_devices = true;
			break;
		case 'p':
			output_tcp_target = optarg;
			break;
		case 'O':
			if ((output_https_target && !strncmp(optarg, "http://", 7)) ||
			    (output_http_target && !strncmp(optarg, "https://", 8))) {
				err_printf("Use only one of --output-http or --output-https\n");
				return 2;
			}
			output_http_target = optarg;
			break;
		case 'T':
			output_https_target = optarg;
			break;
		case 'A':
			signature_algorithm = optarg;
			break;
		case 'r':
			rule_filter = optarg;
			break;
		case 'l':
			list_rules = true;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
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
		output_http_uri = output_http_target;
	if (output_https_target)
		output_http_uri = output_https_target;

	if (output_tcp_target && *output_tcp_target) {
		g_output_sock = ela_connect_tcp_ipv4(output_tcp_target);
		if (g_output_sock < 0) {
			err_printf("Invalid/failed output target (expected IPv4:port): %s\n", output_tcp_target);
			ret = 1;
			goto out;
		}
	}

	if (output_tcp_target && *output_tcp_target)
		setenv("ELA_OUTPUT_TCP", output_tcp_target, 1);
	else
		unsetenv("ELA_OUTPUT_TCP");
	if (output_http_target && *output_http_target)
		setenv("ELA_OUTPUT_HTTP", output_http_target, 1);
	else
		unsetenv("ELA_OUTPUT_HTTP");
	if (output_https_target && *output_https_target)
		setenv("ELA_OUTPUT_HTTPS", output_https_target, 1);
	else
		unsetenv("ELA_OUTPUT_HTTPS");
	setenv("ELA_OUTPUT_INSECURE", insecure ? "1" : "0", 1);

	g_output_http_uri = output_http_uri;
	g_http_insecure = insecure;
	g_http_verbose = verbose;

	if (list_rules) {
		if (fmt == FW_OUTPUT_CSV)
			out_printf("record,rule,description\n");

		for (rulep = start; rulep < stop; rulep++) {
			const struct embedded_linux_audit_rule *rule = *rulep;

			if (!rule->name || !rule->run)
				continue;
			print_rule_listing(fmt, rule);
		}
		ret = 0;
		goto out;
	}

	if (!dev) {
		if (size_explicit) {
			err_printf("--dev is required when running audit rules\n");
			ret = 2;
			goto out;
		}

		ret = ensure_fw_env_config_exists(true, verbose);
		if (ret != 0) {
			err_printf("fw_env.config not found and env scan failed (rc=%d)\n", ret);
			ret = 1;
			goto out;
		}

		if (fmt == FW_OUTPUT_TXT)
			out_printf("Prepared fw_env.config via env scan for subsequent auditing\n");
		ret = 0;
		goto out;
	}

	if (!size) {
		usage(argv[0]);
		return 2;
	}

	ret = ensure_fw_env_config_exists(false, verbose);
	if (ret != 0) {
		err_printf("fw_env.config not found and env scan failed (rc=%d)\n", ret);
		ret = 1;
		goto out;
	}

	if (!signature_blob_path && signature_blob_scan) {
		signature_blob_path = resolve_first_readable_glob(signature_blob_scan, &scanned_blob_path);
		if (!signature_blob_path) {
			err_printf("No readable files matched --scan-signature-blob pattern: %s\n", signature_blob_scan);
			ret = 2;
			goto out;
		}
	}

	if (!signature_pubkey_path && signature_pubkey_scan) {
		signature_pubkey_path = resolve_first_readable_glob(signature_pubkey_scan, &scanned_pubkey_path);
		if (!signature_pubkey_path) {
			err_printf("No readable files matched --scan-signature-pubkey pattern: %s\n", signature_pubkey_scan);
			ret = 2;
			goto out;
		}
	}

	if (scan_signature_devices ||
	    ((!signature_blob_path || !signature_pubkey_path) &&
	     audit_rule_may_need_signature_artifacts(rule_filter))) {
		int found_count = auto_scan_signature_artifacts(&scanned_blob_path, &scanned_pubkey_path);
		if (found_count < 0) {
			err_printf("Warning: signature artifact device scan failed\n");
		} else if (verbose && found_count > 0) {
			err_printf("Auto-discovered %d signature artifact(s) from device scan\n", found_count);
		}
		if (!signature_blob_path)
			signature_blob_path = scanned_blob_path;
		if (!signature_pubkey_path)
			signature_pubkey_path = scanned_pubkey_path;

		if (scanned_blob_path) {
			send_artifact_network_record(fmt,
						 output_tcp_target,
						 output_http_uri,
						 insecure,
						 verbose,
						 "signature_blob",
						 scanned_blob_path);
		}

		if (scanned_pubkey_path) {
			send_artifact_network_record(fmt,
						 output_tcp_target,
						 output_http_uri,
						 insecure,
						 verbose,
						 "signature_pubkey",
						 scanned_pubkey_path);
		}
	}

	if (signature_blob_path && access(signature_blob_path, R_OK) != 0) {
		err_printf("Cannot read --signature-blob %s: %s\n", signature_blob_path, strerror(errno));
		return 2;
	}

	if (signature_pubkey_path && access(signature_pubkey_path, R_OK) != 0) {
		err_printf("Cannot read --signature-pubkey %s: %s\n", signature_pubkey_path, strerror(errno));
		return 2;
	}

	if (size > (uint64_t)SIZE_MAX) {
		err_printf("Requested --size is too large for this host\n");
		return 2;
	}

	read_len = (size_t)size;
	buf = malloc(read_len);
	if (!buf) {
		err_printf("Unable to allocate %zu bytes for audit input\n", read_len);
		return 1;
	}

	fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		err_printf("Cannot open %s: %s\n", dev, strerror(errno));
		ret = 1;
		goto out;
	}

	got = pread(fd, buf, read_len, (off_t)offset);
	if (got < 0 || (size_t)got != read_len) {
		err_printf("Failed to read %zu bytes from %s at 0x%jx\n",
			read_len, dev, (uintmax_t)offset);
		ret = 1;
		goto out;
	}

	ela_crc32_init(crc32_table);

	if (fmt == FW_OUTPUT_CSV)
		out_printf("record,rule,status,message\n");

	for (rulep = start; rulep < stop; rulep++) {
		const struct embedded_linux_audit_rule *rule = *rulep;
		char message[512] = {0};
		int rc;
		struct embedded_linux_audit_input input;

		if (!rule_name_selected(rule_filter, rule))
			continue;
		if (!rule->run)
			continue;

		ran_any = true;
		if (verbose)
			print_verbose_rule_begin(fmt, rule);
		input.device = dev;
		input.offset = offset;
		input.data = buf;
		input.data_len = read_len;
		input.crc32_table = crc32_table;
		input.signature_blob_path = signature_blob_path;
		input.signature_pubkey_path = signature_pubkey_path;
		input.signature_algorithm = signature_algorithm;
		input.verbose = verbose;

		rc = rule->run(&input, message, sizeof(message));
		print_rule_record(fmt, rule, rc, message[0] ? message : NULL);
		if (rc != 0)
			ret = 1;
	}

	if (!ran_any) {
		err_printf("No audit rules matched%s%s\n",
			rule_filter ? " filter: " : "",
			rule_filter ? rule_filter : "");
		ret = 2;
	}

	if (verbose && ran_any)
		print_verbose_audit_end(fmt, ret);

out:
	if (flush_output_http_buffer() < 0 && ret == 0)
		ret = 1;
	if (fd >= 0)
		close(fd);
	if (g_output_sock >= 0)
		close(g_output_sock);
	free(scanned_blob_path);
	free(scanned_pubkey_path);
	free(buf);
	free(g_output_http_buf);
	g_output_http_buf = NULL;
	g_output_http_len = 0;
	g_output_http_cap = 0;
	g_output_http_uri = NULL;
	return ret;
}
