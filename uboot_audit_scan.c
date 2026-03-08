// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "uboot_scan.h"

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define FIT_MIN_TOTAL_SIZE 0x100U
#define FIT_MAX_TOTAL_SIZE (64U * 1024U * 1024U)
#define AUTO_SCAN_STEP 0x1000ULL

static uint32_t read_be32_local(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) |
		((uint32_t)p[1] << 16) |
		((uint32_t)p[2] << 8) |
		(uint32_t)p[3];
}

enum uboot_output_format {
	FW_OUTPUT_TXT = 0,
	FW_OUTPUT_CSV,
	FW_OUTPUT_JSON,
};

static enum uboot_output_format detect_output_format(void)
{
	const char *fmt = getenv("FW_AUDIT_OUTPUT_FORMAT");

	if (!fmt || !*fmt || !strcmp(fmt, "txt"))
		return FW_OUTPUT_TXT;
	if (!strcmp(fmt, "csv"))
		return FW_OUTPUT_CSV;
	if (!strcmp(fmt, "json"))
		return FW_OUTPUT_JSON;

	return FW_OUTPUT_TXT;
}

static uint64_t parse_u64(const char *s)
{
	uint64_t v;

	if (uboot_parse_u64(s, &v)) {
		fprintf(stderr, "Invalid number: %s\n", s);
		exit(2);
	}

	return v;
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

	for (off = 0; off + sizeof(hdr) <= dev_size; off += AUTO_SCAN_STEP) {
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

	for (off = 0; off < dev_size; off += sizeof(chunk)) {
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

static int auto_scan_signature_artifacts(char **blob_path_out, char **pubkey_path_out)
{
	glob_t g;
	unsigned int scan_flags = FW_SCAN_GLOB_MTDBLOCK | FW_SCAN_GLOB_UBI |
		FW_SCAN_GLOB_UBIBLOCK | FW_SCAN_GLOB_MMCBLK | FW_SCAN_GLOB_SDBLK;
	char *pem = NULL;
	char *blob_path = NULL;
	char *pubkey_path = NULL;

	if (!blob_path_out || !pubkey_path_out)
		return -1;

	if (mkdir("generated", 0755) != 0 && errno != EEXIST)
		return -1;

	if (uboot_glob_scan_devices(&g, scan_flags) < 0)
		return -1;

	for (size_t i = 0; i < g.gl_pathc && (!blob_path || !pubkey_path); i++) {
		const char *dev = g.gl_pathv[i];

		if (!blob_path) {
			uint64_t fit_off;
			uint32_t fit_size;
			if (find_fit_blob_in_device(dev, &fit_off, &fit_size) == 0) {
				blob_path = strdup("generated/auto_signature_blob.fit");
				if (blob_path && extract_region_to_file(dev, fit_off, fit_size, blob_path) != 0) {
					free(blob_path);
					blob_path = NULL;
				}
			}
		}

		if (!pubkey_path) {
			if (find_pubkey_pem_in_device(dev, &pem) == 0) {
				int fd;
				pubkey_path = strdup("generated/auto_signature_pubkey.pem");
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

	*blob_path_out = blob_path;
	*pubkey_path_out = pubkey_path;

	return (blob_path ? 1 : 0) + (pubkey_path ? 1 : 0);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--list-rules] [--rule <name>] --dev <device> [--offset <bytes>] --size <bytes> [--verbose]\n"
		"  --list-rules    List compiled audit rules\n"
		"  --rule <name>   Run only one rule by name\n"
		"  --dev <device>  Input device/file to audit\n"
		"  --offset <n>    Read offset (default: 0)\n"
		"  --size <n>      Number of bytes to read for audit\n"
		"  --signature-blob <path>   Blob file used for signature verification rules\n"
		"  --signature-pubkey <path> Public key PEM file for signature verification rules\n"
		"  --scan-signature-devices  Force device scan for FIT blob and PEM pubkey (default if paths missing)\n"
		"  --scan-signature-blob <glob>   Auto-select first readable blob path matching glob\n"
		"  --scan-signature-pubkey <glob> Auto-select first readable pubkey path matching glob\n"
		"  --signature-alg <name>    Digest algorithm (if omitted: tries sha256, sha384, sha512, sha1, sha224)\n"
		"  --verbose       Enable verbose audit output\n",
		prog);
}

static bool rule_name_selected(const char *filter, const struct uboot_audit_rule *rule)
{
	if (!rule || !rule->name || !*rule->name)
		return false;

	if (!filter || !*filter)
		return true;

	return !strcmp(filter, rule->name);
}

static void print_rule_record(enum uboot_output_format fmt,
			      const struct uboot_audit_rule *rule,
			      int rc,
			      const char *message)
{
	const char *status = (rc == 0) ? "pass" : ((rc > 0) ? "fail" : "error");

	if (fmt == FW_OUTPUT_CSV) {
		printf("audit_rule,%s,%s,%s\n",
		       rule->name ? rule->name : "",
		       status,
		       message ? message : "");
		return;
	}

	if (fmt == FW_OUTPUT_JSON) {
		printf("{\"record\":\"audit_rule\",\"rule\":\"%s\",\"status\":\"%s\",\"message\":\"",
		       rule->name ? rule->name : "", status);
		if (message) {
			for (const char *p = message; *p; p++) {
				if (*p == '\\' || *p == '"')
					putchar('\\');
				putchar(*p);
			}
		}
		printf("\"}\n");
		return;
	}

	printf("[%s] %s: %s\n",
	       status,
	       rule->name ? rule->name : "(unnamed-rule)",
	       message ? message : "");
}

static void print_rule_listing(enum uboot_output_format fmt, const struct uboot_audit_rule *rule)
{
	if (fmt == FW_OUTPUT_CSV) {
		printf("audit_rule_list,%s,%s\n",
		       rule->name ? rule->name : "",
		       (rule->description && *rule->description) ? rule->description : "");
		return;
	}

	if (fmt == FW_OUTPUT_JSON) {
		printf("{\"record\":\"audit_rule_list\",\"rule\":\"%s\",\"description\":\"",
		       rule->name ? rule->name : "");
		if (rule->description) {
			for (const char *p = rule->description; *p; p++) {
				if (*p == '\\' || *p == '"')
					putchar('\\');
				putchar(*p);
			}
		}
		printf("\"}\n");
		return;
	}

	printf("%s", rule->name ? rule->name : "");
	if (rule->description && *rule->description)
		printf(" - %s", rule->description);
	printf("\n");
}

int uboot_audit_scan_main(int argc, char **argv)
{
	const char *dev = NULL;
	const char *rule_filter = NULL;
	const char *signature_blob_path = NULL;
	const char *signature_pubkey_path = NULL;
	const char *signature_blob_scan = NULL;
	const char *signature_pubkey_scan = NULL;
	const char *signature_algorithm = NULL;
	bool scan_signature_devices = false;
	uint64_t offset = 0;
	uint64_t size = 0;
	bool verbose = false;
	bool list_rules = false;
	uint32_t crc32_table[256];
	const struct uboot_audit_rule * const *rulep;
	const struct uboot_audit_rule * const *start = __start_uboot_audit_rules;
	const struct uboot_audit_rule * const *stop = __stop_uboot_audit_rules;
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
		{ "signature-alg", required_argument, NULL, 'A' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "rule", required_argument, NULL, 'r' },
		{ "list-rules", no_argument, NULL, 'l' },
		{ 0, 0, 0, 0 }
	};

	optind = 1;
	fmt = detect_output_format();

	while ((opt = getopt_long(argc, argv, "hd:o:s:B:K:X:Y:ZA:vr:l", long_opts, NULL)) != -1) {
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
		case 'A':
			signature_algorithm = optarg;
			break;
		case 'v':
			verbose = true;
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

	if (list_rules) {
		if (fmt == FW_OUTPUT_CSV)
			printf("record,rule,description\n");

		for (rulep = start; rulep < stop; rulep++) {
			const struct uboot_audit_rule *rule = *rulep;

			if (!rule->name || !rule->run)
				continue;
			print_rule_listing(fmt, rule);
		}
		return 0;
	}

	if (!dev || !size) {
		usage(argv[0]);
		return 2;
	}

	if (!signature_blob_path && signature_blob_scan) {
		signature_blob_path = resolve_first_readable_glob(signature_blob_scan, &scanned_blob_path);
		if (!signature_blob_path) {
			fprintf(stderr, "No readable files matched --scan-signature-blob pattern: %s\n", signature_blob_scan);
			ret = 2;
			goto out;
		}
	}

	if (!signature_pubkey_path && signature_pubkey_scan) {
		signature_pubkey_path = resolve_first_readable_glob(signature_pubkey_scan, &scanned_pubkey_path);
		if (!signature_pubkey_path) {
			fprintf(stderr, "No readable files matched --scan-signature-pubkey pattern: %s\n", signature_pubkey_scan);
			ret = 2;
			goto out;
		}
	}

	if (!signature_blob_path || !signature_pubkey_path || scan_signature_devices) {
		int found_count = auto_scan_signature_artifacts(&scanned_blob_path, &scanned_pubkey_path);
		if (found_count < 0) {
			fprintf(stderr, "Warning: signature artifact device scan failed\n");
		} else if (verbose && found_count > 0) {
			fprintf(stderr, "Auto-discovered %d signature artifact(s) from device scan\n", found_count);
		}
		if (!signature_blob_path)
			signature_blob_path = scanned_blob_path;
		if (!signature_pubkey_path)
			signature_pubkey_path = scanned_pubkey_path;
	}

	if (signature_blob_path && access(signature_blob_path, R_OK) != 0) {
		fprintf(stderr, "Cannot read --signature-blob %s: %s\n", signature_blob_path, strerror(errno));
		return 2;
	}

	if (signature_pubkey_path && access(signature_pubkey_path, R_OK) != 0) {
		fprintf(stderr, "Cannot read --signature-pubkey %s: %s\n", signature_pubkey_path, strerror(errno));
		return 2;
	}

	if (size > (uint64_t)SIZE_MAX) {
		fprintf(stderr, "Requested --size is too large for this host\n");
		return 2;
	}

	read_len = (size_t)size;
	buf = malloc(read_len);
	if (!buf) {
		fprintf(stderr, "Unable to allocate %zu bytes for audit input\n", read_len);
		return 1;
	}

	fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n", dev, strerror(errno));
		ret = 1;
		goto out;
	}

	got = pread(fd, buf, read_len, (off_t)offset);
	if (got < 0 || (size_t)got != read_len) {
		fprintf(stderr, "Failed to read %zu bytes from %s at 0x%jx\n",
			read_len, dev, (uintmax_t)offset);
		ret = 1;
		goto out;
	}

	uboot_crc32_init(crc32_table);

	if (fmt == FW_OUTPUT_CSV)
		printf("record,rule,status,message\n");

	for (rulep = start; rulep < stop; rulep++) {
		const struct uboot_audit_rule *rule = *rulep;
		char message[512] = {0};
		int rc;
		struct uboot_audit_input input;

		if (!rule_name_selected(rule_filter, rule))
			continue;
		if (!rule->run)
			continue;

		ran_any = true;
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
		fprintf(stderr, "No audit rules matched%s%s\n",
			rule_filter ? " filter: " : "",
			rule_filter ? rule_filter : "");
		ret = 2;
	}

out:
	if (fd >= 0)
		close(fd);
	free(scanned_blob_path);
	free(scanned_pubkey_path);
	free(buf);
	return ret;
}
