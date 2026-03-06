// SPDX-License-Identifier: GPL-2.0+
/*
 * Minimal U-Boot environment scanner for Linux hosts without Python.
 *
 * Build example (static ARM32 LE):
 *   arm-linux-gnueabi-gcc -O2 -static -o fw_env_scan tools/env/fw_env_scan.c
 *
 * Usage:
 *   ./fw_env_scan -s 0x10000
 *   ./fw_env_scan -s 0x10000 /dev/mtd0:0x10000 /dev/mtd1:0x20000
 *   ./fw_env_scan                  (tries common env sizes automatically)
 */

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/*
 * Auto-mode scan granularity cap.
 *
 * Many devices report large erasesize (e.g. 0x20000), but environment
 * offsets can be aligned more finely (e.g. 0x10000). To avoid missing valid
 * offsets in auto mode, cap step to this value.
 */
#define AUTO_SCAN_MAX_STEP 0x10000ULL

static uint32_t crc32_table[256];

static void crc32_init(void)
{
	uint32_t poly = 0xEDB88320U;
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t c = i;
		for (int j = 0; j < 8; j++)
			c = (c & 1) ? (poly ^ (c >> 1)) : (c >> 1);
		crc32_table[i] = c;
	}
}

static uint32_t crc32_calc(const uint8_t *buf, size_t len)
{
	uint32_t c = 0xFFFFFFFFU;
	for (size_t i = 0; i < len; i++)
		c = crc32_table[(c ^ buf[i]) & 0xff] ^ (c >> 8);
	return c ^ 0xFFFFFFFFU;
}

static uint32_t read_le32(const uint8_t *p)
{
	return (uint32_t)p[0] |
		((uint32_t)p[1] << 8) |
		((uint32_t)p[2] << 16) |
		((uint32_t)p[3] << 24);
}

static uint32_t read_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) |
		((uint32_t)p[1] << 16) |
		((uint32_t)p[2] << 8) |
		(uint32_t)p[3];
}

static uint64_t parse_u64(const char *s)
{
	char *end;
	unsigned long long v;

	errno = 0;
	v = strtoull(s, &end, 0);
	while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')
		end++;
	if (errno || end == s || *end != '\0') {
		fprintf(stderr, "Invalid number: %s\n", s);
		exit(2);
	}
	return (uint64_t)v;
}

static int get_mtd_index(const char *dev, char *idx, size_t idx_sz)
{
	const char *base = strrchr(dev, '/');
	const char *p;
	size_t j = 0;

	if (!idx || idx_sz < 2)
		return -1;

	base = base ? base + 1 : dev;
	if (!strncmp(base, "mtdblock", 8))
		p = base + 8;
	else if (!strncmp(base, "mtd", 3))
		p = base + 3;
	else
		return -1;

	while (*p >= '0' && *p <= '9' && j < idx_sz - 1)
		idx[j++] = *p++;

	if (!j)
		return -1;
	if (*p && strcmp(p, "ro"))
		return -1;

	idx[j] = '\0';
	return 0;
}

static uint64_t read_u64_from_file(const char *path)
{
	char buf[64];
	int fd;
	ssize_t n;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return 0;

	buf[n] = '\0';
	return parse_u64(buf);
}

static uint64_t guess_size_from_sysfs(const char *dev)
{
	char idx[32], path[256];

	if (get_mtd_index(dev, idx, sizeof(idx)))
		return 0;
	snprintf(path, sizeof(path), "/sys/class/mtd/mtd%s/size", idx);
	return read_u64_from_file(path);
}

static uint64_t guess_erasesize_from_sysfs(const char *dev)
{
	char idx[32], path[256];

	if (get_mtd_index(dev, idx, sizeof(idx)))
		return 0;
	snprintf(path, sizeof(path), "/sys/class/mtd/mtd%s/erasesize", idx);
	return read_u64_from_file(path);
}

static void make_proc_mtd_name(const char *dev, char *out, size_t out_sz)
{
	char idx[32];
	size_t idx_len;

	if (!out || out_sz < 5) {
		if (out && out_sz)
			*out = '\0';
		return;
	}

	if (get_mtd_index(dev, idx, sizeof(idx))) {
		*out = '\0';
		return;
	}

	out[0] = 'm';
	out[1] = 't';
	out[2] = 'd';

	idx_len = strnlen(idx, out_sz - 4);
	memcpy(out + 3, idx, idx_len);
	out[3 + idx_len] = '\0';
}

static uint64_t guess_size_from_proc_mtd(const char *dev)
{
	char want[32], line[256];
	FILE *fp;

	make_proc_mtd_name(dev, want, sizeof(want));
	if (!want[0])
		return 0;

	fp = fopen("/proc/mtd", "r");
	if (!fp)
		return 0;

	while (fgets(line, sizeof(line), fp)) {
		char name[32];
		unsigned long long size;
		if (sscanf(line, "%31[^:]: %llx", name, &size) == 2 && !strcmp(name, want)) {
			fclose(fp);
			return (uint64_t)size;
		}
	}

	fclose(fp);
	return 0;
}

static uint64_t guess_erasesize_from_proc_mtd(const char *dev)
{
	char want[32], line[256];
	FILE *fp;

	make_proc_mtd_name(dev, want, sizeof(want));
	if (!want[0])
		return 0;

	fp = fopen("/proc/mtd", "r");
	if (!fp)
		return 0;

	while (fgets(line, sizeof(line), fp)) {
		char name[32];
		unsigned long long size, erase;
		if (sscanf(line, "%31[^:]: %llx %llx", name, &size, &erase) == 3 && !strcmp(name, want)) {
			fclose(fp);
			return (uint64_t)erase;
		}
	}

	fclose(fp);
	return 0;
}

static bool has_hint_var(const uint8_t *data, size_t len)
{
	static const char *hints[] = {
		"bootcmd=", "bootargs=", "baudrate=", "ethaddr=", "stdin=",
	};

	for (size_t i = 0; i < ARRAY_SIZE(hints); i++) {
		size_t hlen = strlen(hints[i]);
		for (size_t off = 0; off + hlen <= len; off++) {
			if (!memcmp(data + off, hints[i], hlen))
				return true;
		}
	}

	return false;
}

/* returns number of candidates, or -1 on error */
static int scan_dev(const char *dev, uint64_t step, uint64_t env_size)
{
	int fd;
	struct stat st;
	uint8_t *buf;
	off_t off;
	int hits = 0;

	if (!step || !env_size)
		return -1;

	fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n", dev, strerror(errno));
		return -1;
	}

	if (fstat(fd, &st) < 0) {
		fprintf(stderr, "fstat(%s) failed: %s\n", dev, strerror(errno));
		close(fd);
		return -1;
	}

	if (st.st_size == 0) {
		uint64_t sz = guess_size_from_sysfs(dev);
		if (!sz)
			sz = guess_size_from_proc_mtd(dev);
		st.st_size = (off_t)sz;
	}

	if (st.st_size == 0) {
		fprintf(stderr, "Cannot determine size for %s\n", dev);
		close(fd);
		return -1;
	}

	buf = malloc((size_t)env_size);
	if (!buf) {
		close(fd);
		return -1;
	}

	printf("\nScanning %s (size=0x%jx, step=0x%jx, env_size=0x%jx)\n",
	       dev, (uintmax_t)st.st_size, (uintmax_t)step, (uintmax_t)env_size);

	for (off = 0; (uint64_t)off + env_size <= (uint64_t)st.st_size; off += (off_t)step) {
		ssize_t n = pread(fd, buf, (size_t)env_size, off);
		if (n < 0) {
			fprintf(stderr, "pread(%s, 0x%jx) failed: %s\n",
				dev, (uintmax_t)off, strerror(errno));
			break;
		}
		if ((uint64_t)n != env_size)
			break;

		{
			uint32_t stored_le = read_le32(buf);
			uint32_t stored_be = read_be32(buf);
			uint32_t calc = crc32_calc(buf + 4, (size_t)env_size - 4);
			if (calc != stored_le && calc != stored_be)
				continue;

			printf("  candidate offset=0x%jx  crc=%s-endian  %s\n",
			       (uintmax_t)off,
			       (calc == stored_le) ? "LE" : "BE",
			       has_hint_var(buf + 4, (size_t)env_size - 4) ?
			       "(has known vars)" : "(crc ok)");
			printf("    fw_env.config line: %s 0x%jx 0x%jx 0x%jx\n",
			       dev, (uintmax_t)off, (uintmax_t)env_size, (uintmax_t)step);
			hits++;
		}
	}

	if (!hits)
		printf("  no candidates found\n");

	free(buf);
	close(fd);
	return hits;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-s <env_size>] [<dev:step> ...]\n"
		"  no args: auto-devices + common env sizes\n"
		"  -s: fixed env size\n"
		"Examples:\n"
		"  %s\n"
		"  %s -s 0x10000\n"
		"  %s -s 0x10000 /dev/mtd0:0x10000\n",
		prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
	static const uint64_t common_sizes[] = {
		0x1000, 0x2000, 0x4000, 0x8000,
		0x10000, 0x20000, 0x40000, 0x80000,
	};
	bool fixed_size = false;
	uint64_t env_size = 0;
	int argi = 1;
	int i;

	if (argc > 1 && !strcmp(argv[1], "-h")) {
		usage(argv[0]);
		return 0;
	}

	if (argc > 1 && !strcmp(argv[1], "-s")) {
		if (argc < 3) {
			usage(argv[0]);
			return 2;
		}
		env_size = parse_u64(argv[2]);
		fixed_size = true;
		argi = 3;
	}

	crc32_init();

	if (argi >= argc) {
		glob_t g;
		size_t gi;
		int scanned = 0;

		memset(&g, 0, sizeof(g));
		glob("/dev/mtd[0-9]*", 0, NULL, &g);
		glob("/dev/mtdblock[0-9]*", GLOB_APPEND, NULL, &g);

		for (gi = 0; gi < g.gl_pathc; gi++) {
			const char *dev = g.gl_pathv[gi];
			uint64_t step = guess_erasesize_from_sysfs(dev);
			if (!step)
				step = guess_erasesize_from_proc_mtd(dev);
			if (!step)
				continue;

			if (step > AUTO_SCAN_MAX_STEP)
				step = AUTO_SCAN_MAX_STEP;

			scanned++;
			if (fixed_size) {
				if (scan_dev(dev, step, env_size) < 0) {
					globfree(&g);
					return 1;
				}
			} else {
				for (i = 0; i < (int)ARRAY_SIZE(common_sizes); i++) {
					printf("\n== trying env_size=0x%jx on %s ==\n",
					       (uintmax_t)common_sizes[i], dev);
					if (scan_dev(dev, step, common_sizes[i]) < 0) {
						globfree(&g);
						return 1;
					}
				}
			}
		}

		globfree(&g);
		if (!scanned) {
			fprintf(stderr, "No usable /dev/mtd* or /dev/mtdblock* devices found\n");
			return 1;
		}
		return 0;
	}

	for (i = argi; i < argc; i++) {
		char *arg = argv[i];
		char *colon = strrchr(arg, ':');
		uint64_t step;

		if (!colon || colon == arg || *(colon + 1) == '\0') {
			fprintf(stderr, "Invalid dev:step argument: %s\n", arg);
			continue;
		}

		*colon = '\0';
		step = parse_u64(colon + 1);

		if (fixed_size) {
			if (scan_dev(arg, step, env_size) < 0) {
				*colon = ':';
				return 1;
			}
		} else {
			for (int si = 0; si < (int)ARRAY_SIZE(common_sizes); si++) {
				printf("\n== trying env_size=0x%jx on %s ==\n",
				       (uintmax_t)common_sizes[si], arg);
				if (scan_dev(arg, step, common_sizes[si]) < 0) {
					*colon = ':';
					return 1;
				}
			}
		}

		*colon = ':';
	}

	return 0;
}
