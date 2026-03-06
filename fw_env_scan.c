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
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <glob.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
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

static int get_ubi_indices(const char *dev, unsigned int *ubi, unsigned int *vol)
{
	const char *base = strrchr(dev, '/');
	char extra;

	if (!ubi || !vol)
		return -1;

	base = base ? base + 1 : dev;
	if (!strncmp(base, "ubiblock", 8))
		base += 8;
	else if (!strncmp(base, "ubi", 3))
		base += 3;
	else
		return -1;

	if (sscanf(base, "%u_%u%c", ubi, vol, &extra) != 2)
		return -1;

	return 0;
}

static uint64_t guess_size_from_ubi_sysfs(const char *dev)
{
	unsigned int ubi, vol;
	char path[256];
	uint64_t data_bytes;
	uint64_t reserved_ebs;
	uint64_t usable_eb_size;

	if (get_ubi_indices(dev, &ubi, &vol))
		return 0;

	snprintf(path, sizeof(path), "/sys/class/ubi/ubi%u_%u/data_bytes", ubi, vol);
	data_bytes = read_u64_from_file(path);
	if (data_bytes)
		return data_bytes;

	snprintf(path, sizeof(path), "/sys/class/ubi/ubi%u_%u/reserved_ebs", ubi, vol);
	reserved_ebs = read_u64_from_file(path);
	if (!reserved_ebs)
		return 0;

	snprintf(path, sizeof(path), "/sys/class/ubi/ubi%u/usable_eb_size", ubi);
	usable_eb_size = read_u64_from_file(path);
	if (!usable_eb_size)
		return 0;

	return reserved_ebs * usable_eb_size;
}

static uint64_t guess_step_from_ubi_sysfs(const char *dev)
{
	unsigned int ubi, vol;
	char path[256];
	uint64_t step;

	if (get_ubi_indices(dev, &ubi, &vol))
		return 0;

	snprintf(path, sizeof(path), "/sys/class/ubi/ubi%u/min_io_size", ubi);
	step = read_u64_from_file(path);
	if (step)
		return step;

	snprintf(path, sizeof(path), "/sys/class/ubi/ubi%u/usable_eb_size", ubi);
	return read_u64_from_file(path);
}

static void create_node_if_missing(const char *path, mode_t mode, dev_t devno)
{
	struct stat st;

	if (!stat(path, &st))
		return;
	if (errno != ENOENT)
		return;

	if (mknod(path, mode, devno) < 0) {
		fprintf(stderr, "Warning: cannot create %s: %s\n",
			path, strerror(errno));
		return;
	}

	printf("Created missing node: %s\n", path);
}

static void ensure_mtd_nodes(void)
{
	DIR *dir;
	struct dirent *de;

	dir = opendir("/sys/class/mtd");
	if (!dir)
		return;

	while ((de = readdir(dir))) {
		unsigned int idx;
		char extra;
		char devpath[64];
		char devpath_ro[64];
		char blockpath[64];

		if (sscanf(de->d_name, "mtd%u%c", &idx, &extra) != 1)
			continue;

		snprintf(devpath, sizeof(devpath), "/dev/mtd%u", idx);
		snprintf(devpath_ro, sizeof(devpath_ro), "/dev/mtd%uro", idx);
		snprintf(blockpath, sizeof(blockpath), "/dev/mtdblock%u", idx);

		create_node_if_missing(devpath, S_IFCHR | 0600, makedev(90, idx * 2));
		create_node_if_missing(devpath_ro, S_IFCHR | 0400, makedev(90, idx * 2 + 1));
		create_node_if_missing(blockpath, S_IFBLK | 0600, makedev(31, idx));
	}

	closedir(dir);
}

static bool has_hint_var(const uint8_t *data, size_t len, const char *hint_override)
{
	static const char *hints[] = {
		"bootcmd=", "bootargs=", "baudrate=", "ethaddr=", "stdin=",
	};
	size_t hlen;

	if (hint_override && *hint_override) {
		hlen = strlen(hint_override);
		if (!hlen)
			return false;
		for (size_t off = 0; off + hlen <= len; off++) {
			if (!memcmp(data + off, hint_override, hlen))
				return true;
		}
		return false;
	}

	for (size_t i = 0; i < ARRAY_SIZE(hints); i++) {
		hlen = strlen(hints[i]);
		for (size_t off = 0; off + hlen <= len; off++) {
			if (!memcmp(data + off, hints[i], hlen))
				return true;
		}
	}

	return false;
}

/* returns number of candidates, or -1 on error */
static int scan_dev(const char *dev, uint64_t step, uint64_t env_size,
		    const char *hint_override)
{
	int fd;
	struct stat st;
	uint8_t *buf;
	off_t off;
	int hits = 0;
	uint64_t sysfs_erasesize;
	uint64_t erase_size;
	uint64_t sector_count;
	uint64_t cfg_off;

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
		if (!sz)
			sz = guess_size_from_ubi_sysfs(dev);
		st.st_size = (off_t)sz;
	}

	if (st.st_size == 0) {
		fprintf(stderr, "Cannot determine size for %s\n", dev);
		close(fd);
		return -1;
	}

	sysfs_erasesize = guess_erasesize_from_sysfs(dev);
	erase_size = sysfs_erasesize ? sysfs_erasesize : step;
	sector_count = erase_size ? ((env_size + erase_size - 1) / erase_size) : 0;

	buf = malloc((size_t)env_size);
	if (!buf) {
		close(fd);
		return -1;
	}

	printf("\nScanning %s (size=0x%jx, step=0x%jx, env_size=0x%jx, erase_size=0x%jx)\n",
	       dev, (uintmax_t)st.st_size, (uintmax_t)step, (uintmax_t)env_size, (uintmax_t)erase_size);

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

			cfg_off = erase_size ? ((uint64_t)off - ((uint64_t)off % erase_size)) : (uint64_t)off;

			printf("  candidate offset=0x%jx  crc=%s-endian  %s\n",
			       (uintmax_t)off,
			       (calc == stored_le) ? "LE" : "BE",
			       has_hint_var(buf + 4, (size_t)env_size - 4, hint_override) ?
			       "(has known vars)" : "(crc ok)");
			if (cfg_off != (uint64_t)off)
				printf("    aligned offset (erase block floor): 0x%jx\n",
				       (uintmax_t)cfg_off);
			printf("    fw_env.config line: %s 0x%jx 0x%jx 0x%jx 0x%jx\n",
			       dev, (uintmax_t)cfg_off, (uintmax_t)env_size,
			       (uintmax_t)erase_size, (uintmax_t)sector_count);
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
		"Usage: %s [-s <env_size>] [-H <hint>] [-d <dev>|--dev <dev>] [<dev:step> ...]\n"
		"  no args: auto-devices + common env sizes\n"
		"  -s: fixed env size\n"
		"  -H: override default env hint string (example: bootcmd=)\n"
		"  -d, --dev: scan only the specified MTD device path (step from sysfs/proc)\n"
		"Examples:\n"
		"  %s\n"
		"  %s -s 0x10000\n"
		"  %s -H bootcmd=\n"
		"  %s --dev /dev/mtd3 -s 0x10000\n"
		"  %s -s 0x10000 /dev/mtd0:0x10000\n",
		prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
	static const uint64_t common_sizes[] = {
		0x1000, 0x2000, 0x4000, 0x8000,
		0x10000, 0x20000, 0x40000, 0x80000,
	};
	bool fixed_size = false;
	uint64_t env_size = 0;
	const char *hint_override = NULL;
	const char *dev_override = NULL;
	int argi;
	int opt;
	int i;
	static const struct option long_opts[] = {
		{ "dev", required_argument, NULL, 'd' },
		{ 0, 0, 0, 0 }
	};

	opterr = 0;
	while ((opt = getopt_long(argc, argv, "hs:H:d:", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 's':
			env_size = parse_u64(optarg);
			fixed_size = true;
			break;
		case 'H':
			hint_override = optarg;
			break;
		case 'd':
			dev_override = optarg;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	argi = optind;
	if (argi < argc && argv[argi][0] == '-') {
		usage(argv[0]);
		return 2;
	}

	crc32_init();
	ensure_mtd_nodes();

	if (dev_override) {
		uint64_t step = guess_erasesize_from_sysfs(dev_override);

		if (argi < argc) {
			fprintf(stderr, "Do not combine --dev with <dev:step> positional args\n");
			return 2;
		}

		if (!step)
			step = guess_erasesize_from_proc_mtd(dev_override);
		if (!step)
			step = guess_step_from_ubi_sysfs(dev_override);
		if (!step) {
			fprintf(stderr, "Cannot determine scan step for %s\n", dev_override);
			return 1;
		}

		if (step > AUTO_SCAN_MAX_STEP)
			step = AUTO_SCAN_MAX_STEP;

		if (fixed_size) {
			if (scan_dev(dev_override, step, env_size, hint_override) < 0)
				return 1;
		} else {
			for (i = 0; i < (int)ARRAY_SIZE(common_sizes); i++) {
				printf("\n== trying env_size=0x%jx on %s ==\n",
				       (uintmax_t)common_sizes[i], dev_override);
				if (scan_dev(dev_override, step, common_sizes[i], hint_override) < 0)
					return 1;
			}
		}

		return 0;
	}

	if (argi >= argc) {
		glob_t g;
		size_t gi;
		int scanned = 0;

		memset(&g, 0, sizeof(g));
		glob("/dev/mtd[0-9]*", 0, NULL, &g);
		glob("/dev/mtdblock[0-9]*", GLOB_APPEND, NULL, &g);
		glob("/dev/ubi[0-9]*_[0-9]*", GLOB_APPEND, NULL, &g);
		glob("/dev/ubiblock[0-9]*_[0-9]*", GLOB_APPEND, NULL, &g);

		for (gi = 0; gi < g.gl_pathc; gi++) {
			const char *dev = g.gl_pathv[gi];
			uint64_t step = guess_erasesize_from_sysfs(dev);
			if (!step)
				step = guess_erasesize_from_proc_mtd(dev);
			if (!step)
				step = guess_step_from_ubi_sysfs(dev);
			if (!step)
				continue;

			if (step > AUTO_SCAN_MAX_STEP)
				step = AUTO_SCAN_MAX_STEP;

			scanned++;
			if (fixed_size) {
				if (scan_dev(dev, step, env_size, hint_override) < 0) {
					globfree(&g);
					return 1;
				}
			} else {
				for (i = 0; i < (int)ARRAY_SIZE(common_sizes); i++) {
					printf("\n== trying env_size=0x%jx on %s ==\n",
					       (uintmax_t)common_sizes[i], dev);
					if (scan_dev(dev, step, common_sizes[i], hint_override) < 0) {
						globfree(&g);
						return 1;
					}
				}
			}
		}

		globfree(&g);
		if (!scanned) {
			fprintf(stderr,
				"No usable /dev/mtd*, /dev/mtdblock*, /dev/ubi*_* or /dev/ubiblock*_* devices found\n");
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
			if (scan_dev(arg, step, env_size, hint_override) < 0) {
				*colon = ':';
				return 1;
			}
		} else {
			for (int si = 0; si < (int)ARRAY_SIZE(common_sizes); si++) {
				printf("\n== trying env_size=0x%jx on %s ==\n",
				       (uintmax_t)common_sizes[si], arg);
				if (scan_dev(arg, step, common_sizes[si], hint_override) < 0) {
					*colon = ':';
					return 1;
				}
			}
		}

		*colon = ':';
	}

	return 0;
}
