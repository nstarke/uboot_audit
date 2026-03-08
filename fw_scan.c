#include "fw_scan.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static uint64_t read_u64_from_file(const char *path)
{
	char buf[64];
	int fd;
	ssize_t n;
	char *end;
	unsigned long long v;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return 0;

	buf[n] = '\0';
	errno = 0;
	v = strtoull(buf, &end, 0);
	while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')
		end++;
	if (errno || end == buf || *end != '\0')
		return 0;

	return (uint64_t)v;
}

int fw_parse_u64(const char *s, uint64_t *out)
{
	char *end;
	unsigned long long v;

	if (!s || !out)
		return -1;

	errno = 0;
	v = strtoull(s, &end, 0);
	while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')
		end++;
	if (errno || end == s || *end != '\0')
		return -1;

	*out = (uint64_t)v;
	return 0;
}

uint32_t fw_read_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) |
	       ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) |
	       (uint32_t)p[3];
}

int fw_connect_tcp_ipv4(const char *spec)
{
	char host[64];
	char *colon;
	char *end;
	unsigned long port_ul;
	int sock;
	struct sockaddr_in sa;

	if (!spec || !*spec)
		return -1;

	strncpy(host, spec, sizeof(host) - 1);
	host[sizeof(host) - 1] = '\0';
	colon = strrchr(host, ':');
	if (!colon || colon == host || *(colon + 1) == '\0')
		return -1;

	*colon = '\0';
	errno = 0;
	port_ul = strtoul(colon + 1, &end, 10);
	if (errno || *end || port_ul == 0 || port_ul > 65535)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)port_ul);
	if (inet_pton(AF_INET, host, &sa.sin_addr) != 1)
		return -1;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(sock);
		return -1;
	}

	return sock;
}

int fw_send_all(int sock, const uint8_t *buf, size_t len)
{
	while (len) {
		ssize_t n = send(sock, buf, len, 0);
		if (n <= 0)
			return -1;
		buf += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
}

void fw_crc32_init(uint32_t table[256])
{
	const uint32_t poly = 0xEDB88320U;

	if (!table)
		return;

	for (uint32_t i = 0; i < 256; i++) {
		uint32_t c = i;
		for (int j = 0; j < 8; j++)
			c = (c & 1U) ? (poly ^ (c >> 1)) : (c >> 1);
		table[i] = c;
	}
}

uint32_t fw_crc32_calc(const uint32_t table[256], const uint8_t *buf, size_t len)
{
	uint32_t c = 0xFFFFFFFFU;

	if (!table || !buf)
		return 0;

	for (size_t i = 0; i < len; i++)
		c = table[(c ^ buf[i]) & 0xFFU] ^ (c >> 8);

	return c ^ 0xFFFFFFFFU;
}

int fw_get_mtd_index(const char *dev, char *idx, size_t idx_sz)
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

uint64_t fw_guess_size_from_sysfs(const char *dev)
{
	char idx[32], path[256];

	if (fw_get_mtd_index(dev, idx, sizeof(idx)))
		return 0;
	snprintf(path, sizeof(path), "/sys/class/mtd/mtd%s/size", idx);
	return read_u64_from_file(path);
}

uint64_t fw_guess_erasesize_from_sysfs(const char *dev)
{
	char idx[32], path[256];

	if (fw_get_mtd_index(dev, idx, sizeof(idx)))
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

	if (fw_get_mtd_index(dev, idx, sizeof(idx))) {
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

uint64_t fw_guess_size_from_proc_mtd(const char *dev)
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

uint64_t fw_guess_erasesize_from_proc_mtd(const char *dev)
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

uint64_t fw_guess_size_from_ubi_sysfs(const char *dev)
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

uint64_t fw_guess_step_from_ubi_sysfs(const char *dev)
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

static void create_node_if_missing(const char *path, mode_t mode, dev_t devno, bool verbose)
{
	struct stat st;

	if (!stat(path, &st))
		return;
	if (errno != ENOENT)
		return;

	if (mknod(path, mode, devno) < 0) {
		if (verbose)
			fprintf(stderr, "Warning: cannot create %s: %s\n", path, strerror(errno));
		return;
	}

	if (verbose)
		printf("Created missing node: %s\n", path);
}

static int read_major_minor_from_sysfs(const char *dev_attr_path,
				       unsigned int *major_out,
				       unsigned int *minor_out)
{
	char buf[64];
	int fd;
	ssize_t n;
	unsigned int major, minor;

	if (!major_out || !minor_out)
		return -1;

	fd = open(dev_attr_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;

	buf[n] = '\0';
	if (sscanf(buf, "%u:%u", &major, &minor) != 2)
		return -1;

	*major_out = major;
	*minor_out = minor;
	return 0;
}

void fw_ensure_mtd_nodes(bool verbose)
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
		char blockpath[64];

		if (sscanf(de->d_name, "mtd%u%c", &idx, &extra) != 1)
			continue;

		snprintf(devpath, sizeof(devpath), "/dev/mtd%u", idx);
		snprintf(blockpath, sizeof(blockpath), "/dev/mtdblock%u", idx);

		create_node_if_missing(devpath, S_IFCHR | 0600, makedev(90, idx * 2), verbose);
		create_node_if_missing(blockpath, S_IFBLK | 0600, makedev(31, idx), verbose);
	}

	closedir(dir);
}

void fw_ensure_ubi_nodes(bool verbose)
{
	DIR *dir;
	struct dirent *de;
	const char *ubi_prefix = "/sys/class/ubi/";
	const char *blk_prefix = "/sys/class/block/";
	const char *dev_suffix = "/dev";

	dir = opendir("/sys/class/ubi");
	if (dir) {
		while ((de = readdir(dir))) {
			unsigned int ubi, vol;
			char extra;
			char dev_attr[256];
			char devnode[64];
			unsigned int major, minor;
			size_t name_len;
			size_t prefix_len;
			size_t suffix_len;

			if (sscanf(de->d_name, "ubi%u_%u%c", &ubi, &vol, &extra) == 2) {
				snprintf(devnode, sizeof(devnode), "/dev/ubi%u_%u", ubi, vol);
			} else if (sscanf(de->d_name, "ubi%u%c", &ubi, &extra) == 1) {
				snprintf(devnode, sizeof(devnode), "/dev/ubi%u", ubi);
			} else {
				continue;
			}

			name_len = strnlen(de->d_name, sizeof(dev_attr));
			prefix_len = strlen(ubi_prefix);
			suffix_len = strlen(dev_suffix);
			if (name_len >= sizeof(dev_attr))
				continue;
			if (prefix_len + name_len + suffix_len + 1 > sizeof(dev_attr))
				continue;

			memcpy(dev_attr, ubi_prefix, prefix_len);
			memcpy(dev_attr + prefix_len, de->d_name, name_len);
			memcpy(dev_attr + prefix_len + name_len, dev_suffix, suffix_len + 1);

			if (read_major_minor_from_sysfs(dev_attr, &major, &minor))
				continue;

			create_node_if_missing(devnode, S_IFCHR | 0600, makedev(major, minor), verbose);
		}

		closedir(dir);
	}

	dir = opendir("/sys/class/block");
	if (!dir)
		return;

	while ((de = readdir(dir))) {
		unsigned int ubi, vol;
		char extra;
		char dev_attr[256];
		char devnode[64];
		unsigned int major, minor;
		size_t name_len;
		size_t prefix_len;
		size_t suffix_len;

		if (sscanf(de->d_name, "ubiblock%u_%u%c", &ubi, &vol, &extra) != 2)
			continue;

		snprintf(devnode, sizeof(devnode), "/dev/ubiblock%u_%u", ubi, vol);

		name_len = strnlen(de->d_name, sizeof(dev_attr));
		prefix_len = strlen(blk_prefix);
		suffix_len = strlen(dev_suffix);
		if (name_len >= sizeof(dev_attr))
			continue;
		if (prefix_len + name_len + suffix_len + 1 > sizeof(dev_attr))
			continue;

		memcpy(dev_attr, blk_prefix, prefix_len);
		memcpy(dev_attr + prefix_len, de->d_name, name_len);
		memcpy(dev_attr + prefix_len + name_len, dev_suffix, suffix_len + 1);

		if (read_major_minor_from_sysfs(dev_attr, &major, &minor))
			continue;

		create_node_if_missing(devnode, S_IFBLK | 0600, makedev(major, minor), verbose);
	}

	closedir(dir);
}
