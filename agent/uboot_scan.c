#include "uboot_scan.h"

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
#include <curl/curl.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef S_IFCHR
#define S_IFCHR 0020000
#endif

#ifndef S_IFBLK
#define S_IFBLK 0060000
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
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

int uboot_parse_u64(const char *s, uint64_t *out)
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

uint32_t uboot_read_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) |
	       ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) |
	       (uint32_t)p[3];
}

int uboot_connect_tcp_ipv4(const char *spec)
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

int uboot_send_all(int sock, const uint8_t *buf, size_t len)
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

static size_t curl_write_to_fp(void *ptr, size_t size, size_t nmemb, void *userdata)
{
	FILE *fp = (FILE *)userdata;
	if (!fp)
		return 0;
	return fwrite(ptr, size, nmemb, fp);
}

char *uboot_http_uri_normalize_default_port(const char *uri, uint16_t default_port)
{
	const char *scheme_end;
	const char *authority;
	const char *authority_end;
	const char *path;
	const char *host_start;
	const char *at;
	const char *port_sep = NULL;
	char port_buf[8];
	char *out;
	size_t prefix_len;
	size_t suffix_len;
	size_t port_len;

	if (!uri || !*uri)
		return NULL;

	scheme_end = strstr(uri, "://");
	if (!scheme_end)
		return strdup(uri);

	authority = scheme_end + 3;
	authority_end = authority;
	while (*authority_end && *authority_end != '/' && *authority_end != '?' && *authority_end != '#')
		authority_end++;

	if (authority == authority_end)
		return strdup(uri);

	path = authority_end;
	at = memchr(authority, '@', (size_t)(authority_end - authority));
	host_start = at ? (at + 1) : authority;

	if (host_start >= authority_end)
		return strdup(uri);

	if (*host_start == '[') {
		const char *host_end = memchr(host_start, ']', (size_t)(authority_end - host_start));
		if (!host_end)
			return strdup(uri);
		if (host_end + 1 < authority_end && *(host_end + 1) == ':')
			port_sep = host_end + 1;
	} else {
		for (const char *p = host_start; p < authority_end; p++) {
			if (*p == ':')
				port_sep = p;
		}
	}

	if (port_sep)
		return strdup(uri);

	snprintf(port_buf, sizeof(port_buf), ":%u", (unsigned int)default_port);
	port_len = strlen(port_buf);
	prefix_len = (size_t)(authority_end - uri);
	suffix_len = strlen(path);

	out = malloc(prefix_len + port_len + suffix_len + 1);
	if (!out)
		return NULL;

	memcpy(out, uri, prefix_len);
	memcpy(out + prefix_len, port_buf, port_len);
	memcpy(out + prefix_len + port_len, path, suffix_len + 1);
	return out;
}

int uboot_http_post(const char *uri, const uint8_t *data, size_t len,
		 const char *content_type, bool insecure, bool verbose,
		 char *errbuf, size_t errbuf_len)
{
	CURL *curl;
	CURLcode rc;
	long http_code = 0;
	struct curl_slist *headers = NULL;
	struct curl_blob ca_blob;
	char header_line[256];
	static bool curl_global_ready;
	bool is_https = false;
	char *normalized_uri = NULL;
	const char *effective_uri = uri;

	if (errbuf && errbuf_len)
		errbuf[0] = '\0';

	if (!uri || !*uri) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "HTTP URI is empty");
		return -1;
	}

	is_https = !strncmp(uri, "https://", 8);
	if (!strncmp(uri, "http://", 7)) {
		normalized_uri = uboot_http_uri_normalize_default_port(uri, 80);
	} else if (is_https) {
		normalized_uri = uboot_http_uri_normalize_default_port(uri, 443);
	}
	if ((!strncmp(uri, "http://", 7) || is_https) && !normalized_uri) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to normalize HTTP URI");
		return -1;
	}
	if (normalized_uri)
		effective_uri = normalized_uri;

	if (!curl_global_ready) {
		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "curl_global_init failed");
			free(normalized_uri);
			return -1;
		}
		curl_global_ready = true;
	}

	curl = curl_easy_init();
	if (!curl) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "curl_easy_init failed");
		free(normalized_uri);
		return -1;
	}

	if (!content_type || !*content_type)
		content_type = "text/plain; charset=utf-8";
	if (verbose) {
		fprintf(stderr,
			"HTTP POST request uri=%s bytes=%zu content-type=%s insecure=%s\n",
			effective_uri,
			len,
			content_type,
			insecure ? "true" : "false");
	}
	snprintf(header_line, sizeof(header_line), "Content-Type: %s", content_type);
	headers = curl_slist_append(headers, header_line);
	if (!headers) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to prepare HTTP headers");
		curl_easy_cleanup(curl);
		free(normalized_uri);
		return -1;
	}
	curl_easy_setopt(curl, CURLOPT_URL, effective_uri);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const char *)data);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)len);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
	if (is_https) {
		if (insecure) {
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		} else {
			ca_blob.data = (void *)uboot_default_ca_bundle_pem;
			ca_blob.len = uboot_default_ca_bundle_pem_len;
			ca_blob.flags = CURL_BLOB_COPY;
			rc = curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &ca_blob);
			if (rc != CURLE_OK) {
				if (errbuf && errbuf_len)
					snprintf(errbuf, errbuf_len, "failed to configure HTTPS CA bundle: %s",
						 curl_easy_strerror(rc));
				curl_slist_free_all(headers);
				curl_easy_cleanup(curl);
				free(normalized_uri);
				return -1;
			}
		}
	}

	rc = curl_easy_perform(curl);
	if (rc != CURLE_OK) {
		if (verbose)
			fprintf(stderr, "HTTP POST transport failure uri=%s error=%s\n",
				effective_uri, curl_easy_strerror(rc));
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "curl perform failed: %s", curl_easy_strerror(rc));
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
		free(normalized_uri);
		return -1;
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	if (http_code < 200 || http_code >= 300) {
		if (verbose)
			fprintf(stderr, "HTTP POST response failure uri=%s status=%ld\n",
				effective_uri, http_code);
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "HTTP status %ld", http_code);
		free(normalized_uri);
		return -1;
	}

	if (verbose)
		fprintf(stderr, "HTTP POST success uri=%s status=%ld\n", effective_uri, http_code);

	free(normalized_uri);

	return 0;
}

int uboot_http_get_to_file(const char *uri, const char *output_path,
			   bool insecure, bool verbose,
			   char *errbuf, size_t errbuf_len)
{
	CURL *curl;
	CURLcode rc;
	long http_code = 0;
	struct curl_blob ca_blob;
	static bool curl_global_ready;
	bool is_https;
	char *normalized_uri = NULL;
	const char *effective_uri = uri;
	FILE *fp = NULL;

	if (errbuf && errbuf_len)
		errbuf[0] = '\0';

	if (!uri || !*uri || !output_path || !*output_path) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "HTTP GET requires URI and output path");
		return -1;
	}

	is_https = !strncmp(uri, "https://", 8);
	if (!strncmp(uri, "http://", 7)) {
		normalized_uri = uboot_http_uri_normalize_default_port(uri, 80);
	} else if (is_https) {
		normalized_uri = uboot_http_uri_normalize_default_port(uri, 443);
	} else {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "unsupported URI scheme (expected http:// or https://)");
		return -1;
	}

	if (!normalized_uri) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to normalize HTTP URI");
		return -1;
	}
	effective_uri = normalized_uri;

	if (!curl_global_ready) {
		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "curl_global_init failed");
			free(normalized_uri);
			return -1;
		}
		curl_global_ready = true;
	}

	fp = fopen(output_path, "wb");
	if (!fp) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "cannot open output file %s: %s", output_path, strerror(errno));
		free(normalized_uri);
		return -1;
	}

	curl = curl_easy_init();
	if (!curl) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "curl_easy_init failed");
		fclose(fp);
		unlink(output_path);
		free(normalized_uri);
		return -1;
	}

	if (verbose) {
		fprintf(stderr, "HTTP GET request uri=%s -> file=%s insecure=%s\n",
			effective_uri,
			output_path,
			insecure ? "true" : "false");
	}

	curl_easy_setopt(curl, CURLOPT_URL, effective_uri);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_to_fp);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

	if (is_https) {
		if (insecure) {
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		} else {
			ca_blob.data = (void *)uboot_default_ca_bundle_pem;
			ca_blob.len = uboot_default_ca_bundle_pem_len;
			ca_blob.flags = CURL_BLOB_COPY;
			rc = curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &ca_blob);
			if (rc != CURLE_OK) {
				if (errbuf && errbuf_len)
					snprintf(errbuf, errbuf_len, "failed to configure HTTPS CA bundle: %s",
						 curl_easy_strerror(rc));
				curl_easy_cleanup(curl);
				fclose(fp);
				unlink(output_path);
				free(normalized_uri);
				return -1;
			}
		}
	}

	rc = curl_easy_perform(curl);
	if (rc != CURLE_OK) {
		if (verbose)
			fprintf(stderr, "HTTP GET transport failure uri=%s error=%s\n",
				effective_uri, curl_easy_strerror(rc));
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "curl perform failed: %s", curl_easy_strerror(rc));
		curl_easy_cleanup(curl);
		fclose(fp);
		unlink(output_path);
		free(normalized_uri);
		return -1;
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	curl_easy_cleanup(curl);

	if (fclose(fp) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to finalize output file %s", output_path);
		unlink(output_path);
		free(normalized_uri);
		return -1;
	}
	fp = NULL;

	if (http_code < 200 || http_code >= 300) {
		if (verbose)
			fprintf(stderr, "HTTP GET response failure uri=%s status=%ld\n",
				effective_uri, http_code);
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "HTTP status %ld", http_code);
		unlink(output_path);
		free(normalized_uri);
		return -1;
	}

	if (verbose)
		fprintf(stderr, "HTTP GET success uri=%s status=%ld\n", effective_uri, http_code);

	free(normalized_uri);
	return 0;
}

void uboot_crc32_init(uint32_t table[256])
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

uint32_t uboot_crc32_calc(const uint32_t table[256], const uint8_t *buf, size_t len)
{
	uint32_t c = 0xFFFFFFFFU;

	if (!table || !buf)
		return 0;

	for (size_t i = 0; i < len; i++)
		c = table[(c ^ buf[i]) & 0xFFU] ^ (c >> 8);

	return c ^ 0xFFFFFFFFU;
}

int uboot_get_mtd_index(const char *dev, char *idx, size_t idx_sz)
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

uint64_t uboot_guess_size_from_sysfs(const char *dev)
{
	char idx[32], path[256];

	if (uboot_get_mtd_index(dev, idx, sizeof(idx)))
		return 0;
	snprintf(path, sizeof(path), "/sys/class/mtd/mtd%s/size", idx);
	return read_u64_from_file(path);
}

uint64_t uboot_guess_erasesize_from_sysfs(const char *dev)
{
	char idx[32], path[256];

	if (uboot_get_mtd_index(dev, idx, sizeof(idx)))
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

	if (uboot_get_mtd_index(dev, idx, sizeof(idx))) {
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

uint64_t uboot_guess_size_from_proc_mtd(const char *dev)
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

uint64_t uboot_guess_erasesize_from_proc_mtd(const char *dev)
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

uint64_t uboot_guess_size_from_ubi_sysfs(const char *dev)
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

uint64_t uboot_guess_step_from_ubi_sysfs(const char *dev)
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

static const char *dev_basename(const char *dev)
{
	const char *base;

	if (!dev)
		return NULL;

	base = strrchr(dev, '/');
	return base ? base + 1 : dev;
}

uint64_t uboot_guess_size_from_block_sysfs(const char *dev)
{
	const char *base = dev_basename(dev);
	char path[PATH_MAX];
	uint64_t sectors;
	uint64_t logical_block_size;

	if (!base || !*base)
		return 0;

	snprintf(path, sizeof(path), "/sys/class/block/%s/size", base);
	sectors = read_u64_from_file(path);
	if (!sectors)
		return 0;

	snprintf(path, sizeof(path), "/sys/class/block/%s/queue/logical_block_size", base);
	logical_block_size = read_u64_from_file(path);
	if (!logical_block_size)
		logical_block_size = 512;

	return sectors * logical_block_size;
}

uint64_t uboot_guess_step_from_block_sysfs(const char *dev)
{
	const char *base = dev_basename(dev);
	char path[PATH_MAX];
	uint64_t step;

	if (!base || !*base)
		return 0;

	snprintf(path, sizeof(path), "/sys/class/block/%s/queue/minimum_io_size", base);
	step = read_u64_from_file(path);
	if (step)
		return step;

	snprintf(path, sizeof(path), "/sys/class/block/%s/queue/logical_block_size", base);
	step = read_u64_from_file(path);
	if (step)
		return step;

	return 512;
}

uint64_t uboot_guess_size_any(const char *dev)
{
	uint64_t sz = uboot_guess_size_from_sysfs(dev);

	if (!sz)
		sz = uboot_guess_size_from_proc_mtd(dev);
	if (!sz)
		sz = uboot_guess_size_from_ubi_sysfs(dev);
	if (!sz)
		sz = uboot_guess_size_from_block_sysfs(dev);

	return sz;
}

uint64_t uboot_guess_step_any(const char *dev)
{
	uint64_t step = uboot_guess_erasesize_from_sysfs(dev);

	if (!step)
		step = uboot_guess_erasesize_from_proc_mtd(dev);
	if (!step)
		step = uboot_guess_step_from_ubi_sysfs(dev);
	if (!step)
		step = uboot_guess_step_from_block_sysfs(dev);

	return step;
}

int uboot_glob_scan_devices(glob_t *out, unsigned int flags)
{
	const char *patterns[8];
	size_t n = 0;
	bool did_call = false;

	if (!out)
		return -1;

	memset(out, 0, sizeof(*out));

	if (flags & FW_SCAN_GLOB_MTDBLOCK)
		patterns[n++] = "/dev/mtdblock[0-9]*";
	if (flags & FW_SCAN_GLOB_MTDCHAR)
		patterns[n++] = "/dev/mtd[0-9]*";
	if (flags & FW_SCAN_GLOB_UBI)
		patterns[n++] = "/dev/ubi[0-9]*_[0-9]*";
	if (flags & FW_SCAN_GLOB_UBIBLOCK)
		patterns[n++] = "/dev/ubiblock[0-9]*_[0-9]*";
	if (flags & FW_SCAN_GLOB_MMCBLK) {
		patterns[n++] = "/dev/mmcblk[0-9]*";
		patterns[n++] = "/dev/mmcblk[0-9]*p[0-9]*";
	}
	if (flags & FW_SCAN_GLOB_SDBLK) {
		patterns[n++] = "/dev/sd[a-z]";
		patterns[n++] = "/dev/sd[a-z][0-9]*";
	}

	for (size_t i = 0; i < n; i++) {
		int rc = glob(patterns[i], did_call ? GLOB_APPEND : 0, NULL, out);
		did_call = true;
		if (rc == GLOB_NOMATCH)
			continue;
		if (rc != 0) {
			globfree(out);
			memset(out, 0, sizeof(*out));
			return -1;
		}
	}

	return 0;
}

static int add_created_node(char ***nodes, size_t *count, const char *path)
{
	char **tmp;
	char *dup;

	if (!nodes || !count || !path)
		return -1;

	dup = strdup(path);
	if (!dup)
		return -1;

	tmp = realloc(*nodes, (*count + 1) * sizeof(*tmp));
	if (!tmp) {
		free(dup);
		return -1;
	}

	*nodes = tmp;
	(*nodes)[*count] = dup;
	(*count)++;
	return 0;
}

void uboot_free_created_nodes(char **nodes, size_t count)
{
	if (!nodes)
		return;

	for (size_t i = 0; i < count; i++)
		free(nodes[i]);

	free(nodes);
}

static void create_node_if_missing(const char *path, mode_t mode, dev_t devno, bool verbose,
					   char ***created_nodes, size_t *created_count)
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

	if (created_nodes && created_count && add_created_node(created_nodes, created_count, path) < 0) {
		if (verbose)
			fprintf(stderr, "Warning: failed to track created node %s\n", path);
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

static bool str_all_digits(const char *s)
{
	if (!s || !*s)
		return false;

	for (const char *p = s; *p; p++) {
		if (*p < '0' || *p > '9')
			return false;
	}

	return true;
}

static bool is_sd_block_name(const char *name)
{
	if (!name || strncmp(name, "sd", 2))
		return false;
	if (name[2] < 'a' || name[2] > 'z')
		return false;
	if (name[3] == '\0')
		return true;

	return str_all_digits(name + 3);
}

static bool is_emmc_block_name(const char *name)
{
	const char *p;

	if (!name || strncmp(name, "mmcblk", 6))
		return false;

	p = name + 6;
	while (*p >= '0' && *p <= '9')
		p++;
	if (p == name + 6)
		return false;
	if (*p == '\0')
		return true;
	if (*p != 'p')
		return false;

	return str_all_digits(p + 1);
}

int uboot_ensure_block_nodes_collect(bool verbose, bool include_sd, bool include_emmc,
				  char ***created_nodes, size_t *created_count)
{
	DIR *dir;
	struct dirent *de;

	dir = opendir("/sys/class/block");
	if (!dir)
		return -1;

	while ((de = readdir(dir))) {
		char dev_attr[PATH_MAX];
		char devnode[PATH_MAX];
		unsigned int major;
		unsigned int minor;

		if (!include_sd && is_sd_block_name(de->d_name))
			continue;
		if (!include_emmc && is_emmc_block_name(de->d_name))
			continue;
		if ((include_sd && is_sd_block_name(de->d_name)) ||
		    (include_emmc && is_emmc_block_name(de->d_name))) {
			snprintf(dev_attr, sizeof(dev_attr), "/sys/class/block/%s/dev", de->d_name);
			snprintf(devnode, sizeof(devnode), "/dev/%s", de->d_name);

			if (read_major_minor_from_sysfs(dev_attr, &major, &minor))
				continue;

			create_node_if_missing(devnode, S_IFBLK | 0600, makedev(major, minor), verbose,
				created_nodes, created_count);
		}
	}

	closedir(dir);
	return 0;
}

void uboot_ensure_block_nodes(bool verbose, bool include_sd, bool include_emmc)
{
	uboot_ensure_block_nodes_collect(verbose, include_sd, include_emmc, NULL, NULL);
}

int uboot_ensure_mtd_nodes_collect(bool verbose, char ***created_nodes, size_t *created_count)
{
	DIR *dir;
	struct dirent *de;

	dir = opendir("/sys/class/mtd");
	if (!dir)
		return -1;

	while ((de = readdir(dir))) {
		unsigned int idx;
		char extra;
		char blockpath[64];

		if (sscanf(de->d_name, "mtd%u%c", &idx, &extra) != 1)
			continue;

		snprintf(blockpath, sizeof(blockpath), "/dev/mtdblock%u", idx);

		create_node_if_missing(blockpath, S_IFBLK | 0600, makedev(31, idx), verbose,
			created_nodes, created_count);
	}

	closedir(dir);
	return 0;
}

void uboot_ensure_mtd_nodes(bool verbose)
{
	uboot_ensure_mtd_nodes_collect(verbose, NULL, NULL);
}

int uboot_ensure_ubi_nodes_collect(bool verbose, char ***created_nodes, size_t *created_count)
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

			create_node_if_missing(devnode, S_IFCHR | 0600, makedev(major, minor), verbose,
				created_nodes, created_count);
		}

		closedir(dir);
	}

	dir = opendir("/sys/class/block");
	if (!dir)
		return 0;

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

		create_node_if_missing(devnode, S_IFBLK | 0600, makedev(major, minor), verbose,
			created_nodes, created_count);
	}

	closedir(dir);
	return 0;
}

void uboot_ensure_ubi_nodes(bool verbose)
{
	uboot_ensure_ubi_nodes_collect(verbose, NULL, NULL);
}
