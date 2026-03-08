// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "uboot_scan.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <glob.h>
#include <inttypes.h>
#include <ctype.h>
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
#include <json.h>
#include <csv.h>
#include <libuboot.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define AUTO_SCAN_MAX_STEP 0x10000ULL

#if defined(__GNUC__) || defined(__clang__)
#define MAYBE_UNUSED __attribute__((unused))
#else
#define MAYBE_UNUSED
#endif

struct env_kv {
	char *name;
	char *value;
};

struct uboot_cfg_entry {
	char dev[256];
	uint64_t off;
	uint64_t env_size;
	uint64_t erase_size;
	uint64_t sectors;
};

static uint32_t crc32_table[256];
static bool g_verbose;
static bool g_bruteforce;
static bool g_parse_vars;
static bool g_insecure;
static int g_output_sock = -1;
static const char *g_output_http_uri = NULL;
static char *g_output_http_buf = NULL;
static size_t g_output_http_len;
static size_t g_output_http_cap;
static FILE *g_output_config_fp = NULL;
static void out_printf(const char *fmt, ...);
static void err_printf(const char *fmt, ...);
enum uboot_output_format {
	FW_OUTPUT_TXT = 0,
	FW_OUTPUT_CSV,
	FW_OUTPUT_JSON,
};
static enum uboot_output_format g_output_format = FW_OUTPUT_TXT;
static bool g_csv_header_emitted;

static const char *env_http_content_type(void)
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

static void detect_output_format(void)
{
	const char *fmt = getenv("FW_AUDIT_OUTPUT_FORMAT");

	g_output_format = FW_OUTPUT_TXT;
	if (!fmt || !*fmt)
		return;

	if (!strcmp(fmt, "csv"))
		g_output_format = FW_OUTPUT_CSV;
	else if (!strcmp(fmt, "json"))
		g_output_format = FW_OUTPUT_JSON;
}

static void emit_env_csv_header(void)
{
	if (g_csv_header_emitted)
		return;
	out_printf("record,device,offset,crc_endian,mode,has_known_vars,cfg_offset,env_size,erase_size,sector_count\n");
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

static void emit_env_candidate_record(const char *dev, uint64_t off,
				      const char *crc_endian,
				      const char *mode,
				      bool has_known_vars,
				      uint64_t cfg_off,
				      uint64_t env_size,
				      uint64_t erase_size,
				      uint64_t sector_count)
{
	if (g_output_format == FW_OUTPUT_CSV) {
		char off_s[32], cfg_s[32], env_s[32], erase_s[32], sec_s[32];

		snprintf(off_s, sizeof(off_s), "0x%jx", (uintmax_t)off);
		snprintf(cfg_s, sizeof(cfg_s), "0x%jx", (uintmax_t)cfg_off);
		snprintf(env_s, sizeof(env_s), "0x%jx", (uintmax_t)env_size);
		snprintf(erase_s, sizeof(erase_s), "0x%jx", (uintmax_t)erase_size);
		snprintf(sec_s, sizeof(sec_s), "0x%jx", (uintmax_t)sector_count);

		emit_env_csv_header();
		csv_out_field("env_candidate"); out_printf(",");
		csv_out_field(dev); out_printf(",");
		csv_out_field(off_s); out_printf(",");
		csv_out_field(crc_endian ? crc_endian : ""); out_printf(",");
		csv_out_field(mode ? mode : ""); out_printf(",");
		csv_out_field(has_known_vars ? "true" : "false"); out_printf(",");
		csv_out_field(cfg_s); out_printf(",");
		csv_out_field(env_s); out_printf(",");
		csv_out_field(erase_s); out_printf(",");
		csv_out_field(sec_s); out_printf("\n");
		return;
	}

	if (g_output_format == FW_OUTPUT_JSON) {
		json_object *obj = json_object_new_object();
		if (!obj)
			return;
		json_object_object_add(obj, "record", json_object_new_string("env_candidate"));
		json_object_object_add(obj, "device", json_object_new_string(dev));
		json_object_object_add(obj, "offset", json_object_new_uint64(off));
		json_object_object_add(obj, "crc_endian", json_object_new_string(crc_endian ? crc_endian : ""));
		json_object_object_add(obj, "mode", json_object_new_string(mode ? mode : ""));
		json_object_object_add(obj, "has_known_vars", json_object_new_boolean(has_known_vars));
		json_object_object_add(obj, "cfg_offset", json_object_new_uint64(cfg_off));
		json_object_object_add(obj, "env_size", json_object_new_uint64(env_size));
		json_object_object_add(obj, "erase_size", json_object_new_uint64(erase_size));
		json_object_object_add(obj, "sector_count", json_object_new_uint64(sector_count));
		out_printf("%s\n", json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN));
		json_object_put(obj);
		return;
	}

	if (!strcmp(mode, "hint-only"))
		out_printf("  candidate offset=0x%jx  mode=hint-only  (has known vars)\n", (uintmax_t)off);
	else if (!strcmp(mode, "redundant"))
		out_printf("  candidate offset=0x%jx  crc=%s-endian  %s (redundant-env layout)\n", (uintmax_t)off,
			crc_endian, has_known_vars ? "(has known vars)" : "(crc ok)");
	else
		out_printf("  candidate offset=0x%jx  crc=%s-endian  %s\n", (uintmax_t)off,
			crc_endian, has_known_vars ? "(has known vars)" : "(crc ok)");

	out_printf("    uboot_env.config line: %s 0x%jx 0x%jx 0x%jx 0x%jx\n",
		dev, (uintmax_t)cfg_off, (uintmax_t)env_size,
		(uintmax_t)erase_size, (uintmax_t)sector_count);
}

static void emit_redundant_pair_record(const char *dev, uint64_t a, uint64_t b)
{
	if (g_output_format == FW_OUTPUT_CSV) {
		char a_s[32], b_s[32];

		snprintf(a_s, sizeof(a_s), "0x%jx", (uintmax_t)a);
		snprintf(b_s, sizeof(b_s), "0x%jx", (uintmax_t)b);

		emit_env_csv_header();
		csv_out_field("redundant_pair"); out_printf(",");
		csv_out_field(dev); out_printf(",");
		csv_out_field(a_s); out_printf(",");
		csv_out_field(""); out_printf(",");
		csv_out_field(""); out_printf(",");
		csv_out_field("false"); out_printf(",");
		csv_out_field(b_s); out_printf(",");
		csv_out_field(""); out_printf(",");
		csv_out_field(""); out_printf(",");
		csv_out_field(""); out_printf("\n");
		return;
	}

	if (g_output_format == FW_OUTPUT_JSON) {
		json_object *obj = json_object_new_object();
		if (!obj)
			return;
		json_object_object_add(obj, "record", json_object_new_string("redundant_pair"));
		json_object_object_add(obj, "device", json_object_new_string(dev));
		json_object_object_add(obj, "offset_a", json_object_new_uint64(a));
		json_object_object_add(obj, "offset_b", json_object_new_uint64(b));
		out_printf("%s\n", json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN));
		json_object_put(obj);
		return;
	}

	out_printf("    redundant env candidate pair: %s 0x%jx <-> 0x%jx\n",
		dev, (uintmax_t)a, (uintmax_t)b);
}

static void emit_env_verbose(const char *dev, uint64_t off, const char *msg)
{
	if (!g_verbose || !msg)
		return;

	if (g_output_format == FW_OUTPUT_TXT) {
		out_printf("%s\n", msg);
		return;
	}

	if (g_output_format == FW_OUTPUT_CSV) {
		char off_s[32];

		snprintf(off_s, sizeof(off_s), "0x%jx", (uintmax_t)off);
		emit_env_csv_header();
		csv_out_field("verbose"); out_printf(",");
		csv_out_field(dev ? dev : ""); out_printf(",");
		csv_out_field(off_s); out_printf(",");
		csv_out_field(""); out_printf(",");
		csv_out_field(msg); out_printf(",");
		csv_out_field("false"); out_printf(",");
		csv_out_field(""); out_printf(",");
		csv_out_field(""); out_printf(",");
		csv_out_field(""); out_printf(",");
		csv_out_field(""); out_printf("\n");
		return;
	}

	{
		json_object *obj = json_object_new_object();
		if (!obj)
			return;
		json_object_object_add(obj, "record", json_object_new_string("verbose"));
		if (dev)
			json_object_object_add(obj, "device", json_object_new_string(dev));
		json_object_object_add(obj, "offset", json_object_new_uint64(off));
		json_object_object_add(obj, "message", json_object_new_string(msg));
		out_printf("%s\n", json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN));
		json_object_put(obj);
	}
}

static void emit_env_verbosef(const char *dev, uint64_t off, const char *fmt, ...)
{
	va_list ap;
	va_list aq;
	char stack[256];
	char *dyn = NULL;
	int needed;

	if (!fmt)
		return;

	va_start(ap, fmt);
	va_copy(aq, ap);
	needed = vsnprintf(stack, sizeof(stack), fmt, aq);
	va_end(aq);

	if (needed < 0) {
		va_end(ap);
		return;
	}

	if ((size_t)needed < sizeof(stack)) {
		emit_env_verbose(dev, off, stack);
		va_end(ap);
		return;
	}

	dyn = malloc((size_t)needed + 1U);
	if (!dyn) {
		va_end(ap);
		return;
	}

	vsnprintf(dyn, (size_t)needed + 1U, fmt, ap);
	va_end(ap);
	emit_env_verbose(dev, off, dyn);
	free(dyn);
}

struct env_candidate {
	uint64_t cfg_off;
	bool crc_standard;
	bool crc_redundant;
};

static int add_or_merge_candidate(struct env_candidate **cands, size_t *count,
					  uint64_t cfg_off, bool crc_standard, bool crc_redundant)
{
	struct env_candidate *tmp;

	if (!cands || !count)
		return -1;

	for (size_t i = 0; i < *count; i++) {
		if ((*cands)[i].cfg_off != cfg_off)
			continue;
		(*cands)[i].crc_standard = (*cands)[i].crc_standard || crc_standard;
		(*cands)[i].crc_redundant = (*cands)[i].crc_redundant || crc_redundant;
		return 0;
	}

	tmp = realloc(*cands, (*count + 1) * sizeof(**cands));
	if (!tmp)
		return -1;

	*cands = tmp;
	(*cands)[*count].cfg_off = cfg_off;
	(*cands)[*count].crc_standard = crc_standard;
	(*cands)[*count].crc_redundant = crc_redundant;
	(*count)++;
	return 0;
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

static int flush_output_http_buffer(void)
{
	char errbuf[256];

	if (!g_output_http_uri)
		return 0;

	if (uboot_http_post(g_output_http_uri,
			 (const uint8_t *)(g_output_http_buf ? g_output_http_buf : ""),
			 g_output_http_len,
			 env_http_content_type(),
			 g_insecure,
			 g_verbose,
			 errbuf,
			 sizeof(errbuf)) < 0) {
		err_printf("Failed to POST output to %s: %s\n", g_output_http_uri,
			   errbuf[0] ? errbuf : "unknown error");
		return -1;
	}

	return 0;
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

	if (needed < 0)
		return;

	if ((size_t)needed < sizeof(stack)) {
		send_to_output_socket(stack, (size_t)needed);
		append_output_http_buffer(stack, (size_t)needed);
		return;
	}

	dyn = malloc((size_t)needed + 1);
	if (!dyn)
		return;

	va_copy(aq, ap);
	vsnprintf(dyn, (size_t)needed + 1, fmt, aq);
	va_end(aq);
	send_to_output_socket(dyn, (size_t)needed);
	append_output_http_buffer(dyn, (size_t)needed);
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

static uint64_t parse_u64(const char *s)
{
	uint64_t v;

	if (uboot_parse_u64(s, &v)) {
		err_printf("Invalid number: %s\n", s);
		exit(2);
	}
	return v;
}

static uint32_t read_le32(const uint8_t *p)
{
	return (uint32_t)p[0] |
		((uint32_t)p[1] << 8) |
		((uint32_t)p[2] << 16) |
		((uint32_t)p[3] << 24);
}

static bool file_exists(const char *path)
{
	struct stat st;

	if (!path || !*path)
		return false;
	return stat(path, &st) == 0;
}

static bool uboot_valid_var_name(const char *name)
{
	if (!name || !*name)
		return false;

	for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
		if (*p == '=')
			return false;
		if (isspace(*p) || iscntrl(*p))
			return false;
	}

	return true;
}

static bool uboot_is_sensitive_env_var(const char *name)
{
	static const char *sensitive_vars[] = {
		"bootcmd",
		"altbootcmd",
		"bootargs",
		"boot_targets",
		"bootdelay",
		"preboot",
		"stdin",
		"stdout",
		"stderr",
	};

	if (!name || !*name)
		return false;

	for (size_t i = 0; i < ARRAY_SIZE(sensitive_vars); i++)
		if (!strcmp(name, sensitive_vars[i]))
			return true;

	return false;
}

static bool uboot_confirm_sensitive_write(const char *name)
{
	char answer[32];

	out_printf("Modifying %s might render the host unbootable.  Do you wish to proceed? ", name);
	fflush(stdout);

	if (!fgets(answer, sizeof(answer), stdin))
		return false;

	return answer[0] == 'Y' || answer[0] == 'y';
}

static char *uboot_trim(char *s)
{
	char *end;

	if (!s)
		return s;

	while (*s && isspace((unsigned char)*s))
		s++;

	if (!*s)
		return s;

	end = s + strlen(s) - 1;
	while (end >= s && isspace((unsigned char)*end)) {
		*end = '\0';
		end--;
	}

	return s;
}

static MAYBE_UNUSED void free_env_kvs(struct env_kv *kvs, size_t count)
{
	if (!kvs)
		return;
	for (size_t i = 0; i < count; i++) {
		free(kvs[i].name);
		free(kvs[i].value);
	}
	free(kvs);
}

static MAYBE_UNUSED int env_set_kv(struct env_kv **kvs, size_t *count, const char *name, const char *value)
{
	struct env_kv *tmp;
	char *name_dup;
	char *value_dup;

	if (!kvs || !count || !name || !value)
		return -1;

	for (size_t i = 0; i < *count; i++) {
		if (strcmp((*kvs)[i].name, name))
			continue;
		value_dup = strdup(value);
		if (!value_dup)
			return -1;
		free((*kvs)[i].value);
		(*kvs)[i].value = value_dup;
		return 0;
	}

	tmp = realloc(*kvs, (*count + 1) * sizeof(**kvs));
	if (!tmp)
		return -1;
	*kvs = tmp;

	name_dup = strdup(name);
	value_dup = strdup(value);
	if (!name_dup || !value_dup) {
		free(name_dup);
		free(value_dup);
		return -1;
	}

	(*kvs)[*count].name = name_dup;
	(*kvs)[*count].value = value_dup;
	(*count)++;
	return 0;
}

static MAYBE_UNUSED int env_unset_kv(struct env_kv *kvs, size_t *count, const char *name)
{
	if (!kvs || !count || !name)
		return -1;

	for (size_t i = 0; i < *count; i++) {
		if (strcmp(kvs[i].name, name))
			continue;
		free(kvs[i].name);
		free(kvs[i].value);
		for (size_t j = i + 1; j < *count; j++)
			kvs[j - 1] = kvs[j];
		(*count)--;
		return 0;
	}

	return 0;
}

static MAYBE_UNUSED int parse_fw_config(const char *path, struct uboot_cfg_entry out[2], size_t *out_count)
{
	FILE *fp;
	char line[1024];
	size_t count = 0;

	if (!path || !out || !out_count)
		return -1;

	fp = fopen(path, "r");
	if (!fp) {
		err_printf("Cannot open %s: %s\n", path, strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		char *s = uboot_trim(line);
		char dev[256], off_s[64], size_s[64], erase_s[64], sec_s[64];
		uint64_t off, env_size, erase, sec;

		if (!*s || *s == '#')
			continue;

		if (sscanf(s, "%255s %63s %63s %63s %63s", dev, off_s, size_s, erase_s, sec_s) != 5) {
			err_printf("Invalid uboot_env.config line: %s\n", s);
			fclose(fp);
			return -1;
		}

		if (uboot_parse_u64(off_s, &off) || uboot_parse_u64(size_s, &env_size) ||
		    uboot_parse_u64(erase_s, &erase) || uboot_parse_u64(sec_s, &sec)) {
			err_printf("Invalid numeric values in uboot_env.config line: %s\n", s);
			fclose(fp);
			return -1;
		}

		if (!env_size || env_size < 8) {
			err_printf("Invalid env size in uboot_env.config line: %s\n", s);
			fclose(fp);
			return -1;
		}

		if (count >= 2) {
			err_printf("uboot_env.config must contain one or two usable entries for --write\n");
			fclose(fp);
			return -1;
		}

		strncpy(out[count].dev, dev, sizeof(out[count].dev) - 1);
		out[count].dev[sizeof(out[count].dev) - 1] = '\0';
		out[count].off = off;
		out[count].env_size = env_size;
		out[count].erase_size = erase;
		out[count].sectors = sec;
		count++;
	}

	fclose(fp);

	if (!count) {
		err_printf("No usable entries in %s\n", path);
		return -1;
	}

	if (count == 2 && out[0].env_size != out[1].env_size) {
		err_printf("Redundant entries in uboot_env.config must use same env size\n");
		return -1;
	}

	*out_count = count;
	return 0;
}

static MAYBE_UNUSED int parse_existing_env_data(const uint8_t *buf, size_t buf_len, size_t data_off,
					   struct env_kv **kvs, size_t *count)
{
	size_t off = data_off;

	if (!buf || !kvs || !count || data_off >= buf_len)
		return -1;

	while (off < buf_len) {
		const char *entry;
		size_t slen;
		const char *eq;
		char *name, *value;

		if (buf[off] == '\0') {
			if (off + 1 >= buf_len || buf[off + 1] == '\0')
				break;
			off++;
			continue;
		}

		entry = (const char *)(buf + off);
		slen = strnlen(entry, buf_len - off);
		if (slen >= buf_len - off)
			break;

		eq = memchr(entry, '=', slen);
		if (!eq) {
			off += slen + 1;
			continue;
		}

		name = strndup(entry, (size_t)(eq - entry));
		value = strndup(eq + 1, slen - (size_t)(eq - entry) - 1);
		if (!name || !value || env_set_kv(kvs, count, name, value)) {
			free(name);
			free(value);
			return -1;
		}
		free(name);
		free(value);

		off += slen + 1;
	}

	return 0;
}

static MAYBE_UNUSED int apply_write_script(const char *script_path, struct env_kv **kvs, size_t *count)
{
	FILE *fp;
	char line[4096];
	unsigned long lineno = 0;

	if (!script_path || !kvs || !count)
		return -1;

	fp = fopen(script_path, "r");
	if (!fp) {
		err_printf("Cannot open write script %s: %s\n", script_path, strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		char *s;
		char *name;
		char *value = NULL;
		char *eq;
		char *space;
		bool delete_var = false;

		lineno++;
		s = uboot_trim(line);
		if (!*s || *s == '#')
			continue;

		eq = strchr(s, '=');
		space = strpbrk(s, " \t");
		if (eq && (!space || eq < space)) {
			*eq = '\0';
			name = uboot_trim(s);
			value = eq + 1;
		} else {
			if (space) {
				*space = '\0';
				name = uboot_trim(s);
				value = uboot_trim(space + 1);
				if (!*value)
					delete_var = true;
			} else {
				name = uboot_trim(s);
				delete_var = true;
			}
		}

		if (!uboot_valid_var_name(name)) {
			err_printf("Invalid variable name at %s:%lu\n", script_path, lineno);
			fclose(fp);
			return -1;
		}

		if (uboot_is_sensitive_env_var(name) && !uboot_confirm_sensitive_write(name)) {
			out_printf("Skipping update for %s\n", name);
			continue;
		}

		if (delete_var) {
			if (env_unset_kv(*kvs, count, name)) {
				fclose(fp);
				return -1;
			}
			continue;
		}

		if (!value)
			value = "";

		if (env_set_kv(kvs, count, name, value)) {
			fclose(fp);
			return -1;
		}
	}

	fclose(fp);
	return 0;
}

static int apply_write_script_libuboot(const char *script_path, struct uboot_ctx *ctx)
{
	FILE *fp;
	char line[4096];
	unsigned long lineno = 0;

	if (!script_path || !ctx)
		return -1;

	fp = fopen(script_path, "r");
	if (!fp) {
		err_printf("Cannot open write script %s: %s\n", script_path, strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		char *s;
		char *name;
		char *value = NULL;
		char *eq;
		char *space;
		bool delete_var = false;

		lineno++;
		s = uboot_trim(line);
		if (!*s || *s == '#')
			continue;

		eq = strchr(s, '=');
		space = strpbrk(s, " \t");
		if (eq && (!space || eq < space)) {
			*eq = '\0';
			name = uboot_trim(s);
			value = eq + 1;
		} else {
			if (space) {
				*space = '\0';
				name = uboot_trim(s);
				value = uboot_trim(space + 1);
				if (!*value)
					delete_var = true;
			} else {
				name = uboot_trim(s);
				delete_var = true;
			}
		}

		if (!uboot_valid_var_name(name)) {
			err_printf("Invalid variable name at %s:%lu\n", script_path, lineno);
			fclose(fp);
			return -1;
		}

		if (uboot_is_sensitive_env_var(name) && !uboot_confirm_sensitive_write(name)) {
			out_printf("Skipping update for %s\n", name);
			continue;
		}

		if (delete_var) {
			if (libuboot_set_env(ctx, name, NULL) < 0) {
				err_printf("Failed to delete variable '%s' via libubootenv\n", name);
				fclose(fp);
				return -1;
			}
			continue;
		}

		if (!value)
			value = "";

		if (libuboot_set_env(ctx, name, value) < 0) {
			err_printf("Failed to set variable '%s' via libubootenv\n", name);
			fclose(fp);
			return -1;
		}
	}

	fclose(fp);
	return 0;
}

static void dump_env_vars_libuboot(const char *dev, uint64_t off, uint64_t env_size,
				   uint64_t erase_size, uint64_t sector_count)
{
	struct uboot_ctx *ctx = NULL;
	struct uboot_env_device envdevs[2];
	void *entry = NULL;
	size_t count = 0;

	if (!dev || !env_size)
		return;

	memset(envdevs, 0, sizeof(envdevs));
	envdevs[0].devname = (char *)dev;
	envdevs[0].offset = (long long)off;
	envdevs[0].envsize = (size_t)env_size;
	envdevs[0].sectorsize = (size_t)(erase_size ? erase_size : env_size);
	envdevs[0].envsectors = (unsigned long)(sector_count ? sector_count : 1);

	if (libuboot_initialize(&ctx, envdevs) < 0 || !ctx) {
		emit_env_verbosef(dev, off,
			"libubootenv: initialize failed while parsing variables at 0x%jx",
			(uintmax_t)off);
		return;
	}

	if (libuboot_open(ctx) < 0) {
		emit_env_verbosef(dev, off,
			"libubootenv: open failed while parsing variables at 0x%jx",
			(uintmax_t)off);
		libuboot_exit(ctx);
		return;
	}

	out_printf("    parsed env vars:\n");
	while ((entry = libuboot_iterator(ctx, entry)) != NULL) {
		const char *name = libuboot_getname(entry);
		const char *value = libuboot_getvalue(entry);

		if (!name)
			continue;

		out_printf("      %s=%s\n", name, value ? value : "");
		count++;
		if (count >= 256) {
			out_printf("      ... truncated after 256 vars ...\n");
			break;
		}
	}

	if (!count)
		out_printf("      (no parseable variables found)\n");

	libuboot_close(ctx);
	libuboot_exit(ctx);
}

static MAYBE_UNUSED int build_env_region(const struct env_kv *kvs, size_t count, uint8_t *out, size_t out_len)
{
	size_t pos = 0;

	if (!out || out_len < 2)
		return -1;

	memset(out, 0, out_len);
	for (size_t i = 0; i < count; i++) {
		size_t nlen = strlen(kvs[i].name);
		size_t vlen = strlen(kvs[i].value);
		size_t need = nlen + 1 + vlen + 1;

		if (pos + need + 1 > out_len)
			return -1;

		memcpy(out + pos, kvs[i].name, nlen);
		pos += nlen;
		out[pos++] = '=';
		memcpy(out + pos, kvs[i].value, vlen);
		pos += vlen;
		out[pos++] = '\0';
	}

	if (pos + 1 > out_len)
		return -1;
	out[pos++] = '\0';
	return 0;
}

static MAYBE_UNUSED int read_env_copy(const struct uboot_cfg_entry *cfg, uint8_t **out)
{
	int fd;
	uint8_t *buf;

	if (!cfg || !out)
		return -1;

	buf = malloc((size_t)cfg->env_size);
	if (!buf)
		return -1;

	fd = open(cfg->dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		err_printf("Cannot open %s for read: %s\n", cfg->dev, strerror(errno));
		free(buf);
		return -1;
	}

	if ((uint64_t)pread(fd, buf, (size_t)cfg->env_size, (off_t)cfg->off) != cfg->env_size) {
		err_printf("Failed reading env from %s at 0x%jx\n", cfg->dev, (uintmax_t)cfg->off);
		close(fd);
		free(buf);
		return -1;
	}

	close(fd);
	*out = buf;
	return 0;
}

static MAYBE_UNUSED bool env_crc_matches(const uint8_t *buf, size_t env_size, size_t data_off, bool *is_le)
{
	uint32_t stored_le;
	uint32_t stored_be;
	uint32_t calc;

	if (!buf || env_size <= data_off || !is_le)
		return false;

	stored_le = read_le32(buf);
	stored_be = uboot_read_be32(buf);
	calc = uboot_crc32_calc(crc32_table, buf + data_off, env_size - data_off);
	if (calc == stored_le) {
		*is_le = true;
		return true;
	}
	if (calc == stored_be) {
		*is_le = false;
		return true;
	}

	return false;
}

static MAYBE_UNUSED int write_env_copy(const struct uboot_cfg_entry *cfg, const uint8_t *buf)
{
	int fd;

	if (!cfg || !buf)
		return -1;

	fd = open(cfg->dev, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		err_printf("Cannot open %s for write: %s\n", cfg->dev, strerror(errno));
		return -1;
	}

	if ((uint64_t)pwrite(fd, buf, (size_t)cfg->env_size, (off_t)cfg->off) != cfg->env_size) {
		err_printf("Failed writing env to %s at 0x%jx: %s\n", cfg->dev, (uintmax_t)cfg->off, strerror(errno));
		close(fd);
		return -1;
	}

	if (fsync(fd) < 0 && g_verbose)
		emit_env_verbosef(cfg->dev, cfg->off,
			"Warning: fsync failed on %s: %s", cfg->dev, strerror(errno));

	close(fd);
	return 0;
}

static int perform_write_operation(const char *config_path, const char *script_path)
{
	struct uboot_ctx *ctx = NULL;
	int ret = 1;

	if (!config_path || !script_path)
		return 1;

	if (libuboot_initialize(&ctx, NULL) < 0 || !ctx) {
		err_printf("libubootenv initialization failed\n");
		goto out;
	}

	if (libuboot_read_config(ctx, config_path) < 0) {
		err_printf("libubootenv failed reading config %s\n", config_path);
		goto out;
	}

	if (libuboot_open(ctx) < 0) {
		err_printf("libubootenv failed opening current environment from %s\n", config_path);
		goto out;
	}

	if (apply_write_script_libuboot(script_path, ctx))
		goto out;

	if (libuboot_env_store(ctx) < 0) {
		err_printf("libubootenv failed storing updated environment\n");
		goto out;
	}

	out_printf("Environment write complete using %s\n", config_path);
	ret = 0;

out:
	if (ctx) {
		libuboot_close(ctx);
		libuboot_exit(ctx);
	}
	return ret;
}

static bool has_hint_var(const uint8_t *data, size_t len, const char *hint_override)
{
	static const char *hints[] = {
		"bootcmd=", "bootargs=", "baudrate=", "ethaddr=", "stdin=",
	};

	if (hint_override && *hint_override) {
		size_t hlen = strlen(hint_override);
		for (size_t off = 0; off + hlen <= len; off++)
			if (!memcmp(data + off, hint_override, hlen))
				return true;
		return false;
	}

	for (size_t i = 0; i < ARRAY_SIZE(hints); i++) {
		size_t hlen = strlen(hints[i]);
		for (size_t off = 0; off + hlen <= len; off++)
			if (!memcmp(data + off, hints[i], hlen))
				return true;
	}

	return false;
}

static MAYBE_UNUSED void dump_env_vars(const uint8_t *data, size_t len)
{
	size_t off = 0;
	size_t count = 0;

	out_printf("    parsed env vars:\n");
	while (off < len) {
		const char *s;
		size_t slen;
		const char *eq;
		bool printable = true;

		if (data[off] == '\0') {
			if ((off + 1 < len && data[off + 1] == '\0') || off + 1 >= len)
				break;
			off++;
			continue;
		}

		s = (const char *)(data + off);
		slen = strnlen(s, len - off);
		if (slen == len - off)
			break;

		eq = memchr(s, '=', slen);
		if (eq) {
			for (size_t i = 0; i < slen; i++) {
				if (!isprint((unsigned char)s[i]) && s[i] != '\t') {
					printable = false;
					break;
				}
			}

			if (printable) {
				out_printf("      %.*s\n", (int)slen, s);
				count++;
			}
		}

		off += slen + 1;
		if (count >= 256) {
			out_printf("      ... truncated after 256 vars ...\n");
			break;
		}
	}

	if (!count)
		out_printf("      (no parseable variables found)\n");
}

static int scan_dev(const char *dev, uint64_t step, uint64_t env_size, const char *hint_override)
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
	struct env_candidate *cands = NULL;
	size_t cand_count = 0;

	fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == EBUSY) {
			if (g_verbose)
				emit_env_verbosef(dev, 0, "Skipping busy device %s: %s", dev, strerror(errno));
			return 0;
		}
		err_printf("Cannot open %s: %s\n", dev, strerror(errno));
		return -1;
	}

	if (fstat(fd, &st) < 0) {
		close(fd);
		return -1;
	}

	if (st.st_size == 0) {
		uint64_t sz = uboot_guess_size_any(dev);
		st.st_size = (off_t)sz;
	}

	if (st.st_size == 0) {
		close(fd);
		return -1;
	}

	sysfs_erasesize = uboot_guess_erasesize_from_sysfs(dev);
	erase_size = sysfs_erasesize ? sysfs_erasesize : step;
	sector_count = erase_size ? ((env_size + erase_size - 1) / erase_size) : 0;

	buf = malloc((size_t)env_size);
	if (!buf) {
		close(fd);
		return -1;
	}

	for (off = 0; (uint64_t)off + env_size <= (uint64_t)st.st_size; off += (off_t)step) {
		if ((uint64_t)pread(fd, buf, (size_t)env_size, off) != env_size)
			break;

		uint32_t stored_le = read_le32(buf);
		uint32_t stored_be = uboot_read_be32(buf);
		uint32_t calc = uboot_crc32_calc(crc32_table, buf + 4, (size_t)env_size - 4);
		uint32_t calc_redund = (env_size > 5)
			? uboot_crc32_calc(crc32_table, buf + 5, (size_t)env_size - 5)
			: 0;
		bool crc_ok_std = (calc == stored_le || calc == stored_be);
		bool crc_ok_redund = (env_size > 5) && (calc_redund == stored_le || calc_redund == stored_be);
		bool hint_ok = has_hint_var(buf + 4, (size_t)env_size - 4, hint_override);
		bool hint_ok_redund = (env_size > 5) && has_hint_var(buf + 5, (size_t)env_size - 5, hint_override);

		if (!g_bruteforce && !crc_ok_std && !crc_ok_redund)
			continue;
		if (g_bruteforce && !hint_ok && !hint_ok_redund)
			continue;

		cfg_off = erase_size ? ((uint64_t)off - ((uint64_t)off % erase_size)) : (uint64_t)off;
		(void)add_or_merge_candidate(&cands, &cand_count, cfg_off, crc_ok_std, crc_ok_redund);

		if (g_bruteforce)
			emit_env_candidate_record(dev, (uint64_t)off, "", "hint-only", true,
				cfg_off, env_size, erase_size, sector_count);
		else if (crc_ok_redund && !crc_ok_std)
			emit_env_candidate_record(dev, (uint64_t)off,
				(calc_redund == stored_le) ? "LE" : "BE", "redundant", hint_ok_redund,
				cfg_off, env_size, erase_size, sector_count);
		else
			emit_env_candidate_record(dev, (uint64_t)off,
				(calc == stored_le) ? "LE" : "BE", "standard", hint_ok,
				cfg_off, env_size, erase_size, sector_count);
		if (g_output_config_fp) {
			fprintf(g_output_config_fp, "%s 0x%jx 0x%jx 0x%jx 0x%jx\n",
				dev, (uintmax_t)cfg_off, (uintmax_t)env_size,
				(uintmax_t)erase_size, (uintmax_t)sector_count);
		}
		if (g_parse_vars) {
			dump_env_vars_libuboot(dev, (uint64_t)off, env_size, erase_size, sector_count);
		}
		hits++;
	}

	if (cand_count >= 2 && erase_size) {
		uint64_t expected = erase_size * (sector_count ? sector_count : 1);
		for (size_t i = 1; i < cand_count; i++) {
			uint64_t prev = cands[i - 1].cfg_off;
			uint64_t curr = cands[i].cfg_off;
			uint64_t diff = curr - prev;

			if (diff != erase_size && diff != expected)
				continue;

			emit_redundant_pair_record(dev, prev, curr);
		}
	}

	free(cands);
	free(buf);
	close(fd);
	return hits;
}

static void usage(const char *prog)
{
	err_printf("Usage: %s [--verbose] [--size <env_size>] [--hint <hint>] [--dev <dev>] [--brutefoce] [--skip-remove] [--skip-mtd] [--skip-ubi] [--skip-sd] [--skip-emmc] [--output-config[=<path>]] [--write <path>] [<dev:step> ...]\n"
		"             [--parse-vars]\n"
		"             [--output-tcp <ip:port>]\n"
		"             [--output-http <http://host:port/>]\n"
		"             [--output-https <https://host:port/>]\n"
		"             [--insecure]\n", prog);
}

int uboot_env_scan_main(int argc, char **argv)
{
	static const uint64_t common_sizes[] = { 0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000, 0x40000, 0x80000 };
	bool fixed_size = false;
	uint64_t env_size = 0;
	const char *hint_override = NULL;
	const char *dev_override = NULL;
	const char *output_tcp_target = NULL;
	const char *output_http_target = NULL;
	const char *output_https_target = NULL;
	const char *output_config_path = NULL;
	const char *write_script_path = NULL;
	bool write_mode = false;
	bool need_generate_config = false;
	bool skip_remove = false;
	bool skip_mtd = false;
	bool skip_ubi = false;
	bool skip_sd = false;
	bool skip_emmc = false;
	bool helper_verbose = false;
	char **created_mtdblock_nodes = NULL;
	size_t created_mtdblock_count = 0;
	char **created_ubi_nodes = NULL;
	size_t created_ubi_count = 0;
	char **created_block_nodes = NULL;
	size_t created_block_count = 0;
	int ret = 0;
	int argi;
	int opt;

	optind = 1;
	detect_output_format();
	g_verbose = false;
	g_bruteforce = false;
	g_insecure = false;
	g_csv_header_emitted = false;
	g_parse_vars = false;
	if (g_output_sock >= 0) {
		close(g_output_sock);
		g_output_sock = -1;
	}

	static const struct option long_opts[] = {
		{ "verbose", no_argument, NULL, 'v' },
		{ "size", required_argument, NULL, 's' },
		{ "hint", required_argument, NULL, 'H' },
		{ "dev", required_argument, NULL, 'd' },
		{ "brutefoce", no_argument, NULL, 'b' },
		{ "bruteforce", no_argument, NULL, 'b' },
		{ "skip-remove", no_argument, NULL, 'R' },
		{ "skip-mtd", no_argument, NULL, 'M' },
		{ "skip-ubi", no_argument, NULL, 'U' },
		{ "skip-sd", no_argument, NULL, 'S' },
		{ "skip-emmc", no_argument, NULL, 'E' },
		{ "parse-vars", no_argument, NULL, 'P' },
		{ "output-config", optional_argument, NULL, 'c' },
		{ "output-tcp", required_argument, NULL, 'o' },
		{ "output-http", required_argument, NULL, 'O' },
		{ "output-https", required_argument, NULL, 'T' },
		{ "insecure", no_argument, NULL, 'k' },
		{ "write", required_argument, NULL, 'w' },
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "hvs:H:d:bo:O:T:kRMUSEPc::w:", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h': usage(argv[0]); return 0;
		case 'v': g_verbose = true; break;
		case 's': env_size = parse_u64(optarg); fixed_size = true; break;
		case 'H': hint_override = optarg; break;
		case 'd': dev_override = optarg; break;
		case 'b': g_bruteforce = true; break;
		case 'R': skip_remove = true; break;
		case 'M': skip_mtd = true; break;
		case 'U': skip_ubi = true; break;
		case 'S': skip_sd = true; break;
		case 'E': skip_emmc = true; break;
		case 'P': g_parse_vars = true; break;
		case 'c': output_config_path = optarg ? optarg : "uboot_env.config"; break;
		case 'o': output_tcp_target = optarg; break;
		case 'O': output_http_target = optarg; break;
		case 'T': output_https_target = optarg; break;
		case 'k': g_insecure = true; break;
		case 'w': write_script_path = optarg; break;
		default: usage(argv[0]); return 2;
		}
	}

	helper_verbose = (g_output_format == FW_OUTPUT_TXT) && g_verbose;

	argi = optind;
	if (geteuid() != 0) {
		err_printf("This program must be run as root.\n");
		ret = 1;
		goto out;
	}

	if (write_script_path) {
		write_mode = true;
		if (access(write_script_path, R_OK) < 0) {
			err_printf("Cannot read --write file %s: %s\n", write_script_path, strerror(errno));
			ret = 2;
			goto out;
		}
		if (output_config_path && strcmp(output_config_path, "uboot_env.config")) {
			err_printf("--write uses ./uboot_env.config only\n");
			ret = 2;
			goto out;
		}
		if (file_exists("uboot_env.config")) {
			need_generate_config = false;
		} else {
			need_generate_config = true;
			output_config_path = "uboot_env.config";
		}
	}

	if (write_mode && !need_generate_config) {
		uboot_crc32_init(crc32_table);
		if (!skip_mtd)
			uboot_ensure_mtd_nodes_collect(helper_verbose, &created_mtdblock_nodes, &created_mtdblock_count);
		if (!skip_ubi)
			uboot_ensure_ubi_nodes_collect(helper_verbose, &created_ubi_nodes, &created_ubi_count);
		uboot_ensure_block_nodes_collect(helper_verbose, !skip_sd, !skip_emmc,
			&created_block_nodes, &created_block_count);
		ret = perform_write_operation("uboot_env.config", write_script_path);
		goto out;
	}

	if (output_tcp_target && *output_tcp_target) {
		g_output_sock = uboot_connect_tcp_ipv4(output_tcp_target);
		if (g_output_sock < 0) {
			err_printf("Invalid/failed output target (expected IPv4:port): %s\n", output_tcp_target);
			ret = 2;
			goto out;
		}
	}

	if (output_http_target && *output_http_target) {
		if (strncmp(output_http_target, "http://", 7)) {
			err_printf("Invalid --output-http URI (expected http://host:port/...): %s\n", output_http_target);
			ret = 2;
			goto out;
		}
		g_output_http_uri = output_http_target;
	}

	if (output_https_target && *output_https_target) {
		if (strncmp(output_https_target, "https://", 8)) {
			err_printf("Invalid --output-https URI (expected https://host:port/...): %s\n", output_https_target);
			ret = 2;
			goto out;
		}
		if (g_output_http_uri) {
			err_printf("Use only one of --output-http or --output-https\n");
			ret = 2;
			goto out;
		}
		g_output_http_uri = output_https_target;
	}

	if (output_config_path && *output_config_path) {
		g_output_config_fp = fopen(output_config_path, "w");
		if (!g_output_config_fp) {
			err_printf("Cannot open output-config file %s: %s\n", output_config_path, strerror(errno));
			ret = 2;
			goto out;
		}
	}

	uboot_crc32_init(crc32_table);
	if (!skip_mtd)
		uboot_ensure_mtd_nodes_collect(helper_verbose, &created_mtdblock_nodes, &created_mtdblock_count);
	if (!skip_ubi)
		uboot_ensure_ubi_nodes_collect(helper_verbose, &created_ubi_nodes, &created_ubi_count);
	uboot_ensure_block_nodes_collect(helper_verbose, !skip_sd, !skip_emmc,
		&created_block_nodes, &created_block_count);

	if (dev_override) {
		if (!strncmp(dev_override, "/dev/mtd", 8) && strncmp(dev_override, "/dev/mtdblock", 13)) {
			err_printf("Refusing to scan raw MTD char device: %s (use /dev/mtdblock* instead)\n", dev_override);
			ret = 2;
			goto out;
		}

		uint64_t step = uboot_guess_step_any(dev_override);
		if (!step)
			goto scan_fail;
		if (step > AUTO_SCAN_MAX_STEP)
			step = AUTO_SCAN_MAX_STEP;

		if (fixed_size)
			goto one_scan_done;

		for (size_t i = 0; i < ARRAY_SIZE(common_sizes); i++)
			if (scan_dev(dev_override, step, common_sizes[i], hint_override) < 0)
				goto scan_fail;
		ret = 0;
		goto post_scan;

one_scan_done:
		ret = (scan_dev(dev_override, step, env_size, hint_override) < 0) ? 1 : 0;
		goto post_scan;
	}

	if (argi >= argc) {
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

		if (uboot_glob_scan_devices(&g, scan_flags) < 0)
			goto scan_fail;
		for (size_t gi = 0; gi < g.gl_pathc; gi++) {
			const char *dev = g.gl_pathv[gi];
			uint64_t step = uboot_guess_step_any(dev);
			if (!step)
				continue;
			if (step > AUTO_SCAN_MAX_STEP)
				step = AUTO_SCAN_MAX_STEP;

			if (fixed_size) {
				if (scan_dev(dev, step, env_size, hint_override) < 0)
					goto scan_fail;
			} else {
				for (size_t i = 0; i < ARRAY_SIZE(common_sizes); i++)
					if (scan_dev(dev, step, common_sizes[i], hint_override) < 0)
						goto scan_fail;
			}
		}
		globfree(&g);
		ret = 0;
		goto post_scan;
	}

	for (int i = argi; i < argc; i++) {
		char *arg = argv[i];
		char *colon = strrchr(arg, ':');
		if (!colon || colon == arg || *(colon + 1) == '\0')
			continue;
		*colon = '\0';
		if (!strncmp(arg, "/dev/mtd", 8) && strncmp(arg, "/dev/mtdblock", 13)) {
			err_printf("Refusing to scan raw MTD char device: %s (use /dev/mtdblock* instead)\n", arg);
			*colon = ':';
			continue;
		}
		uint64_t step = parse_u64(colon + 1);
		if (fixed_size) {
			if (scan_dev(arg, step, env_size, hint_override) < 0)
				goto scan_fail;
		} else {
			for (size_t si = 0; si < ARRAY_SIZE(common_sizes); si++)
				if (scan_dev(arg, step, common_sizes[si], hint_override) < 0)
					goto scan_fail;
		}
		*colon = ':';
	}
	ret = 0;
	goto post_scan;

scan_fail:
	ret = 1;
	goto out;

post_scan:
	if (write_mode && ret == 0) {
		if (g_output_config_fp) {
			fclose(g_output_config_fp);
			g_output_config_fp = NULL;
		}
		ret = perform_write_operation("uboot_env.config", write_script_path);
	}

out:
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
	if (g_output_config_fp) {
		fclose(g_output_config_fp);
		g_output_config_fp = NULL;
	}
	if (g_output_sock >= 0)
		close(g_output_sock);
	if (flush_output_http_buffer() < 0 && ret == 0)
		ret = 1;
	free(g_output_http_buf);
	g_output_http_buf = NULL;
	g_output_http_len = 0;
	g_output_http_cap = 0;
	g_output_http_uri = NULL;
	return ret;
}
