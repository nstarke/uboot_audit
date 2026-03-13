// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

struct env_kv_view {
	const char *name;
	const char *value;
};

static int parse_env_pairs(const uint8_t *buf,
			   size_t len,
			   size_t data_off,
			   struct env_kv_view *pairs,
			   size_t max_pairs)
{
	size_t off = data_off;
	size_t count = 0;

	if (!buf || data_off >= len || !pairs || !max_pairs)
		return -1;

	while (off < len && count < max_pairs) {
		const char *entry;
		size_t slen;
		const char *eq;

		if (buf[off] == '\0') {
			if (off + 1 >= len || buf[off + 1] == '\0')
				break;
			off++;
			continue;
		}

		entry = (const char *)(buf + off);
		slen = strnlen(entry, len - off);
		if (slen >= len - off)
			break;

		eq = memchr(entry, '=', slen);
		if (eq) {
			pairs[count].name = entry;
			pairs[count].value = eq + 1;
			count++;
		}

		off += slen + 1;
	}

	return (int)count;
}

static const char *find_env_value(const struct env_kv_view *pairs, size_t count, const char *name)
{
	for (size_t i = 0; i < count; i++) {
		size_t nlen;

		if (!pairs[i].name || !pairs[i].value)
			continue;

		nlen = strcspn(pairs[i].name, "=");
		if (strlen(name) == nlen && !strncmp(pairs[i].name, name, nlen))
			return pairs[i].value;
	}

	return NULL;
}

static int choose_env_data_offset(const struct embedded_linux_audit_input *input, size_t *data_off)
{
	uint32_t stored_le;
	uint32_t stored_be;
	uint32_t calc_std;
	uint32_t calc_redund;

	if (!input || !data_off || !input->data || !input->crc32_table || input->data_len < 8)
		return -1;

	stored_le = (uint32_t)input->data[0] |
		((uint32_t)input->data[1] << 8) |
		((uint32_t)input->data[2] << 16) |
		((uint32_t)input->data[3] << 24);
	stored_be = ela_read_be32(input->data);

	calc_std = ela_crc32_calc(input->crc32_table, input->data + 4, input->data_len - 4);
	if (calc_std == stored_le || calc_std == stored_be) {
		*data_off = 4;
		return 0;
	}

	if (input->data_len <= 5)
		return -1;

	calc_redund = ela_crc32_calc(input->crc32_table, input->data + 5, input->data_len - 5);
	if (calc_redund == stored_le || calc_redund == stored_be) {
		*data_off = 5;
		return 0;
	}

	return -1;
}

static bool init_path_looks_valid(const char *v)
{
	if (!v || !*v)
		return false;

	if (*v != '/')
		return false;

	for (const unsigned char *p = (const unsigned char *)v; *p; p++) {
		if (isspace(*p) || iscntrl(*p) || *p == '"' || *p == '\'')
			return false;
	}

	return true;
}

static bool parse_init_parameter(const char *cmdline, char *init_value, size_t init_value_len)
{
	const char *p = cmdline;

	if (!cmdline || !*cmdline || !init_value || init_value_len == 0)
		return false;

	while (*p) {
		const char *tok_start;
		size_t tok_len = 0;

		while (*p && isspace((unsigned char)*p))
			p++;
		if (!*p)
			break;

		tok_start = p;
		while (*p && !isspace((unsigned char)*p))
			p++;
		tok_len = (size_t)(p - tok_start);

		if (tok_len > 5 && !strncmp(tok_start, "init=", 5)) {
			size_t val_len = tok_len - 5;
			if (val_len >= init_value_len)
				val_len = init_value_len - 1;
			memcpy(init_value, tok_start + 5, val_len);
			init_value[val_len] = '\0';
			return true;
		}
	}

	return false;
}

static bool env_block_is_writeable(const char *dev)
{
	int fd;

	if (!dev || !*dev)
		return false;

	fd = open(dev, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return false;
	close(fd);
	return true;
}

static int run_validate_cmdline_init_writeability(const struct embedded_linux_audit_input *input,
						  char *message,
						  size_t message_len)
{
	struct env_kv_view pairs[512];
	const char *bootargs;
	size_t data_off = 0;
	int count;
	char init_value[256] = {0};
	bool has_init;
	bool init_valid;
	bool writeable;

	if (!input || !input->data || !input->crc32_table || input->data_len < 8) {
		if (message && message_len)
			snprintf(message, message_len, "input too small (need at least 8 bytes)");
		return -1;
	}

	if (choose_env_data_offset(input, &data_off) != 0) {
		if (message && message_len)
			snprintf(message, message_len, "unable to parse env vars: invalid CRC32 for standard/redundant layouts");
		return -1;
	}

	count = parse_env_pairs(input->data, input->data_len, data_off, pairs, sizeof(pairs) / sizeof(pairs[0]));
	if (count < 0) {
		if (message && message_len)
			snprintf(message, message_len, "failed to parse environment key/value pairs");
		return -1;
	}

	bootargs = find_env_value(pairs, (size_t)count, "bootargs");
	if (!bootargs || !*bootargs) {
		if (message && message_len)
			snprintf(message, message_len, "bootargs missing; no kernel cmdline parameters to evaluate");
		return 0;
	}

	has_init = parse_init_parameter(bootargs, init_value, sizeof(init_value));
	if (!has_init) {
		if (message && message_len)
			snprintf(message, message_len, "kernel cmdline parsed; init= not present");
		return 0;
	}

	init_valid = init_path_looks_valid(init_value);
	if (!init_valid) {
		if (message && message_len)
			snprintf(message, message_len, "kernel cmdline parsed; init= present but invalid (%s)", init_value);
		return 0;
	}

	writeable = env_block_is_writeable(input->device);
	if (writeable) {
		if (message && message_len) {
			snprintf(message, message_len,
				 "WARNING: valid init=%s and environment block appears writeable (%s)",
				 init_value,
				 input->device ? input->device : "(unknown)");
		}
		return 1;
	}

	if (message && message_len)
		snprintf(message, message_len, "kernel cmdline parsed; valid init=%s and environment block not writeable", init_value);

	return 0;
}

static const struct embedded_linux_audit_rule uboot_validate_cmdline_init_writeability_rule = {
	.name = "uboot_validate_cmdline_init_writeability",
	.description = "Parse kernel cmdline from bootargs and warn when valid init= is combined with writeable env block",
	.run = run_validate_cmdline_init_writeability,
};

ELA_REGISTER_RULE(uboot_validate_cmdline_init_writeability_rule);