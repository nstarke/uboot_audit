// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../embedded_linux_audit_cmd.h"

#include <stddef.h>
#include <stdint.h>

void ela_crc32_init(uint32_t table[256])
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

uint32_t ela_crc32_calc(const uint32_t table[256], const uint8_t *buf, size_t len)
{
	uint32_t c = 0xFFFFFFFFU;

	if (!table || !buf)
		return 0;

	for (size_t i = 0; i < len; i++)
		c = table[(c ^ buf[i]) & 0xFFU] ^ (c >> 8);

	return c ^ 0xFFFFFFFFU;
}
