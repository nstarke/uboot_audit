// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_IMAGE_INTERNAL_H
#define ELA_UBOOT_IMAGE_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define UIMAGE_HDR_SIZE 64U
#define FIT_MIN_TOTAL_SIZE 0x100U
#define FIT_MAX_TOTAL_SIZE (64U * 1024U * 1024U)
#define UIMAGE_MAX_DATA_SIZE (256U * 1024U * 1024U)

enum uboot_output_format {
	FW_OUTPUT_TXT = 0,
	FW_OUTPUT_CSV,
	FW_OUTPUT_JSON,
};

struct extracted_command {
	char *name;
	unsigned int hits;
	int best_occ_score;
	bool known;
	bool context_seen;
};

/* Global state definitions live in uboot_image_cmd.c */
extern bool g_verbose;
extern bool g_allow_text;
extern const char *g_allow_text_pattern;
extern bool g_send_logs;
extern bool g_insecure;
extern uint32_t g_crc32_table[256];
extern int g_log_sock;
extern const char *g_pull_binary_content_type;
extern const char *g_output_http_uri;
extern char *g_output_http_buf;
extern size_t g_output_http_len;
extern size_t g_output_http_cap;
extern enum uboot_output_format g_output_format;
extern bool g_csv_header_emitted;

/* Shared internal function declarations */
void uboot_img_out_printf(const char *fmt, ...);
void uboot_img_err_printf(const char *fmt, ...);
int flush_output_http_buffer(void);
void emit_image_record(const char *record, const char *dev, uint64_t off,
		       const char *type, const char *value);
void emit_image_verbose(const char *dev, uint64_t off, const char *msg);
uint64_t uboot_guess_size_any(const char *dev);
bool validate_fit_header(const uint8_t *p, uint64_t abs_off, uint64_t dev_size);
bool validate_uimage_header(const uint8_t *p, uint64_t abs_off, uint64_t dev_size);
bool fit_find_load_address(const uint8_t *blob, size_t blob_size,
			   uint32_t *addr_out, uint64_t *uboot_off_out,
			   bool *uboot_off_found_out);
int list_image_commands(const char *dev, uint64_t offset);

#endif /* ELA_UBOOT_IMAGE_INTERNAL_H */
