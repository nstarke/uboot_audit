// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_ENV_INTERNAL_H
#define ELA_UBOOT_ENV_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <libuboot.h>

/* Shared internal function declarations (defined in uboot_env_cmd.c) */
void uboot_env_out_printf(const char *fmt, ...);
void uboot_env_err_printf(const char *fmt, ...);
char *uboot_trim(char *s);
bool uboot_valid_var_name(const char *name);
bool uboot_is_sensitive_env_var(const char *name);
bool uboot_confirm_sensitive_write(const char *name);

/* Functions defined in uboot_env_write_op.c */
int apply_write_script_libuboot(const char *script_path, struct uboot_ctx *ctx);
int perform_write_operation(const char *config_path, const char *script_path);

#endif /* ELA_UBOOT_ENV_INTERNAL_H */
