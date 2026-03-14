// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "uboot/env/uboot_env_internal.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libuboot.h>

int apply_write_script_libuboot(const char *script_path, struct uboot_ctx *ctx)
{
	FILE *fp;
	char line[4096];
	unsigned long lineno = 0;

	if (!script_path || !ctx)
		return -1;

	fp = fopen(script_path, "r");
	if (!fp) {
		uboot_env_err_printf("Cannot open write script %s: %s\n", script_path, strerror(errno));
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
			uboot_env_err_printf("Invalid variable name at %s:%lu\n", script_path, lineno);
			fclose(fp);
			return -1;
		}

		if (uboot_is_sensitive_env_var(name) && !uboot_confirm_sensitive_write(name)) {
			uboot_env_out_printf("Skipping update for %s\n", name);
			continue;
		}

		if (delete_var) {
			if (libuboot_set_env(ctx, name, NULL) < 0) {
				uboot_env_err_printf("Failed to delete variable '%s' via libubootenv\n", name);
				fclose(fp);
				return -1;
			}
			continue;
		}

		if (!value)
			value = "";

		if (libuboot_set_env(ctx, name, value) < 0) {
			uboot_env_err_printf("Failed to set variable '%s' via libubootenv\n", name);
			fclose(fp);
			return -1;
		}
	}

	fclose(fp);
	return 0;
}

int perform_write_operation(const char *config_path, const char *script_path)
{
	struct uboot_ctx *ctx = NULL;
	int ret = 1;

	if (!config_path || !script_path)
		return 1;

	if (libuboot_initialize(&ctx, NULL) < 0 || !ctx) {
		uboot_env_err_printf("libubootenv initialization failed\n");
		goto out;
	}

	if (libuboot_read_config(ctx, config_path) < 0) {
		uboot_env_err_printf("libubootenv failed reading config %s\n", config_path);
		goto out;
	}

	if (libuboot_open(ctx) < 0) {
		uboot_env_err_printf("libubootenv failed opening current environment from %s\n", config_path);
		goto out;
	}

	if (apply_write_script_libuboot(script_path, ctx))
		goto out;

	if (libuboot_env_store(ctx) < 0) {
		uboot_env_err_printf("libubootenv failed storing updated environment\n");
		goto out;
	}

	uboot_env_out_printf("Environment write complete using %s\n", config_path);
	ret = 0;

out:
	if (ctx) {
		libuboot_close(ctx);
		libuboot_exit(ctx);
	}
	return ret;
}
