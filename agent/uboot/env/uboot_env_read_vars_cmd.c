// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include <stdlib.h>

int uboot_env_read_vars_main(int argc, char **argv)
{
	char **sub_argv;
	int sub_argc;

	if (argc < 1 || !argv)
		return 2;

	sub_argc = argc + 1;
	sub_argv = calloc((size_t)sub_argc + 1, sizeof(*sub_argv));
	if (!sub_argv)
		return 2;

	sub_argv[0] = argv[0];
	sub_argv[1] = "--parse-vars";
	for (int i = 1; i < argc; i++)
		sub_argv[i + 1] = argv[i];
	sub_argv[sub_argc] = NULL;

	argc = uboot_env_scan_core_main(sub_argc, sub_argv);
	free(sub_argv);
	return argc;
}
