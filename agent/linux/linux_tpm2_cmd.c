// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <tpm2-command> [command-arguments...]\n"
		"       %s list-commands\n"
		"\n"
		"Dispatches TPM2 commands using the installed tpm2-tools style executable\n"
		"naming convention: `tpm2_<tpm2-command>`. For example:\n"
		"  %s getcap properties-fixed\n"
		"  %s pcrread sha256:0,1,2\n"
		"\n"
		"Notes:\n"
		"  - This command is a generic wrapper, so any installed `tpm2_*` tool is\n"
		"    available as `linux tpm2 <command>`.\n"
		"  - `list-commands` scans PATH for available `tpm2_*` executables.\n"
		"  - Output formatting and transport are controlled by the delegated TPM2\n"
		"    tool, not by embedded_linux_audit.\n",
		prog, prog, prog, prog);
}

static int cmp_strings(const void *lhs, const void *rhs)
{
	const char *const *a = (const char *const *)lhs;
	const char *const *b = (const char *const *)rhs;

	return strcmp(*a, *b);
}

static bool path_entry_has_command(const char *dir, const char *name)
{
	char full_path[PATH_MAX];
	struct stat st;
	int n;

	if (!dir || !*dir || !name || !*name)
		return false;

	n = snprintf(full_path, sizeof(full_path), "%s/%s", dir, name);
	if (n < 0 || (size_t)n >= sizeof(full_path))
		return false;

	if (stat(full_path, &st) != 0)
		return false;

	if (!S_ISREG(st.st_mode))
		return false;

	return access(full_path, X_OK) == 0;
}

static bool command_exists_in_path(const char *name)
{
	const char *path_env;
	char *path_copy;
	char *saveptr = NULL;
	char *entry;
	bool found = false;

	if (!name || !*name)
		return false;

	path_env = getenv("PATH");
	if (!path_env || !*path_env)
		return false;

	path_copy = strdup(path_env);
	if (!path_copy)
		return false;

	for (entry = strtok_r(path_copy, ":", &saveptr);
	     entry;
	     entry = strtok_r(NULL, ":", &saveptr)) {
		if (!*entry)
			entry = ".";
		if (path_entry_has_command(entry, name)) {
			found = true;
			break;
		}
	}

	free(path_copy);
	return found;
}

static int append_command_name(char ***names, size_t *count, size_t *cap, const char *name)
{
	char **tmp;
	char *dup;
	size_t i;

	if (!names || !count || !cap || !name || !*name)
		return -1;

	for (i = 0; i < *count; i++) {
		if (!strcmp((*names)[i], name))
			return 0;
	}

	dup = strdup(name);
	if (!dup)
		return -1;

	if (*count == *cap) {
		size_t new_cap = *cap ? (*cap * 2) : 32;
		tmp = realloc(*names, new_cap * sizeof(*tmp));
		if (!tmp) {
			free(dup);
			return -1;
		}
		*names = tmp;
		*cap = new_cap;
	}

	(*names)[*count] = dup;
	(*count)++;
	return 0;
}

static void free_command_names(char **names, size_t count)
{
	size_t i;

	if (!names)
		return;

	for (i = 0; i < count; i++)
		free(names[i]);
	free(names);
}

static int linux_tpm2_list_commands(void)
{
	const char *path_env;
	char *path_copy;
	char *saveptr = NULL;
	char *entry;
	char **names = NULL;
	size_t count = 0;
	size_t cap = 0;
	int ret = 0;

	path_env = getenv("PATH");
	if (!path_env || !*path_env) {
		fprintf(stderr, "linux tpm2: PATH is empty\n");
		return 1;
	}

	path_copy = strdup(path_env);
	if (!path_copy)
		return 1;

	for (entry = strtok_r(path_copy, ":", &saveptr);
	     entry;
	     entry = strtok_r(NULL, ":", &saveptr)) {
		DIR *dir;
		struct dirent *de;

		if (!*entry)
			entry = ".";

		dir = opendir(entry);
		if (!dir)
			continue;

		while ((de = readdir(dir)) != NULL) {
			if (strncmp(de->d_name, "tpm2_", 5))
				continue;
			if (!path_entry_has_command(entry, de->d_name))
				continue;
			if (append_command_name(&names, &count, &cap, de->d_name + 5) != 0) {
				closedir(dir);
				free(path_copy);
				free_command_names(names, count);
				return 1;
			}
		}

		closedir(dir);
	}

	free(path_copy);

	if (count == 0) {
		fprintf(stderr, "linux tpm2: no tpm2_* commands found in PATH\n");
		free_command_names(names, count);
		return 1;
	}

	qsort(names, count, sizeof(*names), cmp_strings);
	for (size_t i = 0; i < count; i++)
		printf("%s\n", names[i]);

	free_command_names(names, count);
	return ret;
}

static int linux_tpm2_exec_command(const char *subcommand, int argc, char **argv)
{
	char command_name[PATH_MAX];
	char **child_argv;
	pid_t pid;
	int status;
	int i;

	if (!subcommand || !*subcommand)
		return 2;

	if (snprintf(command_name, sizeof(command_name), "tpm2_%s", subcommand) >= (int)sizeof(command_name)) {
		fprintf(stderr, "linux tpm2: command name too long: %s\n", subcommand);
		return 2;
	}

	if (!command_exists_in_path(command_name)) {
		fprintf(stderr,
			"linux tpm2: command `%s` was not found in PATH (expected executable `%s`)\n",
			subcommand,
			command_name);
		return 127;
	}

	child_argv = calloc((size_t)argc + 1, sizeof(*child_argv));
	if (!child_argv)
		return 1;

	child_argv[0] = command_name;
	for (i = 2; i < argc; i++)
		child_argv[i - 1] = argv[i];
	child_argv[argc - 1] = NULL;

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "linux tpm2: fork failed: %s\n", strerror(errno));
		free(child_argv);
		return 1;
	}

	if (pid == 0) {
		execvp(command_name, child_argv);
		fprintf(stderr, "linux tpm2: exec failed for %s: %s\n", command_name, strerror(errno));
		_exit(127);
	}

	free(child_argv);

	if (waitpid(pid, &status, 0) < 0) {
		fprintf(stderr, "linux tpm2: waitpid failed: %s\n", strerror(errno));
		return 1;
	}

	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	if (WIFSIGNALED(status))
		return 128 + WTERMSIG(status);

	return 1;
}

int linux_tpm2_scan_main(int argc, char **argv)
{
	int opt;
	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};

	optind = 1;
	while ((opt = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	if (optind >= argc) {
		usage(argv[0]);
		return 2;
	}

	if (!strcmp(argv[optind], "help") || !strcmp(argv[optind], "--help") || !strcmp(argv[optind], "-h")) {
		usage(argv[0]);
		return 0;
	}

	if (!strcmp(argv[optind], "list-commands")) {
		if (optind + 1 != argc) {
			fprintf(stderr, "linux tpm2: list-commands does not accept additional arguments\n");
			usage(argv[0]);
			return 2;
		}
		return linux_tpm2_list_commands();
	}

	return linux_tpm2_exec_command(argv[optind], argc, argv);
}