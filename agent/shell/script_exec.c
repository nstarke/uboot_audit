// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "script_exec.h"
#include "interactive.h"
#include "../embedded_linux_audit_cmd.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Forward declaration: defined in embedded_linux_audit.c (non-static) */
int embedded_linux_audit_dispatch(int argc, char **argv);

/* Forward declaration of usage() for help command handling in scripts */
void ela_usage(const char *prog);

static bool is_http_script_source(const char *value)
{
	if (!value)
		return false;

	return !strncmp(value, "http://", 7) || !strncmp(value, "https://", 8);
}

static bool local_script_source_exists(const char *value)
{
	struct stat st;

	if (!value || !*value)
		return false;

	return stat(value, &st) == 0 && S_ISREG(st.st_mode);
}

static const char *script_basename(const char *path)
{
	const char *base;

	if (!path || !*path)
		return NULL;

	base = strrchr(path, '/');
	return base ? base + 1 : path;
}

static char *script_url_percent_encode(const char *text)
{
	static const char hex[] = "0123456789ABCDEF";
	const unsigned char *p;
	char *out;
	size_t out_len = 0;
	size_t text_len;

	if (!text)
		return NULL;

	text_len = strlen(text);
	out = malloc(text_len * 3 + 1);
	if (!out)
		return NULL;

	for (p = (const unsigned char *)text; *p; p++) {
		if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~') {
			out[out_len++] = (char)*p;
		} else {
			out[out_len++] = '%';
			out[out_len++] = hex[*p >> 4];
			out[out_len++] = hex[*p & 0x0F];
		}
	}
	out[out_len] = '\0';
	return out;
}

static int create_temp_script_path(char *dir_path, size_t dir_path_len,
				      char *file_path, size_t file_path_len,
				      const char *script_source)
{
	const char *script_name;
	int n;

	if (!dir_path || dir_path_len == 0 || !file_path || file_path_len == 0)
		return -1;

	script_name = script_basename(script_source);
	if (!script_name || !*script_name)
		script_name = "script.txt";

	snprintf(dir_path, dir_path_len, "/tmp/embedded_linux_audit_script.XXXXXX");
	if (!mkdtemp(dir_path))
		return -1;

	n = snprintf(file_path, file_path_len, "%s/%s", dir_path, script_name);
	if (n < 0 || (size_t)n >= file_path_len) {
		rmdir(dir_path);
		dir_path[0] = '\0';
		return -1;
	}

	return 0;
}

static char *build_script_fallback_uri(const char *output_uri, const char *script_source)
{
	const char *scheme_end;
	const char *authority;
	const char *authority_end;
	const char *script_name;
	char *escaped_script_name;
	char *uri;
	size_t prefix_len;
	size_t route_len;
	size_t escaped_len;

	if (!output_uri || !*output_uri || !script_source || !*script_source)
		return NULL;

	scheme_end = strstr(output_uri, "://");
	if (!scheme_end)
		return NULL;

	authority = scheme_end + 3;
	authority_end = authority;
	while (*authority_end && *authority_end != '/' && *authority_end != '?' && *authority_end != '#')
		authority_end++;

	script_name = script_basename(script_source);
	if (!script_name || !*script_name)
		return NULL;

	escaped_script_name = script_url_percent_encode(script_name);
	if (!escaped_script_name)
		return NULL;

	prefix_len = (size_t)(authority_end - output_uri);
	route_len = strlen("/scripts/");
	escaped_len = strlen(escaped_script_name);
	uri = malloc(prefix_len + route_len + escaped_len + 1);
	if (!uri) {
		free(escaped_script_name);
		return NULL;
	}

	memcpy(uri, output_uri, prefix_len);
	memcpy(uri + prefix_len, "/scripts/", route_len);
	memcpy(uri + prefix_len + route_len, escaped_script_name, escaped_len + 1);
	free(escaped_script_name);
	return uri;
}

static char *script_trim(char *s)
{
	char *end;

	if (!s)
		return NULL;

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

int execute_script_commands(const char *prog, const char *script_source)
{
	FILE *fp = NULL;
	char line[4096];
	char script_dir[PATH_MAX];
	char script_path[PATH_MAX];
	char errbuf[256];
	char *fallback_uri = NULL;
	const char *effective_path = script_source;
	const char *output_uri;
	bool downloaded = false;
	bool insecure;
	unsigned long lineno = 0;
	int final_rc = 0;

	if (!prog || !script_source || !*script_source)
		return 2;
	script_dir[0] = '\0';

	insecure = getenv("ELA_OUTPUT_INSECURE") &&
		!strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	output_uri = getenv("ELA_OUTPUT_HTTP");
	if ((!output_uri || !*output_uri) && getenv("ELA_OUTPUT_HTTPS") && *getenv("ELA_OUTPUT_HTTPS"))
		output_uri = getenv("ELA_OUTPUT_HTTPS");

	if (is_http_script_source(script_source)) {
		if (create_temp_script_path(script_dir,
					 sizeof(script_dir),
					 script_path,
					 sizeof(script_path),
					 script_source) < 0) {
			fprintf(stderr, "Failed to create temp file for script %s: %s\n",
				script_source,
				strerror(errno));
			return 2;
		}

		if (ela_http_get_to_file(script_source,
					  script_path,
					  insecure,
					  false,
					  errbuf,
					  sizeof(errbuf)) < 0) {
			fprintf(stderr, "Failed to fetch script %s: %s\n",
				script_source,
				errbuf[0] ? errbuf : "unknown error");
			unlink(script_path);
			rmdir(script_dir);
			script_dir[0] = '\0';
			return 2;
		}

		effective_path = script_path;
		downloaded = true;
	} else if (!local_script_source_exists(script_source) && output_uri && *output_uri) {
		fallback_uri = build_script_fallback_uri(output_uri, script_source);
		if (!fallback_uri) {
			fprintf(stderr,
				"Cannot resolve fallback script URI for %s using %s\n",
				script_source,
				output_uri);
			return 2;
		}

		if (create_temp_script_path(script_dir,
					 sizeof(script_dir),
					 script_path,
					 sizeof(script_path),
					 script_source) < 0) {
			fprintf(stderr, "Failed to create temp file for script %s: %s\n",
				script_source,
				strerror(errno));
			free(fallback_uri);
			return 2;
		}

		if (ela_http_get_to_file(fallback_uri,
					  script_path,
					  insecure,
					  false,
					  errbuf,
					  sizeof(errbuf)) < 0) {
			fprintf(stderr,
				"Cannot open script %s: %s\n",
				script_source,
				errbuf[0] ? errbuf : "not found");
			unlink(script_path);
			rmdir(script_dir);
			script_dir[0] = '\0';
			free(fallback_uri);
			return 2;
		}

		effective_path = script_path;
		downloaded = true;
	}

	fp = fopen(effective_path, "r");
	if (!fp) {
		fprintf(stderr, "Cannot open script %s: %s\n", effective_path, strerror(errno));
		final_rc = 2;
		goto out;
	}

	while (fgets(line, sizeof(line), fp)) {
		char **argv = NULL;
		char **dispatch_argv = NULL;
		int dispatch_argc;
		int script_cmd_idx = 0;
		char *trimmed;
		int argc = 0;
		int rc;

		lineno++;
		trimmed = script_trim(line);
		if (!trimmed || !*trimmed || *trimmed == '#')
			continue;

		rc = interactive_parse_line(trimmed, &argv, &argc);
		if (rc == -1) {
			fprintf(stderr, "Out of memory while parsing script line %lu\n", lineno);
			final_rc = 2;
			goto out;
		}
		if (rc != 0) {
			fprintf(stderr, "Failed parsing script line %lu in %s\n", lineno, effective_path);
			final_rc = rc;
			interactive_free_argv(argv, argc);
			goto out;
		}
		if (argc == 0) {
			interactive_free_argv(argv, argc);
			continue;
		}

		if (!strcmp(argv[0], "help")) {
			ela_usage(prog);
			interactive_free_argv(argv, argc);
			continue;
		}

		if (!strcmp(argv[0], "set")) {
			rc = interactive_set_command(argc, argv);
			interactive_free_argv(argv, argc);
			if (rc != 0) {
				final_rc = rc;
				goto out;
			}
			continue;
		}

		if (!strcmp(argv[0], "ela") || !strcmp(argv[0], "embedded_linux_audit"))
			script_cmd_idx = 1;

		if (script_cmd_idx >= argc) {
			fprintf(stderr,
				"Script line %lu in %s must include a command after %s\n",
				lineno,
				effective_path,
				argv[0]);
			interactive_free_argv(argv, argc);
			final_rc = 2;
			goto out;
		}

		dispatch_argc = argc + 1 - script_cmd_idx;

		dispatch_argv = calloc((size_t)dispatch_argc + 1, sizeof(*dispatch_argv));
		if (!dispatch_argv) {
			fprintf(stderr, "Out of memory while preparing script line %lu\n", lineno);
			interactive_free_argv(argv, argc);
			final_rc = 2;
			goto out;
		}

		dispatch_argv[0] = (char *)prog;
		for (int i = script_cmd_idx; i < argc; i++)
			dispatch_argv[i - script_cmd_idx + 1] = argv[i];

		(void)embedded_linux_audit_dispatch(dispatch_argc, dispatch_argv);
		free(dispatch_argv);
		interactive_free_argv(argv, argc);

		/*
		 * Script coverage files intentionally mix commands that may return
		 * runtime/status failures (for example, no matching firmware payloads,
		 * missing EFI support on the host, or root-only scan paths) with parser
		 * and help coverage. Only failures in reading/parsing the script file
		 * itself are treated as fatal for the overall script execution; per-line
		 * command return codes are intentionally ignored so coverage can continue
		 * across commands that legitimately return non-zero status.
		 */
	}

out:
	if (fp)
		fclose(fp);
	if (downloaded) {
		unlink(script_path);
		if (script_dir[0])
			rmdir(script_dir);
	}
	free(fallback_uri);
	return final_rc;
}
