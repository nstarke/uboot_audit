// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "interactive.h"
#include "../embedded_linux_audit_cmd.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#if defined(ELA_HAS_READLINE)
#include <readline/history.h>
#include <readline/readline.h>
#endif

/* Forward declaration: defined in embedded_linux_audit.c (non-static) */
int embedded_linux_audit_dispatch(int argc, char **argv);

#if defined(ELA_HAS_READLINE)
static const char *const interactive_top_level_commands[] = {
	"help",
	"quit",
	"exit",
	"set",
	"uboot",
	"linux",
	"efi",
	"bios",
	NULL,
};

static const char *const interactive_group_uboot[] = {
	"env",
	"image",
	"audit",
	NULL,
};

static const char *const interactive_group_linux[] = {
	"dmesg",
	"download-file",
	"execute-command",
	"grep",
	"list-files",
	"list-symlinks",
	"remote-copy",
	"ssh",
	"tpm2",
	NULL,
};

static const char *const interactive_group_efi[] = {
	"orom",
	"dump-vars",
	NULL,
};

static const char *const interactive_group_bios[] = {
	"orom",
	NULL,
};

static const char *const interactive_set_variables[] = {
	"ELA_API_URL",
	"ELA_API_INSECURE",
	"ELA_QUIET",
	"ELA_OUTPUT_FORMAT",
	"ELA_OUTPUT_TCP",
	"ELA_SCRIPT",
	NULL,
};

static const char *const *interactive_completion_candidates;
#endif

static void interactive_usage(const char *prog)
{
	printf("Interactive mode commands:\n"
	       "  help                          Show this interactive help\n"
	       "  quit | exit                   Leave interactive mode\n"

#if defined(ELA_HAS_READLINE)
	       "  <Tab>                         Complete commands/groups/subcommands\n"
#else
	       "  <Up>/<Down>                   Recall previous commands from history\n"
#endif
	       "  set                           Show supported interactive environment variables\n"
	       "  set ELA_API_URL <url>         Set default HTTP/HTTPS upload endpoint\n"
	       "  set ELA_API_INSECURE <bool>   Set TLS verification policy (true/false)\n"
	       "  set ELA_QUIET <bool>          Set default top-level quiet mode (true/false)\n"
	       "  set ELA_OUTPUT_FORMAT <fmt>   Set default top-level output format (txt/csv/json)\n"
	       "  set ELA_OUTPUT_TCP <target>   Set default top-level TCP output (IPv4:port)\n"
	       "  set ELA_SCRIPT <path|url>     Set default top-level script source\n"
	       "\n"
	       "Available command groups:\n"
	       "  uboot env\n"
	       "  uboot image\n"
	       "  uboot audit\n"
	       "  linux dmesg\n"
	       "  linux download-file\n"
	       "  linux execute-command\n"
	       "  linux grep\n"
	       "  linux list-files\n"
	       "  linux list-symlinks\n"
	       "  linux remote-copy\n"
	       "  linux ssh\n"
	       "  linux tpm2\n"
	       "  efi orom\n"
	       "  efi dump-vars\n"
	       "  bios orom\n"
	       "\n"
	       "Examples:\n"
	       "  %s> set ELA_API_URL http://127.0.0.1:5000/upload\n"
	       "  %s> set ELA_API_INSECURE true\n"
	       "  %s> set ELA_QUIET true\n"
	       "  %s> set ELA_OUTPUT_FORMAT json\n"
	       "  %s> set ELA_OUTPUT_TCP 127.0.0.1:5000\n"
	       "  %s> set ELA_SCRIPT ./commands.txt\n"
	       "  %s> linux dmesg\n"
	       "  %s> linux execute-command \"uname -a\"\n"
	       "  %s> uboot env --size 0x10000\n",
	       prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

static void print_set_values(void)
{
	const char *ela_api_url = getenv("ELA_API_URL");
	const char *ela_api_insecure = getenv("ELA_API_INSECURE");
	const char *ela_quiet = getenv("ELA_QUIET");
	const char *ela_output_format = getenv("ELA_OUTPUT_FORMAT");
	const char *ela_output_tcp = getenv("ELA_OUTPUT_TCP");
	const char *ela_script = getenv("ELA_SCRIPT");

	printf("Supported variables:\n"
	       "  ELA_API_URL        current=%s\n"
	       "  ELA_API_INSECURE   current=%s\n"
	       "  ELA_QUIET          current=%s\n"
	       "  ELA_OUTPUT_FORMAT  current=%s\n"
	       "  ELA_OUTPUT_TCP     current=%s\n"
	       "  ELA_SCRIPT         current=%s\n",
	       (ela_api_url && *ela_api_url) ? ela_api_url : "<unset>",
	       (ela_api_insecure && *ela_api_insecure) ? ela_api_insecure : "<unset>",
	       (ela_quiet && *ela_quiet) ? ela_quiet : "<unset>",
	       (ela_output_format && *ela_output_format) ? ela_output_format : "<unset>",
	       (ela_output_tcp && *ela_output_tcp) ? ela_output_tcp : "<unset>",
	       (ela_script && *ela_script) ? ela_script : "<unset>");
}

static int interactive_list_supported_variables(FILE *stream)
{
	const char *ela_api_url = getenv("ELA_API_URL");
	const char *ela_api_insecure = getenv("ELA_API_INSECURE");
	const char *ela_quiet = getenv("ELA_QUIET");
	const char *ela_output_format = getenv("ELA_OUTPUT_FORMAT");
	const char *ela_output_tcp = getenv("ELA_OUTPUT_TCP");
	const char *ela_script = getenv("ELA_SCRIPT");

	return fprintf(stream,
		       "Supported variables:\n"
		       "  ELA_API_URL        current=%s\n"
		       "  ELA_API_INSECURE   current=%s\n"
		       "  ELA_QUIET          current=%s\n"
		       "  ELA_OUTPUT_FORMAT  current=%s\n"
		       "  ELA_OUTPUT_TCP     current=%s\n"
		       "  ELA_SCRIPT         current=%s\n",
		       (ela_api_url && *ela_api_url) ? ela_api_url : "<unset>",
		       (ela_api_insecure && *ela_api_insecure) ? ela_api_insecure : "<unset>",
		       (ela_quiet && *ela_quiet) ? ela_quiet : "<unset>",
		       (ela_output_format && *ela_output_format) ? ela_output_format : "<unset>",
		       (ela_output_tcp && *ela_output_tcp) ? ela_output_tcp : "<unset>",
		       (ela_script && *ela_script) ? ela_script : "<unset>");
}

static bool interactive_parse_bool(const char *value, const char **normalized)
{
	if (!value || !normalized)
		return false;

	if (!strcmp(value, "1") || !strcmp(value, "true") || !strcmp(value, "yes") ||
	    !strcmp(value, "on")) {
		*normalized = "true";
		return true;
	}

	if (!strcmp(value, "0") || !strcmp(value, "false") || !strcmp(value, "no") ||
	    !strcmp(value, "off")) {
		*normalized = "false";
		return true;
	}

	return false;
}

int interactive_set_command(int argc, char **argv)
{
	const char *normalized_bool;

	if (argc == 1) {
		print_set_values();
		return 0;
	}

	if (argc != 3) {
		fprintf(stderr,
			"Usage: set <ELA_API_URL|ELA_API_INSECURE|ELA_QUIET|ELA_OUTPUT_FORMAT|ELA_OUTPUT_TCP|ELA_SCRIPT> <value>\n"
			"  set ELA_API_URL http://127.0.0.1:5000/upload\n"
			"  set ELA_API_INSECURE true\n"
			"  set ELA_QUIET true\n"
			"  set ELA_OUTPUT_FORMAT json\n"
			"  set ELA_OUTPUT_TCP 127.0.0.1:5000\n"
			"  set ELA_SCRIPT ./commands.txt\n");
		return 2;
	}

	if (!strcmp(argv[1], "ELA_API_URL")) {
		if (strncmp(argv[2], "http://", 7) && strncmp(argv[2], "https://", 8)) {
			fprintf(stderr,
				"Invalid ELA_API_URL (expected http://host:port/... or https://host:port/...): %s\n",
				argv[2]);
			return 2;
		}

		if (setenv("ELA_API_URL", argv[2], 1) != 0) {
			fprintf(stderr, "Failed to set ELA_API_URL\n");
			return 2;
		}

		printf("ELA_API_URL=%s\n", argv[2]);
		return 0;
	}

	if (!strcmp(argv[1], "ELA_API_INSECURE")) {
		if (!interactive_parse_bool(argv[2], &normalized_bool)) {
			fprintf(stderr,
				"Invalid ELA_API_INSECURE value: %s (expected true/false, 1/0, yes/no, on/off)\n",
				argv[2]);
			return 2;
		}

		if (setenv("ELA_API_INSECURE", normalized_bool, 1) != 0) {
			fprintf(stderr, "Failed to set ELA_API_INSECURE\n");
			return 2;
		}

		printf("ELA_API_INSECURE=%s\n", normalized_bool);
		return 0;
	}

	if (!strcmp(argv[1], "ELA_QUIET")) {
		if (!interactive_parse_bool(argv[2], &normalized_bool)) {
			fprintf(stderr,
				"Invalid ELA_QUIET value: %s (expected true/false, 1/0, yes/no, on/off)\n",
				argv[2]);
			return 2;
		}

		if (setenv("ELA_QUIET", normalized_bool, 1) != 0) {
			fprintf(stderr, "Failed to set ELA_QUIET\n");
			return 2;
		}

		printf("ELA_QUIET=%s\n", normalized_bool);
		return 0;
	}

	if (!strcmp(argv[1], "ELA_OUTPUT_FORMAT")) {
		if (strcmp(argv[2], "txt") && strcmp(argv[2], "csv") && strcmp(argv[2], "json")) {
			fprintf(stderr,
				"Invalid ELA_OUTPUT_FORMAT: %s (expected: csv, json, txt)\n",
				argv[2]);
			return 2;
		}

		if (setenv("ELA_OUTPUT_FORMAT", argv[2], 1) != 0) {
			fprintf(stderr, "Failed to set ELA_OUTPUT_FORMAT\n");
			return 2;
		}

		printf("ELA_OUTPUT_FORMAT=%s\n", argv[2]);
		return 0;
	}

	if (!strcmp(argv[1], "ELA_OUTPUT_TCP")) {
		if (!fw_audit_is_valid_tcp_output_target(argv[2])) {
			fprintf(stderr,
				"Invalid ELA_OUTPUT_TCP target (expected IPv4:port): %s\n",
				argv[2]);
			return 2;
		}

		if (setenv("ELA_OUTPUT_TCP", argv[2], 1) != 0) {
			fprintf(stderr, "Failed to set ELA_OUTPUT_TCP\n");
			return 2;
		}

		printf("ELA_OUTPUT_TCP=%s\n", argv[2]);
		return 0;
	}

	if (!strcmp(argv[1], "ELA_SCRIPT")) {
		if (setenv("ELA_SCRIPT", argv[2], 1) != 0) {
			fprintf(stderr, "Failed to set ELA_SCRIPT\n");
			return 2;
		}

		printf("ELA_SCRIPT=%s\n", argv[2]);
		return 0;
	}

	fprintf(stderr, "Unsupported variable for set: %s\n", argv[1]);
	interactive_list_supported_variables(stderr);
	return 2;
}

#if defined(ELA_HAS_READLINE)
static const char *const *interactive_candidates_for_position(int argc, char **argv)
{
	if (argc <= 0)
		return interactive_top_level_commands;

	if (argc == 1)
		return interactive_top_level_commands;

	if (!strcmp(argv[0], "uboot"))
		return interactive_group_uboot;

	if (!strcmp(argv[0], "linux"))
		return interactive_group_linux;

	if (!strcmp(argv[0], "efi"))
		return interactive_group_efi;

	if (!strcmp(argv[0], "bios"))
		return interactive_group_bios;

	if (!strcmp(argv[0], "set") && argc == 2)
		return interactive_set_variables;

	return NULL;
}

static char *interactive_completion_generator(const char *text, int state)
{
	static int index;
	const char *name;
	size_t text_len;

	if (state == 0)
		index = 0;

	if (!interactive_completion_candidates)
		return NULL;

	text_len = strlen(text);
	while ((name = interactive_completion_candidates[index++]) != NULL) {
		if (!strncmp(name, text, text_len))
			return strdup(name);
	}

	return NULL;
}

static char **interactive_completion(const char *text, int start, int end)
{
	char *prefix;
	char **argv = NULL;
	int argc = 0;
	int rc;
	bool new_token;
	int completion_argc;

	(void)end;

	if (start < 0)
		return NULL;

	interactive_completion_candidates = NULL;
	prefix = malloc((size_t)start + 1);
	if (!prefix)
		return NULL;
	memcpy(prefix, rl_line_buffer, (size_t)start);
	prefix[start] = '\0';

	rc = interactive_parse_line(prefix, &argv, &argc);
	new_token = (start > 0) && isspace((unsigned char)rl_line_buffer[start - 1]);
	free(prefix);
	if (rc != 0) {
		interactive_free_argv(argv, argc);
		return NULL;
	}

	completion_argc = argc + (new_token ? 1 : 0);
	interactive_completion_candidates = interactive_candidates_for_position(completion_argc, argv);
	interactive_free_argv(argv, argc);
	if (!interactive_completion_candidates)
		return NULL;

	rl_attempted_completion_over = 1;
	return rl_completion_matches(text, interactive_completion_generator);
}
#endif

static int interactive_append_arg(char ***argv_out, int *argc_out, const char *start, size_t len)
{
	char **tmp_argv;
	char *arg;

	if (!argv_out || !argc_out)
		return -1;

	arg = malloc(len + 1);
	if (!arg)
		return -1;
	memcpy(arg, start, len);
	arg[len] = '\0';

	tmp_argv = realloc(*argv_out, (size_t)(*argc_out + 2) * sizeof(*tmp_argv));
	if (!tmp_argv) {
		free(arg);
		return -1;
	}

	*argv_out = tmp_argv;
	(*argv_out)[*argc_out] = arg;
	(*argc_out)++;
	(*argv_out)[*argc_out] = NULL;
	return 0;
}

void interactive_free_argv(char **argv, int argc)
{
	if (!argv)
		return;

	for (int i = 0; i < argc; i++)
		free(argv[i]);
	free(argv);
}

int interactive_parse_line(const char *line, char ***argv_out, int *argc_out)
{
	const char *p = line;
	char **argv = NULL;
	int argc = 0;

	if (!argv_out || !argc_out)
		return -1;

	while (*p) {
		const char *start;
		char quote = '\0';
		char *arg = NULL;
		size_t arg_len = 0;
		size_t arg_cap = 0;

		while (*p && isspace((unsigned char)*p))
			p++;
		if (*p == '#')
			break;
		if (!*p || *p == '\n')
			break;

		start = p;
		while (*p && (!isspace((unsigned char)*p) || quote)) {
			char ch = *p++;
			if (!quote && ch == '#') {
				p--;
				break;
			}
			if (!quote && (ch == '\'' || ch == '"')) {
				quote = ch;
				continue;
			}
			if (quote && ch == quote) {
				quote = '\0';
				continue;
			}
			if (ch == '\\' && *p) {
				ch = *p++;
			}
			if (arg_len + 2 > arg_cap) {
				size_t new_cap = arg_cap ? arg_cap * 2 : 32;
				char *tmp = realloc(arg, new_cap);
				if (!tmp) {
					free(arg);
					interactive_free_argv(argv, argc);
					return -1;
				}
				arg = tmp;
				arg_cap = new_cap;
			}
			arg[arg_len++] = ch;
		}

		if (quote) {
			fprintf(stderr, "Unterminated quote in interactive command: %s\n", start);
			free(arg);
			interactive_free_argv(argv, argc);
			return 2;
		}

		if (!arg) {
			if (interactive_append_arg(&argv, &argc, start, (size_t)(p - start)) != 0) {
				interactive_free_argv(argv, argc);
				return -1;
			}
		} else {
			char **tmp_argv;
			arg[arg_len] = '\0';
			tmp_argv = realloc(argv, (size_t)(argc + 2) * sizeof(*tmp_argv));
			if (!tmp_argv) {
				free(arg);
				interactive_free_argv(argv, argc);
				return -1;
			}
			argv = tmp_argv;
			argv[argc++] = arg;
			argv[argc] = NULL;
		}

		if (*p == '#')
			break;
	}

	*argv_out = argv;
	*argc_out = argc;
	return 0;
}

static void interactive_restore_terminal(int tty_fd,
					 const struct termios *saved_termios,
					 bool have_saved_termios)
{
	if (tty_fd < 0 || !saved_termios || !have_saved_termios)
		return;

	(void)tcsetattr(tty_fd, TCSANOW, saved_termios);
}

#if !defined(ELA_HAS_READLINE)
struct interactive_history {
	char **entries;
	size_t count;
	size_t cap;
};

static void interactive_history_free(struct interactive_history *history)
{
	if (!history)
		return;

	for (size_t i = 0; i < history->count; i++)
		free(history->entries[i]);
	free(history->entries);
	history->entries = NULL;
	history->count = 0;
	history->cap = 0;
}

static int interactive_history_add(struct interactive_history *history, const char *line)
{
	char **tmp_entries;
	char *copy;

	if (!history || !line || !*line)
		return 0;

	copy = strdup(line);
	if (!copy)
		return -1;

	if (history->count == history->cap) {
		size_t new_cap = history->cap ? history->cap * 2 : 16;

		tmp_entries = realloc(history->entries, new_cap * sizeof(*tmp_entries));
		if (!tmp_entries) {
			free(copy);
			return -1;
		}

		history->entries = tmp_entries;
		history->cap = new_cap;
	}

	history->entries[history->count++] = copy;
	return 0;
}

static int interactive_set_raw_mode(int tty_fd,
				    const struct termios *saved_termios,
				    bool have_saved_termios)
{
	struct termios raw;

	if (tty_fd < 0 || !saved_termios || !have_saved_termios)
		return 0;

	raw = *saved_termios;
	raw.c_iflag &= (tcflag_t)~(IXON | ICRNL);
	raw.c_lflag &= (tcflag_t)~(ICANON | ECHO);
	raw.c_cc[VMIN] = 1;
	raw.c_cc[VTIME] = 0;

	return tcsetattr(tty_fd, TCSANOW, &raw);
}

static void interactive_redraw_prompt_line(const char *prompt, const char *line)
{
	printf("\r\033[2K%s%s", prompt ? prompt : "", line ? line : "");
	fflush(stdout);
}

static char *interactive_read_line_fallback(const char *prompt,
					    int tty_fd,
					    const struct termios *saved_termios,
					    bool have_saved_termios,
					    struct interactive_history *history)
{
	char *line = NULL;
	char *draft = NULL;
	size_t len = 0;
	size_t cap = 0;
	ssize_t history_index;
	bool tty_input;

	tty_input = tty_fd >= 0 && have_saved_termios && isatty(tty_fd);
	if (!tty_input) {
		size_t line_cap = 0;

		fputs(prompt, stdout);
		fflush(stdout);
		if (getline(&line, &line_cap, stdin) < 0) {
			free(line);
			return NULL;
		}

		if (line[0]) {
			size_t line_len = strlen(line);

			if (line_len > 0 && line[line_len - 1] == '\n')
				line[line_len - 1] = '\0';
		}

		if (interactive_history_add(history, line) != 0) {
			free(line);
			return NULL;
		}

		return line;
	}

	if (interactive_set_raw_mode(tty_fd, saved_termios, have_saved_termios) != 0)
		return NULL;

	history_index = (ssize_t)(history ? history->count : 0);
	interactive_redraw_prompt_line(prompt, "");

	for (;;) {
		unsigned char ch;
		ssize_t nread = read(tty_fd, &ch, 1);

		if (nread <= 0) {
			if (nread < 0 && errno == EINTR)
				continue;
			free(line);
			free(draft);
			interactive_restore_terminal(tty_fd, saved_termios, have_saved_termios);
			return NULL;
		}

		if (ch == '\r' || ch == '\n') {
			putchar('\n');
			break;
		}

		if (ch == 0x04) {
			if (len == 0) {
				putchar('\n');
				free(line);
				free(draft);
				interactive_restore_terminal(tty_fd, saved_termios, have_saved_termios);
				return NULL;
			}
			continue;
		}

		if (ch == 0x7f || ch == 0x08) {
			if (len > 0) {
				line[--len] = '\0';
				interactive_redraw_prompt_line(prompt, line);
			}
			continue;
		}

		if (ch == '\033') {
			unsigned char seq[2];

			if (read(tty_fd, &seq[0], 1) != 1 || read(tty_fd, &seq[1], 1) != 1)
				continue;

			if (seq[0] == '[' && history) {
				const char *replacement = NULL;
				size_t replacement_len;

				if (seq[1] == 'A') {
					if (history->count == 0 || history_index <= 0)
						continue;
					if (history_index == (ssize_t)history->count) {
						free(draft);
						draft = strdup(line ? line : "");
						if (!draft)
							goto oom;
					}
					history_index--;
					replacement = history->entries[history_index];
				} else if (seq[1] == 'B') {
					if (history->count == 0 || history_index >= (ssize_t)history->count)
						continue;
					history_index++;
					if (history_index == (ssize_t)history->count)
						replacement = draft ? draft : "";
					else
						replacement = history->entries[history_index];
				} else {
					continue;
				}

				replacement_len = strlen(replacement);
				if (replacement_len + 1 > cap) {
					size_t new_cap = replacement_len + 32;
					char *tmp = realloc(line, new_cap);

					if (!tmp)
						goto oom;
					line = tmp;
					cap = new_cap;
				}

				memcpy(line, replacement, replacement_len + 1);
				len = replacement_len;
				interactive_redraw_prompt_line(prompt, line);
			}
			continue;
		}

		if (isprint(ch)) {
			if (len + 2 > cap) {
				size_t new_cap = cap ? cap * 2 : 64;
				char *tmp;

				while (new_cap < len + 2)
					new_cap *= 2;

				tmp = realloc(line, new_cap);
				if (!tmp)
					goto oom;
				line = tmp;
				cap = new_cap;
			}

			line[len++] = (char)ch;
			line[len] = '\0';
			interactive_redraw_prompt_line(prompt, line);
		}
	}

	interactive_restore_terminal(tty_fd, saved_termios, have_saved_termios);
	free(draft);

	if (!line) {
		line = strdup("");
		if (!line)
			return NULL;
	}

	if (interactive_history_add(history, line) != 0) {
		free(line);
		return NULL;
	}

	return line;

oom:
	interactive_restore_terminal(tty_fd, saved_termios, have_saved_termios);
	free(line);
	free(draft);
	return NULL;
}
#endif

int interactive_loop(const char *prog)
{
	char *line;
	int last_rc = 0;
	int tty_fd = -1;
	struct termios saved_termios;
	bool have_saved_termios = false;

#if !defined(ELA_HAS_READLINE)
	struct interactive_history history = {0};
#endif

	if (isatty(STDIN_FILENO)) {
		tty_fd = STDIN_FILENO;
		if (tcgetattr(tty_fd, &saved_termios) == 0)
			have_saved_termios = true;
	}

	printf("Entering interactive mode for %s. Type 'help' for commands or 'quit' to exit.\n\n", prog);
	interactive_usage(prog);

#if defined(ELA_HAS_READLINE)
	rl_attempted_completion_function = interactive_completion;
#endif

	for (;;) {
		char **dispatch_argv = NULL;
		char **argv = NULL;
		int argc = 0;
		int rc;

#if defined(ELA_HAS_READLINE)
		char prompt[128];

		snprintf(prompt, sizeof(prompt), "%s> ", prog);
		interactive_restore_terminal(tty_fd, &saved_termios, have_saved_termios);
		line = readline(prompt);
		if (!line) {
			putchar('\n');
			break;
		}

		if (*line)
			add_history(line);
#else
		char prompt[128];

		snprintf(prompt, sizeof(prompt), "%s> ", prog);
		line = interactive_read_line_fallback(prompt,
						 tty_fd,
						 &saved_termios,
						 have_saved_termios,
						 &history);
		if (!line) {
			putchar('\n');
			break;
		}
#endif

		rc = interactive_parse_line(line, &argv, &argc);
		if (rc == -1) {
			fprintf(stderr, "Out of memory while parsing interactive command\n");
			free(line);
			return 2;
		}
		if (rc != 0) {
			last_rc = rc;
			free(line);
			continue;
		}
		if (argc == 0) {
			interactive_free_argv(argv, argc);
			free(line);
			continue;
		}

		if (!strcmp(argv[0], "quit") || !strcmp(argv[0], "exit")) {
			interactive_free_argv(argv, argc);
			free(line);
			break;
		}

		if (!strcmp(argv[0], "help")) {
			interactive_usage(prog);
			interactive_free_argv(argv, argc);
			free(line);
			last_rc = 0;
			continue;
		}

		if (!strcmp(argv[0], "set")) {
			last_rc = interactive_set_command(argc, argv);
			interactive_free_argv(argv, argc);
			free(line);
			continue;
		}

		dispatch_argv = calloc((size_t)argc + 2, sizeof(*dispatch_argv));
		if (!dispatch_argv) {
			fprintf(stderr, "Out of memory while preparing interactive command\n");
			interactive_free_argv(argv, argc);
			free(line);
			return 2;
		}

		dispatch_argv[0] = (char *)prog;
		for (int i = 0; i < argc; i++)
			dispatch_argv[i + 1] = argv[i];

		last_rc = embedded_linux_audit_dispatch(argc + 1, dispatch_argv);
		free(dispatch_argv);
		interactive_free_argv(argv, argc);
		free(line);
	}

	interactive_restore_terminal(tty_fd, &saved_termios, have_saved_termios);

#if !defined(ELA_HAS_READLINE)
	interactive_history_free(&history);
#endif

	return last_rc;
}
