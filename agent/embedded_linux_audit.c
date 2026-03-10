// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(ELA_HAS_READLINE)
#include <readline/history.h>
#include <readline/readline.h>
#endif

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
	"execute-command",
	"list-files",
	"list-symlinks",
	"remote-copy",
	NULL,
};

static const char *const interactive_group_efi[] = {
	"orom",
	NULL,
};

static const char *const interactive_group_bios[] = {
	"orom",
	NULL,
};

static const char *const interactive_set_variables[] = {
	"ELA_API_URL",
	"ELA_API_INSECURE",
	NULL,
};

static const char *const *interactive_completion_candidates;

static int embedded_linux_audit_dispatch(int argc, char **argv);

#if defined(ELA_HAS_READLINE)
static char *interactive_completion_generator(const char *text, int state);
static char **interactive_completion(const char *text, int start, int end);
#endif
static void interactive_free_argv(char **argv, int argc);
static int interactive_parse_line(const char *line, char ***argv_out, int *argc_out);
static void interactive_restore_terminal(int tty_fd,
					 const struct termios *saved_termios,
					 bool have_saved_termios);

static void interactive_usage(const char *prog)
{
	printf("Interactive mode commands:\n"
	       "  help                          Show this interactive help\n"
	       "  quit | exit                   Leave interactive mode\n"

#if defined(ELA_HAS_READLINE)
	       "  <Tab>                         Complete commands/groups/subcommands\n"
#endif
	       "  set                           Show supported interactive environment variables\n"
	       "  set ELA_API_URL <url>         Set default HTTP/HTTPS upload endpoint\n"
	       "  set ELA_API_INSECURE <bool>   Set TLS verification policy (true/false)\n"
	       "\n"
	       "Available command groups:\n"
	       "  uboot env\n"
	       "  uboot image\n"
	       "  uboot audit\n"
	       "  linux dmesg\n"
	       "  linux execute-command\n"
	       "  linux list-files\n"
	       "  linux list-symlinks\n"
	       "  linux remote-copy\n"
	       "  efi orom\n"
	       "  bios orom\n"
	       "\n"
	       "Examples:\n"
	       "  %s> set ELA_API_URL http://127.0.0.1:5000/upload\n"
	       "  %s> set ELA_API_INSECURE true\n"
	       "  %s> linux dmesg\n"
	       "  %s> linux execute-command \"uname -a\"\n"
	       "  %s> uboot env --size 0x10000\n",
	       prog, prog, prog, prog, prog);
}

static void print_set_values(void)
{
	const char *ela_api_url = getenv("ELA_API_URL");
	const char *ela_api_insecure = getenv("ELA_API_INSECURE");

	printf("Supported variables:\n"
	       "  ELA_API_URL        current=%s\n"
	       "  ELA_API_INSECURE   current=%s\n",
	       (ela_api_url && *ela_api_url) ? ela_api_url : "<unset>",
	       (ela_api_insecure && *ela_api_insecure) ? ela_api_insecure : "<unset>");
}

static int interactive_list_supported_variables(FILE *stream)
{
	const char *ela_api_url = getenv("ELA_API_URL");
	const char *ela_api_insecure = getenv("ELA_API_INSECURE");

	return fprintf(stream,
		       "Supported variables:\n"
		       "  ELA_API_URL        current=%s\n"
		       "  ELA_API_INSECURE   current=%s\n",
		       (ela_api_url && *ela_api_url) ? ela_api_url : "<unset>",
		       (ela_api_insecure && *ela_api_insecure) ? ela_api_insecure : "<unset>");
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

static int interactive_set_command(int argc, char **argv)
{
	const char *normalized_bool;

	if (argc == 1) {
		print_set_values();
		return 0;
	}

	if (argc != 3) {
		fprintf(stderr,
			"Usage: set <ELA_API_URL|ELA_API_INSECURE> <value>\n"
			"  set ELA_API_URL http://127.0.0.1:5000/upload\n"
			"  set ELA_API_INSECURE true\n");
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

	fprintf(stderr, "Unsupported variable for set: %s\n", argv[1]);
	interactive_list_supported_variables(stderr);
	return 2;
}

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

#if defined(ELA_HAS_READLINE)
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

static void interactive_free_argv(char **argv, int argc)
{
	if (!argv)
		return;

	for (int i = 0; i < argc; i++)
		free(argv[i]);
	free(argv);
}

static int interactive_parse_line(const char *line, char ***argv_out, int *argc_out)
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
		if (!*p || *p == '\n')
			break;

		start = p;
		while (*p && (!isspace((unsigned char)*p) || quote)) {
			char ch = *p++;
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

static int interactive_loop(const char *prog)
{
	char *line;
	int last_rc = 0;
	int tty_fd = -1;
	struct termios saved_termios;
	bool have_saved_termios = false;

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
		size_t line_cap = 0;

		snprintf(prompt, sizeof(prompt), "%s> ", prog);
		interactive_restore_terminal(tty_fd, &saved_termios, have_saved_termios);
		fputs(prompt, stdout);
		fflush(stdout);
		line = NULL;
		if (getline(&line, &line_cap, stdin) < 0) {
			free(line);
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

	return last_rc;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--output-format <csv|json|txt>] [--quiet] [--insecure] [--output-tcp <IPv4:port>] [--output-http <http://host:port/path>] [--output-https <https://host:port/path>] <group> <subcommand> [options]\n"
		"\n"
		"Run without arguments to enter interactive mode.\n"
		"\n"
		"Global options:\n"
		"  --output-format <csv|json|txt>  Set output format for subcommands\n"
		"  --quiet                         Disable verbose mode for commands/subcommands\n"
		"  --insecure                      Disable TLS certificate/hostname verification for HTTPS\n"
		"  --output-tcp <IPv4:port>         Configure TCP remote output for commands/subcommands\n"
		"  --output-http <http://...>       Configure HTTP remote output for commands/subcommands\n"
		"  --output-https <https://...>     Configure HTTPS remote output for commands/subcommands\n"
		"\n"
		"Groups and subcommands:\n"
		"  uboot env          Scan for U-Boot environment candidates\n"
		"  uboot image        Scan or extract U-Boot images\n"
		"  uboot audit        Run U-Boot audit rules\n"
		"  linux dmesg        Dump kernel ring buffer output\n"
		"  linux execute-command Execute a shell command and capture/upload its output\n"
		"  linux list-files   List files under a directory (use --recursive to recurse)\n"
		"  linux list-symlinks List symlinks under a directory (use --recursive to recurse)\n"
		"  linux remote-copy  Copy a local file to remote destination\n"
		"  efi orom           EFI option ROM utilities (pull/list)\n"
		"  bios orom          BIOS option ROM utilities (pull/list)\n"
		"\n"
		"Interactive-only helper:\n"
		"  set ELA_API_URL <http(s)://...>\n"
		"  set ELA_API_INSECURE <true|false>\n"
		"\n"
		"Examples:\n"
		"  %s uboot env\n"
		"  %s uboot image --dev /dev/mtdblock4 --step 0x1000\n"
		"  %s uboot audit --dev /dev/mtdblock4 --offset 0x0 --size 0x10000\n"
		"  %s --output-http http://127.0.0.1:5000/dmesg linux dmesg\n"
		"  %s --output-format json --output-http http://127.0.0.1:5000 linux execute-command \"uname -a\"\n"
		"  %s --output-http http://127.0.0.1:5000 linux list-files /etc\n"
		"  %s --output-format json --output-http http://127.0.0.1:5000 linux list-symlinks /etc --recursive\n"
		"  %s --output-https https://127.0.0.1:5443 linux remote-copy /tmp/fw.bin\n"
		"  %s --quiet --output-http http://127.0.0.1:5000/orom efi orom pull\n"
		"  %s --quiet --output-tcp 127.0.0.1:5001 bios orom list\n",
		prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

static int embedded_linux_audit_dispatch(int argc, char **argv)
{
	const char *output_format = "txt";
	const char *output_tcp = NULL;
	const char *output_http = NULL;
	const char *output_https = NULL;
	const char *ela_api_url = NULL;
	const char *ela_api_insecure = NULL;
	bool verbose = true;
	bool insecure = false;
	bool output_format_explicit = false;
	int cmd_idx = 1;

	while (cmd_idx < argc) {
		if (!strcmp(argv[cmd_idx], "--output-format")) {
			cmd_idx++;
			if (cmd_idx >= argc) {
				fprintf(stderr, "Missing value for --output-format\n\n");
				usage(argv[0]);
				return 2;
			}
			output_format = argv[cmd_idx++];
			output_format_explicit = true;
			continue;
		}

		if (!strncmp(argv[cmd_idx], "--output-format=", 16)) {
			output_format = argv[cmd_idx] + 16;
			output_format_explicit = true;
			cmd_idx++;
			continue;
		}

		if (!strcmp(argv[cmd_idx], "--quiet")) {
			verbose = false;
			cmd_idx++;
			continue;
		}

		if (!strcmp(argv[cmd_idx], "--insecure")) {
			insecure = true;
			cmd_idx++;
			continue;
		}

		if (!strcmp(argv[cmd_idx], "--output-tcp")) {
			cmd_idx++;
			if (cmd_idx >= argc) {
				fprintf(stderr, "Missing value for --output-tcp\n\n");
				usage(argv[0]);
				return 2;
			}
			output_tcp = argv[cmd_idx++];
			continue;
		}

		if (!strncmp(argv[cmd_idx], "--output-tcp=", 13)) {
			output_tcp = argv[cmd_idx] + 13;
			cmd_idx++;
			continue;
		}

		if (!strcmp(argv[cmd_idx], "--output-http")) {
			cmd_idx++;
			if (cmd_idx >= argc) {
				fprintf(stderr, "Missing value for --output-http\n\n");
				usage(argv[0]);
				return 2;
			}
			output_http = argv[cmd_idx++];
			continue;
		}

		if (!strncmp(argv[cmd_idx], "--output-http=", 14)) {
			output_http = argv[cmd_idx] + 14;
			cmd_idx++;
			continue;
		}

		if (!strcmp(argv[cmd_idx], "--output-https")) {
			cmd_idx++;
			if (cmd_idx >= argc) {
				fprintf(stderr, "Missing value for --output-https\n\n");
				usage(argv[0]);
				return 2;
			}
			output_https = argv[cmd_idx++];
			continue;
		}

		if (!strncmp(argv[cmd_idx], "--output-https=", 15)) {
			output_https = argv[cmd_idx] + 15;
			cmd_idx++;
			continue;
		}

		if (!strcmp(argv[cmd_idx], "-h") || !strcmp(argv[cmd_idx], "--help") || !strcmp(argv[cmd_idx], "help")) {
			usage(argv[0]);
			return 0;
		}

		break;
	}

	if (strcmp(output_format, "txt") && strcmp(output_format, "csv") && strcmp(output_format, "json")) {
		fprintf(stderr, "Invalid --output-format: %s (expected: csv, json, txt)\n\n", output_format);
		usage(argv[0]);
		return 2;
	}

	ela_api_url = getenv("ELA_API_URL");
	if ((!output_http || !*output_http) && (!output_https || !*output_https) &&
	    ela_api_url && *ela_api_url) {
		if (!strncmp(ela_api_url, "http://", 7)) {
			output_http = ela_api_url;
		} else if (!strncmp(ela_api_url, "https://", 8)) {
			output_https = ela_api_url;
		} else {
			fprintf(stderr,
				"Invalid ELA_API_URL (expected http://host:port/... or https://host:port/...): %s\n\n",
				ela_api_url);
			usage(argv[0]);
			return 2;
		}
	}

	ela_api_insecure = getenv("ELA_API_INSECURE");
	if (!insecure && ela_api_insecure && !strcmp(ela_api_insecure, "true"))
		insecure = true;

	if (output_http && strncmp(output_http, "http://", 7)) {
		fprintf(stderr, "Invalid --output-http URI (expected http://host:port/...): %s\n\n", output_http);
		usage(argv[0]);
		return 2;
	}

	if (output_https && strncmp(output_https, "https://", 8)) {
		fprintf(stderr, "Invalid --output-https URI (expected https://host:port/...): %s\n\n", output_https);
		usage(argv[0]);
		return 2;
	}

	if (output_http && output_https) {
		fprintf(stderr, "Use only one of --output-http or --output-https\n\n");
		usage(argv[0]);
		return 2;
	}

	if (cmd_idx >= argc) {
		usage(argv[0]);
		return 2;
	}

	if (setenv("FW_AUDIT_OUTPUT_FORMAT", output_format, 1) != 0) {
		fprintf(stderr, "Failed to set FW_AUDIT_OUTPUT_FORMAT\n");
		return 2;
	}

	if (setenv("FW_AUDIT_VERBOSE", verbose ? "1" : "0", 1) != 0) {
		fprintf(stderr, "Failed to set FW_AUDIT_VERBOSE\n");
		return 2;
	}

	if (setenv("FW_AUDIT_OUTPUT_INSECURE", insecure ? "1" : "0", 1) != 0) {
		fprintf(stderr, "Failed to set FW_AUDIT_OUTPUT_INSECURE\n");
		return 2;
	}

	if (output_tcp && *output_tcp) {
		if (setenv("FW_AUDIT_OUTPUT_TCP", output_tcp, 1) != 0) {
			fprintf(stderr, "Failed to set FW_AUDIT_OUTPUT_TCP\n");
			return 2;
		}
	} else {
		unsetenv("FW_AUDIT_OUTPUT_TCP");
	}

	if (output_http && *output_http) {
		if (setenv("FW_AUDIT_OUTPUT_HTTP", output_http, 1) != 0) {
			fprintf(stderr, "Failed to set FW_AUDIT_OUTPUT_HTTP\n");
			return 2;
		}
	} else {
		unsetenv("FW_AUDIT_OUTPUT_HTTP");
	}

	if (output_https && *output_https) {
		if (setenv("FW_AUDIT_OUTPUT_HTTPS", output_https, 1) != 0) {
			fprintf(stderr, "Failed to set FW_AUDIT_OUTPUT_HTTPS\n");
			return 2;
		}
	} else {
		unsetenv("FW_AUDIT_OUTPUT_HTTPS");
	}

	if (!strcmp(argv[cmd_idx], "-h") || !strcmp(argv[cmd_idx], "--help") || !strcmp(argv[cmd_idx], "help")) {
		usage(argv[0]);
		return 0;
	}

	if (!strcmp(argv[cmd_idx], "uboot")) {
		int sub_idx = cmd_idx + 1;

		if (sub_idx >= argc || !strcmp(argv[sub_idx], "-h") ||
		    !strcmp(argv[sub_idx], "--help") || !strcmp(argv[sub_idx], "help")) {
			usage(argv[0]);
			return 0;
		}

		if (!strcmp(argv[sub_idx], "env"))
			return uboot_env_scan_main(argc - sub_idx, argv + sub_idx);

		if (!strcmp(argv[sub_idx], "image"))
			return uboot_image_scan_main(argc - sub_idx, argv + sub_idx);

		if (!strcmp(argv[sub_idx], "audit"))
			return embedded_linux_audit_scan_main(argc - sub_idx, argv + sub_idx);

		fprintf(stderr, "Unknown uboot subcommand: %s\n\n", argv[sub_idx]);
		usage(argv[0]);
		return 2;
	}

	if (!strcmp(argv[cmd_idx], "linux")) {
		int sub_idx = cmd_idx + 1;

		if (sub_idx >= argc || !strcmp(argv[sub_idx], "-h") ||
		    !strcmp(argv[sub_idx], "--help") || !strcmp(argv[sub_idx], "help")) {
			usage(argv[0]);
			return 0;
		}

		if (!strcmp(argv[sub_idx], "dmesg")) {
			if (output_format_explicit)
				fprintf(stderr,
					"Warning: --output-format has no effect for dmesg; remote output is always text/plain\n");
			return linux_dmesg_scan_main(argc - sub_idx, argv + sub_idx);
		}

		if (!strcmp(argv[sub_idx], "execute-command"))
			return linux_execute_command_scan_main(argc - sub_idx, argv + sub_idx);

		if (!strcmp(argv[sub_idx], "remote-copy")) {
			if (output_format_explicit)
				fprintf(stderr,
					"Warning: --output-format has no effect for remote-copy; file transfer is raw bytes\n");
			return linux_remote_copy_scan_main(argc - sub_idx, argv + sub_idx);
		}

		if (!strcmp(argv[sub_idx], "list-files")) {
			if (output_format_explicit)
				fprintf(stderr,
					"Warning: --output-format has no effect for list-files; output is always text/plain\n");
			return linux_list_files_scan_main(argc - sub_idx, argv + sub_idx);
		}

		if (!strcmp(argv[sub_idx], "list-symlinks"))
			return linux_list_symlinks_scan_main(argc - sub_idx, argv + sub_idx);

		fprintf(stderr, "Unknown linux subcommand: %s\n\n", argv[sub_idx]);
		usage(argv[0]);
		return 2;
	}

	if (!strcmp(argv[cmd_idx], "efi")) {
		int sub_idx = cmd_idx + 1;

		if (sub_idx >= argc || !strcmp(argv[sub_idx], "-h") ||
		    !strcmp(argv[sub_idx], "--help") || !strcmp(argv[sub_idx], "help")) {
			usage(argv[0]);
			return 0;
		}

		if (!strcmp(argv[sub_idx], "orom"))
			return efi_orom_main(argc - sub_idx, argv + sub_idx);

		fprintf(stderr, "Unknown efi subcommand: %s\n\n", argv[sub_idx]);
		usage(argv[0]);
		return 2;
	}

	if (!strcmp(argv[cmd_idx], "bios")) {
		int sub_idx = cmd_idx + 1;

		if (sub_idx >= argc || !strcmp(argv[sub_idx], "-h") ||
		    !strcmp(argv[sub_idx], "--help") || !strcmp(argv[sub_idx], "help")) {
			usage(argv[0]);
			return 0;
		}

		if (!strcmp(argv[sub_idx], "orom"))
			return bios_orom_main(argc - sub_idx, argv + sub_idx);

		fprintf(stderr, "Unknown bios subcommand: %s\n\n", argv[sub_idx]);
		usage(argv[0]);
		return 2;
	}

	fprintf(stderr, "Unknown command group: %s\n\n", argv[cmd_idx]);
	usage(argv[0]);
	return 2;
}

int main(int argc, char **argv)
{
	char **interactive_argv;

	if (argc < 2)
		return interactive_loop(argv[0]);

	interactive_argv = argv;
	return embedded_linux_audit_dispatch(argc, interactive_argv);
}