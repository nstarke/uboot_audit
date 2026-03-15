// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "net/api_key.h"
#include "net/ws_client.h"
#include "shell/interactive.h"
#include "shell/script_exec.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--output-format <csv|json|txt>] [--quiet] [--insecure] [--output-tcp <IPv4:port>] [--output-http <http(s)://host:port/path>] [--script <path|http(s)://...>] <group> <subcommand> [options]\n"
		"       %s --remote <host:port>\n"
		"\n"
		"Run without arguments to enter interactive mode.\n"
		"\n"
		"Global options:\n"
		"  --output-format <csv|json|txt>  Set output format for subcommands\n"
		"  --quiet                         Disable verbose mode for commands/subcommands\n"
		"  --insecure                      Disable TLS certificate/hostname verification for HTTPS\n"
	"  --api-key <key>                 Bearer token for Authorization header (also: ELA_API_KEY env,\n"
	"                                  /tmp/ela.key file; multiple sources tried in order)\n"
		"  --output-tcp <IPv4:port>         Configure TCP remote output for commands/subcommands\n"
		"  --output-http <http(s)://...>    Configure HTTP or HTTPS remote output for commands/subcommands\n"
		"  --script <path|http(s)://...>    Execute commands from a local or remote script file\n"
		"  --remote <host:port>             Connect out to host:port, daemonize, and serve an interactive\n"
		"                                   session over the TCP connection (reverse shell)\n"
		"\n"
		"Groups and subcommands:\n"
		"  uboot env          Scan for U-Boot environment candidates\n"
		"  uboot image        Scan or extract U-Boot images\n"
		"  uboot audit        Run U-Boot audit rules\n"
		"  linux dmesg        Dump kernel ring buffer output\n"
		"  linux download-file Download a file from HTTP(S) to a local path\n"
		"  linux execute-command Execute a shell command and capture/upload its output\n"
		"  linux grep         Search files in a directory for a string\n"
		"  linux list-files   List files under a directory (use --recursive to recurse)\n"
		"  linux list-symlinks List symlinks under a directory (use --recursive to recurse)\n"
		"  linux remote-copy  Copy a local file to remote destination\n"
		"  linux ssh          SSH client/copy/tunnel operations\n"
		"  tpm2               Run built-in TPM2 commands through the TPM2-TSS library\n"
		"  efi orom           EFI option ROM utilities (pull/list)\n"
		"  efi dump-vars      Dump EFI variables with txt/csv/json formatting\n"
		"  bios orom          BIOS option ROM utilities (pull/list)\n"
		"  transfer <host:port>  Transfer (send) this binary to a receiver at host:port\n"
		"\n"
		"Interactive-only helper:\n"
		"  set ELA_API_URL <http(s)://...>\n"
		"  set ELA_API_INSECURE <true|false>\n"
		"  set ELA_QUIET <true|false>\n"
		"  set ELA_OUTPUT_FORMAT <txt|csv|json>\n"
		"  set ELA_OUTPUT_TCP <IPv4:port>\n"
		"  set ELA_SCRIPT <path|http(s)://...>\n"
		"\n"
		"Examples:\n"
		"  %s uboot env\n"
		"  %s uboot image --dev /dev/mtdblock4 --step 0x1000\n"
		"  %s uboot audit --dev /dev/mtdblock4 --offset 0x0 --size 0x10000\n"
		"  %s --output-http http://127.0.0.1:5000/dmesg linux dmesg\n"
		"  %s linux download-file https://example.com/fw.bin /tmp/fw.bin\n"
		"  %s --output-format json --output-http http://127.0.0.1:5000 linux execute-command \"uname -a\"\n"
		"  %s --output-http http://127.0.0.1:5000 linux grep --search root --path /etc --recursive\n"
		"  %s --output-http http://127.0.0.1:5000 linux list-files /etc\n"
		"  %s --output-format json --output-http http://127.0.0.1:5000 linux list-symlinks /etc --recursive\n"
		"  %s --output-http https://127.0.0.1:5443 linux remote-copy /tmp/fw.bin\n"
		"  %s linux ssh client 192.168.1.10 --port 22\n"
		"  %s tpm2 getcap properties-fixed\n"
		"  %s --quiet --output-http http://127.0.0.1:5000/orom efi orom pull\n"
		"  %s --output-format json --output-http http://127.0.0.1:5000 efi dump-vars\n"
		"  %s --quiet --output-tcp 127.0.0.1:5001 bios orom list\n"
		"  %s --output-format json --script ./commands.txt\n"
		"  %s --remote 192.168.1.10:4444\n"
		"  %s transfer 192.168.1.10:4445\n",
		prog, prog, prog, prog,
		prog, prog, prog, prog,
		prog, prog, prog, prog,
		prog, prog, prog, prog,
		prog, prog, prog, prog);
}

/* Declared non-static so interactive.c and script_exec.c can call it. */
void ela_usage(const char *prog)
{
	usage(prog);
}

static bool command_should_emit_lifecycle_events(int argc, char **argv, int cmd_idx, const char *script_path)
{
	const char *group;
	const char *subcommand;

	if (script_path && *script_path)
		return true;

	if (!argv || cmd_idx < 0 || cmd_idx >= argc)
		return true;

	group = argv[cmd_idx];
	subcommand = (cmd_idx + 1 < argc) ? argv[cmd_idx + 1] : NULL;

	if (group && subcommand && !strcmp(group, "linux") &&
	    (!strcmp(subcommand, "download-file") ||
	     !strcmp(subcommand, "list-files") ||
	     !strcmp(subcommand, "list-symlinks") ||
	     !strcmp(subcommand, "remote-copy")))
		return false;

	return true;
}

static int summary_append_text(char **buf, size_t *len, size_t *cap, const char *text)
{
	char *tmp;
	size_t text_len;
	size_t need;
	size_t new_cap;

	if (!buf || !len || !cap || !text)
		return -1;

	text_len = strlen(text);
	need = *len + text_len + 1;
	if (need > *cap) {
		new_cap = *cap ? *cap : 128;
		while (new_cap < need)
			new_cap *= 2;
		tmp = realloc(*buf, new_cap);
		if (!tmp)
			return -1;
		*buf = tmp;
		*cap = new_cap;
	}

	memcpy(*buf + *len, text, text_len);
	*len += text_len;
	(*buf)[*len] = '\0';
	return 0;
}

static char *build_command_summary(int argc, char **argv, int start_idx)
{
	char *summary = NULL;
	size_t len = 0;
	size_t cap = 0;

	if (!argv || start_idx < 0 || start_idx >= argc)
		return strdup("interactive");

	for (int i = start_idx; i < argc; i++) {
		if (summary_append_text(&summary, &len, &cap, argv[i]) != 0)
			goto fail;
		if (i + 1 < argc && summary_append_text(&summary, &len, &cap, " ") != 0)
			goto fail;
	}

	return summary;

fail:
	free(summary);
	return NULL;
}

/* Declared non-static so shell/interactive.c and shell/script_exec.c can call it. */
int embedded_linux_audit_dispatch(int argc, char **argv)
{
	const char *output_format = "txt";
	const char *output_tcp = getenv("ELA_OUTPUT_TCP");
	const char *output_http = getenv("ELA_OUTPUT_HTTP");
	const char *output_https = getenv("ELA_OUTPUT_HTTPS");
	const char *ela_output_format;
	const char *ela_quiet;
	const char *ela_output_tcp;
	const char *ela_script;
	const char *parsed_output_http;
	const char *parsed_output_https;
	const char *script_path = NULL;
	const char *ela_api_url = NULL;
	const char *ela_api_insecure = NULL;
	const char *remote_target = NULL;
	const char *api_key = NULL;
	bool verbose = true;
	bool insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	bool output_format_explicit = false;
	int cmd_idx = 1;
	int ret;
	char *command_summary;
	bool emit_lifecycle_events;
	char errbuf[256];

	ela_output_format = getenv("ELA_OUTPUT_FORMAT");
	if (ela_output_format && *ela_output_format)
		output_format = ela_output_format;

	if (getenv("ELA_OUTPUT_FORMAT") && *getenv("ELA_OUTPUT_FORMAT"))
		output_format = getenv("ELA_OUTPUT_FORMAT");

	ela_quiet = getenv("ELA_QUIET");
	if (ela_quiet && (!strcmp(ela_quiet, "1") || !strcmp(ela_quiet, "true") ||
	    !strcmp(ela_quiet, "yes") || !strcmp(ela_quiet, "on")))
		verbose = false;

	ela_output_tcp = getenv("ELA_OUTPUT_TCP");
	if ((!output_tcp || !*output_tcp) && ela_output_tcp && *ela_output_tcp)
		output_tcp = ela_output_tcp;

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
			const char *new_output_http;
			const char *new_output_https;

			cmd_idx++;
			if (cmd_idx >= argc) {
				fprintf(stderr, "Missing value for --output-http\n\n");
				usage(argv[0]);
				return 2;
			}
			if (ela_parse_http_output_uri(argv[cmd_idx++],
						  &new_output_http,
						  &new_output_https,
						  errbuf,
						  sizeof(errbuf)) < 0) {
				fprintf(stderr, "%s\n\n", errbuf);
				usage(argv[0]);
				return 2;
			}
			parsed_output_http = new_output_http;
			parsed_output_https = new_output_https;
			output_http = new_output_http;
			output_https = new_output_https;
			continue;
		}

		if (!strncmp(argv[cmd_idx], "--output-http=", 14)) {
			const char *new_output_http;
			const char *new_output_https;

			if (ela_parse_http_output_uri(argv[cmd_idx] + 14,
						  &new_output_http,
						  &new_output_https,
						  errbuf,
						  sizeof(errbuf)) < 0) {
				fprintf(stderr, "%s\n\n", errbuf);
				usage(argv[0]);
				return 2;
			}
			parsed_output_http = new_output_http;
			parsed_output_https = new_output_https;
			output_http = new_output_http;
			output_https = new_output_https;
			cmd_idx++;
			continue;
		}

		if (!strcmp(argv[cmd_idx], "--script")) {
			cmd_idx++;
			if (cmd_idx >= argc) {
				fprintf(stderr, "Missing value for --script\n\n");
				usage(argv[0]);
				return 2;
			}
			script_path = argv[cmd_idx++];
			continue;
		}

		if (!strncmp(argv[cmd_idx], "--script=", 9)) {
			script_path = argv[cmd_idx] + 9;
			cmd_idx++;
			continue;
		}

		if (!strcmp(argv[cmd_idx], "--remote")) {
			cmd_idx++;
			if (cmd_idx >= argc) {
				fprintf(stderr, "Missing value for --remote\n\n");
				usage(argv[0]);
				return 2;
			}
			remote_target = argv[cmd_idx++];
			continue;
		}

		if (!strncmp(argv[cmd_idx], "--remote=", 9)) {
			remote_target = argv[cmd_idx] + 9;
			cmd_idx++;
			continue;
		}

		if (!strcmp(argv[cmd_idx], "--api-key")) {
			cmd_idx++;
			if (cmd_idx >= argc) {
				fprintf(stderr, "Missing value for --api-key\n\n");
				usage(argv[0]);
				return 2;
			}
			api_key = argv[cmd_idx++];
			continue;
		}

		if (!strncmp(argv[cmd_idx], "--api-key=", 10)) {
			api_key = argv[cmd_idx] + 10;
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

	ela_api_key_init(api_key);

	ela_api_url = getenv("ELA_API_URL");
	if ((!output_http || !*output_http) && (!output_https || !*output_https) &&
	    ela_api_url && *ela_api_url) {
		if (ela_parse_http_output_uri(ela_api_url,
						  &parsed_output_http,
						  &parsed_output_https,
						  errbuf,
						  sizeof(errbuf)) < 0) {
			fprintf(stderr,
				"%s\n\n",
				errbuf);
			usage(argv[0]);
			return 2;
		}
		output_http = parsed_output_http;
		output_https = parsed_output_https;
	}

	ela_api_insecure = getenv("ELA_API_INSECURE");
	if (!insecure && ela_api_insecure && !strcmp(ela_api_insecure, "true"))
		insecure = true;

	ela_script = getenv("ELA_SCRIPT");
	if (!script_path && cmd_idx >= argc && ela_script && *ela_script)
		script_path = ela_script;

	if (output_http && strncmp(output_http, "http://", 7)) {
		fprintf(stderr, "Invalid internal HTTP output URI: %s\n\n", output_http);
		usage(argv[0]);
		return 2;
	}

	if (output_https && strncmp(output_https, "https://", 8)) {
		fprintf(stderr, "Invalid internal HTTPS output URI: %s\n\n", output_https);
		usage(argv[0]);
		return 2;
	}

	if (output_http && output_https) {
		fprintf(stderr, "Use only one of --output-http or --output-https\n\n");
		usage(argv[0]);
		return 2;
	}

	if (output_tcp && *output_tcp && !ela_is_valid_tcp_output_target(output_tcp)) {
		fprintf(stderr,
			"Invalid --output-tcp target (expected IPv4:port): %s\n\n",
			output_tcp);
		usage(argv[0]);
		return 2;
	}

	if (cmd_idx >= argc && !script_path && !remote_target) {
		usage(argv[0]);
		return 2;
	}

	if (setenv("ELA_OUTPUT_FORMAT", output_format, 1) != 0) {
		fprintf(stderr, "Failed to set ELA_OUTPUT_FORMAT\n");
		return 2;
	}

	if (setenv("ELA_VERBOSE", verbose ? "1" : "0", 1) != 0) {
		fprintf(stderr, "Failed to set ELA_VERBOSE\n");
		return 2;
	}

	if (setenv("ELA_OUTPUT_INSECURE", insecure ? "1" : "0", 1) != 0) {
		fprintf(stderr, "Failed to set ELA_OUTPUT_INSECURE\n");
		return 2;
	}

	if (output_tcp && *output_tcp) {
		if (setenv("ELA_OUTPUT_TCP", output_tcp, 1) != 0) {
			fprintf(stderr, "Failed to set ELA_OUTPUT_TCP\n");
			return 2;
		}
	} else {
		unsetenv("ELA_OUTPUT_TCP");
	}

	if (output_http && *output_http) {
		if (setenv("ELA_OUTPUT_HTTP", output_http, 1) != 0) {
			fprintf(stderr, "Failed to set ELA_OUTPUT_HTTP\n");
			return 2;
		}
	} else {
		unsetenv("ELA_OUTPUT_HTTP");
	}

	if (output_https && *output_https) {
		if (setenv("ELA_OUTPUT_HTTPS", output_https, 1) != 0) {
			fprintf(stderr, "Failed to set ELA_OUTPUT_HTTPS\n");
			return 2;
		}
	} else {
		unsetenv("ELA_OUTPUT_HTTPS");
	}

	if (cmd_idx < argc && (!strcmp(argv[cmd_idx], "-h") || !strcmp(argv[cmd_idx], "--help") || !strcmp(argv[cmd_idx], "help"))) {
		usage(argv[0]);
		return 0;
	}

	if (remote_target && *remote_target) {
		pid_t pid;

		if (cmd_idx < argc) {
			fprintf(stderr, "--remote cannot be combined with a command\n\n");
			usage(argv[0]);
			return 2;
		}

		if (ela_is_ws_url(remote_target)) {
			struct ela_ws_conn ws;

			if (ela_ws_connect(remote_target, insecure, &ws) != 0) {
				fprintf(stderr, "--remote: failed to connect to %s\n", remote_target);
				return 1;
			}

			pid = fork();
			if (pid < 0) {
				fprintf(stderr, "--remote: fork failed: %s\n", strerror(errno));
				ela_ws_close_parent_fd(&ws);
				return 1;
			}

			if (pid > 0) {
				ela_ws_close_parent_fd(&ws);
				fprintf(stdout, "Remote session started (pid=%ld)\n", (long)pid);
				return 0;
			}

			/* Daemon child */
			setsid();
			exit(ela_ws_run_interactive(&ws, argv[0]));
		}

		int sock = ela_connect_tcp_any(remote_target);
		if (sock < 0) {
			fprintf(stderr, "--remote: failed to connect to %s\n", remote_target);
			return 1;
		}

		pid = fork();
		if (pid < 0) {
			fprintf(stderr, "--remote: fork failed: %s\n", strerror(errno));
			close(sock);
			return 1;
		}

		if (pid > 0) {
			/* Parent: report and exit */
			close(sock);
			fprintf(stdout, "Remote session started (pid=%ld)\n", (long)pid);
			return 0;
		}

		/* Daemon child */
		setsid();
		dup2(sock, STDIN_FILENO);
		dup2(sock, STDOUT_FILENO);
		dup2(sock, STDERR_FILENO);
		close(sock);
		exit(interactive_loop(argv[0]));
	}

	if (script_path && (cmd_idx < argc)) {
		fprintf(stderr, "Use either --script or a direct command, not both\n\n");
		usage(argv[0]);
		return 2;
	}

	command_summary = script_path
		? build_command_summary(argc, argv, 1)
		: build_command_summary(argc, argv, cmd_idx);
	emit_lifecycle_events = command_should_emit_lifecycle_events(argc, argv, cmd_idx, script_path);
	if (!command_summary)
		command_summary = strdup("unknown");
	if (command_summary && emit_lifecycle_events)
		(void)ela_emit_lifecycle_event(output_format,
			output_tcp,
			output_http,
			output_https,
			insecure,
			command_summary,
			"start",
			0);

	if (script_path) {
		ret = execute_script_commands(argv[0], script_path);
		goto done;
	}

	if (!strcmp(argv[cmd_idx], "uboot")) {
		int sub_idx = cmd_idx + 1;

		if (sub_idx >= argc || !strcmp(argv[sub_idx], "-h") ||
		    !strcmp(argv[sub_idx], "--help") || !strcmp(argv[sub_idx], "help")) {
			usage(argv[0]);
			ret = 0;
			goto done;
		}

		if (!strcmp(argv[sub_idx], "env"))
			ret = uboot_env_scan_main(argc - sub_idx, argv + sub_idx);
		else if (!strcmp(argv[sub_idx], "image"))
			ret = uboot_image_scan_main(argc - sub_idx, argv + sub_idx);
		else if (!strcmp(argv[sub_idx], "audit"))
			ret = embedded_linux_audit_scan_main(argc - sub_idx, argv + sub_idx);
		else {
			fprintf(stderr, "Unknown uboot subcommand: %s\n\n", argv[sub_idx]);
			usage(argv[0]);
			ret = 2;
		}

		goto done;
	}

	if (!strcmp(argv[cmd_idx], "linux")) {
		int sub_idx = cmd_idx + 1;

		if (sub_idx >= argc || !strcmp(argv[sub_idx], "-h") ||
		    !strcmp(argv[sub_idx], "--help") || !strcmp(argv[sub_idx], "help")) {
			usage(argv[0]);
			ret = 0;
			goto done;
		}

		if (!strcmp(argv[sub_idx], "dmesg")) {
			bool dmesg_watch = (sub_idx + 1 < argc &&
					    !strcmp(argv[sub_idx + 1], "watch"));
			if (output_format_explicit && !dmesg_watch)
				fprintf(stderr,
					"Warning: --output-format has no effect for dmesg; remote output is always text/plain\n");
			ret = linux_dmesg_scan_main(argc - sub_idx, argv + sub_idx);
			goto done;
		}

		if (!strcmp(argv[sub_idx], "download-file")) {
			if (output_format_explicit)
				fprintf(stderr,
					"Warning: --output-format has no effect for download-file; downloaded data is written to a local file\n");
			ret = linux_download_file_scan_main(argc - sub_idx, argv + sub_idx);
		}
		else if (!strcmp(argv[sub_idx], "execute-command"))
			ret = linux_execute_command_scan_main(argc - sub_idx, argv + sub_idx);
		else if (!strcmp(argv[sub_idx], "grep")) {
			if (output_format_explicit)
				fprintf(stderr,
					"Warning: --output-format has no effect for grep; output is always text/plain\n");
			ret = linux_grep_scan_main(argc - sub_idx, argv + sub_idx);
		}
		else if (!strcmp(argv[sub_idx], "remote-copy")) {
			if (output_format_explicit)
				fprintf(stderr,
					"Warning: --output-format has no effect for remote-copy; file transfer is raw bytes\n");
			ret = linux_remote_copy_scan_main(argc - sub_idx, argv + sub_idx);
		} else if (!strcmp(argv[sub_idx], "ssh")) {
			if (output_format_explicit)
				fprintf(stderr,
					"Warning: --output-format has no effect for ssh; output is always plain text\n");
			ret = linux_ssh_scan_main(argc - sub_idx, argv + sub_idx);
		} else if (!strcmp(argv[sub_idx], "list-files")) {
			if (output_format_explicit)
				fprintf(stderr,
					"Warning: --output-format has no effect for list-files; output is always text/plain\n");
			ret = linux_list_files_scan_main(argc - sub_idx, argv + sub_idx);
		} else if (!strcmp(argv[sub_idx], "list-symlinks"))
			ret = linux_list_symlinks_scan_main(argc - sub_idx, argv + sub_idx);
		else {
			fprintf(stderr, "Unknown linux subcommand: %s\n\n", argv[sub_idx]);
			usage(argv[0]);
			ret = 2;
		}

		goto done;
	}

	if (!strcmp(argv[cmd_idx], "efi")) {
		int sub_idx = cmd_idx + 1;

		if (sub_idx >= argc || !strcmp(argv[sub_idx], "-h") ||
		    !strcmp(argv[sub_idx], "--help") || !strcmp(argv[sub_idx], "help")) {
			usage(argv[0]);
			ret = 0;
			goto done;
		}

		if (!strcmp(argv[sub_idx], "orom"))
			ret = efi_orom_main(argc - sub_idx, argv + sub_idx);
		else if (!strcmp(argv[sub_idx], "dump-vars"))
			ret = efi_dump_vars_main(argc - sub_idx, argv + sub_idx);
		else {
			fprintf(stderr, "Unknown efi subcommand: %s\n\n", argv[sub_idx]);
			usage(argv[0]);
			ret = 2;
		}

		goto done;
	}

	if (!strcmp(argv[cmd_idx], "bios")) {
		int sub_idx = cmd_idx + 1;

		if (sub_idx >= argc || !strcmp(argv[sub_idx], "-h") ||
		    !strcmp(argv[sub_idx], "--help") || !strcmp(argv[sub_idx], "help")) {
			usage(argv[0]);
			ret = 0;
			goto done;
		}

		if (!strcmp(argv[sub_idx], "orom"))
			ret = bios_orom_main(argc - sub_idx, argv + sub_idx);
		else {
			fprintf(stderr, "Unknown bios subcommand: %s\n\n", argv[sub_idx]);
			usage(argv[0]);
			ret = 2;
		}

		goto done;
	}

	if (!strcmp(argv[cmd_idx], "tpm2")) {
		ret = tpm2_scan_main(argc - cmd_idx, argv + cmd_idx);
		goto done;
	}

	if (!strcmp(argv[cmd_idx], "transfer")) {
		ret = transfer_main(argc - cmd_idx, argv + cmd_idx);
		goto done;
	}

	fprintf(stderr, "Unknown command group: %s\n\n", argv[cmd_idx]);
	usage(argv[0]);
	ret = 2;

done:
	if (command_summary && emit_lifecycle_events) {
		(void)ela_emit_lifecycle_event(output_format,
			output_tcp,
			output_http,
			output_https,
			insecure,
			command_summary,
			"complete",
			ret);
	}
	free(command_summary);
	return ret;
}

int main(int argc, char **argv)
{
	char **interactive_argv;

	if (argc < 2 && !(getenv("ELA_SCRIPT") && *getenv("ELA_SCRIPT")))
		return interactive_loop(argv[0]);

	interactive_argv = argv;
	return embedded_linux_audit_dispatch(argc, interactive_argv);
}
