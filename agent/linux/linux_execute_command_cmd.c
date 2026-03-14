// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include "util/output_buffer.h"

#include <errno.h>
#include <getopt.h>
#include <json.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <command-string>\n"
		"  Execute a shell command string and emit/upload its formatted output\n"
		"  Output honors --output-format as txt, csv, or json\n"
		"  When global --output-http is configured, POST output to /:mac/upload/cmd\n",
		prog);
}

static int format_command_output(const char *command,
				 const char *command_output,
				 const char *output_format,
				 struct output_buffer *formatted)
{
	if (!command || !command_output || !output_format || !formatted)
		return -1;

	if (!strcmp(output_format, "txt")) {
		if (output_buffer_append(formatted, command) != 0 ||
		    output_buffer_append(formatted, "\n") != 0 ||
		    output_buffer_append(formatted, command_output) != 0)
			return -1;
		return 0;
	}

	if (!strcmp(output_format, "csv")) {
		if (csv_write_to_buf(formatted, command) != 0 ||
		    output_buffer_append(formatted, ",") != 0 ||
		    csv_write_to_buf(formatted, command_output) != 0 ||
		    output_buffer_append(formatted, "\n") != 0)
			return -1;
		return 0;
	}

	if (!strcmp(output_format, "json")) {
		json_object *obj;
		const char *js;
		int err;

		obj = json_object_new_object();
		if (!obj)
			return -1;
		json_object_object_add(obj, "command", json_object_new_string(command));
		json_object_object_add(obj, "output",  json_object_new_string(command_output));
		js = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
		err = output_buffer_append(formatted, js);
		if (err == 0)
			err = output_buffer_append(formatted, "\n");
		json_object_put(obj);
		return err;
	}

	return -1;
}

int linux_execute_command_scan_main(int argc, char **argv)
{
	const char *output_format = getenv("ELA_OUTPUT_FORMAT");
	const char *output_tcp = getenv("ELA_OUTPUT_TCP");
	const char *output_http = getenv("ELA_OUTPUT_HTTP");
	const char *output_https = getenv("ELA_OUTPUT_HTTPS");
	const char *parsed_output_http = NULL;
	const char *parsed_output_https = NULL;
	const char *output_uri = NULL;
	const char *command = NULL;
	const char *content_type;
	bool insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	int output_sock = -1;
	struct output_buffer raw = {0};
	struct output_buffer formatted = {0};
	char *upload_uri = NULL;
	char errbuf[256];
	FILE *fp = NULL;
	int ret = 0;
	int opt;

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};

	if (!output_format || !*output_format)
		output_format = "txt";

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
		fprintf(stderr, "execute-command requires a command string\n");
		usage(argv[0]);
		return 2;
	}

	command = argv[optind++];
	if (optind < argc) {
		fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
		usage(argv[0]);
		return 2;
	}

	if (strcmp(output_format, "txt") && strcmp(output_format, "csv") && strcmp(output_format, "json")) {
		fprintf(stderr, "Invalid output format for execute-command: %s\n", output_format);
		return 2;
	}

	if (output_http && *output_http &&
	    ela_parse_http_output_uri(output_http,
					    &parsed_output_http,
					    &parsed_output_https,
					    errbuf,
					    sizeof(errbuf)) < 0) {
		fprintf(stderr, "%s\n", errbuf);
		return 2;
	}

	if (output_http && output_https) {
		fprintf(stderr, "Use only one of --output-http or --output-https\n");
		return 2;
	}

	if (parsed_output_http)
		output_uri = parsed_output_http;
	if (parsed_output_https)
		output_uri = parsed_output_https;
	if (output_https)
		output_uri = output_https;

	if (output_tcp && *output_tcp) {
		output_sock = ela_connect_tcp_ipv4(output_tcp);
		if (output_sock < 0) {
			fprintf(stderr, "Invalid/failed output target (expected IPv4:port): %s\n", output_tcp);
			return 2;
		}
	}

	fp = popen(command, "r");
	if (!fp) {
		fprintf(stderr, "Failed to execute command '%s': %s\n", command, strerror(errno));
		ret = 1;
		goto out;
	}

	for (;;) {
		char chunk[4096];
		size_t got = fread(chunk, 1, sizeof(chunk), fp);
		if (got > 0 && output_buffer_append_len(&raw, chunk, got) != 0) {
			fprintf(stderr, "Out of memory while capturing command output\n");
			ret = 1;
			goto out;
		}
		if (got < sizeof(chunk)) {
			if (ferror(fp)) {
				fprintf(stderr, "Failed while reading command output for '%s'\n", command);
				ret = 1;
				goto out;
			}
			break;
		}
	}

	if (format_command_output(command,
				  raw.data ? raw.data : "",
				  output_format,
				  &formatted) != 0) {
		fprintf(stderr, "Failed to format command output\n");
		ret = 1;
		goto out;
	}

	if (formatted.len && fwrite(formatted.data, 1, formatted.len, stdout) != formatted.len) {
		fprintf(stderr, "Failed to write formatted command output\n");
		ret = 1;
		goto out;
	}

	if (output_sock >= 0 && formatted.len && ela_send_all(output_sock, (const uint8_t *)formatted.data, formatted.len) < 0) {
		fprintf(stderr, "Failed sending bytes to %s\n", output_tcp);
		ret = 1;
		goto out;
	}

	if (output_uri) {
		upload_uri = ela_http_build_upload_uri(output_uri, "cmd", NULL);
		if (!upload_uri) {
			fprintf(stderr, "Unable to build upload URI for command output\n");
			ret = 1;
			goto out;
		}

		content_type = !strcmp(output_format, "csv") ? "text/csv; charset=utf-8" :
			(!strcmp(output_format, "json") ? "application/json; charset=utf-8" : "text/plain; charset=utf-8");

		if (ela_http_post(upload_uri,
				   (const uint8_t *)(formatted.data ? formatted.data : ""),
				   formatted.len,
				   content_type,
				   insecure,
				   false,
				   errbuf,
				   sizeof(errbuf)) < 0) {
			fprintf(stderr, "Failed HTTP(S) POST to %s: %s\n", upload_uri, errbuf[0] ? errbuf : "unknown error");
			ret = 1;
			goto out;
		}
	}

	if (fp) {
		int status = pclose(fp);
		fp = NULL;
		if (status == -1 || (WIFEXITED(status) && WEXITSTATUS(status) != 0) || WIFSIGNALED(status))
			ret = 1;
	}

out:
	if (fp)
		(void)pclose(fp);
	if (output_sock >= 0)
		close(output_sock);
	free(upload_uri);
	free(raw.data);
	free(formatted.data);
	return ret;
}