// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include <errno.h>
#include <getopt.h>
#include <json.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <efivar/efivar.h>

struct output_buffer {
	char *data;
	size_t len;
	size_t cap;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--help]\n"
		"  Dump EFI variables using the top-level --output-format (txt, csv, json)\n"
		"  When global --output-http is configured, POST to /:mac/upload/efi-vars\n"
		"  When global --output-tcp is configured, stream formatted records over TCP\n",
		prog);
}

static int output_buffer_append_len(struct output_buffer *buf, const char *text, size_t text_len)
{
	size_t need;
	char *tmp;
	size_t new_cap;

	if (!buf || (!text && text_len != 0))
		return -1;

	need = buf->len + text_len + 1;
	if (need > buf->cap) {
		new_cap = buf->cap ? buf->cap : 1024;
		while (new_cap < need)
			new_cap *= 2;
		tmp = realloc(buf->data, new_cap);
		if (!tmp)
			return -1;
		buf->data = tmp;
		buf->cap = new_cap;
	}

	if (text_len > 0)
		memcpy(buf->data + buf->len, text, text_len);
	buf->len += text_len;
	buf->data[buf->len] = '\0';
	return 0;
}

static int output_buffer_append(struct output_buffer *buf, const char *text)
{
	if (!text)
		return -1;
	return output_buffer_append_len(buf, text, strlen(text));
}

static int csv_escape_append(struct output_buffer *buf, const char *text)
{
	const char *p = text ? text : "";

	if (output_buffer_append(buf, "\"") != 0)
		return -1;

	while (*p) {
		if (*p == '"') {
			if (output_buffer_append(buf, "\"\"") != 0)
				return -1;
		} else if (output_buffer_append_len(buf, p, 1) != 0) {
			return -1;
		}
		p++;
	}

	return output_buffer_append(buf, "\"");
}

static char *hex_encode(const uint8_t *data, size_t len)
{
	static const char hex[] = "0123456789abcdef";
	char *out;

	out = calloc((len * 2) + 1, 1);
	if (!out)
		return NULL;

	for (size_t i = 0; i < len; i++) {
		out[i * 2] = hex[(data[i] >> 4) & 0x0f];
		out[i * 2 + 1] = hex[data[i] & 0x0f];
	}

	return out;
}

static const char *efi_vars_content_type(const char *output_format)
{
	if (!strcmp(output_format, "csv"))
		return "text/csv; charset=utf-8";
	if (!strcmp(output_format, "json"))
		return "application/x-ndjson; charset=utf-8";
	return "text/plain; charset=utf-8";
}

static void report_dump_error(const char *output_uri, bool insecure, const char *message)
{
	char errbuf[256];

	if (!message || !*message)
		return;

	fputs(message, stderr);
	if (!output_uri || !*output_uri)
		return;

	if (ela_http_post_log_message(output_uri, message, insecure, false, errbuf, sizeof(errbuf)) < 0)
		fprintf(stderr, "Failed HTTP(S) POST log to %s: %s\n", output_uri, errbuf[0] ? errbuf : "unknown error");
}

static int emit_record(const char *output_format,
			 const char *guid_str,
			 const char *name,
			 uint32_t attributes,
			 size_t data_size,
			 const char *hex_data,
			 int output_sock,
			 bool capture,
			 struct output_buffer *capture_buf)
{
	struct output_buffer line = {0};
	char attr_buf[32];
	char size_buf[32];
	int ret = -1;

	snprintf(attr_buf, sizeof(attr_buf), "0x%08x", attributes);
	snprintf(size_buf, sizeof(size_buf), "%zu", data_size);

	if (!strcmp(output_format, "txt")) {
		if (output_buffer_append(&line, "guid=") != 0 ||
		    output_buffer_append(&line, guid_str) != 0 ||
		    output_buffer_append(&line, " name=") != 0 ||
		    output_buffer_append(&line, name) != 0 ||
		    output_buffer_append(&line, " attributes=") != 0 ||
		    output_buffer_append(&line, attr_buf) != 0 ||
		    output_buffer_append(&line, " size=") != 0 ||
		    output_buffer_append(&line, size_buf) != 0 ||
		    output_buffer_append(&line, " data_hex=") != 0 ||
		    output_buffer_append(&line, hex_data) != 0 ||
		    output_buffer_append(&line, "\n") != 0)
			goto out;
	} else if (!strcmp(output_format, "csv")) {
		if (csv_escape_append(&line, guid_str) != 0 ||
		    output_buffer_append(&line, ",") != 0 ||
		    csv_escape_append(&line, name) != 0 ||
		    output_buffer_append(&line, ",") != 0 ||
		    csv_escape_append(&line, attr_buf) != 0 ||
		    output_buffer_append(&line, ",") != 0 ||
		    csv_escape_append(&line, size_buf) != 0 ||
		    output_buffer_append(&line, ",") != 0 ||
		    csv_escape_append(&line, hex_data) != 0 ||
		    output_buffer_append(&line, "\n") != 0)
			goto out;
	} else if (!strcmp(output_format, "json")) {
		json_object *obj = json_object_new_object();
		const char *js;

		if (!obj)
			goto out;
		json_object_object_add(obj, "record", json_object_new_string("efi_var"));
		json_object_object_add(obj, "guid", json_object_new_string(guid_str));
		json_object_object_add(obj, "name", json_object_new_string(name));
		json_object_object_add(obj, "attributes", json_object_new_uint64((uint64_t)attributes));
		json_object_object_add(obj, "size", json_object_new_uint64((uint64_t)data_size));
		json_object_object_add(obj, "data_hex", json_object_new_string(hex_data));
		js = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
		if (output_buffer_append(&line, js) != 0 || output_buffer_append(&line, "\n") != 0) {
			json_object_put(obj);
			goto out;
		}
		json_object_put(obj);
	} else {
		goto out;
	}

	if (output_sock >= 0 && ela_send_all(output_sock, (const uint8_t *)line.data, line.len) < 0)
		goto out;

	if (capture) {
		if (output_buffer_append_len(capture_buf, line.data, line.len) != 0)
			goto out;
	} else if (fwrite(line.data, 1, line.len, stdout) != line.len) {
		goto out;
	}

	ret = 0;
out:
	free(line.data);
	return ret;
}

int efi_dump_vars_main(int argc, char **argv)
{
	const char *output_format = getenv("ELA_OUTPUT_FORMAT");
	const char *output_tcp = getenv("ELA_OUTPUT_TCP");
	const char *output_http = getenv("ELA_OUTPUT_HTTP");
	const char *output_https = getenv("ELA_OUTPUT_HTTPS");
	const char *parsed_output_http = NULL;
	const char *parsed_output_https = NULL;
	const char *output_uri = NULL;
	bool insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	struct output_buffer capture_buf = {0};
	char *upload_uri = NULL;
	char errbuf[256];
	int output_sock = -1;
	int opt;
	int ret = 0;
	bool saw_any = false;
	efi_guid_t *guid = NULL;
	char *name = NULL;
	int rc;

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

	if (optind < argc) {
		fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
		usage(argv[0]);
		return 2;
	}

	if (strcmp(output_format, "txt") && strcmp(output_format, "csv") && strcmp(output_format, "json")) {
		fprintf(stderr, "Invalid output format for efi dump-vars: %s\n", output_format);
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
			return 1;
		}
	}

	{
		const char *isa = ela_detect_isa();

		if (!ela_isa_supported_for_efi_bios(isa)) {
			fprintf(stderr,
				"Unsupported ISA for efi group: %s (supported: x86, x86_64, aarch64-be, aarch64-le)\n",
				isa ? isa : "unknown");
			return 1;
		}
	}

	if (efi_variables_supported() < 0) {
		report_dump_error(output_uri, insecure, "EFI variables are not supported on this system\n");
		ret = 1;
		goto out;
	}

	while ((rc = efi_get_next_variable_name(&guid, &name)) > 0) {
		char *guid_str = NULL;
		uint8_t *data = NULL;
		size_t data_size = 0;
		uint32_t attributes = 0;
		char *hex_data = NULL;

		saw_any = true;
		if (efi_guid_to_str(guid, &guid_str) < 0 || !guid_str) {
			report_dump_error(output_uri, insecure, "Failed to stringify EFI variable GUID\n");
			ret = 1;
			free(guid_str);
			break;
		}

		if (efi_get_variable(*guid, name, &data, &data_size, &attributes) < 0) {
			char msg[512];
			snprintf(msg, sizeof(msg), "Failed to read EFI variable %s-%s: %s\n", guid_str, name, strerror(errno));
			report_dump_error(output_uri, insecure, msg);
			free(guid_str);
			free(data);
			ret = 1;
			break;
		}

		hex_data = hex_encode(data, data_size);
		if (!hex_data) {
			report_dump_error(output_uri, insecure, "Out of memory while formatting EFI variable data\n");
			free(guid_str);
			free(data);
			ret = 1;
			break;
		}

		if (emit_record(output_format, guid_str, name, attributes, data_size, hex_data,
				output_sock, output_uri != NULL, &capture_buf) != 0) {
			report_dump_error(output_uri, insecure, "Failed to emit EFI variable record\n");
			free(hex_data);
			free(guid_str);
			free(data);
			ret = 1;
			break;
		}

		free(hex_data);
		free(guid_str);
		free(data);
	}

	if (rc < 0) {
		report_dump_error(output_uri, insecure, "Failed to enumerate EFI variables\n");
		ret = 1;
		goto out;
	}

	if (!saw_any) {
		report_dump_error(output_uri, insecure, "No EFI variables found\n");
		ret = 1;
		goto out;
	}

	if (output_uri) {
		upload_uri = ela_http_build_upload_uri(output_uri, "efi-vars", NULL);
		if (!upload_uri) {
			fprintf(stderr, "Unable to build upload URI for EFI variables\n");
			ret = 1;
			goto out;
		}

		if (ela_http_post(upload_uri,
				   (const uint8_t *)(capture_buf.data ? capture_buf.data : ""),
				   capture_buf.len,
				   efi_vars_content_type(output_format),
				   insecure,
				   false,
				   errbuf,
				   sizeof(errbuf)) < 0) {
			fprintf(stderr, "Failed HTTP(S) POST to %s: %s\n", upload_uri, errbuf[0] ? errbuf : "unknown error");
			ret = 1;
			goto out;
		}
	}

out:
	if (output_sock >= 0)
		close(output_sock);
	free(upload_uri);
	free(capture_buf.data);
	return ret;
}