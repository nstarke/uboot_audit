// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "lifecycle.h"
#include "embedded_linux_audit_cmd.h"
#include "net/http_client.h"
#include "util/str_util.h"

#include <csv.h>
#include <json.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int build_lifecycle_payload(const char *output_format,
				   const char *command,
				   const char *phase,
				   int rc,
				   char **payload_out)
{
	char *buf = NULL;
	size_t len = 0;
	size_t cap = 0;
	char rc_buf[32];
	char ts_buf[64];
	const char *fmt = output_format && *output_format ? output_format : "txt";
	time_t now;
	struct tm tm_now;

	if (!command || !phase || !payload_out)
		return -1;

	snprintf(rc_buf, sizeof(rc_buf), "%d", rc);
	now = time(NULL);
	if (gmtime_r(&now, &tm_now) == NULL)
		return -1;
	/* Use snprintf instead of strftime to avoid a crash in strftime on
	 * arm32-be under QEMU 8.x user-mode emulation. */
	snprintf(ts_buf, sizeof(ts_buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
		 (int)(tm_now.tm_year + 1900), (int)(tm_now.tm_mon + 1),
		 (int)tm_now.tm_mday, (int)tm_now.tm_hour,
		 (int)tm_now.tm_min, (int)tm_now.tm_sec);

	if (!strcmp(fmt, "json")) {
		json_object *obj;
		const char *js;
		size_t js_len;

		obj = json_object_new_object();
		if (!obj)
			goto fail;
		json_object_object_add(obj, "record",          json_object_new_string("log"));
		json_object_object_add(obj, "agent_timestamp", json_object_new_string(ts_buf));
		json_object_object_add(obj, "phase",           json_object_new_string(phase));
		json_object_object_add(obj, "command",         json_object_new_string(command));
		json_object_object_add(obj, "rc",              json_object_new_int(rc));
		js = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
		js_len = strlen(js);
		if (append_bytes(&buf, &len, &cap, js, js_len) != 0 ||
		    append_text(&buf, &len, &cap, "\n") != 0) {
			json_object_put(obj);
			goto fail;
		}
		json_object_put(obj);
	} else if (!strcmp(fmt, "csv")) {
		const char *vals[5];
		size_t i;

		vals[0] = "log";
		vals[1] = ts_buf;
		vals[2] = phase;
		vals[3] = command;
		vals[4] = rc_buf;
		for (i = 0; i < 5; i++) {
			const char *in = vals[i];
			size_t in_len = strlen(in);
			size_t field_sz = (in_len * 2U) + 3U;
			char *field = malloc(field_sz);
			size_t written;
			int err;

			if (!field)
				goto fail;
			written = csv_write(field, field_sz, in, in_len);
			err = append_bytes(&buf, &len, &cap, field, written);
			free(field);
			if (err != 0)
				goto fail;
			if (append_text(&buf, &len, &cap, i < 4 ? "," : "\n") != 0)
				goto fail;
		}
	} else {
		if (append_text(&buf, &len, &cap, "log agent_timestamp=") != 0 ||
		    append_text(&buf, &len, &cap, ts_buf) != 0 ||
		    append_text(&buf, &len, &cap, " phase=") != 0 ||
		    append_text(&buf, &len, &cap, phase) != 0 ||
		    append_text(&buf, &len, &cap, " command=") != 0 ||
		    append_text(&buf, &len, &cap, command) != 0 ||
		    append_text(&buf, &len, &cap, " rc=") != 0 ||
		    append_text(&buf, &len, &cap, rc_buf) != 0 ||
		    append_text(&buf, &len, &cap, "\n") != 0)
			goto fail;
	}

	*payload_out = buf;
	return 0;

fail:
	free(buf);
	return -1;
}

static const char *lifecycle_content_type(const char *output_format)
{
	if (output_format && !strcmp(output_format, "json"))
		return "application/json; charset=utf-8";
	if (output_format && !strcmp(output_format, "csv"))
		return "text/csv; charset=utf-8";
	return "text/plain; charset=utf-8";
}

static int write_text_lifecycle_event(const char *command,
				      const char *phase,
				      int rc,
				      char *payload_buf,
				      size_t payload_buf_size,
				      size_t *payload_len_out)
{
	char ts_buf[64];
	char rc_buf[32];
	time_t now;
	struct tm tm_now;
	int payload_len;

	if (!command || !phase || !payload_buf || !payload_len_out || payload_buf_size == 0)
		return -1;

	now = time(NULL);
	if (gmtime_r(&now, &tm_now) == NULL)
		return -1;

	/* Avoid strftime/fputs on arm32-be under QEMU user-mode emulation. */
	snprintf(ts_buf, sizeof(ts_buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
		 (int)(tm_now.tm_year + 1900), (int)(tm_now.tm_mon + 1),
		 (int)tm_now.tm_mday, (int)tm_now.tm_hour,
		 (int)tm_now.tm_min, (int)tm_now.tm_sec);
	snprintf(rc_buf, sizeof(rc_buf), "%d", rc);

	payload_len = snprintf(payload_buf,
			       payload_buf_size,
			       "log agent_timestamp=%s phase=%s command=%s rc=%s\n",
			       ts_buf,
			       phase,
			       command,
			       rc_buf);
	if (payload_len < 0 || (size_t)payload_len >= payload_buf_size)
		return -1;

	*payload_len_out = (size_t)payload_len;
	(void)write(STDERR_FILENO, payload_buf, *payload_len_out);
	return 0;
}

bool ela_lifecycle_logging_enabled(void)
{
	const char *ela_debug = getenv("ELA_DEBUG");

	return ela_debug && !strcmp(ela_debug, "1");
}

int ela_emit_lifecycle_event(const char *output_format,
				  const char *output_tcp,
				  const char *output_http,
				  const char *output_https,
				  bool insecure,
				  const char *command,
				  const char *phase,
				  int rc)
{
	char *payload = NULL;
	char text_payload[4096];
	const char *fmt = output_format && *output_format ? output_format : "txt";
	const uint8_t *payload_bytes = NULL;
	size_t payload_len = 0;
	const char *output_uri = output_http && *output_http ? output_http : output_https;
	char errbuf[256];

	if (!ela_lifecycle_logging_enabled())
		return 0;

	if (!strcmp(fmt, "txt")) {
		if (write_text_lifecycle_event(command,
					       phase,
					       rc,
					       text_payload,
					       sizeof(text_payload),
					       &payload_len) != 0)
			return -1;
		payload_bytes = (const uint8_t *)text_payload;
	} else {
		if (build_lifecycle_payload(output_format, command, phase, rc, &payload) != 0)
			return -1;
		payload_len = strlen(payload);
		payload_bytes = (const uint8_t *)payload;
	}

	if (output_tcp && *output_tcp) {
		int sock = ela_connect_tcp_ipv4(output_tcp);
		if (sock >= 0) {
			(void)ela_send_all(sock, payload_bytes, payload_len);
			close(sock);
		}
	}

	if (output_uri && *output_uri) {
		char *upload_uri = ela_http_build_upload_uri(output_uri, "log", NULL);
		if (!upload_uri) {
			fprintf(stderr, "Failed to build HTTP(S) log upload URI for %s\n", output_uri);
		} else if (ela_http_post(upload_uri,
					      payload_bytes,
					      payload_len,
					      lifecycle_content_type(output_format),
					      insecure,
					      false,
					      errbuf,
					      sizeof(errbuf)) < 0) {
			fprintf(stderr, "Failed HTTP(S) POST log to %s: %s\n",
				upload_uri,
				errbuf[0] ? errbuf : "unknown error");
		}
		free(upload_uri);
	}

	free(payload);
	return 0;
}
