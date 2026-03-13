// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "lifecycle.h"
#include "embedded_linux_audit_cmd.h"
#include "net/http_client.h"
#include "util/str_util.h"

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
	if (localtime_r(&now, &tm_now) == NULL)
		return -1;
	if (strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%dT%H:%M:%S%z", &tm_now) == 0)
		return -1;

	if (!strcmp(fmt, "json")) {
		if (append_text(&buf, &len, &cap, "{\"record\":\"log\",\"agent_timestamp\":\"") != 0 ||
		    append_json_escaped(&buf, &len, &cap, ts_buf) != 0 ||
		    append_text(&buf, &len, &cap, "\",\"phase\":\"") != 0 ||
		    append_json_escaped(&buf, &len, &cap, phase) != 0 ||
		    append_text(&buf, &len, &cap, "\",\"command\":\"") != 0 ||
		    append_json_escaped(&buf, &len, &cap, command) != 0 ||
		    append_text(&buf, &len, &cap, "\",\"rc\":") != 0 ||
		    append_text(&buf, &len, &cap, rc_buf) != 0 ||
		    append_text(&buf, &len, &cap, "}\n") != 0)
			goto fail;
	} else if (!strcmp(fmt, "csv")) {
		if (append_csv_field(&buf, &len, &cap, "log") != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, ts_buf) != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, phase) != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, command) != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, rc_buf) != 0 ||
		    append_text(&buf, &len, &cap, "\n") != 0)
			goto fail;
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

bool fw_audit_lifecycle_logging_enabled(void)
{
	const char *ela_debug = getenv("ELA_DEBUG");

	return ela_debug && !strcmp(ela_debug, "1");
}

int fw_audit_emit_lifecycle_event(const char *output_format,
				  const char *output_tcp,
				  const char *output_http,
				  const char *output_https,
				  bool insecure,
				  const char *command,
				  const char *phase,
				  int rc)
{
	char *payload = NULL;
	const char *output_uri = output_http && *output_http ? output_http : output_https;
	char errbuf[256];

	if (!fw_audit_lifecycle_logging_enabled())
		return 0;

	if (build_lifecycle_payload(output_format, command, phase, rc, &payload) != 0)
		return -1;

	fputs(payload, stderr);

	if (output_tcp && *output_tcp) {
		int sock = uboot_connect_tcp_ipv4(output_tcp);
		if (sock >= 0) {
			(void)uboot_send_all(sock, (const uint8_t *)payload, strlen(payload));
			close(sock);
		}
	}

	if (output_uri && *output_uri) {
		char *upload_uri = uboot_http_build_upload_uri(output_uri, "log", NULL);
		if (!upload_uri) {
			fprintf(stderr, "Failed to build HTTP(S) log upload URI for %s\n", output_uri);
		} else if (uboot_http_post(upload_uri,
					      (const uint8_t *)payload,
					      strlen(payload),
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
