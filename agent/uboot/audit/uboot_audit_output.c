// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "uboot/audit/uboot_audit_internal.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

const char *audit_http_content_type(enum uboot_output_format fmt)
{
	switch (fmt) {
	case FW_OUTPUT_JSON:
		return "application/x-ndjson; charset=utf-8";
	case FW_OUTPUT_CSV:
		return "text/csv; charset=utf-8";
	case FW_OUTPUT_TXT:
	default:
		return "text/plain; charset=utf-8";
	}
}

int send_artifact_network_record(enum uboot_output_format fmt,
				 const char *output_tcp_target,
				 const char *output_http_uri,
				 bool insecure,
				 bool verbose,
				 const char *artifact_name,
				 const char *artifact_value)
{
	char payload[2048];
	int plen;

	if ((!output_tcp_target || !*output_tcp_target) && (!output_http_uri || !*output_http_uri))
		return 0;

	if (!artifact_name || !artifact_value)
		return 0;

	if (fmt == FW_OUTPUT_JSON) {
		plen = snprintf(payload, sizeof(payload),
			"{\"record\":\"audit_artifact\",\"artifact\":\"%s\",\"value\":\"%s\"}\n",
			artifact_name, artifact_value);
	} else if (fmt == FW_OUTPUT_CSV) {
		plen = snprintf(payload, sizeof(payload), "audit_artifact,%s,%s\n", artifact_name, artifact_value);
	} else {
		plen = snprintf(payload, sizeof(payload), "audit artifact %s=%s\n", artifact_name, artifact_value);
	}

	if (plen <= 0 || (size_t)plen >= sizeof(payload))
		return -1;

	if (output_tcp_target && *output_tcp_target) {
		int sock = ela_connect_tcp_ipv4(output_tcp_target);
		if (sock < 0) {
			uboot_audit_err_printf("Failed to send artifact record over TCP to %s\n", output_tcp_target);
			return -1;
		}
		if (ela_send_all(sock, (const uint8_t *)payload, (size_t)plen) < 0) {
			uboot_audit_err_printf("Failed to send artifact record over TCP to %s\n", output_tcp_target);
			close(sock);
			return -1;
		}
		close(sock);
	}

	if (output_http_uri && *output_http_uri) {
		char errbuf[256];
		char *upload_uri = ela_http_build_upload_uri(output_http_uri, "log", NULL);
		if (!upload_uri)
			return -1;
		if (ela_http_post(upload_uri,
				   (const uint8_t *)payload,
				   (size_t)plen,
				   audit_http_content_type(fmt),
				   insecure,
				   verbose,
				   errbuf,
				   sizeof(errbuf)) < 0) {
			uboot_audit_err_printf("Failed to POST artifact record to %s: %s\n",
				   upload_uri,
				   errbuf[0] ? errbuf : "unknown error");
			free(upload_uri);
			return -1;
		}
		free(upload_uri);
	}

	return 0;
}

bool rule_name_selected(const char *filter, const struct embedded_linux_audit_rule *rule)
{
	if (!rule || !rule->name || !*rule->name)
		return false;

	if (!filter || !*filter)
		return true;

	return !strcmp(filter, rule->name);
}

void print_rule_record(enum uboot_output_format fmt,
		       const struct embedded_linux_audit_rule *rule,
		       int rc,
		       const char *message)
{
	const char *status = (rc == 0) ? "pass" : ((rc > 0) ? "fail" : "error");

	if (fmt == FW_OUTPUT_CSV) {
		uboot_audit_out_printf("audit_rule,%s,%s,%s\n",
		       rule->name ? rule->name : "",
		       status,
		       message ? message : "");
		return;
	}

	if (fmt == FW_OUTPUT_JSON) {
		uboot_audit_out_printf("{\"record\":\"audit_rule\",\"rule\":\"%s\",\"status\":\"%s\",\"message\":\"",
		       rule->name ? rule->name : "", status);
		uboot_audit_out_json_escaped(message);
		uboot_audit_out_printf("\"}\n");
		return;
	}

	uboot_audit_out_printf("[%s] %s: %s\n",
	       status,
	       rule->name ? rule->name : "(unnamed-rule)",
	       message ? message : "");
}

void print_rule_listing(enum uboot_output_format fmt, const struct embedded_linux_audit_rule *rule)
{
	if (fmt == FW_OUTPUT_CSV) {
		uboot_audit_out_printf("audit_rule_list,%s,%s\n",
		       rule->name ? rule->name : "",
		       (rule->description && *rule->description) ? rule->description : "");
		return;
	}

	if (fmt == FW_OUTPUT_JSON) {
		uboot_audit_out_printf("{\"record\":\"audit_rule_list\",\"rule\":\"%s\",\"description\":\"",
		       rule->name ? rule->name : "");
		uboot_audit_out_json_escaped(rule->description);
		uboot_audit_out_printf("\"}\n");
		return;
	}

	uboot_audit_out_printf("%s", rule->name ? rule->name : "");
	if (rule->description && *rule->description)
		uboot_audit_out_printf(" - %s", rule->description);
	uboot_audit_out_printf("\n");
}

void print_verbose_rule_begin(enum uboot_output_format fmt,
			      const struct embedded_linux_audit_rule *rule)
{
	const char *name = (rule && rule->name) ? rule->name : "";

	if (fmt == FW_OUTPUT_CSV) {
		uboot_audit_out_printf("audit_rule_progress,%s,begin,rule execution started\n", name);
		return;
	}

	if (fmt == FW_OUTPUT_JSON) {
		uboot_audit_out_printf("{\"record\":\"audit_rule_progress\",\"rule\":\"%s\",\"status\":\"begin\",\"message\":\"rule execution started\"}\n",
		       name);
		return;
	}

	uboot_audit_out_printf("audit rule begin: %s\n", name[0] ? name : "(unnamed-rule)");
}

void print_verbose_audit_end(enum uboot_output_format fmt, int rc)
{
	if (fmt == FW_OUTPUT_CSV) {
		uboot_audit_out_printf("audit_run,,end,audit completed with rc=%d\n", rc);
		return;
	}

	if (fmt == FW_OUTPUT_JSON) {
		uboot_audit_out_printf("{\"record\":\"audit_run\",\"status\":\"end\",\"message\":\"audit completed with rc=%d\"}\n",
		       rc);
		return;
	}

	uboot_audit_out_printf("audit run end: rc=%d\n", rc);
}
