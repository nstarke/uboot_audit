// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_AUDIT_INTERNAL_H
#define ELA_UBOOT_AUDIT_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>

enum uboot_output_format {
	FW_OUTPUT_TXT = 0,
	FW_OUTPUT_CSV,
	FW_OUTPUT_JSON,
};

/* Shared internal function declarations (defined in uboot_security_audit_cmd.c) */
void uboot_audit_out_printf(const char *fmt, ...);
void uboot_audit_err_printf(const char *fmt, ...);
void uboot_audit_out_json_escaped(const char *s);

/* Functions defined in uboot_audit_output.c */
const char *audit_http_content_type(enum uboot_output_format fmt);
int send_artifact_network_record(enum uboot_output_format fmt,
				 const char *output_tcp_target,
				 const char *output_http_uri,
				 bool insecure,
				 bool verbose,
				 const char *artifact_name,
				 const char *artifact_value);
bool rule_name_selected(const char *filter,
			const struct embedded_linux_audit_rule *rule);
void print_rule_record(enum uboot_output_format fmt,
		       const struct embedded_linux_audit_rule *rule,
		       int rc,
		       const char *message);
void print_rule_listing(enum uboot_output_format fmt,
			const struct embedded_linux_audit_rule *rule);
void print_verbose_rule_begin(enum uboot_output_format fmt,
			      const struct embedded_linux_audit_rule *rule);
void print_verbose_audit_end(enum uboot_output_format fmt, int rc);

#endif /* ELA_UBOOT_AUDIT_INTERNAL_H */
