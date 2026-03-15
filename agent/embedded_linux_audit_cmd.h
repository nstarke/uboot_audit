// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UBOOT_SCAN_H
#define UBOOT_SCAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <glob.h>
#include <sys/types.h>

#define FW_SCAN_GLOB_MTDBLOCK  (1U << 0)
#define FW_SCAN_GLOB_MTDCHAR   (1U << 1)
#define FW_SCAN_GLOB_UBI       (1U << 2)
#define FW_SCAN_GLOB_UBIBLOCK  (1U << 3)
#define FW_SCAN_GLOB_MMCBLK    (1U << 4)
#define FW_SCAN_GLOB_SDBLK     (1U << 5)

#define ELA_ISA_X86          "x86"
#define ELA_ISA_X86_64       "x86_64"
#define ELA_ISA_AARCH64_BE   "aarch64-be"
#define ELA_ISA_AARCH64_LE   "aarch64-le"

int uboot_get_mtd_index(const char *dev, char *idx, size_t idx_sz);

uint64_t uboot_guess_size_from_sysfs(const char *dev);
uint64_t uboot_guess_erasesize_from_sysfs(const char *dev);
uint64_t uboot_guess_size_from_proc_mtd(const char *dev);
uint64_t uboot_guess_erasesize_from_proc_mtd(const char *dev);
uint64_t uboot_guess_size_from_ubi_sysfs(const char *dev);
uint64_t uboot_guess_step_from_ubi_sysfs(const char *dev);
uint64_t uboot_guess_size_from_block_sysfs(const char *dev);
uint64_t uboot_guess_step_from_block_sysfs(const char *dev);
uint64_t uboot_guess_size_any(const char *dev);
uint64_t uboot_guess_step_any(const char *dev);
int uboot_glob_scan_devices(glob_t *out, unsigned int flags);

void uboot_ensure_mtd_nodes(bool verbose);
int uboot_ensure_mtd_nodes_collect(bool verbose, char ***created_nodes, size_t *created_count);
void uboot_free_created_nodes(char **nodes, size_t count);
void uboot_ensure_ubi_nodes(bool verbose);
int uboot_ensure_ubi_nodes_collect(bool verbose, char ***created_nodes, size_t *created_count);
int uboot_ensure_block_nodes_collect(bool verbose, bool include_sd, bool include_emmc,
				  char ***created_nodes, size_t *created_count);
void uboot_ensure_block_nodes(bool verbose, bool include_sd, bool include_emmc);

int ela_parse_u64(const char *s, uint64_t *out);
uint32_t ela_read_be32(const uint8_t *p);
const char *ela_detect_isa(void);
bool ela_isa_supported_for_efi_bios(const char *isa);
bool ela_is_valid_tcp_output_target(const char *spec);
int ela_connect_tcp_ipv4(const char *spec);
int ela_connect_tcp_any(const char *spec);
int ela_send_all(int sock, const uint8_t *buf, size_t len);
char *ela_http_uri_normalize_default_port(const char *uri, uint16_t default_port);
int ela_parse_http_output_uri(const char *uri,
				  const char **output_http,
				  const char **output_https,
				  char *errbuf,
				  size_t errbuf_len);
int ela_http_get_upload_mac(const char *base_uri, char *mac_buf, size_t mac_buf_len);
char *ela_http_build_upload_uri(const char *base_uri, const char *upload_type, const char *file_path);
int ela_http_post_log_message(const char *base_uri, const char *message,
				bool insecure, bool verbose,
				char *errbuf, size_t errbuf_len);
int ela_emit_lifecycle_event(const char *output_format,
				  const char *output_tcp,
				  const char *output_http,
				  const char *output_https,
				  bool insecure,
				  const char *command,
				  const char *phase,
				  int rc);
int ela_http_get_to_file(const char *uri, const char *output_path,
			   bool insecure, bool verbose,
			   char *errbuf, size_t errbuf_len);
int ela_http_post(const char *uri, const uint8_t *data, size_t len,
		 const char *content_type, bool insecure, bool verbose,
		 char *errbuf, size_t errbuf_len);
extern const unsigned char ela_default_ca_bundle_pem[];
extern const size_t ela_default_ca_bundle_pem_len;
void ela_crc32_init(uint32_t table[256]);
uint32_t ela_crc32_calc(const uint32_t table[256], const uint8_t *buf, size_t len);

int uboot_env_scan_main(int argc, char **argv);
int uboot_env_scan_core_main(int argc, char **argv);
int uboot_env_read_vars_main(int argc, char **argv);
int uboot_env_write_vars_main(int argc, char **argv);
int uboot_image_scan_main(int argc, char **argv);
int embedded_linux_audit_scan_main(int argc, char **argv);
int linux_dmesg_scan_main(int argc, char **argv);
int linux_dmesg_watch_main(int argc, char **argv);
int linux_execute_command_scan_main(int argc, char **argv);
int linux_grep_scan_main(int argc, char **argv);
int linux_download_file_scan_main(int argc, char **argv);
int linux_list_files_scan_main(int argc, char **argv);
int linux_list_symlinks_scan_main(int argc, char **argv);
int linux_remote_copy_scan_main(int argc, char **argv);
int linux_ssh_scan_main(int argc, char **argv);
int tpm2_scan_main(int argc, char **argv);
int efi_orom_main(int argc, char **argv);
int efi_dump_vars_main(int argc, char **argv);
int bios_orom_main(int argc, char **argv);
int transfer_main(int argc, char **argv);

struct embedded_linux_audit_input {
	const char *device;
	uint64_t offset;
	const uint8_t *data;
	size_t data_len;
	const uint32_t *crc32_table;
	const char *signature_blob_path;
	const char *signature_pubkey_path;
	const char *signature_algorithm;
	bool verbose;
};

struct embedded_linux_audit_rule {
	const char *name;
	const char *description;
	int (*run)(const struct embedded_linux_audit_input *input, char *message, size_t message_len);
};

#define ELA_RULE_SECTION "embedded_linux_audit_rules"

#if defined(__has_attribute)
#  if __has_attribute(retain)
#    define UBOOT_SECTION_RETAIN __attribute__((retain))
#  else
#    define UBOOT_SECTION_RETAIN
#  endif
#elif defined(__GNUC__) && (__GNUC__ >= 11)
#  define UBOOT_SECTION_RETAIN __attribute__((retain))
#else
#  define UBOOT_SECTION_RETAIN
#endif

#define ELA_REGISTER_RULE(symbol) \
	static const struct embedded_linux_audit_rule * const __embedded_linux_audit_rule_ptr_##symbol \
	__attribute__((used, section(ELA_RULE_SECTION))) UBOOT_SECTION_RETAIN = &(symbol)

extern const struct embedded_linux_audit_rule * const __start_embedded_linux_audit_rules[];
extern const struct embedded_linux_audit_rule * const __stop_embedded_linux_audit_rules[];

#endif