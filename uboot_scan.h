#ifndef UBOOT_SCAN_H
#define UBOOT_SCAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <glob.h>

#define FW_SCAN_GLOB_MTDBLOCK  (1U << 0)
#define FW_SCAN_GLOB_MTDCHAR   (1U << 1)
#define FW_SCAN_GLOB_UBI       (1U << 2)
#define FW_SCAN_GLOB_UBIBLOCK  (1U << 3)
#define FW_SCAN_GLOB_MMCBLK    (1U << 4)
#define FW_SCAN_GLOB_SDBLK     (1U << 5)

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

int uboot_parse_u64(const char *s, uint64_t *out);
uint32_t uboot_read_be32(const uint8_t *p);
int uboot_connect_tcp_ipv4(const char *spec);
int uboot_send_all(int sock, const uint8_t *buf, size_t len);
char *uboot_http_uri_normalize_default_port(const char *uri, uint16_t default_port);
int uboot_http_post(const char *uri, const uint8_t *data, size_t len,
		 const char *content_type, bool insecure, bool verbose,
		 char *errbuf, size_t errbuf_len);
extern const unsigned char uboot_default_ca_bundle_pem[];
extern const size_t uboot_default_ca_bundle_pem_len;
void uboot_crc32_init(uint32_t table[256]);
uint32_t uboot_crc32_calc(const uint32_t table[256], const uint8_t *buf, size_t len);

int uboot_env_scan_main(int argc, char **argv);
int uboot_image_scan_main(int argc, char **argv);
int uboot_audit_scan_main(int argc, char **argv);

struct uboot_audit_input {
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

struct uboot_audit_rule {
	const char *name;
	const char *description;
	int (*run)(const struct uboot_audit_input *input, char *message, size_t message_len);
};

#define FW_AUDIT_RULE_SECTION "uboot_audit_rules"

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

#define FW_REGISTER_AUDIT_RULE(symbol) \
	static const struct uboot_audit_rule * const __uboot_audit_rule_ptr_##symbol \
	__attribute__((used, section(FW_AUDIT_RULE_SECTION))) UBOOT_SECTION_RETAIN = &(symbol)

extern const struct uboot_audit_rule * const __start_uboot_audit_rules[];
extern const struct uboot_audit_rule * const __stop_uboot_audit_rules[];

#endif