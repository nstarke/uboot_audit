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

int fw_get_mtd_index(const char *dev, char *idx, size_t idx_sz);

uint64_t fw_guess_size_from_sysfs(const char *dev);
uint64_t fw_guess_erasesize_from_sysfs(const char *dev);
uint64_t fw_guess_size_from_proc_mtd(const char *dev);
uint64_t fw_guess_erasesize_from_proc_mtd(const char *dev);
uint64_t fw_guess_size_from_ubi_sysfs(const char *dev);
uint64_t fw_guess_step_from_ubi_sysfs(const char *dev);
uint64_t fw_guess_size_any(const char *dev);
uint64_t fw_guess_step_any(const char *dev);
int fw_glob_scan_devices(glob_t *out, unsigned int flags);

void fw_ensure_mtd_nodes(bool verbose);
int fw_ensure_mtd_nodes_collect(bool verbose, char ***created_nodes, size_t *created_count);
void fw_free_created_nodes(char **nodes, size_t count);
void fw_ensure_ubi_nodes(bool verbose);

int fw_parse_u64(const char *s, uint64_t *out);
uint32_t fw_read_be32(const uint8_t *p);
int fw_connect_tcp_ipv4(const char *spec);
int fw_send_all(int sock, const uint8_t *buf, size_t len);
void fw_crc32_init(uint32_t table[256]);
uint32_t fw_crc32_calc(const uint32_t table[256], const uint8_t *buf, size_t len);

int fw_env_scan_main(int argc, char **argv);
int fw_image_scan_main(int argc, char **argv);

#endif