#ifndef FW_SCAN_H
#define FW_SCAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

int fw_get_mtd_index(const char *dev, char *idx, size_t idx_sz);

uint64_t fw_guess_size_from_sysfs(const char *dev);
uint64_t fw_guess_erasesize_from_sysfs(const char *dev);
uint64_t fw_guess_size_from_proc_mtd(const char *dev);
uint64_t fw_guess_erasesize_from_proc_mtd(const char *dev);
uint64_t fw_guess_size_from_ubi_sysfs(const char *dev);
uint64_t fw_guess_step_from_ubi_sysfs(const char *dev);

void fw_ensure_mtd_nodes(bool verbose);
void fw_ensure_ubi_nodes(bool verbose);

int fw_parse_u64(const char *s, uint64_t *out);
uint32_t fw_read_be32(const uint8_t *p);
int fw_connect_tcp_ipv4(const char *spec);
int fw_send_all(int sock, const uint8_t *buf, size_t len);
void fw_crc32_init(uint32_t table[256]);
uint32_t fw_crc32_calc(const uint32_t table[256], const uint8_t *buf, size_t len);

#endif