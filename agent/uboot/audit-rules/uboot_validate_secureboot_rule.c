// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

struct env_kv_view {
	const char *name;
	const char *value;
};

static bool str_ieq(const char *a, const char *b)
{
	if (!a || !b)
		return false;

	while (*a && *b) {
		if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
			return false;
		a++;
		b++;
	}

	return *a == '\0' && *b == '\0';
}

static bool value_is_enabled(const char *value)
{
	if (!value || !*value)
		return false;

	return str_ieq(value, "1") ||
	       str_ieq(value, "y") ||
	       str_ieq(value, "yes") ||
	       str_ieq(value, "true") ||
	       str_ieq(value, "on") ||
	       str_ieq(value, "enabled");
}

static bool value_is_disabled(const char *value)
{
	if (!value || !*value)
		return true;

	return str_ieq(value, "0") ||
	       str_ieq(value, "n") ||
	       str_ieq(value, "no") ||
	       str_ieq(value, "false") ||
	       str_ieq(value, "off") ||
	       str_ieq(value, "disabled");
}

static bool value_is_nonempty(const char *value)
{
	return value && *value;
}

static int read_file_all(const char *path, uint8_t **out, size_t *out_len)
{
	int fd = -1;
	struct stat st;
	uint8_t *buf = NULL;
	ssize_t got;

	if (!path || !*path || !out || !out_len)
		return -1;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	if (fstat(fd, &st) != 0 || st.st_size <= 0 || (uint64_t)st.st_size > (uint64_t)SIZE_MAX) {
		close(fd);
		return -1;
	}

	buf = malloc((size_t)st.st_size);
	if (!buf) {
		close(fd);
		return -1;
	}

	got = read(fd, buf, (size_t)st.st_size);
	close(fd);
	if (got < 0 || (size_t)got != (size_t)st.st_size) {
		free(buf);
		return -1;
	}

	*out = buf;
	*out_len = (size_t)st.st_size;
	return 0;
}

static int hex_nibble(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int decode_hex_signature(const char *sig, uint8_t **out, size_t *out_len)
{
	char *clean = NULL;
	size_t slen;
	size_t cpos = 0;
	uint8_t *buf = NULL;
	size_t blen;

	if (!sig || !*sig || !out || !out_len)
		return -1;

	if (!strncmp(sig, "0x", 2) || !strncmp(sig, "0X", 2))
		sig += 2;

	slen = strlen(sig);
	clean = malloc(slen + 1);
	if (!clean)
		return -1;

	for (size_t i = 0; i < slen; i++) {
		if (isxdigit((unsigned char)sig[i])) {
			clean[cpos++] = sig[i];
			continue;
		}
		if (sig[i] == ':' || sig[i] == '-' || isspace((unsigned char)sig[i]))
			continue;
		free(clean);
		return -1;
	}

	if (!cpos || (cpos % 2) != 0) {
		free(clean);
		return -1;
	}

	blen = cpos / 2;
	buf = malloc(blen);
	if (!buf) {
		free(clean);
		return -1;
	}

	for (size_t i = 0; i < blen; i++) {
		int hi = hex_nibble(clean[i * 2]);
		int lo = hex_nibble(clean[i * 2 + 1]);
		if (hi < 0 || lo < 0) {
			free(clean);
			free(buf);
			return -1;
		}
		buf[i] = (uint8_t)((hi << 4) | lo);
	}

	free(clean);
	*out = buf;
	*out_len = blen;
	return 0;
}

static int decode_base64_signature(const char *sig, uint8_t **out, size_t *out_len)
{
	char *clean = NULL;
	uint8_t *buf = NULL;
	int dec_len;
	size_t slen;
	size_t cpos = 0;

	if (!sig || !*sig || !out || !out_len)
		return -1;

	slen = strlen(sig);
	clean = malloc(slen + 1);
	if (!clean)
		return -1;

	for (size_t i = 0; i < slen; i++) {
		if (!isspace((unsigned char)sig[i]))
			clean[cpos++] = sig[i];
	}
	clean[cpos] = '\0';

	if (!cpos || (cpos % 4) != 0) {
		free(clean);
		return -1;
	}

	buf = malloc(cpos);
	if (!buf) {
		free(clean);
		return -1;
	}

	dec_len = EVP_DecodeBlock(buf, (const unsigned char *)clean, (int)cpos);
	if (dec_len < 0) {
		free(clean);
		free(buf);
		return -1;
	}

	while (cpos && clean[cpos - 1] == '=') {
		dec_len--;
		cpos--;
	}

	free(clean);
	*out = buf;
	*out_len = (size_t)dec_len;
	return 0;
}

static int decode_signature_value(const char *sig, uint8_t **out, size_t *out_len)
{
	if (decode_hex_signature(sig, out, out_len) == 0)
		return 0;
	return decode_base64_signature(sig, out, out_len);
}

static int verify_signature(const char *sig_value,
			    const char *blob_path,
			    const char *pubkey_path,
			    const char *digest_name)
{
	uint8_t *blob = NULL;
	size_t blob_len = 0;
	uint8_t *sig = NULL;
	size_t sig_len = 0;
	BIO *bio = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *mdctx = NULL;
	const EVP_MD *md;
	int rc = -1;

	if (!sig_value || !blob_path || !pubkey_path)
		return -1;

	if (decode_signature_value(sig_value, &sig, &sig_len) != 0 || !sig_len)
		goto out;

	if (read_file_all(blob_path, &blob, &blob_len) != 0 || !blob_len)
		goto out;

	bio = BIO_new_file(pubkey_path, "r");
	if (!bio)
		goto out;

	pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (!pkey)
		goto out;

	md = EVP_get_digestbyname((digest_name && *digest_name) ? digest_name : "sha256");
	if (!md)
		goto out;

	mdctx = EVP_MD_CTX_new();
	if (!mdctx)
		goto out;

	if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pkey) != 1)
		goto out;

	rc = EVP_DigestVerify(mdctx, sig, sig_len, blob, blob_len);

out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	BIO_free(bio);
	free(sig);
	free(blob);
	if (rc == 1)
		return 0;
	if (rc == 0)
		return 1;
	return -1;
}

static int parse_env_pairs(const uint8_t *buf,
			   size_t len,
			   size_t data_off,
			   struct env_kv_view *pairs,
			   size_t max_pairs)
{
	size_t off = data_off;
	size_t count = 0;

	if (!buf || data_off >= len || !pairs || !max_pairs)
		return -1;

	while (off < len && count < max_pairs) {
		const char *entry;
		size_t slen;
		const char *eq;

		if (buf[off] == '\0') {
			if (off + 1 >= len || buf[off + 1] == '\0')
				break;
			off++;
			continue;
		}

		entry = (const char *)(buf + off);
		slen = strnlen(entry, len - off);
		if (slen >= len - off)
			break;

		eq = memchr(entry, '=', slen);
		if (eq) {
			pairs[count].name = entry;
			pairs[count].value = eq + 1;
			count++;
		}

		off += slen + 1;
	}

	return (int)count;
}

static const char *find_env_value(const struct env_kv_view *pairs, size_t count, const char *name)
{
	for (size_t i = 0; i < count; i++) {
		size_t nlen;

		if (!pairs[i].name || !pairs[i].value)
			continue;

		nlen = strcspn(pairs[i].name, "=");
		if (strlen(name) == nlen && !strncmp(pairs[i].name, name, nlen))
			return pairs[i].value;
	}

	return NULL;
}

static int choose_env_data_offset(const struct embedded_linux_audit_input *input, size_t *data_off)
{
	uint32_t stored_le;
	uint32_t stored_be;
	uint32_t calc_std;
	uint32_t calc_redund;

	if (!input || !data_off || !input->data || !input->crc32_table || input->data_len < 8)
		return -1;

	stored_le = (uint32_t)input->data[0] |
		((uint32_t)input->data[1] << 8) |
		((uint32_t)input->data[2] << 16) |
		((uint32_t)input->data[3] << 24);
	stored_be = ela_read_be32(input->data);

	calc_std = ela_crc32_calc(input->crc32_table, input->data + 4, input->data_len - 4);
	if (calc_std == stored_le || calc_std == stored_be) {
		*data_off = 4;
		return 0;
	}

	if (input->data_len <= 5)
		return -1;

	calc_redund = ela_crc32_calc(input->crc32_table, input->data + 5, input->data_len - 5);
	if (calc_redund == stored_le || calc_redund == stored_be) {
		*data_off = 5;
		return 0;
	}

	return -1;
}

static int run_validate_secureboot(const struct embedded_linux_audit_input *input, char *message, size_t message_len)
{
	struct env_kv_view pairs[512];
	const char *secureboot;
	const char *verify;
	const char *bootm_verify_sig;
	const char *signature;
	const char *signature_name;
	const char *used_digest = NULL;
	int verify_rc;
	char detail[320] = "";
	int issues = 0;
	size_t data_off = 0;
	int count;

	if (!input || !input->data || !input->crc32_table || input->data_len < 8) {
		if (message && message_len)
			snprintf(message, message_len, "input too small (need at least 8 bytes)");
		return -1;
	}

	if (choose_env_data_offset(input, &data_off) != 0) {
		if (message && message_len)
			snprintf(message, message_len, "unable to parse env vars: invalid CRC32 for standard/redundant layouts");
		return -1;
	}

	count = parse_env_pairs(input->data, input->data_len, data_off, pairs, sizeof(pairs) / sizeof(pairs[0]));
	if (count < 0) {
		if (message && message_len)
			snprintf(message, message_len, "failed to parse environment key/value pairs");
		return -1;
	}

	secureboot = find_env_value(pairs, (size_t)count, "secureboot");
	verify = find_env_value(pairs, (size_t)count, "verify");
	bootm_verify_sig = find_env_value(pairs, (size_t)count, "bootm_verify_sig");
	signature = find_env_value(pairs, (size_t)count, "signature");
	signature_name = "signature";
	if (!value_is_nonempty(signature)) {
		signature = find_env_value(pairs, (size_t)count, "boot_signature");
		signature_name = "boot_signature";
	}
	if (!value_is_nonempty(signature)) {
		signature = find_env_value(pairs, (size_t)count, "fit_signature");
		signature_name = "fit_signature";
	}

	if (!secureboot || !value_is_enabled(secureboot)) {
		issues++;
		snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
			 "%ssecureboot=%s", detail[0] ? "; " : "", secureboot ? secureboot : "(missing)");
	}

	if (!verify || value_is_disabled(verify)) {
		issues++;
		snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
			 "%sverify=%s", detail[0] ? "; " : "", verify ? verify : "(missing)");
	}

	if (!bootm_verify_sig || !value_is_enabled(bootm_verify_sig)) {
		issues++;
		snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
			 "%sbootm_verify_sig=%s", detail[0] ? "; " : "", bootm_verify_sig ? bootm_verify_sig : "(missing)");
	}

	if (!value_is_nonempty(signature)) {
		issues++;
		snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
			 "%ssignature/boot_signature/fit_signature=(missing)", detail[0] ? "; " : "");
	}

	if (value_is_nonempty(signature)) {
		if (!input->signature_blob_path || !*input->signature_blob_path ||
		    !input->signature_pubkey_path || !*input->signature_pubkey_path) {
			issues++;
			snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
				 "%s--signature-blob/--signature-pubkey required for cryptographic verification",
				 detail[0] ? "; " : "");
		} else {
			if (input->signature_algorithm && *input->signature_algorithm) {
				used_digest = input->signature_algorithm;
				verify_rc = verify_signature(signature,
							     input->signature_blob_path,
							     input->signature_pubkey_path,
							     used_digest);
				if (verify_rc < 0) {
					if (message && message_len) {
						snprintf(message, message_len,
							 "signature verification error (%s): blob=%s pubkey=%s digest=%s",
							 signature_name,
							 input->signature_blob_path,
							 input->signature_pubkey_path,
							 used_digest);
					}
					return -1;
				}
			} else {
				static const char *fallback_digests[] = {
					"sha256", "sha384", "sha512", "sha1", "sha224"
				};
				verify_rc = 1;
				for (size_t i = 0; i < sizeof(fallback_digests) / sizeof(fallback_digests[0]); i++) {
					int try_rc = verify_signature(signature,
								 input->signature_blob_path,
								 input->signature_pubkey_path,
								 fallback_digests[i]);
					if (try_rc == 0) {
						verify_rc = 0;
						used_digest = fallback_digests[i];
						break;
					}
					if (try_rc < 0) {
						if (message && message_len) {
							snprintf(message, message_len,
								 "signature verification error (%s): blob=%s pubkey=%s digest=%s",
								 signature_name,
								 input->signature_blob_path,
								 input->signature_pubkey_path,
								 fallback_digests[i]);
						}
						return -1;
					}
				}
			}

			if (verify_rc > 0) {
				issues++;
				snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
					 "%ssignature verification failed (%s)",
					 detail[0] ? "; " : "", signature_name);
			}
		}
	}

	if (!issues) {
		if (message && message_len) {
			snprintf(message, message_len,
				 "secure boot vars validated: secureboot=%s verify=%s bootm_verify_sig=%s %s=<verified> digest=%s",
				 secureboot, verify, bootm_verify_sig, signature_name,
				 used_digest ? used_digest : (input->signature_algorithm ? input->signature_algorithm : "n/a"));
		}
		return 0;
	}

	if (message && message_len) {
		snprintf(message, message_len,
			 "secure boot variable misconfiguration: %s", detail[0] ? detail : "unknown");
	}

	return 1;
}

static const struct embedded_linux_audit_rule uboot_validate_secureboot_rule = {
	.name = "uboot_validate_secureboot",
	.description = "Validate secure boot env vars and cryptographically verify signature field",
	.run = run_validate_secureboot,
};

ELA_REGISTER_RULE(uboot_validate_secureboot_rule);