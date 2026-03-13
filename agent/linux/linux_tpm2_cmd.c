// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(ELA_HAS_TPM2)
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti_device.h>
#include <tss2/tss2_tpm2_types.h>
#endif

#if !defined(ELA_HAS_TPM2)

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <command>\n"
		"       %s list-commands\n"
		"\n"
		"TPM2 support is not compiled into this build.\n",
		prog, prog);
}

int linux_tpm2_scan_main(int argc, char **argv)
{
	int opt;
	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};

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

	if (optind >= argc || !strcmp(argv[optind], "help") ||
	    !strcmp(argv[optind], "--help") || !strcmp(argv[optind], "-h")) {
		usage(argv[0]);
		return optind >= argc ? 2 : 0;
	}

	fprintf(stderr, "linux tpm2: TPM2-TSS support is unavailable in this build\n");
	return 1;
}

#else

struct tpm2_command_desc {
	const char *name;
	const char *summary;
};

static const struct tpm2_command_desc supported_commands[] = {
	{ "createprimary", "Create a primary object and optionally serialize the ESYS context" },
	{ "getcap", "Query a small built-in set of TPM2 capabilities" },
	{ "nvreadpublic", "Read the public metadata for an NV index" },
	{ "pcrread", "Read PCR values for one or more PCR banks" },
};

static void usage(const char *prog)
{
	size_t i;

	fprintf(stderr,
		"Usage: %s <command> [command-options]\n"
		"       %s list-commands\n"
		"\n"
		"Built-in TPM2 commands implemented through TPM2-TSS:\n",
		prog, prog);

	for (i = 0; i < sizeof(supported_commands) / sizeof(supported_commands[0]); i++)
		fprintf(stderr, "  %-13s %s\n", supported_commands[i].name, supported_commands[i].summary);

	fprintf(stderr,
		"\n"
		"Examples:\n"
		"  %s getcap properties-fixed\n"
		"  %s pcrread sha256:0,1,2\n"
		"  %s nvreadpublic 0x1500016\n"
		"  %s createprimary -C o -g sha256 -G rsa -c primary.ctx\n",
		prog, prog, prog, prog);
}

static void usage_getcap(const char *prog)
{
	fprintf(stderr,
		"Usage: %s getcap <properties-fixed|properties-variable|algorithms|commands|pcrs>\n"
		"  Query a built-in TPM capability set using TPM2-TSS\n",
		prog);
}

static void usage_pcrread(const char *prog)
{
	fprintf(stderr,
		"Usage: %s pcrread <alg:pcr[,pcr...]> [alg:pcr[,pcr...]]...\n"
		"  Example: %s pcrread sha256:0,1,2 sha1:0,7\n",
		prog, prog);
}

static void usage_nvreadpublic(const char *prog)
{
	fprintf(stderr,
		"Usage: %s nvreadpublic <nv-index>\n"
		"  Example: %s nvreadpublic 0x1500016\n",
		prog, prog);
}

static void usage_createprimary(const char *prog)
{
	fprintf(stderr,
		"Usage: %s createprimary [-C <o|p|e|n>] [-g <sha1|sha256|sha384|sha512>] [-G <rsa|ecc>] [-c <context-file>]\n"
		"  Create a primary object with a minimal built-in template.\n"
		"  When -c is provided, the ESYS serialized handle is written to that file.\n",
		prog);
}

static int tpm2_rc_to_exit_code(TSS2_RC rc)
{
	if (rc == TPM2_RC_SUCCESS)
		return 0;
	return 1;
}

static int parse_u32(const char *text, uint32_t *value)
{
	char *end = NULL;
	unsigned long parsed;

	if (!text || !*text || !value)
		return -1;

	errno = 0;
	parsed = strtoul(text, &end, 0);
	if (errno != 0 || !end || *end != '\0' || parsed > UINT32_MAX)
		return -1;

	*value = (uint32_t)parsed;
	return 0;
}

static TPM2_ALG_ID parse_hash_alg(const char *name)
{
	if (!name)
		return TPM2_ALG_ERROR;
	if (!strcmp(name, "sha1"))
		return TPM2_ALG_SHA1;
	if (!strcmp(name, "sha256"))
		return TPM2_ALG_SHA256;
	if (!strcmp(name, "sha384"))
		return TPM2_ALG_SHA384;
	if (!strcmp(name, "sha512"))
		return TPM2_ALG_SHA512;
	return TPM2_ALG_ERROR;
}

static TPMI_RH_HIERARCHY parse_hierarchy(const char *name)
{
	if (!name)
		return TPM2_RH_NULL;
	if (!strcmp(name, "o") || !strcmp(name, "owner"))
		return TPM2_RH_OWNER;
	if (!strcmp(name, "p") || !strcmp(name, "platform"))
		return TPM2_RH_PLATFORM;
	if (!strcmp(name, "e") || !strcmp(name, "endorsement"))
		return TPM2_RH_ENDORSEMENT;
	if (!strcmp(name, "n") || !strcmp(name, "null"))
		return TPM2_RH_NULL;
	return 0;
}

static int parse_pcr_bank(const char *name, TPMI_ALG_HASH *alg)
{
	TPM2_ALG_ID parsed = parse_hash_alg(name);

	if (parsed == TPM2_ALG_ERROR)
		return -1;

	*alg = parsed;
	return 0;
}

static int write_serialized_handle(const char *path, const uint8_t *buf, size_t len)
{
	FILE *fp;

	if (!path || !buf || len == 0)
		return -1;

	fp = fopen(path, "wb");
	if (!fp) {
		fprintf(stderr, "linux tpm2: failed to open %s for writing: %s\n", path, strerror(errno));
		return -1;
	}

	if (fwrite(buf, 1, len, fp) != len) {
		fprintf(stderr, "linux tpm2: failed to write %s: %s\n", path, strerror(errno));
		fclose(fp);
		return -1;
	}

	if (fclose(fp) != 0) {
		fprintf(stderr, "linux tpm2: failed to close %s: %s\n", path, strerror(errno));
		return -1;
	}

	return 0;
}

static int tpm2_open(ESYS_CONTEXT **esys, TSS2_TCTI_CONTEXT **tcti)
{
	TSS2_ABI_VERSION abi = TSS2_ABI_VERSION_CURRENT;
	TSS2_RC rc;
	size_t tcti_size = 0;

	if (!esys || !tcti)
		return 1;

	*esys = NULL;
	*tcti = NULL;

	rc = Tss2_Tcti_Device_Init(NULL, &tcti_size, NULL);
	if (rc != TPM2_RC_SUCCESS) {
		fprintf(stderr, "linux tpm2: failed to size device TCTI context: 0x%08" PRIx32 "\n", rc);
		return tpm2_rc_to_exit_code(rc);
	}

	*tcti = calloc(1, tcti_size);
	if (!*tcti)
		return 1;

	rc = Tss2_Tcti_Device_Init(*tcti, &tcti_size, NULL);
	if (rc != TPM2_RC_SUCCESS) {
		fprintf(stderr, "linux tpm2: failed to initialize device TCTI: 0x%08" PRIx32 "\n", rc);
		free(*tcti);
		*tcti = NULL;
		return tpm2_rc_to_exit_code(rc);
	}

	rc = Esys_Initialize(esys, *tcti, &abi);
	if (rc != TPM2_RC_SUCCESS) {
		fprintf(stderr, "linux tpm2: failed to initialize ESYS context: 0x%08" PRIx32 "\n", rc);
		TSS2_TCTI_FINALIZE(*tcti)(*tcti);
		free(*tcti);
		*tcti = NULL;
		return tpm2_rc_to_exit_code(rc);
	}

	return 0;
}

static void tpm2_close(ESYS_CONTEXT **esys, TSS2_TCTI_CONTEXT **tcti)
{
	if (esys && *esys)
		Esys_Finalize(esys);
	if (tcti && *tcti) {
		TSS2_TCTI_FINALIZE(*tcti)(*tcti);
		free(*tcti);
		*tcti = NULL;
	}
}

static int cmd_list_commands(int argc)
{
	size_t i;

	if (argc != 2) {
		fprintf(stderr, "linux tpm2: list-commands does not accept additional arguments\n");
		return 2;
	}

	for (i = 0; i < sizeof(supported_commands) / sizeof(supported_commands[0]); i++)
		printf("%s\n", supported_commands[i].name);

	return 0;
}

static int cmd_getcap(int argc, char **argv)
{
	ESYS_CONTEXT *esys = NULL;
	TSS2_TCTI_CONTEXT *tcti = NULL;
	TPM2_CAP capability;
	uint32_t property = 0;
	uint32_t property_count = TPM2_MAX_TPM_PROPERTIES;
	TPMI_YES_NO more_data = TPM2_NO;
	TPMS_CAPABILITY_DATA *cap_data = NULL;
	TSS2_RC rc;
	int ret;
	UINT32 i;

	if (argc >= 3 && (!strcmp(argv[2], "--help") || !strcmp(argv[2], "-h"))) {
		usage_getcap(argv[0]);
		return 0;
	}

	if (argc != 3) {
		usage_getcap(argv[0]);
		return 2;
	}

	if (!strcmp(argv[2], "properties-fixed")) {
		capability = TPM2_CAP_TPM_PROPERTIES;
		property = TPM2_PT_FIXED;
		property_count = 16;
	} else if (!strcmp(argv[2], "properties-variable")) {
		capability = TPM2_CAP_TPM_PROPERTIES;
		property = TPM2_PT_VAR;
		property_count = 16;
	} else if (!strcmp(argv[2], "algorithms")) {
		capability = TPM2_CAP_ALGS;
		property = 0;
		property_count = 64;
	} else if (!strcmp(argv[2], "commands")) {
		capability = TPM2_CAP_COMMANDS;
		property = 0;
		property_count = 64;
	} else if (!strcmp(argv[2], "pcrs")) {
		capability = TPM2_CAP_PCRS;
		property = 0;
		property_count = 1;
	} else {
		fprintf(stderr, "linux tpm2: unsupported getcap selector: %s\n", argv[2]);
		usage_getcap(argv[0]);
		return 2;
	}

	ret = tpm2_open(&esys, &tcti);
	if (ret != 0)
		return ret;

	rc = Esys_GetCapability(esys,
				ESYS_TR_NONE,
				ESYS_TR_NONE,
				ESYS_TR_NONE,
				capability,
				property,
				property_count,
				&more_data,
				&cap_data);
	if (rc != TPM2_RC_SUCCESS) {
		fprintf(stderr, "linux tpm2: Esys_GetCapability failed: 0x%08" PRIx32 "\n", rc);
		ret = tpm2_rc_to_exit_code(rc);
		goto done;
	}

	switch (capability) {
	case TPM2_CAP_TPM_PROPERTIES:
		for (i = 0; i < cap_data->data.tpmProperties.count; i++) {
			const TPMS_TAGGED_PROPERTY *prop = &cap_data->data.tpmProperties.tpmProperty[i];
			printf("0x%08" PRIx32 ": 0x%08" PRIx32 "\n", prop->property, prop->value);
		}
		break;
	case TPM2_CAP_ALGS:
		for (i = 0; i < cap_data->data.algorithms.count; i++) {
			const TPMS_ALG_PROPERTY *alg = &cap_data->data.algorithms.algProperties[i];
			printf("0x%04x: 0x%08" PRIx32 "\n", alg->alg, alg->algProperties);
		}
		break;
	case TPM2_CAP_COMMANDS:
		for (i = 0; i < cap_data->data.command.count; i++)
			printf("0x%08" PRIx32 "\n", cap_data->data.command.commandAttributes[i]);
		break;
	case TPM2_CAP_PCRS:
		for (i = 0; i < cap_data->data.assignedPCR.count; i++) {
			const TPMS_PCR_SELECTION *sel = &cap_data->data.assignedPCR.pcrSelections[i];
			printf("0x%04x:", sel->hash);
			for (uint32_t byte_idx = 0; byte_idx < sel->sizeofSelect; byte_idx++)
				printf("%s%02x", byte_idx == 0 ? "" : "", sel->pcrSelect[byte_idx]);
			printf("\n");
		}
		break;
	default:
		fprintf(stderr, "linux tpm2: unhandled capability response\n");
		ret = 1;
		goto done;
	}

	if (more_data == TPM2_YES)
		fprintf(stderr, "linux tpm2: additional capability data is available but was not requested\n");

	ret = 0;

done:
	if (cap_data)
		Esys_Free(cap_data);
	tpm2_close(&esys, &tcti);
	return ret;
}

static int add_pcr_selection(TPML_PCR_SELECTION *selection, const char *spec)
{
	char *copy = NULL;
	char *colon;
	char *bank_name;
	char *list;
	char *token;
	char *saveptr = NULL;
	TPMI_ALG_HASH hash_alg;
	uint32_t pcr_index;
	size_t i;

	if (!selection || !spec || !*spec)
		return -1;

	if (selection->count >= TPM2_NUM_PCR_BANKS) {
		fprintf(stderr, "linux tpm2: too many PCR banks requested\n");
		return -1;
	}

	copy = strdup(spec);
	if (!copy)
		return -1;

	colon = strchr(copy, ':');
	if (!colon) {
		fprintf(stderr, "linux tpm2: PCR selector must be in alg:pcr[,pcr...] form: %s\n", spec);
		free(copy);
		return -1;
	}

	*colon = '\0';
	bank_name = copy;
	list = colon + 1;

	if (parse_pcr_bank(bank_name, &hash_alg) != 0) {
		fprintf(stderr, "linux tpm2: unsupported PCR bank: %s\n", bank_name);
		free(copy);
		return -1;
	}

	selection->pcrSelections[selection->count].hash = hash_alg;
	selection->pcrSelections[selection->count].sizeofSelect = 3;
	memset(selection->pcrSelections[selection->count].pcrSelect, 0, sizeof(selection->pcrSelections[selection->count].pcrSelect));

	for (token = strtok_r(list, ",", &saveptr); token; token = strtok_r(NULL, ",", &saveptr)) {
		if (parse_u32(token, &pcr_index) != 0 || pcr_index > 23) {
			fprintf(stderr, "linux tpm2: invalid PCR index: %s\n", token);
			free(copy);
			return -1;
		}
		selection->pcrSelections[selection->count].pcrSelect[pcr_index / 8] |= (uint8_t)(1U << (pcr_index % 8));
	}

	for (i = 0; i < selection->count; i++) {
		if (selection->pcrSelections[i].hash == hash_alg) {
			fprintf(stderr, "linux tpm2: duplicate PCR bank requested: %s\n", bank_name);
			free(copy);
			return -1;
		}
	}

	selection->count++;
	free(copy);
	return 0;
}

static int cmd_pcrread(int argc, char **argv)
{
	ESYS_CONTEXT *esys = NULL;
	TSS2_TCTI_CONTEXT *tcti = NULL;
	TPML_PCR_SELECTION selection = { 0 };
	TPML_PCR_SELECTION *pcr_update = NULL;
	TPML_DIGEST *values = NULL;
	TSS2_RC rc;
	int ret;
	UINT32 bank_idx;
	UINT32 digest_idx = 0;

	if (argc >= 3 && (!strcmp(argv[2], "--help") || !strcmp(argv[2], "-h"))) {
		usage_pcrread(argv[0]);
		return 0;
	}

	if (argc < 3) {
		usage_pcrread(argv[0]);
		return 2;
	}

	for (int i = 2; i < argc; i++) {
		if (add_pcr_selection(&selection, argv[i]) != 0)
			return 2;
	}

	ret = tpm2_open(&esys, &tcti);
	if (ret != 0)
		return ret;

	rc = Esys_PCR_Read(esys,
			   ESYS_TR_NONE,
			   ESYS_TR_NONE,
			   ESYS_TR_NONE,
			   &selection,
			   NULL,
			   &pcr_update,
			   &values);
	if (rc != TPM2_RC_SUCCESS) {
		fprintf(stderr, "linux tpm2: Esys_PCR_Read failed: 0x%08" PRIx32 "\n", rc);
		ret = tpm2_rc_to_exit_code(rc);
		goto done;
	}

	for (bank_idx = 0; bank_idx < pcr_update->count; bank_idx++) {
		const TPMS_PCR_SELECTION *bank = &pcr_update->pcrSelections[bank_idx];

		for (uint32_t pcr = 0; pcr < (uint32_t)(bank->sizeofSelect * 8); pcr++) {
			if ((bank->pcrSelect[pcr / 8] & (1U << (pcr % 8))) == 0)
				continue;
			if (digest_idx >= values->count) {
				fprintf(stderr, "linux tpm2: PCR digest count mismatch\n");
				ret = 1;
				goto done;
			}

			printf("0x%04x:%u=", bank->hash, pcr);
			for (uint16_t byte_idx = 0; byte_idx < values->digests[digest_idx].size; byte_idx++)
				printf("%02x", values->digests[digest_idx].buffer[byte_idx]);
			printf("\n");
			digest_idx++;
		}
	}

	ret = 0;

done:
	if (pcr_update)
		Esys_Free(pcr_update);
	if (values)
		Esys_Free(values);
	tpm2_close(&esys, &tcti);
	return ret;
}

static int cmd_nvreadpublic(int argc, char **argv)
{
	ESYS_CONTEXT *esys = NULL;
	TSS2_TCTI_CONTEXT *tcti = NULL;
	TPM2_HANDLE nv_index;
	TPM2B_NV_PUBLIC *public_info = NULL;
	TPM2B_NAME *name = NULL;
	TSS2_RC rc;
	int ret;

	if (argc >= 3 && (!strcmp(argv[2], "--help") || !strcmp(argv[2], "-h"))) {
		usage_nvreadpublic(argv[0]);
		return 0;
	}

	if (argc != 3 || parse_u32(argv[2], &nv_index) != 0) {
		usage_nvreadpublic(argv[0]);
		return 2;
	}

	ret = tpm2_open(&esys, &tcti);
	if (ret != 0)
		return ret;

	rc = Esys_NV_ReadPublic(esys,
				ESYS_TR_NONE,
				ESYS_TR_NONE,
				ESYS_TR_NONE,
				nv_index,
				&public_info,
				&name);
	if (rc != TPM2_RC_SUCCESS) {
		fprintf(stderr, "linux tpm2: Esys_NV_ReadPublic failed: 0x%08" PRIx32 "\n", rc);
		ret = tpm2_rc_to_exit_code(rc);
		goto done;
	}

	printf("nv-index: 0x%08" PRIx32 "\n", public_info->nvPublic.nvIndex);
	printf("name-alg: 0x%04x\n", public_info->nvPublic.nameAlg);
	printf("attributes: 0x%08" PRIx32 "\n", public_info->nvPublic.attributes);
	printf("data-size: %u\n", public_info->nvPublic.dataSize);
	printf("name: ");
	for (uint16_t i = 0; i < name->size; i++)
		printf("%02x", name->name[i]);
	printf("\n");

	ret = 0;

done:
	if (public_info)
		Esys_Free(public_info);
	if (name)
		Esys_Free(name);
	tpm2_close(&esys, &tcti);
	return ret;
}

static int build_public_template(const char *key_alg_name,
				 TPM2_ALG_ID name_alg,
				 TPM2B_PUBLIC *public)
{
	if (!key_alg_name || !public)
		return -1;

	memset(public, 0, sizeof(*public));
	public->size = 0;
	public->publicArea.nameAlg = name_alg;
	public->publicArea.objectAttributes =
		TPMA_OBJECT_RESTRICTED |
		TPMA_OBJECT_DECRYPT |
		TPMA_OBJECT_FIXEDTPM |
		TPMA_OBJECT_FIXEDPARENT |
		TPMA_OBJECT_SENSITIVEDATAORIGIN |
		TPMA_OBJECT_USERWITHAUTH;

	if (!strcmp(key_alg_name, "rsa")) {
		public->publicArea.type = TPM2_ALG_RSA;
		public->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
		public->publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
		public->publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
		public->publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
		public->publicArea.parameters.rsaDetail.keyBits = 2048;
		public->publicArea.parameters.rsaDetail.exponent = 0;
		public->publicArea.unique.rsa.size = 0;
		return 0;
	}

	if (!strcmp(key_alg_name, "ecc")) {
		public->publicArea.type = TPM2_ALG_ECC;
		public->publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
		public->publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
		public->publicArea.parameters.eccDetail.symmetric.mode.sym = TPM2_ALG_CFB;
		public->publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
		public->publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
		public->publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
		public->publicArea.unique.ecc.x.size = 0;
		public->publicArea.unique.ecc.y.size = 0;
		return 0;
	}

	return -1;
}

static int cmd_createprimary(int argc, char **argv)
{
	ESYS_CONTEXT *esys = NULL;
	TSS2_TCTI_CONTEXT *tcti = NULL;
	TPMI_RH_HIERARCHY hierarchy = TPM2_RH_OWNER;
	TPM2_ALG_ID name_alg = TPM2_ALG_SHA256;
	const char *key_alg_name = "rsa";
	const char *context_path = NULL;
	TPM2B_SENSITIVE_CREATE in_sensitive = { 0 };
	TPM2B_PUBLIC in_public;
	TPM2B_DATA outside_info = { 0 };
	TPML_PCR_SELECTION creation_pcr = { 0 };
	ESYS_TR object_handle = ESYS_TR_NONE;
	TPM2B_PUBLIC *out_public = NULL;
	TPM2B_CREATION_DATA *creation_data = NULL;
	TPM2B_DIGEST *creation_hash = NULL;
	TPMT_TK_CREATION *creation_ticket = NULL;
	uint8_t *serialized = NULL;
	size_t serialized_size = 0;
	TSS2_RC rc;
	int ret;
	int opt;

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "hierarchy", required_argument, NULL, 'C' },
		{ "hash-alg", required_argument, NULL, 'g' },
		{ "key-alg", required_argument, NULL, 'G' },
		{ "context", required_argument, NULL, 'c' },
		{ 0, 0, 0, 0 }
	};

	if (argc >= 3 && (!strcmp(argv[2], "--help") || !strcmp(argv[2], "-h"))) {
		usage_createprimary(argv[0]);
		return 0;
	}

	optind = 2;
	while ((opt = getopt_long(argc, argv, "hC:g:G:c:", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage_createprimary(argv[0]);
			return 0;
		case 'C':
			hierarchy = parse_hierarchy(optarg);
			if (hierarchy == 0) {
				fprintf(stderr, "linux tpm2: unsupported hierarchy: %s\n", optarg);
				return 2;
			}
			break;
		case 'g':
			name_alg = parse_hash_alg(optarg);
			if (name_alg == TPM2_ALG_ERROR) {
				fprintf(stderr, "linux tpm2: unsupported hash algorithm: %s\n", optarg);
				return 2;
			}
			break;
		case 'G':
			if (strcmp(optarg, "rsa") && strcmp(optarg, "ecc")) {
				fprintf(stderr, "linux tpm2: unsupported key algorithm: %s\n", optarg);
				return 2;
			}
			key_alg_name = optarg;
			break;
		case 'c':
			context_path = optarg;
			break;
		default:
			usage_createprimary(argv[0]);
			return 2;
		}
	}

	if (optind != argc) {
		usage_createprimary(argv[0]);
		return 2;
	}

	if (build_public_template(key_alg_name, name_alg, &in_public) != 0) {
		fprintf(stderr, "linux tpm2: failed to build public template\n");
		return 1;
	}

	ret = tpm2_open(&esys, &tcti);
	if (ret != 0)
		return ret;

	rc = Esys_CreatePrimary(esys,
				hierarchy,
				ESYS_TR_PASSWORD,
				ESYS_TR_NONE,
				ESYS_TR_NONE,
				&in_sensitive,
				&in_public,
				&outside_info,
				&creation_pcr,
				&object_handle,
				&out_public,
				&creation_data,
				&creation_hash,
				&creation_ticket);
	if (rc != TPM2_RC_SUCCESS) {
		fprintf(stderr, "linux tpm2: Esys_CreatePrimary failed: 0x%08" PRIx32 "\n", rc);
		ret = tpm2_rc_to_exit_code(rc);
		goto done;
	}

	if (context_path) {
		rc = Esys_TR_Serialize(esys, object_handle, &serialized, &serialized_size);
		if (rc != TPM2_RC_SUCCESS) {
			fprintf(stderr, "linux tpm2: failed to serialize primary object: 0x%08" PRIx32 "\n", rc);
			ret = tpm2_rc_to_exit_code(rc);
			goto done;
		}
		if (write_serialized_handle(context_path, serialized, serialized_size) != 0) {
			ret = 1;
			goto done;
		}
	}

	printf("hierarchy: 0x%08x\n", hierarchy);
	printf("type: 0x%04x\n", out_public->publicArea.type);
	printf("name-alg: 0x%04x\n", out_public->publicArea.nameAlg);
	if (context_path)
		printf("context: %s\n", context_path);

	ret = 0;

done:
	if (serialized)
		Esys_Free(serialized);
	if (creation_ticket)
		Esys_Free(creation_ticket);
	if (creation_hash)
		Esys_Free(creation_hash);
	if (creation_data)
		Esys_Free(creation_data);
	if (out_public)
		Esys_Free(out_public);
	if (object_handle != ESYS_TR_NONE)
		Esys_TR_Close(esys, &object_handle);
	tpm2_close(&esys, &tcti);
	return ret;
}

int linux_tpm2_scan_main(int argc, char **argv)
{
	int opt;
	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};

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

	if (optind >= argc) {
		usage(argv[0]);
		return 2;
	}

	if (!strcmp(argv[optind], "help") || !strcmp(argv[optind], "--help") || !strcmp(argv[optind], "-h")) {
		usage(argv[0]);
		return 0;
	}

	if (!strcmp(argv[optind], "list-commands"))
		return cmd_list_commands(argc - optind + 1);
	if (!strcmp(argv[optind], "getcap"))
		return cmd_getcap(argc, argv);
	if (!strcmp(argv[optind], "pcrread"))
		return cmd_pcrread(argc, argv);
	if (!strcmp(argv[optind], "nvreadpublic"))
		return cmd_nvreadpublic(argc, argv);
	if (!strcmp(argv[optind], "createprimary"))
		return cmd_createprimary(argc, argv);

	fprintf(stderr, "linux tpm2: unsupported TPM2 command: %s\n", argv[optind]);
	usage(argv[0]);
	return 2;
}

#endif
