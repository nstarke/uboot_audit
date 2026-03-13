// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "isa_util.h"
#include "../embedded_linux_audit_cmd.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

static const char *fw_audit_sigill_stage = "startup";

#ifdef DEBUG
static bool fw_audit_sigill_debug_enabled(void)
{
	const char *v = getenv("FW_AUDIT_SIGILL_DEBUG");
	return v && !strcmp(v, "1");
}
#endif

void fw_audit_set_sigill_stage(const char *stage)
{
	if (stage && *stage)
		fw_audit_sigill_stage = stage;

#ifdef DEBUG
	if (fw_audit_sigill_debug_enabled())
		fprintf(stderr, "FW_AUDIT_SIGILL stage=%s\n", fw_audit_sigill_stage);
#endif
}

#ifdef DEBUG
static void fw_audit_sigill_handler(int signum)
{
	char buf[256];
	int len;
	(void)signum;
	len = snprintf(buf, sizeof(buf),
		"FW_AUDIT_SIGILL caught illegal instruction at stage=%s\n",
		fw_audit_sigill_stage ? fw_audit_sigill_stage : "unknown");
	if (len > 0)
		write(STDERR_FILENO, buf, (size_t)len);
	signal(SIGILL, SIG_DFL);
	raise(SIGILL);
}
#endif

void fw_audit_install_sigill_debug_handler(void)
{
	#ifdef DEBUG
	static bool installed;
	struct sigaction sa;

	if (installed || !fw_audit_sigill_debug_enabled())
		return;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = fw_audit_sigill_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGILL, &sa, NULL) == 0)
		installed = true;
	#endif
}

const char *normalize_isa_name(const char *isa)
{
	if (!isa || !*isa)
		return NULL;

	if (!strcmp(isa, "x86") || !strcmp(isa, "i386") || !strcmp(isa, "i486") ||
	    !strcmp(isa, "i586") || !strcmp(isa, "i686"))
		return FW_AUDIT_ISA_X86;

	if (!strcmp(isa, "x86_64") || !strcmp(isa, "amd64"))
		return FW_AUDIT_ISA_X86_64;

	if (!strcmp(isa, "aarch64") || !strcmp(isa, "arm64") || !strcmp(isa, "aarch64le") ||
	    !strcmp(isa, "aarch64-le"))
		return FW_AUDIT_ISA_AARCH64_LE;

	if (!strcmp(isa, "aarch64_be") || !strcmp(isa, "aarch64be") || !strcmp(isa, "aarch64-be"))
		return FW_AUDIT_ISA_AARCH64_BE;

	return isa;
}

bool isa_is_powerpc_family(const char *isa)
{
	const char *normalized = normalize_isa_name(isa);

	if (!normalized)
		return false;

	return !strcmp(normalized, "powerpc") ||
	       !strcmp(normalized, "ppc") ||
	       !strcmp(normalized, "powerpc64") ||
	       !strcmp(normalized, "ppc64") ||
	       !strcmp(normalized, "powerpc64le") ||
	       !strcmp(normalized, "ppc64le");
}

const char *fw_audit_detect_isa(void)
{
	static char detected_isa[32];
	static bool initialized;
	const char *override_isa;
	struct utsname uts;
	const char *normalized;

	if (initialized)
		return detected_isa[0] ? detected_isa : NULL;

	override_isa = getenv("FW_AUDIT_TEST_ISA");
	if (override_isa && *override_isa) {
		normalized = normalize_isa_name(override_isa);
		snprintf(detected_isa, sizeof(detected_isa), "%s", normalized ? normalized : override_isa);
		initialized = true;
		return detected_isa;
	}

	if (uname(&uts) == 0) {
		normalized = normalize_isa_name(uts.machine);
		if (normalized && *normalized)
			snprintf(detected_isa, sizeof(detected_isa), "%s", normalized);
	}

	initialized = true;
	return detected_isa[0] ? detected_isa : NULL;
}

bool fw_audit_isa_supported_for_efi_bios(const char *isa)
{
	const char *normalized = normalize_isa_name(isa);

	if (!normalized)
		return false;

	return !strcmp(normalized, FW_AUDIT_ISA_X86) ||
	       !strcmp(normalized, FW_AUDIT_ISA_X86_64) ||
	       !strcmp(normalized, FW_AUDIT_ISA_AARCH64_BE) ||
	       !strcmp(normalized, FW_AUDIT_ISA_AARCH64_LE);
}

void fw_audit_force_conservative_powerpc_crypto_caps(void)
{
	const char *isa = fw_audit_detect_isa();
	const char *ppccap;

	if (!isa_is_powerpc_family(isa))
		return;

	/*
	 * For PowerPC troubleshooting builds, force OpenSSL onto its most
	 * conservative generic code paths unless the user explicitly overrides the
	 * capability mask. This helps isolate illegal-instruction faults caused by
	 * runtime CPU feature detection or optimized PowerPC crypto dispatch.
	 */
	ppccap = getenv("OPENSSL_ppccap");
	if (!ppccap || !*ppccap)
		setenv("OPENSSL_ppccap", "0", 0);
}
