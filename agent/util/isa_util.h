// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_ISA_UTIL_H
#define UTIL_ISA_UTIL_H

#include <stdbool.h>

/* Normalize an ISA name string to a canonical form. */
const char *normalize_isa_name(const char *isa);

/* Return true if the given ISA string belongs to the PowerPC family. */
bool isa_is_powerpc_family(const char *isa);

/* Install the SIGILL debug handler (no-op in non-DEBUG builds). */
void ela_install_sigill_debug_handler(void);

/* Set the current SIGILL debug stage label. */
void ela_set_sigill_stage(const char *stage);

/* Force conservative OpenSSL crypto caps on PowerPC to avoid SIGILL faults. */
void ela_force_conservative_crypto_caps(void);

#endif /* UTIL_ISA_UTIL_H */
