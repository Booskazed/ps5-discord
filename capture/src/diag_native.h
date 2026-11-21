// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <stddef.h>

#include "inject.h"

typedef void (*diag_log_fn)(const char *fmt, ...);

// Diagnostic for a firmware where the console's encoder refuses the parameters this helper builds
// (13.60: sceAvcap2OpenVideo answers 0x81950008): finds how SceRemotePlay's own code calls the same
// functions and logs the code leading to each call, so the sequence and the parameter block it builds
// can be read and compared. Read-only: it only reads the stopped target's memory. fn[]/name[] are the
// resolved functions to look for. Console only (needs the SDK's kernel calls).
void diag_native_sequence(sl_inject *ctx, const intptr_t *fn, const char *const *name, size_t count, diag_log_fn log);

// Writes the mapped images of SceRemotePlay's main module and of the two libraries it calls here
// (libSceAvcap2, libSceResourceArbitrator) into `dir`, with an index of their load addresses, so that
// the parameter block the encoder checks and the calls around it can be read offline in full, not
// only the few hundred bytes the log shows. Read-only toward the target, like the sequence above;
// the files stay on the console and are never published. Console only.
void diag_native_dump(sl_inject *ctx, const char *dir, diag_log_fn log);

// The load address of the target's main module (0 when unknown). Console only.
intptr_t diag_native_main_base(sl_inject *ctx);
