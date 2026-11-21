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
