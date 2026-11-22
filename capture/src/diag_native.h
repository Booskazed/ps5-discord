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

// A live copy of the encoder parameter block in the target's memory, with what surrounds it (see
// diag_native_find_blocks). Offsets follow helper.c: the block starts with the 8-byte output slot, and the
// qword 0x2e8 is at offset 8.
struct diag_block {
    uint64_t addr;           // where the qword 0x2e8 is (offset 8 of the block)
    uint8_t block[0x2f0];    // the block: addr - 8 up to addr + 0x2e8
    uint8_t before[0x238];   // the 0x238 bytes before the block (the Glint object's head; the session's fields)
    uint8_t after[0x80];     // the 0x80 bytes at addr + 0x2003a0 (the Glint object's tail; the session's)
    int have_block, have_before, have_after;
};
typedef void (*diag_block_fn)(void *user, const struct diag_block *b);

// Looks for live copies of the parameter block SceRemotePlay's own session keeps while it streams: in the
// target's writable memory (the heap windows, 1 MiB at a time, about 4 s at most), wherever the qword 0x2e8 is
// followed by the qword 0x28 and the encoder variant (2 or 6) sits where the block puts it. Calls `found` for
// each (at most 8), and returns how many there were. Read-only: the target stays stopped and untouched; only
// its memory is read. Console only.
size_t diag_native_find_blocks(sl_inject *ctx, diag_log_fn log, diag_block_fn found, void *user);
