// SPDX-License-Identifier: GPL-3.0-only
// Pure scanners over a copy of a module's image (x86-64), for the capture diagnostic
// (diag_native.c): where a function's address is stored (an import slot), which instructions reach
// that slot, and which calls reach such a thunk. No I/O: the tests run them on made-up bytes.
#pragma once
#include <stddef.h>
#include <stdint.h>

struct diag_hit { uint64_t addr; size_t index; }; // where value #index was found
struct diag_slot_ref { uint64_t site, slot; int call; }; // call [rip+d] (call=1) or jmp [rip+d] (call=0)

// Aligned 8-byte words of data (loaded at base) equal to one of values[]. Returns how many were
// found; out holds the first cap of them.
size_t diag_find_qwords(const uint8_t *data, size_t len, uint64_t base, const uint64_t *values, size_t nvalues,
                        struct diag_hit *out, size_t cap);

// `call [rip+d]` (FF 15) and `jmp [rip+d]` (FF 25) whose slot is one of slots[].
size_t diag_refs_to_slots(const uint8_t *code, size_t len, uint64_t base, const uint64_t *slots, size_t nslots,
                          struct diag_slot_ref *out, size_t cap);

// `call rel32` (E8) whose target is `target`: the call sites, as addresses.
size_t diag_call_sites(const uint8_t *code, size_t len, uint64_t base, uint64_t target, uint64_t *out, size_t cap);
