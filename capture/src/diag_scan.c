// SPDX-License-Identifier: GPL-3.0-only
#include "diag_scan.h"

#include <string.h>

size_t diag_find_qwords(const uint8_t *data, size_t len, uint64_t base, const uint64_t *values, size_t nvalues,
                        struct diag_hit *out, size_t cap)
{
    size_t found = 0;
    for (size_t i = (size_t)((8 - (base & 7)) & 7); i + 8 <= len; i += 8) {
        uint64_t word;
        memcpy(&word, data + i, 8);
        for (size_t v = 0; v < nvalues; v++) {
            if (word != values[v]) continue;
            if (found < cap) out[found] = (struct diag_hit){.addr = base + i, .index = v};
            found++;
        }
    }
    return found;
}

size_t diag_refs_to_slots(const uint8_t *code, size_t len, uint64_t base, const uint64_t *slots, size_t nslots,
                          struct diag_slot_ref *out, size_t cap)
{
    size_t found = 0;
    for (size_t i = 0; i + 6 <= len; i++) {
        if (code[i] != 0xff || (code[i + 1] != 0x15 && code[i + 1] != 0x25)) continue;
        int32_t disp;
        memcpy(&disp, code + i + 2, 4);
        const uint64_t slot = base + i + 6 + (uint64_t)(int64_t)disp;
        for (size_t s = 0; s < nslots; s++) {
            if (slot != slots[s]) continue;
            if (found < cap) out[found] = (struct diag_slot_ref){.site = base + i, .slot = slot, .call = code[i + 1] == 0x15};
            found++;
            break;
        }
    }
    return found;
}

size_t diag_call_sites(const uint8_t *code, size_t len, uint64_t base, uint64_t target, uint64_t *out, size_t cap)
{
    size_t found = 0;
    for (size_t i = 0; i + 5 <= len; i++) {
        if (code[i] != 0xe8) continue;
        int32_t rel;
        memcpy(&rel, code + i + 1, 4);
        if (base + i + 5 + (uint64_t)(int64_t)rel != target) continue;
        if (found < cap) out[found] = base + i;
        found++;
    }
    return found;
}
