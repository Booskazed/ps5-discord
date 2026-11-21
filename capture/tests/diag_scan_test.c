// SPDX-License-Identifier: GPL-3.0-only
// The diagnostic's pure scanners on made-up x86-64 bytes.
#include <assert.h>
#include <string.h>

#include "../src/diag_scan.h"

int main(void)
{
    const uint64_t base = 0x1000;
    uint8_t code[64];
    memset(code, 0x90, sizeof code);
    // call [rip+0x100] at base+4: the slot is base+4+6+0x100 = 0x110a.
    memcpy(code + 4, (const uint8_t[]){0xff, 0x15, 0x00, 0x01, 0x00, 0x00}, 6);
    // jmp [rip-0x10] at base+16 (a PLT thunk): the slot is base+16+6-0x10 = 0x1006.
    memcpy(code + 16, (const uint8_t[]){0xff, 0x25, 0xf0, 0xff, 0xff, 0xff}, 6);
    // call rel32 at base+30 to the thunk at 0x1010: rel = 0x1010 - (0x1000+30+5) = -0x13.
    memcpy(code + 30, (const uint8_t[]){0xe8, 0xed, 0xff, 0xff, 0xff}, 5);
    // The same 8-byte value twice: aligned (base+40 = 0x1028) and not (offset 49).
    memcpy(code + 40, (const uint8_t[]){0xef, 0xbe, 0xad, 0xde, 0, 0, 0, 0}, 8);
    memcpy(code + 49, (const uint8_t[]){0xef, 0xbe, 0xad, 0xde, 0, 0, 0, 0}, 8);

    struct diag_slot_ref refs[4];
    const uint64_t both[] = {0x110a, 0x1006};
    assert(diag_refs_to_slots(code, sizeof code, base, both, 2, refs, 4) == 2);
    assert(refs[0].site == 0x1004 && refs[0].slot == 0x110a && refs[0].call == 1);
    assert(refs[1].site == 0x1010 && refs[1].slot == 0x1006 && refs[1].call == 0);
    assert(diag_refs_to_slots(code, sizeof code, base, both, 1, refs, 4) == 1);
    assert(diag_refs_to_slots(code, sizeof code, base, (const uint64_t[]){0x5555}, 1, refs, 4) == 0);

    uint64_t sites[4];
    assert(diag_call_sites(code, sizeof code, base, 0x1010, sites, 4) == 1 && sites[0] == 0x101e);
    assert(diag_call_sites(code, sizeof code, base, 0x1011, sites, 4) == 0);

    struct diag_hit hits[4];
    const uint64_t values[] = {0x1234, 0xdeadbeef};
    assert(diag_find_qwords(code, sizeof code, base, values, 2, hits, 4) == 1);
    assert(hits[0].addr == 0x1028 && hits[0].index == 1);
    // A base that is not 8-aligned shifts which words count: 0x1004+36 = 0x1028 stays aligned.
    assert(diag_find_qwords(code + 4, sizeof code - 4, base + 4, values, 2, hits, 4) == 1 && hits[0].addr == 0x1028);

    // Patterns cut off by the end of the buffer are not read past it.
    assert(diag_refs_to_slots(code + 4, 5, base + 4, both, 2, refs, 4) == 0);
    assert(diag_call_sites(code + 30, 4, base + 30, 0x1010, sites, 4) == 0);

    // More matches than room: all are counted, the first cap are stored.
    uint8_t words[24];
    for (int i = 0; i < 3; i++) memcpy(words + i * 8, (const uint8_t[]){7, 0, 0, 0, 0, 0, 0, 0}, 8);
    const uint64_t seven[] = {7};
    assert(diag_find_qwords(words, sizeof words, 0x2000, seven, 1, hits, 2) == 3 && hits[1].addr == 0x2008);
    return 0;
}
