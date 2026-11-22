// SPDX-License-Identifier: GPL-3.0-only
// See diag_native.h. Read-only: the target stays stopped and untouched; only its memory is read.
#include "diag_native.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

#include <ps5/kernel.h>

#include "diag_scan.h"

#define PAGE 0x4000u
#define IMAGE_CAP (96u << 20) // how much of a module's image is looked at
#define HOLES_MAX 32u         // unmapped pages tolerated inside the image
#define BUDGET_MS 40000u
#define SITES_MAX 4
#define SLOTS_MAX 4
#define FUNCS_MAX 16

static uint64_t now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}

static void hexdump(diag_log_fn log, const uint8_t *p, uint64_t addr, size_t len)
{
    for (size_t i = 0; i < len; i += 32) {
        char line[32 * 3 + 1];
        const size_t n = len - i < 32 ? len - i : 32;
        for (size_t j = 0; j < n; j++) snprintf(line + j * 3, 4, "%02x ", p[i + j]);
        log("  %llx: %s", (unsigned long long)(addr + i), line);
    }
}

// Reads the image mapped from `base`: 16 KiB pages, a few unmapped holes tolerated, at most `cap` bytes.
// Execute-only code, the usual state of a system process's text, is given read permission for the length
// of one read and put back exactly as it was. Returns a calloc'd buffer of *len_out bytes (the pages that
// could not be read stay zero), or NULL when nothing is mapped there. `what` names the module in the log.
static uint8_t *read_image(sl_inject *ctx, intptr_t base, size_t cap, uint64_t t0, const char *what,
                           diag_log_fn log, size_t *len_out)
{
    const pid_t pid = ctx->target_pid;
    *len_out = 0;

    // How far the image reaches: mapped 16 KiB pages from its base, a few holes tolerated.
    const size_t total = cap / PAGE;
    int *prot = malloc(total * sizeof *prot);
    if (!prot) return NULL;
    size_t pages = 0, holes = 0;
    for (size_t i = 0; i < total && holes <= HOLES_MAX; i++) {
        prot[i] = kernel_get_vmem_protection(pid, base + (intptr_t)(i * PAGE), PAGE);
        if (prot[i] < 0) { holes++; continue; }
        holes = 0;
        pages = i + 1;
    }
    if (!pages) { log("diag: nothing is mapped at the base of %s", what); free(prot); return NULL; }
    const size_t len = pages * PAGE;
    uint8_t *img = calloc(1, len);
    if (!img) { free(prot); return NULL; }

    // The protections of the image, as the console reports them.
    int kinds[8];
    size_t kind_pages[8] = {0}, nkinds = 0;
    for (size_t i = 0; i < pages; i++) {
        if (prot[i] < 0) continue;
        size_t k = 0;
        while (k < nkinds && kinds[k] != prot[i]) k++;
        if (k == nkinds && nkinds < 8) kinds[nkinds++] = prot[i];
        if (k < nkinds) kind_pages[k]++;
    }
    for (size_t k = 0; k < nkinds; k++) log("diag: %s: %zu pages with protection 0x%x", what, kind_pages[k], (unsigned)kinds[k]);

    size_t read_ok = 0, mapped = 0, via_prot = 0, unreadable = 0;
    for (size_t i = 0; i < pages; i++) {
        if (prot[i] < 0) continue;
        mapped++;
        if (now() - t0 > BUDGET_MS) { log("diag: time budget spent after %zu of %zu pages", i, pages); break; }
        uint8_t *dst = img + i * PAGE;
        const intptr_t at = base + (intptr_t)(i * PAGE);
        if (sl_inject_read_at(ctx, at, dst, PAGE) == 0 || sl_inject_read_code_at(ctx, at, dst, PAGE) == 0) { read_ok++; continue; }
        // Execute-only code: give the page read permission for the length of one read, then put its
        // protection back exactly as it was, and check that it is.
        if (!(prot[i] & PROT_EXEC)) { unreadable++; continue; }
        if (kernel_set_vmem_protection(pid, at, PAGE, prot[i] | PROT_READ) != 0) { unreadable++; continue; }
        const int rd = sl_inject_read_at(ctx, at, dst, PAGE);
        int back = kernel_set_vmem_protection(pid, at, PAGE, prot[i]);
        if (back != 0 || kernel_get_vmem_protection(pid, at, PAGE) != prot[i]) {
            back = kernel_set_vmem_protection(pid, at, PAGE, prot[i]); // once more
            if (back != 0 || kernel_get_vmem_protection(pid, at, PAGE) != prot[i]) {
                log("diag: could not restore the protection of 0x%llx; stopping here", (unsigned long long)at);
                break;
            }
        }
        if (rd == 0) { read_ok++; via_prot++; } else unreadable++;
    }
    log("diag: %s: image 0x%zx bytes, %zu mapped pages, %zu read (%zu of them with read permission given for the read), %zu not readable",
        what, len, mapped, read_ok, via_prot, unreadable);
    free(prot);
    *len_out = len;
    return img;
}

void diag_native_sequence(sl_inject *ctx, const intptr_t *fn, const char *const *name, size_t count, diag_log_fn log)
{
    const uint64_t t0 = now();
    const pid_t pid = ctx->target_pid;
    const intptr_t base = kernel_dynlib_mapbase_addr(pid, 0); // handle 0: the main executable
    log("diag: SceRemotePlay pid %d, main module base 0x%llx", (int)pid, (unsigned long long)base);
    if (base <= 0 || count == 0 || count > FUNCS_MAX) return;

    size_t len = 0;
    uint8_t *img = read_image(ctx, base, IMAGE_CAP, t0, "SceRemotePlay", log, &len);
    if (!img) return;

    // Where each function's address is stored (the import slots of this module).
    uint64_t want[FUNCS_MAX];
    for (size_t i = 0; i < count; i++) want[i] = (uint64_t)fn[i];
    struct diag_hit hits[64];
    size_t nh = diag_find_qwords(img, len, (uint64_t)base, want, count, hits, 64);
    if (nh > 64) nh = 64;
    uint64_t slots[FUNCS_MAX][SLOTS_MAX];
    size_t nslots[FUNCS_MAX] = {0};
    for (size_t h = 0; h < nh; h++) {
        const size_t f = hits[h].index;
        log("diag: %s (0x%llx) is held at 0x%llx", name[f], (unsigned long long)fn[f], (unsigned long long)hits[h].addr);
        if (nslots[f] < SLOTS_MAX) slots[f][nslots[f]++] = hits[h].addr;
    }

    // The calls that reach each function, and the code leading to them.
    for (size_t f = 0; f < count; f++) {
        if (!nslots[f]) { log("diag: no import slot of this module holds %s", name[f]); continue; }
        struct diag_slot_ref refs[16];
        size_t nr = diag_refs_to_slots(img, len, (uint64_t)base, slots[f], nslots[f], refs, 16);
        if (nr > 16) nr = 16;
        uint64_t sites[SITES_MAX];
        size_t ns = 0;
        for (size_t r = 0; r < nr; r++) {
            if (refs[r].call) {
                if (ns < SITES_MAX) sites[ns++] = refs[r].site;
                continue;
            }
            uint64_t callers[SITES_MAX];
            size_t nc = diag_call_sites(img, len, (uint64_t)base, refs[r].site, callers, SITES_MAX);
            if (nc > SITES_MAX) nc = SITES_MAX;
            log("diag: %s: thunk at 0x%llx (module+0x%llx), %zu callers", name[f], (unsigned long long)refs[r].site,
                (unsigned long long)(refs[r].site - (uint64_t)base), nc);
            for (size_t c = 0; c < nc && ns < SITES_MAX; c++) sites[ns++] = callers[c];
        }
        const size_t before = strcmp(name[f], "sceAvcap2OpenVideo") == 0 ? 0x600 : 0x180, after = 0x20;
        for (size_t s = 0; s < ns; s++) {
            const uint64_t off = sites[s] - (uint64_t)base;
            const size_t start = off > before ? (size_t)(off - before) : 0;
            const size_t end = off + after < len ? (size_t)(off + after) : len;
            log("diag: %s is called at 0x%llx (module+0x%llx); code from module+0x%zx:", name[f],
                (unsigned long long)sites[s], (unsigned long long)off, start);
            hexdump(log, img + start, (uint64_t)base + start, end - start);
        }
        if (!ns) log("diag: %s: no call found", name[f]);
    }
    log("diag: done in %llu ms", (unsigned long long)(now() - t0));
    free(img);
}

intptr_t diag_native_main_base(sl_inject *ctx)
{
    return kernel_dynlib_mapbase_addr(ctx->target_pid, 0); // handle 0: the main executable
}

static int write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    const size_t n = fwrite(data, 1, len, f);
    return fclose(f) == 0 && n == len ? 0 : -1;
}

void diag_native_dump(sl_inject *ctx, const char *dir, diag_log_fn log)
{
    static const struct { const char *module, *file; } images[] = {
        {NULL, "remoteplay-image.bin"},
        {"libSceAvcap2.sprx", "avcap2-image.bin"},
        {"libSceResourceArbitrator.sprx", "arbitrator-image.bin"},
    };
    const uint64_t t0 = now();
    const pid_t pid = ctx->target_pid;
    char path[256];
    snprintf(path, sizeof path, "%s/dump-index.txt", dir);
    FILE *index = fopen(path, "w"); // one line per image: file, module, load address, size
    for (size_t i = 0; i < sizeof images / sizeof *images; i++) {
        const char *what = images[i].module ? images[i].module : "SceRemotePlay";
        const intptr_t base = images[i].module ? sl_module_base(pid, images[i].module) : kernel_dynlib_mapbase_addr(pid, 0);
        if (base <= 0) { log("diag: %s is not loaded in pid %d", what, (int)pid); continue; }
        size_t len = 0;
        uint8_t *img = read_image(ctx, base, IMAGE_CAP, t0, what, log, &len);
        if (!img) continue;
        snprintf(path, sizeof path, "%s/%s", dir, images[i].file);
        if (write_file(path, img, len)) {
            log("diag: could not write %s", path);
        } else {
            log("diag: wrote %s: %zu bytes of %s, loaded at 0x%llx", path, len, what, (unsigned long long)base);
            if (index) fprintf(index, "%s %s base=0x%llx size=0x%zx\n", images[i].file, what, (unsigned long long)base, len);
        }
        free(img);
    }
    if (index) fclose(index);
    log("diag: images done in %llu ms", (unsigned long long)(now() - t0));
}

// The window of the target's address space where its heap lives (a 1 MiB allocation of SceRemotePlay came
// from 0x8808...); direct memory and the device mappings are left alone.
#define SCAN_LO 0x800000000ull
#define SCAN_HI 0xa00000000ull
#define SCAN_STEP (2u << 20)
#define SCAN_BUDGET_MS 2500u
#define SCAN_FOUND_MAX 8u

static int prot_is_rw(int prot)
{
    return prot >= 0 && ((uint32_t)prot & 0x80000002u) == 2u; // the same test inject.c uses for its scratch
}

size_t diag_native_find_blocks(sl_inject *ctx, diag_log_fn log, diag_block_fn found, void *user)
{
    const uint64_t t0 = now();
    const pid_t pid = ctx->target_pid;
    uint8_t *chunk = malloc(SCAN_STEP);
    struct diag_block *b = calloc(1, sizeof *b);
    if (!chunk || !b) { free(chunk); free(b); return 0; }
    size_t nfound = 0, steps = 0, bytes = 0, unreadable = 0;
    uint64_t at = SCAN_LO;
    for (; at < SCAN_HI; at += SCAN_STEP) {
        if (now() - t0 > SCAN_BUDGET_MS) { log("diag: scan: time budget spent at 0x%llx", (unsigned long long)at); break; }
        if (!prot_is_rw(kernel_get_vmem_protection(pid, (intptr_t)at, PAGE))) continue;
        steps++;
        size_t got = SCAN_STEP;
        if (sl_inject_read_at(ctx, (intptr_t)at, chunk, SCAN_STEP) != 0) { // part of the 2 MiB is not mapped: page by page
            got = 0;
            for (size_t off = 0; off < SCAN_STEP; off += PAGE) {
                if (sl_inject_read_at(ctx, (intptr_t)(at + off), chunk + off, PAGE) == 0) got += PAGE;
                else { memset(chunk + off, 0, PAGE); unreadable++; }
            }
        }
        bytes += got;
        for (size_t i = 0; i + 0x20 <= SCAN_STEP; i += 8) {
            uint64_t q0, q1;
            uint32_t variant;
            memcpy(&q0, chunk + i, 8);
            if (q0 != 0x2e8) continue;
            memcpy(&q1, chunk + i + 8, 8);
            memcpy(&variant, chunk + i + 0x14, 4);
            if (q1 != 0x28 || (variant != 2 && variant != 6)) continue;
            if (nfound++ >= SCAN_FOUND_MAX) continue;
            memset(b, 0, sizeof *b);
            b->addr = at + i;
            b->have_block = sl_inject_read_at(ctx, (intptr_t)(b->addr - 8), b->block, sizeof b->block) == 0;
            b->have_before = sl_inject_read_at(ctx, (intptr_t)(b->addr - 0x240), b->before, sizeof b->before) == 0;
            b->have_after = sl_inject_read_at(ctx, (intptr_t)(b->addr + 0x2003a0), b->after, sizeof b->after) == 0;
            found(user, b);
        }
    }
    log("diag: scan: %zu mapped writable steps of 2 MiB looked at (%zu bytes read, %zu pages unreadable), %zu blocks, %llu ms",
        steps, bytes, unreadable, nfound, (unsigned long long)(now() - t0));
    free(chunk);
    free(b);
    return nfound;
}
