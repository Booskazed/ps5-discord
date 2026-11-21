// SPDX-License-Identifier: GPL-3.0-only
// discord-capture.elf: the wireless Go Live backend's helper. It borrows the console's own
// hardware H.264 encoder (Avcap2) through calls made inside SceRemotePlay, with the sequence
// the PoC (ps5-encoder-poc, tools/encoder-probe/capture_record.c) proved on the console, and
// sends the video over a loopback socket to the core (src/capture_bc.c, protocol in
// src/capture_proto.h). It starts no Remote Play client session, takes no controller and
// changes no display setting. Video only: the core captures the game's sound itself.
//
// Process model (as the PoC): the main process is a small supervisor; the work runs in a forked
// child on a 2 MiB thread stack. The supervisor's watchdog asks the child to clean up after 15 s
// without progress and kills only the child after 25 s. There is no total duration: Go Live is
// open-ended, the core ends it by a CAP_STOP or by closing the socket.
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>
#include <unistd.h>

#include "capture_proto.h"
#include "inject.h"
#include "inject_broker.h"
#include "h264_timing.h"
#ifdef SL_PS5
#include <sys/sysctl.h>
#include "diag_native.h"
#endif
#ifdef SL_PS5
int sceKernelSetProcessName(const char *name); // the SDK's kernel header does not declare it
#endif

#ifndef CAP_DIR
#define CAP_DIR APP_DATA_DIR // capture_proto.h: the stock folder, or the side-by-side edition's
#endif
#ifndef CONN_FILE
#define CONN_FILE CAP_CONN_FILE
#endif
#ifndef LOCK_PATH
#define LOCK_PATH CAP_LOCK_FILE
#endif
#ifndef LOG_PATH
#define LOG_PATH CAP_DIR "/capture.log"
#endif
// Mode 0x40 is the output mode Glint treats as 120 Hz. The PoC refused it (its baseline) and
// only experiments allowed it; no capture was ever shown to work in it, so production refuses.
#ifndef ALLOW_MODE_40
#define ALLOW_MODE_40 0
#endif
#define FRAME_CAP 0x100000u
#define FEATURE 12u
#ifndef START_WAIT_MS
#define START_WAIT_MS CAP_STARTUP_MS
#endif
#define SEND_STALL_MS 5000u
#ifndef MODE_POLL_MS
#define MODE_POLL_MS 1000u
#endif
#ifndef RECOVERY_MAX
#define RECOVERY_MAX 4
#define RECOVERY_WINDOW_MS 60000
#endif
#ifndef NO_PICTURE_MS
#define NO_PICTURE_MS CAP_PICTURE_MS
#endif
#ifndef MODE_WAIT_MS
#define MODE_WAIT_MS CAP_MODE_WAIT_MS // a transitional or changing output mode is waited out this long
#endif

enum function {
    INITIALIZE, TERMINATE, MODE, ENABLE_SCAN, OPEN_VIDEO, START, STOP, CLOSE, BITRATE_SET, HEADERS,
    KEYFRAME, READ_VIDEO, SET_CALLBACK, CHANGE_STATE, CLEAR_CALLBACK, REMOTE_GETPID, REMOTE_MALLOC,
    REMOTE_FREE, REMOTE_MEMSET, FUNCTION_COUNT
};
static const char *const symbols[FUNCTION_COUNT] = {
    "sceAvcap2Initialize", "sceAvcap2Terminate", "sceAvcap2GetVideoOutMode",
    "sceAvcap2EnableScanInEncode", "sceAvcap2OpenVideo", "sceAvcap2Start", "sceAvcap2Stop",
    "sceAvcap2Close", "sceAvcap2SetVideoBitrate", "sceAvcap2GetNonVclNalUnitStream",
    "sceAvcap2RequestKeyFrame", "sceAvcap2ReadVideo", "sceResourceArbitratorSetCallback",
    "sceResourceArbitratorChangeState", "sceResourceArbitratorClearCallback", "getpid", "malloc", "free", "memset"
};

struct progress { _Atomic int function, target; _Atomic uint64_t heartbeat_ms; };
static struct progress *progress;
static _Atomic int quit;
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal cancellation must be lock-free");
static FILE *log_file;

static uint64_t now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}

static void beat(void)
{
    if (progress) atomic_store(&progress->heartbeat_ms, now_ms());
}

static void log_line(const char *fmt, ...)
{
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
#ifdef CAPTURE_QUIET
    FILE *files[] = {log_file};
#else
    FILE *files[] = {stderr, log_file};
#endif
    for (unsigned i = 0; i < sizeof files / sizeof *files; i++)
        if (files[i]) {
            fprintf(files[i], "[capture pid=%d ms=%llu] %s\n", getpid(), (unsigned long long)now_ms(), line);
            fflush(files[i]);
        }
}

// ---- the socket to the core ---------------------------------------------------------------

static int net_fd = -1;
static int net_dead;          // the core closed, or the socket failed: end the session
static int stop_requested;    // CAP_STOP
static int key_requested;     // CAP_KEYFRAME, not yet passed to the encoder
static uint8_t inbox[64];
static size_t inbox_len;

// Closing with unread data from the core would send a reset and could discard the last state
// message we just wrote: finish our side, drain theirs briefly, then close.
static void net_close(void)
{
    if (net_fd >= 0) {
        uint8_t sink[256];
        shutdown(net_fd, SHUT_WR);
        for (unsigned i = 0; i < 4; i++) {
            struct pollfd pf = {.fd = net_fd, .events = POLLIN};
            if (poll(&pf, 1, 50) <= 0 || recv(net_fd, sink, sizeof sink, MSG_DONTWAIT) <= 0) break;
        }
        close(net_fd);
    }
    net_fd = -1;
}

// Everything is sent whole or the connection counts as dead. Never blocks for ever: the
// supervisor's watchdog would kill the worker mid-session otherwise.
static int net_send_raw(const uint8_t *p, size_t n)
{
    uint64_t begin = now_ms();
    while (n && !net_dead) {
        ssize_t w = send(net_fd, p, n, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (w > 0) { p += w; n -= (size_t)w; beat(); continue; }
        if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { net_dead = 1; break; }
        if (now_ms() - begin > SEND_STALL_MS) { log_line("socket send stalled"); net_dead = 1; break; }
        struct pollfd pf = {.fd = net_fd, .events = POLLOUT};
        poll(&pf, 1, 50);
        beat();
    }
    return net_dead ? -1 : 0;
}

// Header and payload; payload may be NULL when len is 0.
static int net_send(uint8_t type, uint8_t flags, const uint8_t *payload, uint32_t len)
{
    uint8_t h[CAP_HEADER_BYTES];
    cap_pack_header(h, type, flags, len);
    if (net_fd < 0 || net_dead) return -1;
    if (net_send_raw(h, sizeof h) || (len && net_send_raw(payload, len))) return -1;
    return 0;
}

// A video frame read straight behind its own header, one send.
static int net_send_inplace(uint8_t *buf, uint8_t type, uint8_t flags, uint32_t len)
{
    cap_pack_header(buf, type, flags, len);
    return net_fd < 0 || net_dead ? -1 : net_send_raw(buf, CAP_HEADER_BYTES + len);
}

static int net_state(enum cap_state s, const char *text)
{
    uint8_t m[1 + 120];
    size_t t = text ? strlen(text) : 0;
    if (t > 120) t = 120;
    m[0] = (uint8_t)s;
    if (t) memcpy(m + 1, text, t);
    return net_send(CAP_STATE, 0, m, (uint32_t)(1 + t));
}

struct start_req { uint32_t selector, fps_flag, bitrate, width, height, fps; };

// What the core sent, if anything, without waiting. Returns when the socket has nothing more.
// Only three messages exist and all are tiny; anything else ends the connection.
static void net_poll(struct start_req *start, int *got_start, int wait_ms)
{
    while (net_fd >= 0 && !net_dead) {
        struct pollfd pf = {.fd = net_fd, .events = POLLIN};
        int r = poll(&pf, 1, wait_ms);
        wait_ms = 0;
        if (r <= 0) return;
        ssize_t n = recv(net_fd, inbox + inbox_len, sizeof inbox - inbox_len, MSG_DONTWAIT);
        if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) { net_dead = 1; return; }
        if (n < 0) return;
        inbox_len += (size_t)n;
        for (;;) {
            cap_header h;
            if (inbox_len < CAP_HEADER_BYTES) break;
            if (cap_parse_header(inbox, &h) || h.len > sizeof inbox - CAP_HEADER_BYTES) { net_dead = 1; return; }
            if (inbox_len < CAP_HEADER_BYTES + h.len) break;
            const uint8_t *p = inbox + CAP_HEADER_BYTES;
            if (h.type == CAP_STOP) stop_requested = 1;
            else if (h.type == CAP_KEYFRAME) key_requested = 1;
            else if (h.type == CAP_START && h.len == 24 && start && !*got_start) {
                start->selector = cap_get32(p), start->fps_flag = cap_get32(p + 4);
                start->bitrate = cap_get32(p + 8), start->width = cap_get32(p + 12);
                start->height = cap_get32(p + 16), start->fps = cap_get32(p + 20);
                *got_start = 1;
            } else { net_dead = 1; return; }
            memmove(inbox, inbox + CAP_HEADER_BYTES + h.len, inbox_len - CAP_HEADER_BYTES - h.len);
            inbox_len -= CAP_HEADER_BYTES + h.len;
        }
    }
}

// "<port> <token hex>\n", written by the core before it launched us.
static int net_connect(void)
{
    char text[80] = {0};
    FILE *f = fopen(CONN_FILE, "r");
    if (!f) { log_line("no %s", CONN_FILE); return -1; }
    size_t n = fread(text, 1, sizeof text - 1, f);
    fclose(f);
    text[n] = 0;
    unsigned port = 0;
    char hex[2 * CAP_TOKEN_BYTES + 1] = {0};
    if (sscanf(text, "%u %32s", &port, hex) != 2 || !port || port > 65535 || strlen(hex) != 2 * CAP_TOKEN_BYTES) {
        log_line("bad connection file");
        return -1;
    }
    uint8_t hello[4 + CAP_TOKEN_BYTES];
    cap_put32(hello, CAP_VERSION);
    for (unsigned i = 0; i < CAP_TOKEN_BYTES; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        hello[4 + i] = (uint8_t)v;
    }
    net_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (net_fd < 0 || connect(net_fd, (struct sockaddr *)&a, sizeof a) != 0) {
        log_line("connect to the core failed (errno %d)", errno);
        net_close();
        return -1;
    }
    // Console 2026-11-09: frames left the encoder every 33 ms but reached the core in pairs
    // (Nagle holding each frame's tail until the previous one was acknowledged). Send at once.
    int one = 1;
    (void)setsockopt(net_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return net_send(CAP_HELLO, 0, hello, sizeof hello);
}

// ---- Annex-B checks (derived from the PoC's record_file.c) ---------------------------------

static uint32_t le32(const uint8_t *p) { return cap_get32(p); }

static int has_nal(const uint8_t *p, size_t n, unsigned type)
{
    for (size_t i = 0; i + 3 < n; i++)
        if (!p[i] && !p[i + 1] && p[i + 2] == 1 && (p[i + 3] & 31) == type) return 1;
    return 0;
}

static int annexb_ok(const uint8_t *p, size_t n)
{
    return n >= 4 && p[0] == 0 && p[1] == 0 && (p[2] == 1 || (n > 4 && p[2] == 0 && p[3] == 1));
}

// The real SPS/PPS from the encoder's header blob (SPS length at 0x10, bytes at 0x18; PPS
// length at 0x98, bytes at 0xa0) as Annex-B, or -1. Nothing is guessed or hardcoded.
static int headers_annexb(const uint8_t *h, size_t n, uint8_t *out, size_t cap, size_t *len)
{
    if (n < 0xa4) return -1;
    uint32_t sps = le32(h + 0x10), pps = le32(h + 0x98);
    if (sps < 5 || sps > 128 || pps < 2 || pps > 128 || 0x18u + sps > n || 0xa0u + pps > n ||
        (h[0x18] & 31) != 7 || (h[0xa0] & 31) != 8 || cap < 8u + sps + pps) return -1;
    static const uint8_t prefix[] = {0, 0, 0, 1};
    size_t m = 0;
    memcpy(out + m, prefix, 4); m += 4;
    memcpy(out + m, h + 0x18, sps); m += sps;
    memcpy(out + m, prefix, 4); m += 4;
    memcpy(out + m, h + 0xa0, pps); m += pps;
    *len = m;
    return 0;
}

// ---- the capture session in SceRemotePlay --------------------------------------------------

// The two buffer descriptors (0x20 bytes each) the encoder service answers to the buffer query on 13.60.
struct buffers { uint8_t out1[0x20], out2[0x20]; };
// Which parameter block open_encoder() writes: 13.00's, or 13.60's without or with the two buffer descriptors.
enum open_kind { OPEN_13_00, OPEN_13_60, OPEN_13_60_BUFFERS };

struct capture {
    sl_inject ctx;
    enum open_kind kind;             // the block that opened the encoder (to open it again) and its descriptors
    struct buffers bufs;
    intptr_t fn[FUNCTION_COUNT];
    uint64_t video, remote_frame, startup_deadline;
    int startup_done, video_unknown;
    int initialized, callback, video_open, video_start_attempted, cleanup, failed, cleanup_failed;
    uint32_t output_mode, final_mode;
    uint32_t feature;                // the id registered with the resource arbitrator (and written in the block)
    uint32_t variant;                // the encoder variant written in 13.60's block
};

// One result per session; the supervisor never conflates capture and cleanup.
struct session_result {
    uint64_t begin_ms, last_video_ms;
    unsigned frames;
    uint32_t api_error, initial_mode, final_mode, stable_mode;
    int cleanup_ok, transport_failed, refused_mode;
    char why[100];
};
static struct session_result segment;

static int64_t remote(struct capture *c, enum function id, const uint64_t args[6])
{
    if (!c->cleanup) {
        net_poll(NULL, &(int){1}, 0);
        if (quit || net_dead || stop_requested || (!c->startup_done && now_ms() >= c->startup_deadline))
            return SL_CALL_ERROR;
    }
    if (c->ctx.quarantined && !(c->cleanup && c->ctx.aborted_restored)) { c->failed = 1; return SL_CALL_ERROR; }
    if (progress) progress->function = id + 1;
    if (id != READ_VIDEO && (id != MODE || !c->startup_done)) log_line("calling %s", symbols[id]);
    // Preserve the pinned borrowed LWP's general and extended CPU state across media calls.
    int64_t rc = c->cleanup ? sl_inject_cleanup_call(&c->ctx, c->fn[id], args) :
                            inj_call_fast(&c->ctx, c->fn[id], args, 1);
    if (progress) progress->function = 0;
    beat();
    if (id != READ_VIDEO && (id != MODE || !c->startup_done)) log_line("%s returned 0x%llx", symbols[id], (unsigned long long)rc);
    if (rc == SL_CALL_ERROR) {
        log_line("transport failure in %s; stage=%s quarantined=%d", symbols[id],
                 c->ctx.stage ? c->ctx.stage : "unknown", c->ctx.quarantined);
        c->failed = 1;
    }
    return rc;
}
#define REMOTE(c, id, ...) remote(c, id, (const uint64_t[6]){__VA_ARGS__})
static int good(int64_t rc) { return rc != SL_CALL_ERROR && (int32_t)rc >= 0; }
static void put32(uint8_t *p, size_t at, uint32_t n) { memcpy(p + at, &n, 4); }
static void put64(uint8_t *p, size_t at, uint64_t n) { memcpy(p + at, &n, 8); }

// Offsets in Glint's scratch block include its leading output-session qword. Selector 3 is
// 720p and 4 is 1080p (native firmware construction at 0x6f8fe/0x6f964); the fps flag is 0 for
// 30 and 1 for 60. Width, height, rate budget and the actual output mode are written
// independently: changing the dimensions alone does not suffice. `size` is the block's own size
// field (0x2e0 as 13.00 wrote it) and `feature` the resource arbitrator id the block names.
static void video_params(uint8_t p[0x2e8], uint32_t mode, const struct start_req *r, uint32_t feature, uint32_t size)
{
    memset(p, 0, 0x2e8);
    put32(p, 8, size); put32(p, 0x10, 0x28);
    put32(p, 0x1c, 2);
    put32(p, 0x20, r->selector);
    put32(p, 0x24, r->fps_flag);
    put32(p, 0x2c, 0); // H.264
    put32(p, 0x30, feature);
    put64(p, 0xc0, 0xe0); put64(p, 0xc8, 0x20);
    put32(p, 0xd0, r->bitrate); put32(p, 0xd4, r->bitrate);
    put32(p, 0xd8, (uint32_t)((r->bitrate * 1001ull + r->fps * 1000u - 1) / (r->fps * 1000u)));
    put32(p, 0xdc, 18); put32(p, 0xe0, 0x33);
    put64(p, 0x1f0, 0xf8); put64(p, 0x1f8, 0x28);
    put32(p, 0x210, r->width); put32(p, 0x214, r->height);
    put64(p, 0x220, 0x88); memset(p + 0x228, 0xff, 0x80);
    put32(p, 0x2a8, mode); put32(p, 0x2ac, 2);
    put64(p, 0x2b0, 0x10); put32(p, 0x2b4, 1); p[0x2bc] = 1;
}

static int bind_functions(struct capture *c)
{
    for (unsigned i = 0; i < FUNCTION_COUNT; i++) {
        const char *module = i >= REMOTE_MALLOC ? "libSceLibcInternal.sprx" :
                             i == REMOTE_GETPID ? "libkernel_sys.sprx" :
                             i >= SET_CALLBACK ? "libSceResourceArbitrator.sprx" : "libSceAvcap2.sprx";
        c->fn[i] = sl_resolve_in(c->ctx.target_pid, module, symbols[i]);
        if (c->fn[i] <= 0 && i == REMOTE_MEMSET) { // only the 13.60 stream buffer needs it; never a reason to refuse
            log_line("no %s in %s: the 13.60 stream buffer will not be filled", symbols[i], module);
            continue;
        }
        if (c->fn[i] <= 0) { log_line("missing %s in %s", symbols[i], module); return -1; }
    }
    return 0;
}

static int read_mode(struct capture *c, uint32_t *mode)
{
    intptr_t at = c->ctx.scratch + 0x700;
    *mode = 0;
    if (sl_inject_write_at(&c->ctx, at, mode, sizeof *mode) || !good(REMOTE(c, MODE, at)) ||
        sl_inject_read_at(&c->ctx, at, mode, sizeof *mode)) return -1;
    return 0;
}

// Poll the existing output-mode query every 100 ms for at most budget_ms; three equal nonzero
// readings are stable. The values are opaque and identify neither HDR nor refresh rate.
static int wait_stable_mode(struct capture *c, uint32_t *stable, unsigned budget_ms)
{
    uint64_t deadline = now_ms() + budget_ms;
    uint32_t previous = 0;
    unsigned equal = 0;
    log_line("WAIT_STABLE (%u ms, three nonzero equal samples)", budget_ms);
    while (!quit && !net_dead && !stop_requested && !c->ctx.quarantined && now_ms() < deadline) {
        uint32_t mode;
        if (read_mode(c, &mode)) return -1;
        log_line("output mode sample=0x%x", mode);
        equal = mode && mode == previous ? equal + 1 : mode ? 1 : 0;
        previous = mode;
        if (equal >= 3) { *stable = mode; return 0; }
        usleep(100000);
        beat();
        net_poll(NULL, &(int){1}, 0);
    }
    log_line("stable mode unavailable within the deadline");
    return -1;
}

// Which firmware this runs on: kern.sdk_version >> 16 (0x1300 is 13.00, 0x1360 is 13.60). The sequence in this
// file was validated on 13.00. On 13.60 (upstream issue #11) sceAvcap2OpenVideo answers 0x81950008 to the 13.00
// block, whatever the arbitrator id, process id, size field or EnableScanInEncode; open_1360() below follows what
// SceRemotePlay's own code does there. The host tests stand for 13.00 unless they say otherwise.
#ifdef CAPTURE_FW_OVERRIDE
static unsigned fw_override = 0x1300;
#endif
static int firmware_is_13_60(void)
{
#ifdef CAPTURE_FW_OVERRIDE
    return fw_override == 0x1360;
#elif defined(SL_PS5)
    uint32_t sdk = 0;
    size_t len = sizeof sdk;
    return sysctlbyname("kern.sdk_version", &sdk, &len, NULL, 0) == 0 && len == sizeof sdk && (sdk >> 16) == 0x1360;
#else
    return 0;
#endif
}

// SceRemotePlay's own code asks again when sceAvcap2OpenVideo answers 0x81950008 (it waits up to 4 s,
// 16 ms apart, reading the output mode again each time). So does this, with a longer step to spare the log.
#define OPEN_BUSY 0x81950008u
#ifndef OPEN_RETRIES
#define OPEN_RETRIES 16u
#define OPEN_RETRY_US 250000u
#endif

static float bits_float(uint32_t b) { float f; memcpy(&f, &b, sizeof f); return f; }
static double bits_double(uint64_t b) { double d; memcpy(&d, &b, sizeof d); return d; }

// The 13.60 parameter block as SceRemotePlay builds it for H.264, read from its code and read-only data (the block
// builder, SetParams and OpenVideo's caller at module+0x6f840, +0x70190 and +0x704c0 of its image). libSceAvcap2
// 13.60 sends the block as a 0x2e8-byte buffer behind the 8-byte output slot, so this is 0x2f0 bytes, with the
// same convention as video_params(): offsets include the output slot. What SceRemotePlay takes from its session's
// settings is not known and is chosen: NATIVE_CAP_BUDGET (a cap on the picture budget) and NATIVE_CAP_BUFFER (a
// cap on two sizes derived from the bitrate). The surface it describes (384 wide, 352 high, pitch 512, 278528
// bytes) comes out the same for selectors 3 and 4: it is computed from constants, not from the picture size.
// `bufs`, when given, are the descriptors the service answered; they go at offsets 0x1b8 and 0x1d8.
#define NATIVE_CAP_BUDGET 0xffffu
#define NATIVE_CAP_BUFFER 8192u
static void video_params_1360(uint8_t p[0x2f0], uint32_t mode, const struct start_req *r, uint32_t feature,
                              uint32_t variant, const struct buffers *bufs)
{
    const uint32_t kbps = r->bitrate / 1000u, bps = kbps * 1000u;
    const uint32_t per_frame = (uint32_t)((uint64_t)bps * 1001u / (r->fps * 1000u)); // floor(kbps * 1001 / fps)
    uint32_t budget = (uint32_t)(((uint64_t)(0x3c000u / r->fps) * 0x4444445u) >> 32); // 136 at 30 fps, 68 at 60
    if (budget > NATIVE_CAP_BUDGET) budget = NATIVE_CAP_BUDGET;
    const float divided = (float)bps / bits_float(0x3f8f5c29u); // the rate over 1.12, as a single
    uint32_t first = (uint32_t)(int64_t)(kbps * bits_double(0x3fd0c49ba5e353f8ull) + bits_double(0x4091a7999999999aull));
    uint32_t second = (uint32_t)(int64_t)(kbps * bits_double(0x3fcaeb1c432ca57aull) + bits_double(0x408157d70a3d70a4ull));
    if (first > NATIVE_CAP_BUFFER) first = NATIVE_CAP_BUFFER;
    if (second > NATIVE_CAP_BUFFER) second = NATIVE_CAP_BUFFER;
    memset(p, 0, 0x2f0);
    put64(p, 0x08, 0x2e8); put64(p, 0x10, 0x28);
    put32(p, 0x1c, variant); // the encoder variant SceRemotePlay's session configures (2 here; 6 is the other it tests for)
    put32(p, 0x20, r->selector); put32(p, 0x24, r->fps_flag);
    put32(p, 0x30, feature);
    put64(p, 0x38, 0x58); put64(p, 0x40, 0x18);
    p[0x48] = 1; put32(p, 0x4c, budget); put32(p, 0x50, 1); put32(p, 0x54, NATIVE_CAP_BUFFER);
    put64(p, 0x58, 0x10); p[0x60] = 1; put32(p, 0x64, 9);
    put64(p, 0x68, 0x18); p[0x70] = 1;
    put64(p, 0x90, 0x30);
    put64(p, 0xc0, 0xe8); put64(p, 0xc8, 0x20);
    put32(p, 0xd0, (uint32_t)(int64_t)divided); put32(p, 0xd4, bps); put32(p, 0xd8, per_frame);
    // 0x23: what SceRemotePlay's own block holds there (compared on the console, lab mode); the read-only word its
    // builder copies to this place (0xffbf5f14) is not what is left in the block.
    put32(p, 0xdc, 0x23); put32(p, 0xe0, 0x33); put64(p, 0xe8, 0x20);
    p[0xf0] = 1;
    put32(p, 0xf4, first); put32(p, 0xf8, second); put32(p, 0xfc, budget); put32(p, 0x100, 1);
    put32(p, 0x104, NATIVE_CAP_BUFFER);
    put64(p, 0x108, 0x20); p[0x110] = 1; put32(p, 0x114, per_frame >> 3);
    put64(p, 0x128, 0x18); p[0x130] = 1; put32(p, 0x134, 0x19); put32(p, 0x138, r->fps);
    put64(p, 0x190, 0x10);
    if (bufs) {
        put64(p, 0x1a8, 0x50); put32(p, 0x1b0, 1);
        memcpy(p + 0x1b8, bufs->out1, sizeof bufs->out1);
        memcpy(p + 0x1d8, bufs->out2, sizeof bufs->out2);
    }
    put64(p, 0x1f8, 0xf8); put64(p, 0x200, 0x28);
    put32(p, 0x214, 384); put32(p, 0x218, 352); put32(p, 0x21c, 512); put64(p, 0x220, 278528);
    put64(p, 0x228, 0x88);
    put32(p, 0x238, 0x3f800000u); put32(p, 0x23c, 0x3f800000u);
    put32(p, 0x2b0, mode); put32(p, 0x2b4, variant == 6 ? 1 : 2); // the code that fills it differs for variant 6
    put64(p, 0x2b8, 0x10); put32(p, 0x2c0, 1); p[0x2c4] = 1;
    put64(p, 0x2c8, 0x10); p[0x2d0] = 1; put32(p, 0x2d4, r->fps == 30 ? 0x37u : 0x6eu);
}

// Writes the parameter block `kind` (arbitrator id c->feature; `bufs` for OPEN_13_60_BUFFERS) and opens the
// encoder, asking again up to `retries` times while it answers OPEN_BUSY (the block is rebuilt each time with
// the output mode as it is then). Returns 0 once the encoder is open, -1 otherwise; *rc is the last answer
// (SL_CALL_ERROR when the transport failed).
static int open_encoder(struct capture *c, intptr_t base, uint32_t *mode, const struct start_req *req,
                        enum open_kind kind, const struct buffers *bufs, unsigned retries, int64_t *rc)
{
    uint8_t block[0x2f0];
    const size_t len = kind == OPEN_13_00 ? 0x2e8 : sizeof block;
    *rc = SL_CALL_ERROR;
    for (unsigned attempt = 0;; attempt++) {
        if (kind == OPEN_13_00) video_params(block, *mode, req, c->feature, 0x2e0);
        else video_params_1360(block, *mode, req, c->feature, c->variant, kind == OPEN_13_60_BUFFERS ? bufs : NULL);
        if (sl_inject_write_at(&c->ctx, base, block, len)) return -1;
        *rc = REMOTE(c, OPEN_VIDEO, base, base + 8, 0);
        if (good(*rc)) return 0;
        if (*rc == SL_CALL_ERROR || (uint32_t)*rc != OPEN_BUSY || attempt >= retries || quit || net_dead ||
            stop_requested || c->ctx.quarantined)
            return -1;
        if (!attempt)
            log_line("OpenVideo is busy (0x%x); asking again for up to %u ms", OPEN_BUSY, retries * OPEN_RETRY_US / 1000u);
        usleep(OPEN_RETRY_US);
        beat();
        net_poll(NULL, &(int){1}, 0);
        uint32_t fresh = 0;
        if (read_mode(c, &fresh) == 0 && fresh) *mode = fresh;
    }
}

// Registers `feature` with the resource arbitrator, replacing the id registered before, and says it is
// running; `pid` is ChangeState's fourth argument (SceRemotePlay passes its own process id there, the 13.00
// sequence passes nothing, and on 13.60 neither that nor the id made the encoder answer differently).
// Returns 0 on success.
static int arbitrate(struct capture *c, intptr_t base, uint32_t feature, uint64_t pid)
{
    if (c->callback) {
        if (!good(REMOTE(c, CLEAR_CALLBACK, c->feature))) return -1;
        c->callback = 0;
    }
    c->feature = feature;
    if (!good(REMOTE(c, SET_CALLBACK, feature, c->fn[REMOTE_GETPID]))) return -1;
    c->callback = 1;
    static const char running[] = "RUNNING";
    if (sl_inject_write_at(&c->ctx, base + 0x600, running, sizeof running) ||
        !good(REMOTE(c, CHANGE_STATE, feature, base + 0x600, 0, pid))) return -1;
    return 0;
}

#ifdef SL_PS5
// Two libSceAvcap2 13.60 entry points SceRemotePlay's own code calls around OpenVideo (offsets read from the
// library's image; only called when the firmware is 13.60, where they are): +0x1750 asks the encoder service
// for its status (0x20 bytes; SceRemotePlay waits while a flag in it is set), +0x1b90 asks it for the two buffer
// descriptors the block carries, given the first 0x88 bytes of the block. Both only read the service.
#define AVCAP2_STATUS 0x1750
#define AVCAP2_QUERY 0x1b90

static void hex_line(const char *what, const uint8_t *p, size_t n)
{
    char hex[0x41 * 2];
    if (n > 0x40) n = 0x40;
    for (size_t i = 0; i < n; i++) snprintf(hex + i * 2, 3, "%02x", p[i]);
    log_line("%s: %s", what, hex);
}

static void probe_status(struct capture *c, intptr_t base)
{
    const intptr_t lib = sl_module_base(c->ctx.target_pid, "libSceAvcap2.sprx");
    if (lib <= 0) { log_line("status query: libSceAvcap2 not found"); return; }
    uint8_t out[0x40] = {0};
    const intptr_t at = base + 0x1000;
    if (sl_inject_write_at(&c->ctx, at, out, sizeof out)) return;
    const uint64_t args[6] = {(uint64_t)at};
    log_line("status query: calling libSceAvcap2+0x%x", AVCAP2_STATUS);
    const int64_t rc = inj_call_fast(&c->ctx, lib + AVCAP2_STATUS, args, 1);
    beat();
    if (rc == SL_CALL_ERROR) { log_line("status query: transport failure"); c->failed = 1; return; }
    log_line("status query returned 0x%llx", (unsigned long long)rc);
    if (sl_inject_read_at(&c->ctx, at, out, sizeof out) == 0) hex_line("status", out, sizeof out);
}

// Returns 0 with the descriptors in *bufs, -1 when the service refused or the call could not be made.
static int query_buffers(struct capture *c, intptr_t base, uint32_t mode, const struct start_req *req, struct buffers *bufs)
{
    const intptr_t lib = sl_module_base(c->ctx.target_pid, "libSceAvcap2.sprx");
    if (lib <= 0) return -1;
    uint8_t block[0x2f0], in[0x90] = {0}, zero[0x20] = {0};
    video_params_1360(block, mode, req, c->feature, c->variant, NULL);
    put64(in, 0, 0x90);
    memcpy(in + 8, block + 0x10, 0x80);
    const intptr_t at_in = base + 0x1100, at_out1 = base + 0x1200, at_out2 = base + 0x1220;
    if (sl_inject_write_at(&c->ctx, at_in, in, sizeof in) || sl_inject_write_at(&c->ctx, at_out1, zero, sizeof zero) ||
        sl_inject_write_at(&c->ctx, at_out2, zero, sizeof zero)) return -1;
    const uint64_t args[6] = {(uint64_t)at_in, (uint64_t)at_out1, (uint64_t)at_out2};
    log_line("buffer query: calling libSceAvcap2+0x%x", AVCAP2_QUERY);
    const int64_t rc = inj_call_fast(&c->ctx, lib + AVCAP2_QUERY, args, 1);
    beat();
    if (rc == SL_CALL_ERROR) { log_line("buffer query: transport failure"); c->failed = 1; return -1; }
    if (!good(rc)) { log_line("buffer query: refused with 0x%llx", (unsigned long long)rc); return -1; }
    if (sl_inject_read_at(&c->ctx, at_out1, bufs->out1, sizeof bufs->out1) ||
        sl_inject_read_at(&c->ctx, at_out2, bufs->out2, sizeof bufs->out2)) return -1;
    hex_line("buffer 1", bufs->out1, sizeof bufs->out1);
    hex_line("buffer 2", bufs->out2, sizeof bufs->out2);
    return 0;
}
#endif

// Firmware 13.60: registers as the 13.00 sequence does (id 12) and calls EnableScanInEncode as it does, then reads
// the encoder service's status and buffer descriptors as SceRemotePlay does (logged), then tries each parameter
// block once: 13.60's block with the descriptors, 13.60's block alone, 13.00's block. Without EnableScanInEncode
// the encoder opens and starts but is not given the display (community.13's Go Live: a 218-byte key frame and
// 41-byte pictures for three minutes, a black screen). Returns 1 once the encoder is open, 0 when all were
// refused, -1 when the session must end.
static int open_1360(struct capture *c, intptr_t base, uint32_t *mode, const struct start_req *req, int64_t *rc)
{
    struct buffers bufs = {{0}, {0}};
    int have = 0;
    *rc = SL_CALL_ERROR;
    if (arbitrate(c, base, FEATURE, 0)) return -1;
    const int64_t scan = REMOTE(c, ENABLE_SCAN);
    if (scan == SL_CALL_ERROR) return -1;
    if (!good(scan)) log_line("EnableScanInEncode was refused (0x%llx); the picture may be blank", (unsigned long long)scan);
#ifdef SL_PS5
    probe_status(c, base);
    have = query_buffers(c, base, *mode, req, &bufs) == 0;
    if (c->failed || c->ctx.quarantined) return -1;
#endif
    static const enum open_kind plan[] = {OPEN_13_60_BUFFERS, OPEN_13_60, OPEN_13_00};
    static const char *const names[] = {"13.60 block with the service's buffers", "13.60 block", "13.00 block"};
    for (unsigned k = 0; k < sizeof plan / sizeof *plan; k++) {
        if (plan[k] == OPEN_13_60_BUFFERS && !have) continue;
        const int ok = open_encoder(c, base, mode, req, plan[k], &bufs, 0, rc) == 0;
        log_line("probe: %s -> 0x%llx", names[k], (unsigned long long)*rc);
        if (ok) { c->kind = plan[k]; c->bufs = bufs; return 1; }
        if (*rc == SL_CALL_ERROR || quit || net_dead || stop_requested || c->ctx.quarantined) return -1;
    }
    return 0;
}

// Reads the handle OpenVideo left in the output slot. Read failures after a successful open still need cleanup;
// the handle is used only after a complete eight-byte transfer, retried once while the target is stopped, and never
// as a partial or zero value. Returns 0 on success.
static int take_handle(struct capture *c, intptr_t base)
{
    c->video_unknown = 1;
    if (sl_inject_read_at(&c->ctx, base, &c->video, 8) || !c->video) {
        c->video = 0;
        if (sl_inject_read_at(&c->ctx, base, &c->video, 8) || !c->video) {
            c->cleanup_failed = 1;
            return -1;
        }
    }
    c->video_unknown = 0;
    c->video_open = 1;
    return 0;
}

#ifdef SL_PS5
// Right after OpenVideo and before Start, SceRemotePlay asks libSceAvcap2 (13.60, +0x1dc0: a getter on the
// handle that does not call the service) where the encoder's stream buffer is, and fills the whole buffer with
// 0x80. This helper did neither, and Start answered 0x80c78000 on every try. Returns 0 (also when there is
// nothing to fill), or -1 on a transport failure.
#define AVCAP2_STREAM_BUFFER 0x1dc0
#define STREAM_BUFFER_MAX (64u << 20)
static int prepare_stream_buffer(struct capture *c, intptr_t base)
{
    const intptr_t lib = sl_module_base(c->ctx.target_pid, "libSceAvcap2.sprx");
    if (lib <= 0) { log_line("stream buffer: libSceAvcap2 not found"); return 0; }
    uint8_t out[16] = {0};
    const intptr_t at = base + 0x1300;
    if (sl_inject_write_at(&c->ctx, at, out, sizeof out)) return -1;
    const uint64_t args[6] = {c->video, (uint64_t)at, (uint64_t)(at + 8)};
    const int64_t rc = inj_call_fast(&c->ctx, lib + AVCAP2_STREAM_BUFFER, args, 1);
    beat();
    if (rc == SL_CALL_ERROR) { log_line("stream buffer: transport failure"); c->failed = 1; return -1; }
    if (sl_inject_read_at(&c->ctx, at, out, sizeof out)) return -1;
    uint64_t ptr, size;
    memcpy(&ptr, out, 8);
    memcpy(&size, out + 8, 8);
    log_line("stream buffer: 0x%llx, at 0x%llx, %llu bytes", (unsigned long long)rc, (unsigned long long)ptr,
             (unsigned long long)size);
    if (!good(rc) || !ptr || !size || size > STREAM_BUFFER_MAX || c->fn[REMOTE_MEMSET] <= 0) return 0;
    return REMOTE(c, REMOTE_MEMSET, ptr, 0x80, size) == SL_CALL_ERROR ? -1 : 0;
}
#else
static int prepare_stream_buffer(struct capture *c, intptr_t base) { (void)c; (void)base; return 0; }
#endif

// How many times the encoder is started on 13.60, and the wait between two tries.
#ifndef START_TRIES
#define START_TRIES 6u
#define START_RETRY_US 250000u
#endif

// Firmware 13.60: SceRemotePlay never calls SetVideoBitrate (the bitrate is in the block) and, when Start is refused
// (0x80c78000 was seen), closes the encoder, waits a frame and opens it again until its time budget is spent. So:
// the first half of the tries start without a bitrate call, the second half with the call 13.00 needs; between two
// tries the encoder is closed, and opened again with the block that worked. Each time it is open, and before
// Start, its stream buffer is prepared as SceRemotePlay does. Returns 0 once started, -1 otherwise (a refusal
// is logged with its code); *rc is the last answer of Start.
static int start_1360(struct capture *c, intptr_t base, uint32_t *mode, const struct start_req *req, int64_t *rc)
{
    if (prepare_stream_buffer(c, base)) return -1;
    for (unsigned attempt = 0; attempt < START_TRIES; attempt++) {
        const int with_rate = attempt >= START_TRIES / 2;
        if (with_rate) {
            // The bitrate is set once per encoder, before Start: a change mid-session wedges it until restart.
            uint8_t rate[16] = {0};
            put64(rate, 0, 16); put32(rate, 8, req->bitrate); put32(rate, 12, req->bitrate);
            if (sl_inject_write_at(&c->ctx, base + 0x780, rate, sizeof rate) ||
                !good(REMOTE(c, BITRATE_SET, c->video, base + 0x780))) return -1;
        }
        c->video_start_attempted = 1;
        *rc = REMOTE(c, START, c->video);
        log_line("start try %u (%s) -> 0x%llx", attempt + 1, with_rate ? "with the bitrate call" : "like SceRemotePlay",
                 (unsigned long long)*rc);
        if (good(*rc)) return 0;
        if (*rc == SL_CALL_ERROR || quit || net_dead || stop_requested || c->ctx.quarantined || attempt + 1 >= START_TRIES)
            return -1;
        // Refused: close the encoder, wait, open it again with the same block.
        if (!good(REMOTE(c, CLOSE, c->video))) return -1;
        c->video_open = 0; c->video_start_attempted = 0; c->video = 0;
        usleep(START_RETRY_US);
        beat();
        net_poll(NULL, &(int){1}, 0);
        int64_t open_rc;
        if (open_encoder(c, base, mode, req, c->kind, &c->bufs, 0, &open_rc)) {
            log_line("start retry: the encoder would not open again (0x%llx)", (unsigned long long)open_rc);
            return -1;
        }
        if (take_handle(c, base) || prepare_stream_buffer(c, base)) return -1;
    }
    return -1;
}

static void cleanup(struct capture *c)
{
    c->cleanup = 1;
    if (!c->ctx.quarantined || c->ctx.aborted_restored) {
        if (c->video_open) {
            if (c->video_start_attempted && !good(REMOTE(c, STOP, c->video))) c->failed = c->cleanup_failed = 1;
            if (!good(REMOTE(c, CLOSE, c->video))) c->failed = c->cleanup_failed = 1;
        }
        // free() has no return value; only transport completion is meaningful.
        if (c->remote_frame && REMOTE(c, REMOTE_FREE, c->remote_frame) == SL_CALL_ERROR) c->failed = c->cleanup_failed = 1;
        if (c->output_mode && !c->ctx.quarantined) {
            uint32_t after = 0;
            if (read_mode(c, &after)) c->failed = c->cleanup_failed = 1;
            else {
                c->final_mode = after;
                log_line("HDMI mode before=0x%x after=0x%x", c->output_mode, after);
            }
        }
        if (c->callback && !good(REMOTE(c, CLEAR_CALLBACK, c->feature))) c->failed = c->cleanup_failed = 1;
        if (c->initialized && !good(REMOTE(c, TERMINATE))) c->failed = c->cleanup_failed = 1;
    } else {
        c->failed = c->cleanup_failed = 1;
        log_line("remote calls quarantined; service cleanup incomplete, reboot may be needed");
    }
    if (c->video_unknown) {
        c->failed = c->cleanup_failed = 1;
        log_line("OpenVideo succeeded but ownership is uncertain; Terminate is not a verified Close");
    }
    if (sl_inject_end(&c->ctx)) { log_line("detach failed"); c->failed = c->cleanup_failed = 1; }
}

static void why(const char *text) { if (!segment.why[0]) snprintf(segment.why, sizeof segment.why, "%s", text); }

#ifdef SL_PS5
// Whether a path exists. Not access(): it checks the real user's rights, and the data folder is root's (0700), so
// it fails for this process where open() and stat() (the effective user's) succeed.
static int file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}
#endif

enum session_end { SESS_STOPPED, SESS_RECOVERABLE, SESS_FAILED };

// One capture session: attach, open the encoder, stream until the core stops it or something
// fails, then tear everything down. `may_recover` lets the 0x81950009 path wait for a stable
// output mode (RECOVERY.md); the caller decides whether to open another session.
static enum session_end capture_session(const struct start_req *req, int may_recover)
{
    memset(&segment, 0, sizeof segment);
    struct capture c = {.startup_deadline = now_ms() + START_WAIT_MS, .feature = FEATURE, .variant = 2};
    uint8_t *frame = NULL;
    int first_idr = 0;
    int64_t window_gap = 0, last_read_us = 0;
    size_t window_max = 0, window_idr = 0;
    unsigned gaps[CAP_GAP_BUCKETS] = {0};
    enum session_end end = SESS_FAILED;
    uint8_t headers[0x200], annexb[512];
    size_t annexb_len = 0;

    if (sl_inject_begin("SceRemotePlay", &c.ctx)) {
        log_line("attach failed: stage=%s errno=%d rip=0x%llx lwp=%d", c.ctx.stage, c.ctx.last_errno,
                 (unsigned long long)c.ctx.last_rip, (int)c.ctx.thread_pid);
        why("Capture could not start.");
        goto done;
    }
    if (progress) progress->target = c.ctx.target_pid;
    log_line("attached: pid=%d lwp=%d rip=0x%llx scratch=0x%llx", (int)c.ctx.target_pid, (int)c.ctx.thread_pid,
             (unsigned long long)c.ctx.last_rip, (unsigned long long)c.ctx.scratch);
    if (c.ctx.scratch <= 0 || c.ctx.scratch_len < 0x4000 || bind_functions(&c)) {
        log_line("setup failed: scratch=0x%llx len=0x%zx stage=%s", (unsigned long long)c.ctx.scratch,
                 (size_t)c.ctx.scratch_len, c.ctx.stage);
        why("Capture could not start."); goto done;
    }
    if (!good(REMOTE(&c, INITIALIZE))) { log_line("Initialize failed: stage=%s", c.ctx.stage); why("Capture could not start."); goto done; }
    c.initialized = 1;
    uint32_t mode = 0;
    intptr_t base = c.ctx.scratch;
    // A transitional mode zero (a game starting or ending) is waited out, not captured in.
    if (wait_stable_mode(&c, &mode, MODE_WAIT_MS)) { why("The display is changing. Try again."); goto done; }
    log_line("HDMI output mode=0x%x; display settings will not be changed", mode);
    c.output_mode = segment.initial_mode = mode;
    if (mode == 0x40 && !ALLOW_MODE_40) {
        log_line("refusing the known 120 Hz output mode");
        segment.refused_mode = 1;
        why("Go Live can't capture while the console outputs 120 Hz.");
        goto done;
    }
    int64_t open_rc = SL_CALL_ERROR;
    int opened = 0;
    if (firmware_is_13_60()) {
        log_line("firmware 13.60: opening the encoder the way SceRemotePlay does");
        const int tried = open_1360(&c, base, &mode, req, &open_rc);
        if (tried < 0) goto done;
        opened = tried == 1;
        if (opened) log_line("probe: the encoder opened");
    } else {
        // The validated sequence, untouched: id 12, no process id, EnableScanInEncode, then 13.00's block.
        if (arbitrate(&c, base, FEATURE, 0) || !good(REMOTE(&c, ENABLE_SCAN))) goto done;
        opened = open_encoder(&c, base, &mode, req, OPEN_13_00, NULL, OPEN_RETRIES, &open_rc) == 0;
    }
    if (!opened) {
#ifdef SL_PS5
        // 0x81950008 on firmware 13.60 (upstream issue #11): log how SceRemotePlay's own code calls the same
        // functions, and write the images of the modules involved next to the log, read-only, so the
        // sequence and the parameter block it builds can be compared with ours offline (once: the files stay).
        if (open_rc != SL_CALL_ERROR && (uint32_t)open_rc == OPEN_BUSY && !c.ctx.quarantined) {
            if (file_exists(CAP_DIR "/remoteplay-image.bin")) {
                log_line("diag: the module images are already on the console; not read again");
            } else {
                diag_native_sequence(&c.ctx, c.fn, symbols, REMOTE_GETPID, log_line);
                beat();
                diag_native_dump(&c.ctx, CAP_DIR, log_line);
                beat();
            }
        }
#endif
        why("The console's encoder would not open.");
        goto done;
    }
    if (take_handle(&c, base)) {
        why("The encoder opened but its handle could not be read.");
        goto done;
    }
    if (firmware_is_13_60()) {
        int64_t start_rc = SL_CALL_ERROR;
        if (start_1360(&c, base, &mode, req, &start_rc)) { why("The console's encoder would not start."); goto done; }
    } else {
        // The bitrate is set once, before Start: a change mid-session wedges the encoder until
        // the console restarts.
        uint8_t rate[16] = {0};
        put64(rate, 0, 16); put32(rate, 8, req->bitrate); put32(rate, 12, req->bitrate);
        if (sl_inject_write_at(&c.ctx, base + 0x780, rate, sizeof rate) ||
            !good(REMOTE(&c, BITRATE_SET, c.video, base + 0x780))) goto done;
        c.video_start_attempted = 1;
        if (!good(REMOTE(&c, START, c.video))) { why("The console's encoder would not start."); goto done; }
    }

    int headers_ready = 0;
    for (unsigned i = 0; i < 20 && !quit && !net_dead && !stop_requested && now_ms() < c.startup_deadline; i++) {
        net_poll(NULL, &(int){1}, 0);
        if (quit || net_dead || stop_requested) goto done;
        memset(headers, 0, sizeof headers);
        if (sl_inject_write_at(&c.ctx, base + 0x2000, headers, sizeof headers) ||
            !good(REMOTE(&c, HEADERS, c.video, base + 0x2000)) ||
            sl_inject_read_at(&c.ctx, base + 0x2000, headers, sizeof headers)) goto done;
        if (!headers_annexb(headers, sizeof headers, annexb, sizeof annexb, &annexb_len)) { headers_ready = 1; break; }
        usleep(50000);
        beat();
    }
    if (!headers_ready || quit || net_dead || stop_requested || now_ms() >= c.startup_deadline) { why("The encoder gave no picture headers."); goto done; }
    if (capture_h264_timing(annexb, &annexb_len, sizeof annexb, req->fps)) {
        why("The encoder gave unsupported picture timing.");
        goto done;
    }
    uint8_t profile[16];
    cap_put32(profile, req->width); cap_put32(profile + 4, req->height);
    cap_put32(profile + 8, req->fps); cap_put32(profile + 12, mode);
    if (net_send(CAP_PROFILE, 0, profile, sizeof profile) ||
        net_send(CAP_HEADERS, 0, annexb, (uint32_t)annexb_len)) goto done;
    int64_t allocated = REMOTE(&c, REMOTE_MALLOC, FRAME_CAP);
    if (allocated == SL_CALL_ERROR || allocated <= 0) goto done;
    c.remote_frame = (uint64_t)allocated;
    frame = malloc(CAP_HEADER_BYTES + FRAME_CAP);
    if (!frame || !good(REMOTE(&c, KEYFRAME, c.video))) goto done;
    net_poll(NULL, &(int){1}, 0);
    if (quit || net_dead || stop_requested || now_ms() >= c.startup_deadline) goto done;
    segment.begin_ms = now_ms();
    uint64_t last_key = segment.begin_ms, next_mode = segment.begin_ms;
    c.startup_done = 1;
    uint64_t last_picture = segment.begin_ms;
    uint32_t observed_mode = c.output_mode;
    unsigned mode_misses = 0;
    while (!quit && !net_dead && !stop_requested) {
        net_poll(NULL, &(int){1}, 0);
        if (net_dead || stop_requested) break;
        if (now_ms() >= next_mode) {
            uint32_t current = 0;
            int mode_ok = read_mode(&c, &current) == 0;
            next_mode = now_ms() + MODE_POLL_MS;
            if (!mode_ok) {
                if (c.failed || c.ctx.quarantined || ++mode_misses >= 3) {
                    why("The display mode could not be checked."); goto done;
                }
                log_line("output mode query missed (%u of 3); picture reads continue", mode_misses);
            } else {
                mode_misses = 0;
                if (current == 0x40 && !ALLOW_MODE_40) {
                    segment.refused_mode = 1;
                    why("Go Live can't capture while the console outputs 120 Hz.");
                    goto done;
                }
                // Transitions may precede the validated ReadVideo error. Keep reading so the
                // existing one-recovery path can run; only 0x40 is refused immediately.
                if (current != observed_mode) {
                    log_line("output mode changed 0x%x -> 0x%x; waiting for picture progress", observed_mode, current);
                    observed_mode = current;
                }
            }
        }
        if (key_requested) {
            key_requested = 0;
            if (!good(REMOTE(&c, KEYFRAME, c.video))) goto done;
        }
        // No IDR yet after a second: ask again. No picture in ten: the encoder is not working.
        if (!first_idr && now_ms() - last_key >= 1000) {
            if (now_ms() - segment.begin_ms > NO_PICTURE_MS) { why("The encoder produced no picture."); goto done; }
            last_key = now_ms();
            if (!good(REMOTE(&c, KEYFRAME, c.video))) goto done;
        }
        if (now_ms() - last_picture >= NO_PICTURE_MS) { why("The picture stopped."); goto done; }
        int64_t n = REMOTE(&c, READ_VIDEO, c.video, c.remote_frame, FRAME_CAP, base + 0x300, 0);
        if (n == SL_CALL_ERROR || n < 0 || n > FRAME_CAP) {
            log_line("ReadVideo failed: 0x%llx", (unsigned long long)n);
            if (n != SL_CALL_ERROR && (int32_t)n < 0) segment.api_error = (uint32_t)n;
            // Only the observed API error is a recovery candidate. Oversize frames, unknown
            // errors and quarantined transport never are.
            if (may_recover && segment.frames && segment.api_error == 0x81950009u && !c.ctx.quarantined) {
                net_state(CAP_RECOVERING, "");
                (void)wait_stable_mode(&c, &segment.stable_mode, MODE_WAIT_MS);
            }
            why("The picture stopped.");
            goto done;
        }
        if (n < 5) {
            usleep(1000);
            continue;
        }
        if (sl_inject_read_at(&c.ctx, (intptr_t)c.remote_frame, frame + CAP_HEADER_BYTES, (size_t)n)) goto done;
        uint8_t *au = frame + CAP_HEADER_BYTES;
        if (!annexb_ok(au, (size_t)n)) { log_line("invalid frame (not Annex-B)"); why("The encoder sent a bad picture."); goto done; }
        const int idr = has_nal(au, (size_t)n, 5);
        if (!first_idr && !idr) continue; // wait for the first IDR; nothing earlier is decodable
        if (!first_idr) {
            first_idr = 1;
            if (net_state(CAP_LIVE, "")) goto done;
        }
        size_t au_len = (size_t)n;
        if (has_nal(au, au_len, 7) && capture_h264_timing(au, &au_len, FRAME_CAP, req->fps)) {
            why("The encoder gave unsupported picture timing."); goto done;
        }
        {   // when each frame came out of the encoder, against the frame period
            struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
            const int64_t us = (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
            if (last_read_us) gaps[cap_gap_bucket(us - last_read_us, 1000000 / (long long)req->fps)]++;
            last_read_us = us;
        }
        if (net_send_inplace(frame, CAP_VIDEO, idr ? CAP_KEY : 0, (uint32_t)au_len)) break;
        const uint64_t got = (uint64_t)now_ms();
        if (segment.frames && (int64_t)(got - last_picture) > window_gap) window_gap = (int64_t)(got - last_picture);
        if (au_len > window_max) window_max = au_len;
        if (idr && au_len > window_idr) window_idr = au_len;
        last_picture = got;
        segment.frames++;
        segment.last_video_ms = got - segment.begin_ms;
        if (segment.frames <= 3 || segment.frames % (req->fps * 10) == 0) {
            // Viewer-side hiccups (2026-11-09): the largest gap and frames of the last 10 s.
            log_line("frames=%u last=%zu bytes; 10 s: max gap %lld ms, largest %zu, largest IDR %zu; "
                     "gaps vs period <.5 %u <.9 %u ~1 %u <1.5 %u <2.5 %u more %u", segment.frames,
                     (size_t)n, (long long)window_gap, window_max, window_idr, gaps[0], gaps[1], gaps[2], gaps[3],
                     gaps[4], gaps[5]);
            window_gap = 0; window_max = window_idr = 0;
            memset(gaps, 0, sizeof gaps);
        }
    }
    end = SESS_STOPPED;
done:
    free(frame);
    cleanup(&c);
    segment.final_mode = c.final_mode;
    segment.cleanup_ok = !c.cleanup_failed && (!c.ctx.quarantined || c.ctx.aborted_restored);
    if (!segment.cleanup_ok)
        snprintf(segment.why, sizeof segment.why, "Capture cleanup failed. The console may need a restart.");
    segment.transport_failed = c.ctx.quarantined && !c.ctx.aborted_restored;
    // A stop (the core's, or its disappearance, or ours) is the normal end whatever stopped
    // the setup; only a failed cleanup makes it a failure.
    if (end == SESS_STOPPED || quit || net_dead || stop_requested)
        return segment.cleanup_ok ? SESS_STOPPED : SESS_FAILED;
    if (segment.api_error == 0x81950009u && may_recover && segment.cleanup_ok && !segment.transport_failed &&
        segment.stable_mode && (segment.stable_mode != 0x40 || ALLOW_MODE_40) && segment.frames)
        return SESS_RECOVERABLE;
    if (segment.stable_mode == 0x40 && !ALLOW_MODE_40)
        snprintf(segment.why, sizeof segment.why, "Go Live can't capture while the console outputs 120 Hz.");
    return SESS_FAILED;
}

#ifdef SL_PS5
// Lab mode: the helper started by hand through elfldr, not by the core, with the file CAP_DIR "/lab" present
// (the file is removed first, so the next start is a normal one). No core and no Discord: on a fixed profile
// (720p60, 6 Mbit/s) it opens, starts and reads the encoder under each combination that could change what it
// encodes (the arbitrator id, EnableScanInEncode, the encoder variant of the block), logs every answer and the
// size of the pictures it gets (the "lab:" lines), and compares this helper's block with SceRemotePlay's own.
// Only 13.60's block with the service's buffers is used (it is the one that opens the encoder there).
static int lab_try(struct capture *c, intptr_t base, uint32_t *mode, const struct start_req *req, const char *what)
{
    int64_t rc = SL_CALL_ERROR;
    if (open_encoder(c, base, mode, req, OPEN_13_60_BUFFERS, &c->bufs, 0, &rc)) {
        log_line("lab: %s: OpenVideo refused (0x%llx)", what, (unsigned long long)rc);
        return rc == SL_CALL_ERROR || c->ctx.quarantined ? -1 : 0;
    }
    if (take_handle(c, base) || prepare_stream_buffer(c, base)) return -1;
    c->video_start_attempted = 1;
    rc = REMOTE(c, START, c->video);
    log_line("lab: %s: Start -> 0x%llx", what, (unsigned long long)rc);
    if (good(rc)) return 1;
    if (rc == SL_CALL_ERROR) return -1;
    if (!good(REMOTE(c, CLOSE, c->video))) return -1;
    c->video_open = 0; c->video_start_attempted = 0; c->video = 0;
    return 0;
}

// Reads pictures from the started encoder and logs what they say about the picture: Annex-B units for a real
// display are tens of kilobytes for a 720p key frame, a few hundred bytes when the encoder is given nothing to
// encode (community.13's Go Live: a 218-byte key frame and 41-byte pictures for three minutes, a black screen).
// Returns 0 when pictures were read (*largest: the size of the largest), -1 when the session cannot go on.
#define LAB_PICTURES 60u
#define LAB_REAL_PICTURE 3000u // a picture bigger than this is not a flat one
static int lab_pictures(struct capture *c, intptr_t base, const char *what, size_t *biggest)
{
    uint8_t headers[0x200] = {0};
    if (sl_inject_write_at(&c->ctx, base + 0x2000, headers, sizeof headers) == 0) {
        const int64_t rc = REMOTE(c, HEADERS, c->video, base + 0x2000);
        log_line("lab: %s: picture headers -> 0x%llx", what, (unsigned long long)rc);
        if (rc == SL_CALL_ERROR) return -1;
    }
    if (!c->remote_frame) {
        const int64_t frame = REMOTE(c, REMOTE_MALLOC, FRAME_CAP);
        if (frame == SL_CALL_ERROR) return -1;
        if (frame <= 0) return 0;
        c->remote_frame = (uint64_t)frame;
    }
    unsigned pictures = 0, keys = 0;
    size_t first_key = 0, largest = 0, largest_p = 0;
    unsigned long long total = 0;
    for (unsigned i = 0; i < LAB_PICTURES && !c->failed && !c->ctx.quarantined; i++) {
        if (i == 0 || i == LAB_PICTURES / 2) {
            const int64_t rc = REMOTE(c, KEYFRAME, c->video);
            if (rc == SL_CALL_ERROR) return -1;
        }
        const int64_t n = REMOTE(c, READ_VIDEO, c->video, c->remote_frame, FRAME_CAP, base + 0x300, 0);
        if (n == SL_CALL_ERROR) return -1;
        if (n > 0 && n <= FRAME_CAP) {
            uint8_t head[0x100]; // enough for the units that may come before the key frame's slice
            const size_t m = (size_t)n < sizeof head ? (size_t)n : sizeof head;
            const int key = sl_inject_read_at(&c->ctx, (intptr_t)c->remote_frame, head, m) == 0 && has_nal(head, m, 5);
            pictures++;
            total += (unsigned long long)n;
            if ((size_t)n > largest) largest = (size_t)n;
            if (key) { if (!keys++) first_key = (size_t)n; }
            else if ((size_t)n > largest_p) largest_p = (size_t)n;
            if (pictures <= 4) log_line("lab: %s: picture %u: %lld bytes%s", what, pictures, (long long)n, key ? " (key frame)" : "");
        }
        usleep(50000);
        beat();
    }
    log_line("lab: %s: %u pictures, %u key frames (the first %zu bytes), largest %zu, largest other %zu, %llu bytes in all", what,
             pictures, keys, first_key, largest, largest_p, total);
    *biggest = largest;
    return 0;
}

// Stops and closes the encoder the lab opened (the lab opens it several times). 0 on success.
static int lab_stop(struct capture *c)
{
    if (!c->video_open) return 0;
    if (c->video_start_attempted && !good(REMOTE(c, STOP, c->video))) return -1;
    if (!good(REMOTE(c, CLOSE, c->video))) return -1;
    c->video_open = 0; c->video_start_attempted = 0; c->video = 0;
    usleep(300000);
    beat();
    return 0;
}

// SceRemotePlay's own functions that build the 13.60 block, as offsets in its main module (read from its image;
// the lab runs on 13.60 only): the Glint object's constructor, the setter of its variant and arbitrator id, the
// block builder (which also asks the service for the buffer descriptors) and the function that fills in the rates.
#define RP_GLINT_CTOR 0x6f1c0
#define RP_GLINT_CONFIGURE 0x71960
#define RP_GLINT_BUILD 0x6f840
#define RP_GLINT_RATES 0x70190
#define RP_RATE_DEFAULTS 0x4a3e80 // the 16 bytes the builder copies to block offset 0xd0

static int64_t lab_call(struct capture *c, intptr_t fn, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                        uint64_t a5)
{
    const uint64_t args[6] = {a0, a1, a2, a3, a4, a5};
    const int64_t rc = inj_call_fast(&c->ctx, fn, args, 1);
    beat();
    if (rc == SL_CALL_ERROR) { log_line("lab: transport failure in the call to 0x%llx", (unsigned long long)fn); c->failed = 1; }
    return rc;
}

// Has SceRemotePlay's own code build the block, on a new Glint object in its heap (nothing it owns is touched),
// and logs every word where this helper's block differs from it (that is how word 0xdc was found). Returns 1 when
// the two are identical, 0 when not (or when it cannot be done here), -1 when the session cannot go on.
static int lab_native(struct capture *c, intptr_t base, uint32_t mode, const struct start_req *req)
{
    const intptr_t rp = diag_native_main_base(&c->ctx);
    if (rp <= 0 || c->fn[REMOTE_MEMSET] <= 0) { log_line("lab: SceRemotePlay's own block: not possible here"); return 0; }
    const int64_t obj = REMOTE(c, REMOTE_MALLOC, 0x200400);
    if (obj == SL_CALL_ERROR) return -1;
    if (obj <= 0) { log_line("lab: SceRemotePlay's own block: malloc failed"); return 0; }
    log_line("lab: SceRemotePlay's own block: a new Glint object at 0x%llx", (unsigned long long)obj);
    uint8_t word[16] = {0};
    if (sl_inject_read_at(&c->ctx, rp + RP_RATE_DEFAULTS, word, sizeof word) == 0) hex_line("lab: the 16 bytes its builder copies to block offset 0xd0, before", word, sizeof word);
    if (lab_call(c, rp + RP_GLINT_CTOR, (uint64_t)obj, 0, 0, 0, 0, 0) == SL_CALL_ERROR) return -1;
    if (lab_call(c, rp + RP_GLINT_CONFIGURE, (uint64_t)obj, c->variant, c->feature, 0, 0, 0) == SL_CALL_ERROR) return -1;
    uint8_t config[0x28] = {0}; // type 2 (H.264), size, flag 0, rate, then the settings this helper had to choose
    put32(config, 0x00, 2); put32(config, 0x04, req->width); put32(config, 0x08, req->height);
    put32(config, 0x10, req->fps); put32(config, 0x18, NATIVE_CAP_BUDGET); put32(config, 0x1c, NATIVE_CAP_BUFFER / 8);
    const intptr_t at_config = base + 0x1400;
    if (sl_inject_write_at(&c->ctx, at_config, config, sizeof config)) return -1;
    const int64_t built = lab_call(c, rp + RP_GLINT_BUILD, (uint64_t)obj, 0, 0, (uint64_t)at_config, 0, 0);
    if (built == SL_CALL_ERROR) return -1;
    log_line("lab: SceRemotePlay's own block: builder -> 0x%llx", (unsigned long long)built);
    if (sl_inject_read_at(&c->ctx, rp + RP_RATE_DEFAULTS, word, sizeof word) == 0) hex_line("lab: the same 16 bytes, after the builder", word, sizeof word);
    if (lab_call(c, rp + RP_GLINT_RATES, (uint64_t)obj, 0, 0, req->bitrate / 1000u, req->fps, req->selector) == SL_CALL_ERROR)
        return -1;
    // What SceRemotePlay's open function writes just before OpenVideo: the output mode (read straight into the
    // block), and the flag derived from the status answer (1 here; the enum next to the mode is already 2).
    if (REMOTE(c, MODE, obj + 0x2e8) == SL_CALL_ERROR || REMOTE(c, REMOTE_MEMSET, obj + 0x2fc, 1, 1) == SL_CALL_ERROR) return -1;
    uint8_t theirs[0x2f0], ours[0x2f0];
    if (sl_inject_read_at(&c->ctx, obj + 0x38, theirs, sizeof theirs)) return -1;
    struct buffers got;
    memcpy(got.out1, theirs + 0x1b8, sizeof got.out1);
    memcpy(got.out2, theirs + 0x1d8, sizeof got.out2);
    video_params_1360(ours, mode, req, c->feature, c->variant, &got);
    unsigned differing = 0;
    for (size_t i = 0; i < sizeof ours; i += 4) {
        uint32_t x, y;
        memcpy(&x, ours + i, 4);
        memcpy(&y, theirs + i, 4);
        if (x == y) continue;
        if (differing++ < 70) log_line("lab: block word 0x%zx: ours 0x%x, SceRemotePlay's 0x%x", i, x, y);
    }
    log_line("lab: SceRemotePlay's own block (selector %u, %u fps, %u bit/s): %u of %zu words differ from this helper's",
             req->selector, req->fps, req->bitrate, differing, sizeof ours / 4);
    (void)REMOTE(c, REMOTE_FREE, obj);
    return differing ? 0 : 1;
}

// What one picture test changes: the arbitrator id (and the id in the block), the encoder variant, and whether
// EnableScanInEncode has been called (it cannot be undone from here, so the tests that need it come after the ones
// that do not).
struct lab_test { const char *what; uint32_t feature, variant; int scan; };

static int lab_run(void)
{
    struct start_req req = {.selector = 3, .fps_flag = 1, .bitrate = 6000000, .width = 1280, .height = 720, .fps = 60};
    struct capture c = {.startup_deadline = now_ms() + 600000u, .feature = FEATURE, .variant = 2};
    int result = 0; // -1: the session cannot go on
    log_line("lab: 720p60 at %u bit/s, no core; which setting makes the encoder see the display?", req.bitrate);
    if (sl_inject_begin("SceRemotePlay", &c.ctx)) { log_line("lab: attach failed: stage=%s", c.ctx.stage); return 1; }
    const intptr_t base = c.ctx.scratch;
    uint32_t mode = 0;
    if (c.ctx.scratch <= 0 || c.ctx.scratch_len < 0x4000 || bind_functions(&c)) { log_line("lab: setup failed"); result = -1; goto end; }
    if (!good(REMOTE(&c, INITIALIZE))) { result = -1; goto end; }
    c.initialized = 1;
    if (wait_stable_mode(&c, &mode, MODE_WAIT_MS)) { log_line("lab: no stable output mode"); result = -1; goto end; }
    c.output_mode = mode;
    if (arbitrate(&c, base, FEATURE, 0)) { result = -1; goto end; }
    probe_status(&c, base);
    if (query_buffers(&c, base, mode, &req, &c.bufs)) { log_line("lab: no buffers from the service"); result = -1; goto end; }
    c.kind = OPEN_13_60_BUFFERS;
    {
        const intptr_t lib = sl_module_base(c.ctx.target_pid, "libSceAvcap2.sprx");
        log_line("lab: %s is libSceAvcap2+0x%llx", symbols[ENABLE_SCAN], (unsigned long long)(c.fn[ENABLE_SCAN] - lib));
    }
    // Community.13 opened the encoder without EnableScanInEncode, which the 13.00 sequence calls before OpenVideo,
    // and every picture of a three-minute Go Live was a few dozen bytes: the encoder was not given the display.
    // Each test opens the encoder with this helper's block, starts it and reads pictures (keep something with
    // detail on the screen: a key frame of a flat picture is 200 bytes, of a real one tens of kilobytes).
    static const struct lab_test tests[] = {
        {"id 12, scan off", FEATURE, 2, 0},
        {"id 12, scan on", FEATURE, 2, 1},
        {"id 12, scan on, variant 6", FEATURE, 6, 1},
        {"id 0xb4, scan on", 0xb4u, 2, 1},
        {"id 0xb9, scan on", 0xb9u, 2, 1},
    };
    int scan_on = 0;
    size_t biggest = 0; // the largest picture of any test so far
    for (unsigned t = 0; t < sizeof tests / sizeof *tests && result == 0; t++) {
        const struct lab_test *test = &tests[t];
        if (t >= 2 && biggest > LAB_REAL_PICTURE) { // scan off and on were both seen; a setting that works: the others are not worth the risk of more registrations
            log_line("lab: pictures of %zu bytes: the remaining settings are not tried", biggest);
            break;
        }
        if (c.feature != test->feature && arbitrate(&c, base, test->feature, test->feature == FEATURE ? 0 : (uint64_t)c.ctx.target_pid)) {
            log_line("lab: %s: the arbitrator refused the id", test->what);
            if (c.failed || c.ctx.quarantined) result = -1;
            continue;
        }
        c.variant = test->variant;
        if (test->scan && !scan_on) {
            const int64_t rc = REMOTE(&c, ENABLE_SCAN);
            log_line("lab: EnableScanInEncode -> 0x%llx", (unsigned long long)rc);
            if (!good(rc)) { result = -1; break; }
            scan_on = 1;
        }
        if (t && query_buffers(&c, base, mode, &req, &c.bufs)) {
            log_line("lab: %s: no buffers from the service", test->what);
            if (c.failed || c.ctx.quarantined) result = -1;
            continue;
        }
        const int started = lab_try(&c, base, &mode, &req, test->what);
        if (started < 0) { result = -1; break; }
        size_t largest = 0;
        if (started == 1 && (lab_pictures(&c, base, test->what, &largest) || lab_stop(&c))) result = -1;
        if (largest > biggest) biggest = largest;
    }
    // Then how this helper's block compares with SceRemotePlay's for the profiles and bitrates Go Live offers
    // (the differing words are logged; nothing is opened).
    static const struct start_req profiles[] = {
        {3, 0, 4000000, 1280, 720, 30}, {3, 1, 6000000, 1280, 720, 60}, {4, 0, 6000000, 1920, 1080, 30},
        {4, 1, 8000000, 1920, 1080, 60}, {3, 1, 10000000, 1280, 720, 60}, {4, 1, 20000000, 1920, 1080, 60},
        {3, 0, 1000000, 1280, 720, 30}, {4, 0, 12500000, 1920, 1080, 30},
    };
    c.feature = FEATURE; c.variant = 2;
    if (result == 0 && arbitrate(&c, base, FEATURE, 0)) result = -1;
    for (unsigned p = 0; p < sizeof profiles / sizeof *profiles && result == 0 && c.ctx.attached && !c.failed && !c.ctx.quarantined; p++)
        if (lab_native(&c, base, mode, &profiles[p]) < 0) result = -1;
end:
    cleanup(&c);
    log_line("lab: done (%s)", result == 0 ? "all tests ran" : "stopped early");
    return result == 0 ? 0 : 1;
}
#endif

// The worker: connect, wait for the core's start, run the session, recover at most once.
static int helper_run(void)
{
#ifdef SL_PS5
    if (file_exists(CAP_DIR "/lab")) {
        (void)unlink(CAP_DIR "/lab");
        return lab_run();
    }
#endif
    if (net_connect()) return 1;
    struct start_req req = {0};
    int got = 0;
    for (uint64_t begin = now_ms(); !got && !net_dead && !quit && !stop_requested && now_ms() - begin < START_WAIT_MS;) {
        net_poll(&req, &got, 100);
        beat();
    }
    if (!got || stop_requested) { net_close(); return stop_requested ? 0 : 1; }
    const int sel_ok = (req.selector == 3 && req.width == 1280 && req.height == 720) ||
                       (req.selector == 4 && req.width == 1920 && req.height == 1080);
    if (!sel_ok || req.fps_flag > 1 || req.fps != (req.fps_flag ? 60u : 30u) || req.bitrate < 500000 || req.bitrate > 30000000) {
        log_line("refusing an unsupported profile");
        net_state(CAP_ERROR, "Unsupported capture profile.");
        net_close();
        return 1;
    }
    log_line("start: %ux%u@%u bitrate=%u", req.width, req.height, req.fps, req.bitrate);
    if (ALLOW_MODE_40)
        log_line("test build: the 120 Hz output mode (0x40) is allowed");
    net_state(CAP_STARTING, "");
    // Console 2026-11-09: launching a game changes the HDMI output twice about 3 s apart; with
    // one recovery per Go Live the second change ended the stream. Each reopened session must
    // deliver frames before it may recover again (capture_session), and at most RECOVERY_MAX
    // reopens fall within any RECOVERY_WINDOW_MS, so a broken encoder still ends with an error.
    int rc = 1;
    int64_t reopened[RECOVERY_MAX] = {0}; // when each recent recovery started, oldest replaced first
    unsigned next_slot = 0;
    for (;;) {
        int recent = 0;
        for (unsigned i = 0; i < RECOVERY_MAX; i++)
            recent += reopened[i] && now_ms() - reopened[i] < RECOVERY_WINDOW_MS;
        enum session_end e = capture_session(&req, recent < RECOVERY_MAX);
        if (e == SESS_STOPPED) { rc = 0; break; }
        if (e == SESS_RECOVERABLE && !net_dead && !quit && !stop_requested) {
            reopened[next_slot] = now_ms(); next_slot = (next_slot + 1) % RECOVERY_MAX;
            log_line("recovery %d of %d in a minute: fresh session (mode 0x%x)", recent + 1, RECOVERY_MAX,
                     segment.stable_mode);
            continue;
        }
        net_state(CAP_ERROR, segment.why[0] ? segment.why : "Capture failed.");
        break;
    }
    net_close();
    log_line("helper done rc=%d", rc);
    return rc;
}

// ---- process: lock, supervisor, worker ---------------------------------------------------


// Idle time, not total time: Go Live has no duration. After 15 s without progress the worker
// is asked to clean up; after 25 s only it is killed.
#ifndef WATCHDOG_SOFT_MS
#define WATCHDOG_SOFT_MS 15000u
#define WATCHDOG_HARD_MS 25000u
#define TERM_GRACE_MS 10000u
#define RECOVERY_POLL_US 1000000u
#endif
static int watchdog_state(uint64_t idle)
{
    return idle >= WATCHDOG_HARD_MS ? 2 : idle >= WATCHDOG_SOFT_MS ? 1 : 0;
}

static sl_broker supervisor;
struct supervision { pid_t child; int lock_fd; };
static void *supervise(void *arg)
{
    const struct supervision *s = arg;
    pid_t child = s->child;
    int lock_fd = s->lock_fd;
    int status = 0, term_sent = 0, worker_failed = 0;
    uint64_t term_deadline = 0;
    for (;;) {
        pid_t rc = waitpid(child, &status, WNOHANG);
        if (rc == child) break;
        if (rc < 0 && errno != EINTR) {
            kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
            worker_failed = 1; break;
        }
        int watchdog = watchdog_state(now_ms() - atomic_load(&progress->heartbeat_ms));
        if (!term_sent && (quit || watchdog >= 1)) {
            log_line("watchdog requesting graceful cleanup");
            kill(child, SIGTERM); term_sent = 1; term_deadline = now_ms() + TERM_GRACE_MS;
        }
        if (watchdog == 2 || (term_sent && now_ms() >= term_deadline)) {
            int id = progress->function;
            log_line("watchdog killing ONLY the owned worker; target=%d stage=%s; reboot may be needed",
                     progress->target, id > 0 && id <= FUNCTION_COUNT ? symbols[id - 1] : "local work");
            kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
            break;
        }
        int broker_rc = sl_broker_poll(&supervisor, 25);
        if (broker_rc < 0) {
            // The worker may have died mid-request, or violated framing. Reap it before
            // recovering the private context; never run worker cleanup concurrently.
            kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
            worker_failed = broker_rc == -2; break;
        }
    }
    log_line("worker status=0x%x", status);
    if (supervisor.context.attached) {
        worker_failed = 1;
        log_line("supervisor recovering owned target after worker exit; encoder cleanup unconfirmed, reboot may be needed");
    }
    uint64_t last_hold_log = 0;
    for (;;) {
        int recovered = sl_broker_recover(&supervisor);
        if (recovered == 0 || recovered == SL_END_GONE) break;
        worker_failed = 1;
        if (!last_hold_log || now_ms() - last_hold_log >= 30000) {
            log_line("restoration incomplete at %s; supervisor retaining tracer and retrying; reboot may be needed",
                     supervisor.context.stage ? supervisor.context.stage : "unknown");
            last_hold_log = now_ms();
        }
        usleep(RECOVERY_POLL_US);
    }
    while (sl_broker_close(&supervisor)) {
        worker_failed = 1;
        log_line("supervisor close refused; retaining recovery ownership");
        (void)sl_broker_recover(&supervisor);
        usleep(RECOVERY_POLL_US);
    }
    munmap(progress, sizeof *progress); progress = NULL;
    close(lock_fd);
    if (log_file) fclose(log_file);
    return (void *)(intptr_t)(!worker_failed && WIFEXITED(status) ? WEXITSTATUS(status) : 1);
}

#ifndef CAPTURE_NO_MAIN
static void on_signal(int sig) { (void)sig; quit = 1; }
static void *worker(void *unused) { (void)unused; return (void *)(intptr_t)helper_run(); }
int main(void)
{
#ifdef SL_PS5
    sceKernelSetProcessName(CAP_PROCESS_NAME);
#endif
    if (mkdir(CAP_DIR, 0700) && errno != EEXIST) return 1;
    int lock_fd = open(LOCK_PATH, O_CREAT | O_RDWR, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB)) return 1; // one helper at a time
    (void)rename(LOG_PATH, LOG_PATH ".prev"); // the session before, kept for diagnosis
    log_file = fopen(LOG_PATH, "w");
    progress = mmap(NULL, sizeof *progress, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    if (progress == MAP_FAILED) return 1;
    memset(progress, 0, sizeof *progress);
    signal(SIGTERM, on_signal); signal(SIGINT, on_signal); signal(SIGPIPE, SIG_IGN);
    atomic_init(&progress->function, 0);
    atomic_init(&progress->target, 0);
    atomic_init(&progress->heartbeat_ms, now_ms());
    if (sl_broker_open(&supervisor)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (!child) {
#ifdef SL_PS5
        sceKernelSetProcessName(CAP_WORKER_NAME); // the parent stays the supervisor
#endif
        sl_broker_worker(&supervisor);
        pthread_attr_t attr;
        pthread_t thread;
        if (pthread_attr_init(&attr)) _exit(1);
        int rc = pthread_attr_setstacksize(&attr, 2u * 1024u * 1024u);
        if (!rc) rc = pthread_create(&thread, &attr, worker, NULL);
        pthread_attr_destroy(&attr);
        if (rc) _exit(1);
        void *result = NULL;
        if (pthread_join(thread, &result)) _exit(1);
        _exit((int)(intptr_t)result);
    }
    sl_broker_parent(&supervisor);
    // Native injector/kernel helpers run on the same generous stack as the capture worker.
    // Threads share tracing ownership; main never exits before this supervisor thread joins.
    struct supervision s = {child, lock_fd};
    pthread_attr_t attr;
    pthread_t thread;
    if (pthread_attr_init(&attr)) {
        kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
        sl_broker_close(&supervisor); close(lock_fd); return 1;
    }
    int rc = pthread_attr_setstacksize(&attr, 2u * 1024u * 1024u);
    if (!rc) rc = pthread_create(&thread, &attr, supervise, &s);
    pthread_attr_destroy(&attr);
    if (rc) {
        kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
        sl_broker_close(&supervisor); close(lock_fd); return 1;
    }
    void *result = NULL;
    // A valid, joinable supervisor thread cannot be discarded while it may own the tracee.
    if (pthread_join(thread, &result)) for (;;) pause();
    return (int)(intptr_t)result;
}
#endif
