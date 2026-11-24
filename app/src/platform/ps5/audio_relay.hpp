// LAB ONLY, never merged into community: forwards the voice playback PCM
// this app already receives from the core to a second, loopback-only
// listener -- the overlay's AudioRelay worker, hosted inside SceShellUI,
// where a measured 2026-11-22 test showed sceAudioOut stays audible while
// a game has AV focus (unlike this app's own AudioOut). Best-effort: never
// blocks or backpressures the real voice link thread.
#pragma once

#include "platform/ps5/system.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace hui::ps5
{

class AudioRelayServer
{
  public:
    // Fixed and known to both ends at compile time (overlay/src/core/worker.cpp
    // hardcodes the same value): no file handoff needed at all, which is what
    // kept failing (measured 2026-11-22, several different ways, across both
    // /data/... and /user/data/...: this app's own sandbox and SceShellUI's
    // do not agree on a single path that one can write and the other read).
    // Loopback-only and this console is single-user, so skipping a handshake
    // is an acceptable trade for not depending on that filesystem agreement.
    static constexpr std::uint16_t kPort = 9043;

    bool start()
    {
        listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ < 0)
            return false;
        const int one = 1;
        setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        sockaddr_in a{};
        a.sin_len = sizeof a;
        a.sin_family = AF_INET;
        a.sin_port = htons(kPort);
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(listen_fd_, reinterpret_cast<sockaddr *>(&a), sizeof a) != 0 || listen(listen_fd_, 1) != 0)
        {
            close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }
        sys::log("[HUI] audio relay listening port=%u", static_cast<unsigned>(kPort));
        return true;
    }

    // Called every link_run() iteration. O_NONBLOCK does not reliably take
    // effect on this console (see voice_audio.cpp's own note by its
    // MSG_DONTWAIT sends): a plain accept() here hung this thread forever
    // the moment it ran, taking all voice audio down with it (measured
    // 2026-11-22). poll() with an explicit timeout first is the part of
    // this file's socket code the console is known to honour.
    void poll_accept()
    {
        if (listen_fd_ < 0)
            return;
        pollfd lp{listen_fd_, POLLIN, 0};
        if (poll(&lp, 1, 0) <= 0 || !(lp.revents & POLLIN))
            return;
        const int fd = accept(listen_fd_, nullptr, nullptr);
        if (fd < 0)
            return;
        const int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        if (client_fd_ >= 0)
            close(client_fd_);
        client_fd_ = fd;
        sys::log("[HUI] audio relay client connected");
    }

    // Raw bytes as received from the core (same stereo S16 48 kHz layout).
    // Best-effort: a stalled client just misses audio, never blocks here.
    // MSG_NOSIGNAL (a Linux-ism; this console's BSD-derived libkernel does
    // not support it the same way) made every send() fail outright, closing
    // the client the moment the next chunk arrived (measured 2026-11-22:
    // "client connected" immediately followed by "client dropped"). The
    // rest of this file already ignores SIGPIPE process-wide
    // (VoiceAudio::start()), which is this codebase's actual answer to a
    // peer that closed mid-write, so this does not need its own.
    void forward(const void *data, std::size_t n)
    {
        if (client_fd_ < 0 || n == 0)
            return;
        const ssize_t sent = send(client_fd_, data, n, MSG_DONTWAIT);
        if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        {
            close(client_fd_);
            client_fd_ = -1;
            sys::log("[HUI] audio relay client dropped");
        }
    }

    ~AudioRelayServer()
    {
        if (client_fd_ >= 0)
            close(client_fd_);
        if (listen_fd_ >= 0)
            close(listen_fd_);
    }

  private:
    int listen_fd_ = -1, client_fd_ = -1;
};

} // namespace hui::ps5
