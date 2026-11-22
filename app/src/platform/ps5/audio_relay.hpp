// LAB ONLY, never merged into community: forwards the voice playback PCM
// this app already receives from the core to a second, loopback-only
// listener -- the overlay's AudioRelay worker, hosted inside SceShellUI,
// where a measured 2026-11-22 test showed sceAudioOut stays audible while
// a game has AV focus (unlike this app's own AudioOut). Best-effort: never
// blocks or backpressures the real voice link thread.
#pragma once

#include "platform/ps5/system.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace hui::ps5
{

class AudioRelayServer
{
  public:
    static constexpr std::uint16_t kPort = 9043;
    static constexpr const char *kDir = "/data/ps5-discord-audio-relay";
    static constexpr const char *kFile = "/data/ps5-discord-audio-relay/audio-relay.bin";

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
        const int flags = fcntl(listen_fd_, F_GETFL, 0);
        fcntl(listen_fd_, F_SETFL, flags | O_NONBLOCK);
        token_ = (static_cast<std::uint64_t>(sys::monotonic_us()) << 1) ^ 0x4c414231ULL;
        // Not /data/discord-overlay-poc: that one is root:755 (created by the
        // loader, an elfldr payload with full privileges) and this app's own
        // process could not create a file in it (silently: no audio-relay.bin
        // ever appeared, measured 2026-11-22). A directory this app creates
        // itself (as tools/audio-probe's app_mic_probe.cpp already does
        // under /data/ps5-discord-probe) it owns, and can write into.
        mkdir(kDir, 0777);
        if (std::FILE *f = std::fopen(kFile, "wb"))
        {
            std::fwrite(&kPort, sizeof kPort, 1, f);
            std::fwrite(&token_, sizeof token_, 1, f);
            std::fclose(f);
        }
        sys::log("[HUI] audio relay listening port=%u", static_cast<unsigned>(kPort));
        return true;
    }

    // Called every link_run() iteration. O_NONBLOCK/SO_RCVTIMEO do not
    // reliably take effect on this console (see voice_audio.cpp's own note
    // by its MSG_DONTWAIT sends): a plain accept()/recv() here hung this
    // thread forever the moment it ran, taking all voice audio down with it
    // (measured 2026-11-22). poll() with an explicit timeout on every read
    // is the only part of this file's socket code the console is known to
    // honour, so every step below goes through it instead.
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
        // Handshake: a few ms total, bounded by polling, never a blocking read.
        std::uint64_t got = 0;
        auto *at = reinterpret_cast<std::uint8_t *>(&got);
        std::size_t have = 0;
        bool ok = false;
        for (int tries = 0; tries < 40; ++tries)
        {
            pollfd hp{fd, POLLIN, 0};
            if (poll(&hp, 1, 5) <= 0 || !(hp.revents & POLLIN))
                continue;
            const ssize_t n = recv(fd, at + have, sizeof got - have, MSG_DONTWAIT);
            if (n <= 0)
                break;
            have += static_cast<std::size_t>(n);
            if (have == sizeof got)
            {
                ok = true;
                break;
            }
        }
        if (!ok || got != token_)
        {
            close(fd);
            return;
        }
        const int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        if (client_fd_ >= 0)
            close(client_fd_);
        client_fd_ = fd;
        sys::log("[HUI] audio relay client connected");
    }

    // Raw bytes as received from the core (same stereo S16 48 kHz layout).
    // Best-effort: a stalled client just misses audio, never blocks here.
    void forward(const void *data, std::size_t n)
    {
        if (client_fd_ < 0 || n == 0)
            return;
        const ssize_t sent = send(client_fd_, data, n, MSG_DONTWAIT | MSG_NOSIGNAL);
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
    std::uint64_t token_ = 0;
};

} // namespace hui::ps5
