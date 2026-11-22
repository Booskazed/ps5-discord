// LAB ONLY, never merged into community: forwards the voice playback PCM
// this app already receives from the core to a second, loopback-only
// listener -- the overlay's AudioRelay worker, hosted inside SceShellUI,
// where a measured 2026-11-22 test showed sceAudioOut stays audible while
// a game has AV focus (unlike this app's own AudioOut). Best-effort: never
// blocks or backpressures the real voice link thread.
#pragma once

#include "platform/ps5/system.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace hui::ps5
{

class AudioRelayServer
{
  public:
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
        const int flags = fcntl(listen_fd_, F_GETFL, 0);
        fcntl(listen_fd_, F_SETFL, flags | O_NONBLOCK);
        token_ = (static_cast<std::uint64_t>(sys::monotonic_us()) << 1) ^ 0x4c414231ULL;
        mkdir("/data/discord-overlay-poc", 0777);
        if (std::FILE *f = std::fopen("/data/discord-overlay-poc/audio-relay.bin", "wb"))
        {
            std::fwrite(&kPort, sizeof kPort, 1, f);
            std::fwrite(&token_, sizeof token_, 1, f);
            std::fclose(f);
        }
        sys::log("[HUI] audio relay listening port=%u", static_cast<unsigned>(kPort));
        return true;
    }

    // Called every link_run() iteration: non-blocking accept of at most one
    // waiting connection, replacing any existing client.
    void poll_accept()
    {
        if (listen_fd_ < 0)
            return;
        const int fd = accept(listen_fd_, nullptr, nullptr);
        if (fd < 0)
            return;
        const int flags = fcntl(fd, F_GETFL, 0);
        timeval tv{2, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        std::uint64_t got = 0;
        const ssize_t n = recv(fd, &got, sizeof got, MSG_WAITALL);
        if (n != static_cast<ssize_t>(sizeof got) || got != token_)
        {
            close(fd);
            return;
        }
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
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
