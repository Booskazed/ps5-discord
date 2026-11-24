// ps5-discord - Loading system modules and finding their functions in a native title.
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "platform/ps5/sce_module.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace hui::ps5
{

namespace
{

std::uintptr_t dlsym_request(const char *query_suffix)
{
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;
    timeval timeout{3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    sockaddr_in to{};
    to.sin_len = sizeof to;
    to.sin_family = AF_INET;
    to.sin_port = htons(9041);
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    char buf[512];
    const int n = std::snprintf(buf, sizeof buf,
                                "GET /api/dlsym?pid=%d&%s HTTP/1.0\r\n"
                                "X-Discord-Native: 1\r\nX-Core-Key: %s\r\n\r\n",
                                static_cast<int>(getpid()), query_suffix, core_key().c_str());
    std::string raw;
    if (connect(fd, reinterpret_cast<sockaddr *>(&to), sizeof to) == 0 && send(fd, buf, n, 0) == n)
        for (ssize_t r; (r = recv(fd, buf, sizeof buf, 0)) > 0;)
            raw.append(buf, static_cast<std::size_t>(r));
    close(fd);
    const std::size_t at = raw.find("\"addr\":");
    return at == std::string::npos ? 0 : std::strtoull(raw.c_str() + at + 7, nullptr, 10);
}

} // namespace

std::uintptr_t core_dlsym(const char *lib, const char *sym)
{
    char suffix[448];
    std::snprintf(suffix, sizeof suffix, "lib=%s&sym=%s", lib, sym);
    return dlsym_request(suffix);
}

std::uintptr_t core_dlsym_handle(int handle, const char *sym)
{
    char suffix[448];
    std::snprintf(suffix, sizeof suffix, "handle=0x%x&sym=%s", static_cast<unsigned>(handle), sym);
    return dlsym_request(suffix);
}

} // namespace hui::ps5
