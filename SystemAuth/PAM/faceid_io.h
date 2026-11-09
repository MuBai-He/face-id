#ifndef FACEID_IO_H
#define FACEID_IO_H

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* One monotonic deadline covers the entire transaction, including partial I/O. */
static inline int64_t fid_now_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static inline int fid_prepare_fd(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 ||
        fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) return 0;
#ifdef SO_NOSIGPIPE
    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof yes) != 0) return 0;
#endif
    return 1;
}

static inline int fid_wait(int fd, short events, int64_t deadline) {
    for (;;) {
        int64_t now = fid_now_ms();
        if (now < 0 || now >= deadline) return 0;
        struct pollfd pfd = { .fd = fd, .events = events, .revents = 0 };
        int rc = poll(&pfd, 1, (int)(deadline - now));
        if (rc < 0 && errno == EINTR) continue;
        if (rc <= 0) return 0;
        if (pfd.revents & events) return 1;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return 0;
    }
}

static inline int fid_send_all(int fd, const void *data, size_t length, int64_t deadline) {
    const unsigned char *p = data;
    while (length) {
        if (!fid_wait(fd, POLLOUT, deadline)) return 0;
#ifdef MSG_NOSIGNAL
        ssize_t n = send(fd, p, length, MSG_NOSIGNAL);
#else
        ssize_t n = send(fd, p, length, 0);
#endif
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n <= 0) return 0;
        p += (size_t)n;
        length -= (size_t)n;
    }
    return 1;
}

static inline int fid_recv_all(int fd, void *data, size_t length, int64_t deadline) {
    unsigned char *p = data;
    while (length) {
        if (!fid_wait(fd, POLLIN, deadline)) return 0;
        ssize_t n = recv(fd, p, length, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n <= 0) return 0;
        p += (size_t)n;
        length -= (size_t)n;
    }
    return 1;
}

#endif
