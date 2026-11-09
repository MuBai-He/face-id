#ifndef __APPLE__
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
/*
 * Transport smoke-test responder, NOT an authentication implementation.
 * It deliberately NEVER emits FID_AUTH_APPROVED. This binary must not be
 * presented as a working sudo face-auth daemon.
 *
 * Run under root only in a disposable development environment. The future
 * Swift daemon must verify process audit credentials, active GUI session,
 * the requesting UID, nonce, freshness, and perform its OWN ArcFace/liveness
 * inference using a root-protected enrollment store.
 */

#include "../PAM/faceid_auth_protocol.h"
#include "../PAM/faceid_io.h"
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static volatile sig_atomic_t should_stop = 0;
static void handle_signal(int signal_number) { (void)signal_number; should_stop = 1; }

int main(void) {
    if (geteuid() != 0) {
        fputs("faceid-authd-probe requires root; it does not approve anyone\n", stderr);
        return 1;
    }
    umask(0077);
    struct stat st;
    if (lstat(FID_AUTH_SOCKET, &st) == 0) {
        fputs("Refusing to replace an existing auth socket\n", stderr);
        return 1;
    }
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    if (strlen(FID_AUTH_SOCKET) >= sizeof(addr.sun_path)) return 1;
    memcpy(addr.sun_path, FID_AUTH_SOCKET, strlen(FID_AUTH_SOCKET) + 1);

    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server < 0) return 1;
    if (bind(server, (struct sockaddr *)&addr, sizeof addr) != 0) {
        perror("probe socket bind");
        close(server);
        return 1; /* Do not unlink a socket we did not bind. */
    }
    if (chmod(FID_AUTH_SOCKET, 0600) != 0 || listen(server, 8) != 0) {
        perror("probe socket setup");
        close(server);
        unlink(FID_AUTH_SOCKET);
        return 1;
    }
    struct sigaction action = {0};
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    fprintf(stderr, "Probe listening at %s; ALL auth attempts will fall back\n", FID_AUTH_SOCKET);

    while (!should_stop) {
        int fd = accept(server, NULL, NULL);
        if (fd < 0) { if (errno == EINTR) continue; break; }
        int64_t start = fid_now_ms();
        if (start < 0 || !fid_prepare_fd(fd)) { close(fd); continue; }
        int64_t deadline = start + FID_AUTH_TIMEOUT_MS;
        uid_t peer_uid = (uid_t)-1;
#ifdef __APPLE__
        gid_t peer_gid;
        if (getpeereid(fd, &peer_uid, &peer_gid) != 0) peer_uid = (uid_t)-1;
#elif defined(SO_PEERCRED)
        struct ucred credentials;
        socklen_t length = sizeof credentials;
        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) == 0)
            peer_uid = credentials.uid;
#endif
        fid_auth_request request;
        if (peer_uid == 0 && fid_recv_all(fd, &request, sizeof request, deadline) &&
            ntohl(request.magic_be) == FID_AUTH_MAGIC &&
            ntohl(request.version_be) == FID_AUTH_VERSION &&
            memchr(request.username, '\0', sizeof request.username) &&
            memchr(request.service, '\0', sizeof request.service) &&
            strcmp(request.service, "sudo") == 0) {
            fid_auth_response response = {0};
            response.magic_be = htonl(FID_AUTH_MAGIC);
            response.version_be = htonl(FID_AUTH_VERSION);
            response.result_be = htonl(FID_AUTH_UNAVAILABLE);
            memcpy(response.nonce, request.nonce, sizeof response.nonce);
            (void)fid_send_all(fd, &response, sizeof response, deadline);
        }
        close(fd);
    }
    close(server);
    unlink(FID_AUTH_SOCKET);
    return 0;
}
