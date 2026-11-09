#ifndef __APPLE__
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
/*
 * Face ID PAM adapter for the macOS sudo PAM stack.
 *
 * Security boundary: NO recognition happens in this module. It accepts an
 * APPROVED result only from a root-owned AF_UNIX socket whose peer is root,
 * and only for the current random challenge. The privileged service must
 * perform face matching itself, not trust a GUI agent's yes/no answer.
 *
 * A missing/invalid service cannot approve authentication. The default
 * 'auth sufficient' PAM rule leaves Touch ID and password authentication
 * intact. This adapter intentionally does not support su or screensaver.
 */

#include "faceid_auth_protocol.h"
#include "faceid_io.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/random.h>
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

static int secure_random(unsigned char *output, size_t length) {
#ifdef __APPLE__
    arc4random_buf(output, length);
    return 1;
#elif defined(__linux__)
    size_t offset = 0;
    while (offset < length) {
        ssize_t n = getrandom(output + offset, length - offset, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 0;
        offset += (size_t)n;
    }
    return 1;
#else
    (void)output; (void)length;
    return 0;
#endif
}

/* Only authenticate the invoker, and only if PAM_USER requests that identity.
 * rootpw/targetpw/runaspw may require a DIFFERENT account; do not substitute
 * the invoker's face for that account. PAM items are context, not peer identity:
 * the future daemon must independently verify process and console credentials.
 */
static int requesting_user(pam_handle_t *pamh, uid_t *uid, char *name, size_t size) {
    uid_t real_uid = getuid();
    struct passwd pwd;
    struct passwd *entry = NULL;
    char storage[8192];

    if (real_uid != 0) {
        if (getpwuid_r(real_uid, &pwd, storage, sizeof storage, &entry) != 0 || !entry) return 0;
    } else {
        const void *ruser = NULL;
        if (pam_get_item(pamh, PAM_RUSER, &ruser) != PAM_SUCCESS || !ruser) return 0;
        const char *value = (const char *)ruser;
        if (!*value || strlen(value) >= FID_AUTH_USERNAME_MAX) return 0;
        if (getpwnam_r(value, &pwd, storage, sizeof storage, &entry) != 0 || !entry) return 0;
    }

    if (entry->pw_uid == 0 || !entry->pw_name) return 0;
    size_t len = strlen(entry->pw_name);
    if (len == 0 || len >= size) return 0;
    memcpy(name, entry->pw_name, len + 1);
    *uid = entry->pw_uid;

    const void *auth_user = NULL;
    if (pam_get_item(pamh, PAM_USER, &auth_user) != PAM_SUCCESS || !auth_user) return 0;
    const char *auth_name = auth_user;
    if (!*auth_name || strlen(auth_name) >= FID_AUTH_USERNAME_MAX) return 0;
    entry = NULL;
    if (getpwnam_r(auth_name, &pwd, storage, sizeof storage, &entry) != 0 || !entry) return 0;
    return entry->pw_uid == *uid;
}

static int connect_root_service(int64_t deadline_ms) {
    struct stat st;
    /* Check the socket path. A user-owned socket is never an auth authority. */
    if (lstat(FID_AUTH_SOCKET, &st) != 0 || !S_ISSOCK(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & 0077) != 0) return -1;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (!fid_prepare_fd(fd)) goto failed;

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    if (strlen(FID_AUTH_SOCKET) >= sizeof addr.sun_path) goto failed;
    strncpy(addr.sun_path, FID_AUTH_SOCKET, sizeof addr.sun_path - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        if (errno != EINPROGRESS || !fid_wait(fd, POLLOUT, deadline_ms)) goto failed;
        int socket_error = 0;
        socklen_t len = sizeof socket_error;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &len) != 0 || socket_error) goto failed;
    }

#ifdef __APPLE__
    uid_t peer_uid;
    gid_t peer_gid;
    if (getpeereid(fd, &peer_uid, &peer_gid) != 0 || peer_uid != 0) goto failed;
#elif defined(SO_PEERCRED)
    struct ucred credentials;
    socklen_t credentials_length = sizeof credentials;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials,
                   &credentials_length) != 0 || credentials.uid != 0) goto failed;
#else
    goto failed;
#endif
    return fd;

failed:
    close(fd);
    return -1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
    (void)argv;
    if (!pamh) return PAM_AUTH_ERR;
    /* No UI during silent auth, no unsupported options, no unprivileged host. */
    if (geteuid() != 0 || (flags & PAM_SILENT) || argc != 0) return PAM_IGNORE;
    const void *service_ptr = NULL;
    if (pam_get_item(pamh, PAM_SERVICE, &service_ptr) != PAM_SUCCESS ||
        !service_ptr || strcmp((const char *)service_ptr, "sudo") != 0) {
        return PAM_IGNORE; /* Never grant su, login, ssh or screen unlock. */
    }

    const void *rhost = NULL;
    if (pam_get_item(pamh, PAM_RHOST, &rhost) != PAM_SUCCESS ||
        (rhost && *(const char *)rhost)) return PAM_IGNORE;
    /* Empty RHOST does NOT prove a local session. The daemon must check that. */

    fid_auth_request request = {0};
    uid_t uid;
    if (!requesting_user(pamh, &uid, request.username, sizeof request.username)) return PAM_IGNORE;
    memcpy(request.service, "sudo", sizeof "sudo");
    request.magic_be = htonl(FID_AUTH_MAGIC);
    request.version_be = htonl(FID_AUTH_VERSION);
    request.uid_be = htonl((uint32_t)uid);
    request.pid_be = htonl((uint32_t)getpid());
    if (!secure_random(request.nonce, sizeof request.nonce)) return PAM_IGNORE;

    int64_t start = fid_now_ms();
    if (start < 0) return PAM_IGNORE;
    int fd = connect_root_service(start + FID_AUTH_TIMEOUT_MS);
    if (fd < 0) return PAM_IGNORE;

    fid_auth_response response = {0};
    int exchanged = fid_send_all(fd, &request, sizeof request, start + FID_AUTH_TIMEOUT_MS) &&
                    fid_recv_all(fd, &response, sizeof response, start + FID_AUTH_TIMEOUT_MS);
    close(fd);

    int64_t finished = fid_now_ms();
    if (finished < 0 || finished >= start + FID_AUTH_TIMEOUT_MS) return PAM_IGNORE;
    if (!exchanged || ntohl(response.magic_be) != FID_AUTH_MAGIC ||
        ntohl(response.version_be) != FID_AUTH_VERSION ||
        memcmp(response.nonce, request.nonce, sizeof request.nonce) != 0) {
        return PAM_IGNORE;
    }

    if (ntohl(response.result_be) == FID_AUTH_APPROVED) return PAM_SUCCESS;
    if (ntohl(response.result_be) == FID_AUTH_REJECTED) return PAM_AUTH_ERR;
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
