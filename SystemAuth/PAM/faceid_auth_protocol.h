#ifndef FACEID_AUTH_PROTOCOL_H
#define FACEID_AUTH_PROTOCOL_H

#include <stdint.h>

/* Local, fixed-size protocol. Both endpoints use network-byte-order integers.
 * The daemon MUST revalidate the caller's audit credentials and the requested
 * user/session before consulting its root-owned face templates.
 */
#ifndef FID_AUTH_SOCKET
#define FID_AUTH_SOCKET "/var/run/com.joeqiao.faceid.authd.sock"
#endif
#define FID_AUTH_MAGIC 0x46494441u /* "FIDA" */
#define FID_AUTH_VERSION 1u
#define FID_AUTH_TIMEOUT_MS 4000
#define FID_AUTH_USERNAME_MAX 64
#define FID_AUTH_SERVICE_MAX 16
#define FID_AUTH_NONCE_SIZE 16

enum fid_auth_result {
    FID_AUTH_REJECTED = 0,
    FID_AUTH_APPROVED = 1,
    FID_AUTH_UNAVAILABLE = 2
};

typedef struct __attribute__((packed)) {
    uint32_t magic_be;
    uint32_t version_be;
    uint32_t uid_be;
    uint32_t pid_be;
    uint8_t nonce[FID_AUTH_NONCE_SIZE];
    char username[FID_AUTH_USERNAME_MAX];
    char service[FID_AUTH_SERVICE_MAX];
} fid_auth_request;

typedef struct __attribute__((packed)) {
    uint32_t magic_be;
    uint32_t version_be;
    uint32_t result_be;
    uint8_t nonce[FID_AUTH_NONCE_SIZE];
} fid_auth_response;

_Static_assert(sizeof(fid_auth_request) == 112, "Unexpected request ABI");
_Static_assert(sizeof(fid_auth_response) == 28, "Unexpected response ABI");

#endif
