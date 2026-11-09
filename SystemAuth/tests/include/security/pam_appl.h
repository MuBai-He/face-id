#ifndef TEST_PAM_APPL_H
#define TEST_PAM_APPL_H
/* Test-only API/ABI. Numeric values are fixtures, not macOS PAM constants.
 * Release builds must include the real macOS SDK headers instead. */
typedef struct pam_handle {
    const char *service;
    const char *ruser;
    const char *user;
    const char *rhost;
} pam_handle_t;
#define PAM_SUCCESS 0
#define PAM_AUTH_ERR 7
#define PAM_IGNORE 25
#define PAM_SERVICE 1
#define PAM_RUSER 2
#define PAM_USER 3
#define PAM_RHOST 4
#define PAM_SILENT 0x8000
int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item);
#endif
