#include <security/pam_appl.h>
int pam_get_item(const pam_handle_t *pamh, int type, const void **out) {
    if (!pamh || !out) return PAM_AUTH_ERR;
    switch (type) {
        case PAM_SERVICE: *out = pamh->service; return PAM_SUCCESS;
        case PAM_RUSER: *out = pamh->ruser; return PAM_SUCCESS;
        case PAM_USER: *out = pamh->user; return PAM_SUCCESS;
        case PAM_RHOST: *out = pamh->rhost; return PAM_SUCCESS;
        default: return PAM_AUTH_ERR;
    }
}
