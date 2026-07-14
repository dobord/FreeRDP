#ifndef FRDP_AUTHD_PAM_H
#define FRDP_AUTHD_PAM_H

#include <stddef.h>

#include <security/pam_appl.h>

typedef enum
{
    FRDP_AUTHD_PAM_OK = 0,
    FRDP_AUTHD_PAM_DENIED,
    FRDP_AUTHD_PAM_ERROR
} frdpAuthdPamStatus;

typedef int (*frdpAuthdPamGetItemFn)(const pam_handle_t *pamh, int item_type,
                                    const void **item);

typedef struct
{
    int (*start)(const char *service, const char *user, const struct pam_conv *conv,
                 pam_handle_t **pamh);
    int (*set_item)(pam_handle_t *pamh, int item_type, const void *item);
    int (*authenticate)(pam_handle_t *pamh, int flags);
    int (*acct_mgmt)(pam_handle_t *pamh, int flags);
    frdpAuthdPamGetItemFn get_item;
    int (*setcred)(pam_handle_t *pamh, int flags);
    int (*end)(pam_handle_t *pamh, int pam_status);
} frdpAuthdPamOps;

int frdp_authd_pam_conversation(int num_msg, const struct pam_message **msg,
                                struct pam_response **resp, void *appdata_ptr);
void frdp_authd_pam_clear_responses(struct pam_response *responses, int count);
frdpAuthdPamStatus frdp_authd_pam_auth_status(int pam_status);
frdpAuthdPamStatus frdp_authd_pam_account_status(int pam_status);
int frdp_authd_user_is_valid(const char *user, size_t user_size);
int frdp_authd_pam_copy_user(const pam_handle_t *pamh, frdpAuthdPamGetItemFn get_item,
                             char *user, size_t user_size);
frdpAuthdPamStatus frdp_authd_pam_authenticate_with_ops(
    const frdpAuthdPamOps *ops, const char *service, const char *rhost, const char *user,
    char *password, char *pam_user, size_t pam_user_size);

#endif /* FRDP_AUTHD_PAM_H */
