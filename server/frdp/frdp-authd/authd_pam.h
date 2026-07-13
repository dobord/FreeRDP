#ifndef FRDP_AUTHD_PAM_H
#define FRDP_AUTHD_PAM_H

#include <security/pam_appl.h>

typedef enum
{
    FRDP_AUTHD_PAM_OK = 0,
    FRDP_AUTHD_PAM_DENIED,
    FRDP_AUTHD_PAM_ERROR
} frdpAuthdPamStatus;

int frdp_authd_pam_conversation(int num_msg, const struct pam_message **msg,
                                struct pam_response **resp, void *appdata_ptr);
void frdp_authd_pam_clear_responses(struct pam_response *responses, int count);
frdpAuthdPamStatus frdp_authd_pam_auth_status(int pam_status);
frdpAuthdPamStatus frdp_authd_pam_account_status(int pam_status);

#endif /* FRDP_AUTHD_PAM_H */
