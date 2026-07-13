#include "authd_pam.h"

#include <stdlib.h>
#include <string.h>

#define FRDP_AUTHD_PAM_MAX_MESSAGES 32

static void clear_secret(char *secret, size_t length)
{
    volatile unsigned char *p = (volatile unsigned char *)secret;

    while (p && length-- > 0)
        *p++ = 0;
}

void frdp_authd_pam_clear_responses(struct pam_response *responses, int count)
{
    if (!responses || count <= 0)
        return;

    for (int x = 0; x < count; x++) {
        if (responses[x].resp) {
            const size_t length = strlen(responses[x].resp) + 1U;

            clear_secret(responses[x].resp, length);
            free(responses[x].resp);
            responses[x].resp = NULL;
        }
    }
}

frdpAuthdPamStatus frdp_authd_pam_auth_status(int pam_status)
{
    switch (pam_status) {
        case PAM_SUCCESS:
            return FRDP_AUTHD_PAM_OK;
        case PAM_AUTH_ERR:
        case PAM_MAXTRIES:
        case PAM_PERM_DENIED:
        case PAM_USER_UNKNOWN:
            return FRDP_AUTHD_PAM_DENIED;
        default:
            return FRDP_AUTHD_PAM_ERROR;
    }
}

frdpAuthdPamStatus frdp_authd_pam_account_status(int pam_status)
{
    switch (pam_status) {
        case PAM_SUCCESS:
            return FRDP_AUTHD_PAM_OK;
        case PAM_ACCT_EXPIRED:
        case PAM_AUTH_ERR:
        case PAM_NEW_AUTHTOK_REQD:
        case PAM_PERM_DENIED:
        case PAM_USER_UNKNOWN:
            return FRDP_AUTHD_PAM_DENIED;
        default:
            return FRDP_AUTHD_PAM_ERROR;
    }
}

int frdp_authd_pam_conversation(int num_msg, const struct pam_message **msg,
                                struct pam_response **resp, void *appdata_ptr)
{
    const char *password = (const char *)appdata_ptr;
    struct pam_response *responses = NULL;
    int answered_password_prompt = 0;

    if (resp)
        *resp = NULL;
    if (num_msg <= 0 || num_msg > FRDP_AUTHD_PAM_MAX_MESSAGES || !msg || !resp)
        return PAM_CONV_ERR;

    responses = calloc((size_t)num_msg, sizeof(struct pam_response));
    if (!responses)
        return PAM_BUF_ERR;

    for (int i = 0; i < num_msg; i++) {
        if (!msg[i])
            goto fail;

        switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
                if (answered_password_prompt)
                    goto fail;
                responses[i].resp = strdup(password ? password : "");
                if (!responses[i].resp)
                    goto fail;
                answered_password_prompt = 1;
                break;
            case PAM_TEXT_INFO:
            case PAM_ERROR_MSG:
                break;
            default:
                goto fail;
        }
    }

    *resp = responses;
    return PAM_SUCCESS;

fail:
    frdp_authd_pam_clear_responses(responses, num_msg);
    free(responses);
    return PAM_CONV_ERR;
}
