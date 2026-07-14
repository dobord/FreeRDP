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

int frdp_authd_user_is_valid(const char *user, size_t user_size)
{
    size_t length = 0;

    if (!user || user_size == 0)
        return -1;
    length = strnlen(user, user_size);
    if ((length == 0) || (length >= user_size))
        return -1;
    for (size_t x = 0; x < length; x++) {
        const unsigned char c = (unsigned char)user[x];

        if ((c < 0x20U) || (c == 0x7fU))
            return -1;
    }
    return 0;
}

int frdp_authd_pam_copy_user(const pam_handle_t *pamh, frdpAuthdPamGetItemFn get_item,
                             char *user, size_t user_size)
{
    const void *item = NULL;
    const char *pam_user = NULL;

    if (user && user_size > 0)
        memset(user, 0, user_size);
    if (!pamh || !get_item || !user || user_size == 0)
        return -1;
    if ((get_item(pamh, PAM_USER, &item) != PAM_SUCCESS) || !item)
        return -1;

    pam_user = (const char *)item;
    if (frdp_authd_user_is_valid(pam_user, user_size) != 0)
        return -1;
    const size_t length = strlen(pam_user);
    memcpy(user, pam_user, length + 1U);
    return 0;
}

frdpAuthdPamStatus frdp_authd_pam_authenticate_with_ops(
    const frdpAuthdPamOps *ops, const char *service, const char *rhost, const char *user,
    char *password, char *pam_user, size_t pam_user_size)
{
    struct pam_conv conv = {frdp_authd_pam_conversation, password};
    pam_handle_t *pamh = NULL;
    frdpAuthdPamStatus status = FRDP_AUTHD_PAM_ERROR;
    int credentials_established = 0;
    int ret = PAM_SYSTEM_ERR;

    if (pam_user && pam_user_size > 0)
        memset(pam_user, 0, pam_user_size);
    if (!ops || !ops->start || !ops->set_item || !ops->authenticate || !ops->acct_mgmt ||
        !ops->get_item || !ops->setcred || !ops->end || !service || !service[0] || !user ||
        !password || !pam_user || pam_user_size == 0)
        return status;

    ret = ops->start(service, user, &conv, &pamh);
    if (ret != PAM_SUCCESS)
        return status;
    if (rhost && rhost[0])
        ret = ops->set_item(pamh, PAM_RHOST, rhost);
    if (ret == PAM_SUCCESS)
        ret = ops->set_item(pamh, PAM_TTY, "rdp");
    if (ret == PAM_SUCCESS)
        ret = ops->set_item(pamh, PAM_RUSER, user);
    if (ret == PAM_SUCCESS) {
        ret = ops->authenticate(pamh, 0);
        status = frdp_authd_pam_auth_status(ret);
    }
    if (status == FRDP_AUTHD_PAM_OK) {
        ret = ops->acct_mgmt(pamh, 0);
        status = frdp_authd_pam_account_status(ret);
    }
    if ((status == FRDP_AUTHD_PAM_OK) &&
        (frdp_authd_pam_copy_user(pamh, ops->get_item, pam_user, pam_user_size) != 0))
        status = FRDP_AUTHD_PAM_ERROR;
    if (status == FRDP_AUTHD_PAM_OK) {
        ret = ops->setcred(pamh, PAM_ESTABLISH_CRED);
        credentials_established = (ret == PAM_SUCCESS);
        if (!credentials_established)
            status = FRDP_AUTHD_PAM_ERROR;
    }
    if (credentials_established) {
        const int cred_ret = ops->setcred(pamh, PAM_DELETE_CRED);

        if (cred_ret != PAM_SUCCESS) {
            ret = cred_ret;
            status = FRDP_AUTHD_PAM_ERROR;
        }
    }
    if (ops->end(pamh, ret) != PAM_SUCCESS)
        status = FRDP_AUTHD_PAM_ERROR;
    if (status != FRDP_AUTHD_PAM_OK)
        memset(pam_user, 0, pam_user_size);
    return status;
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
