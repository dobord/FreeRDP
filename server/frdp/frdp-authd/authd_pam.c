#include "authd_pam.h"

#include <stdlib.h>
#include <string.h>

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

int frdp_authd_pam_conversation(int num_msg, const struct pam_message **msg,
                                struct pam_response **resp, void *appdata_ptr)
{
    const char *password = (const char *)appdata_ptr;
    struct pam_response *responses = NULL;

    if (resp)
        *resp = NULL;
    if (num_msg <= 0 || !msg || !resp)
        return PAM_CONV_ERR;

    responses = calloc((size_t)num_msg, sizeof(struct pam_response));
    if (!responses)
        return PAM_BUF_ERR;

    for (int i = 0; i < num_msg; i++) {
        if (!msg[i])
            goto fail;

        switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
                responses[i].resp = strdup(password ? password : "");
                if (!responses[i].resp)
                    goto fail;
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
