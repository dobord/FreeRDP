#include "sesmand_pam.h"

#include <stdlib.h>

#define FRDP_SESMAND_PAM_MAX_MESSAGES 32

void frdp_sesmand_pam_clear_responses(struct pam_response *responses, int count)
{
    if (!responses || count <= 0)
        return;

    for (int x = 0; x < count; x++) {
        free(responses[x].resp);
        responses[x].resp = NULL;
    }
}

int frdp_sesmand_pam_conversation(int num_msg, const struct pam_message **msg,
                                  struct pam_response **resp, void *appdata_ptr)
{
    struct pam_response *responses = NULL;

    (void)appdata_ptr;

    if (resp)
        *resp = NULL;
    if (num_msg <= 0 || num_msg > FRDP_SESMAND_PAM_MAX_MESSAGES || !msg || !resp)
        return PAM_CONV_ERR;

    for (int x = 0; x < num_msg; x++) {
        if (!msg[x])
            return PAM_CONV_ERR;
        switch (msg[x]->msg_style) {
            case PAM_TEXT_INFO:
            case PAM_ERROR_MSG:
                break;
            default:
                return PAM_CONV_ERR;
        }
    }

    responses = calloc((size_t)num_msg, sizeof(struct pam_response));
    if (!responses)
        return PAM_BUF_ERR;

    *resp = responses;
    return PAM_SUCCESS;
}
