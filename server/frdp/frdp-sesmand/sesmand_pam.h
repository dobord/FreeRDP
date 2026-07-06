#ifndef FRDP_SESMAND_PAM_H
#define FRDP_SESMAND_PAM_H

#include <security/pam_appl.h>

int frdp_sesmand_pam_conversation(int num_msg, const struct pam_message **msg,
                                  struct pam_response **resp, void *appdata_ptr);
void frdp_sesmand_pam_clear_responses(struct pam_response *responses, int count);

#endif /* FRDP_SESMAND_PAM_H */
