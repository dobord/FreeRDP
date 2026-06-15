/*
 * frdp-authd - Authentication broker for FreeRDP-based RDP server
 *
 * This skeleton component performs authentication for the RDP daemon using CredSSP,
 * Kerberos and PAM/SSSD. The code demonstrates secure handling of passwords and
 * illustrates how a future implementation might integrate PAM.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <unistd.h>
#include <sys/mman.h>

static int pam_conversation(int num_msg, const struct pam_message **msg,
                            struct pam_response **resp, void *appdata_ptr)
{
    // The password is passed as appdata_ptr.
    const char *password = (const char *)appdata_ptr;
    struct pam_response *aresp = calloc(num_msg, sizeof(struct pam_response));
    if (!aresp)
        return PAM_BUF_ERR;
    for (int i = 0; i < num_msg; i++) {
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
            aresp[i].resp = strdup(password);
        }
    }
    *resp = aresp;
    return PAM_SUCCESS;
}

int authenticate_user(const char *user, const char *password)
{
    // Copy password into locked memory to prevent swapping.
    size_t pwlen = strlen(password);
    char *buf = mmap(NULL, pwlen + 1, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
    if (!buf)
        return -1;
    memcpy(buf, password, pwlen + 1);
    mlock(buf, pwlen + 1);

    struct pam_conv conv = {pam_conversation, buf};
    pam_handle_t *pamh = NULL;
    int ret = pam_start("frdpd", user, &conv, &pamh);
    if (ret == PAM_SUCCESS) {
        ret = pam_authenticate(pamh, 0);
        if (ret == PAM_SUCCESS)
            ret = pam_acct_mgmt(pamh, 0);
        pam_end(pamh, ret);
    }

    // Zeroize and unlock password buffer.
    memset(buf, 0, pwlen + 1);
    munlock(buf, pwlen + 1);
    munmap(buf, pwlen + 1);

    return (ret == PAM_SUCCESS) ? 0 : -1;
}

int main(int argc, char **argv)
{
    // Example usage for testing only.
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <username> <password>\n", argv[0]);
        return 1;
    }
    if (authenticate_user(argv[1], argv[2]) == 0) {
        printf("Authentication success\n");
        return 0;
    }
    printf("Authentication failed\n");
    return 1;
}
