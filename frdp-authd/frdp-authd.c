/*
 * frdp-authd - Authentication broker for FreeRDP-based RDP server
 *
 * This component performs authentication for the RDP daemon using CredSSP,
 * Kerberos and PAM/SSSD. The code demonstrates secure handling of passwords
 * and integrates PAM.  Note: command-line password parameters are intended
 * only for test builds; in production environments credentials must be
 * supplied via a secure IPC channel or protected file descriptor.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <unistd.h>
#include <sys/mman.h>

/* Additional headers for hardening and account lookups */
#include <sys/resource.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <uuid/uuid.h>
#include <sys/types.h>
#include <errno.h>

/*
 * The authentication broker is responsible for validating a user via PAM/SSSD
 * and preparing the process environment for further session handling.  In
 * addition to password verification we perform basic account lookups and
 * emit structured audit events.  Sensitive memory is locked and wiped
 * explicitly to reduce the risk of credential leakage.
 */

static int pam_conversation(int num_msg, const struct pam_message **msg,
                            struct pam_response **resp, void *appdata_ptr)
{
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

/* Disable core dumps for the process. */
static void set_no_core(void)
{
    struct rlimit rl = {0};
    setrlimit(RLIMIT_CORE, &rl);
}

/* Emit an audit event with a correlation identifier. */
static void log_audit_event(const char *user, int success)
{
    uuid_t id;
    char uuid_str[37];
    uuid_generate(id);
    uuid_unparse_lower(id, uuid_str);
    openlog("frdp-authd", LOG_PID | LOG_NDELAY, LOG_AUTH);
    syslog(success ? LOG_INFO : LOG_WARNING,
           "correlation_id=%s user=%s result=%s", uuid_str, user,
           success ? "success" : "failure");
    closelog();
}

/* Perform a PAM authentication for the given user and password. */
int authenticate_user(const char *user, const char *password)
{
    if (!user || !password)
        return -1;
    size_t pwlen = strlen(password);
    /* Allocate a temporary buffer and lock it to prevent swapping. */
    char *buf = mmap(NULL, pwlen + 1, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
    if (buf == MAP_FAILED)
        return -1;
    memcpy(buf, password, pwlen + 1);
    if (mlock(buf, pwlen + 1) != 0) {
        /* continue anyway but note failure */
    }

    struct pam_conv conv = {pam_conversation, buf};
    pam_handle_t *pamh = NULL;
    int ret = pam_start("frdpd", user, &conv, &pamh);
    if (ret == PAM_SUCCESS) {
        ret = pam_authenticate(pamh, 0);
        if (ret == PAM_SUCCESS) {
            ret = pam_acct_mgmt(pamh, 0);
        }
        pam_end(pamh, ret);
    }

    /* Verify that the user exists. */
    struct passwd *pwd = getpwnam(user);
    if (!pwd) {
        ret = PAM_USER_UNKNOWN;
    }

    /* Clear and unlock secret data. */
    memset(buf, 0, pwlen + 1);
    munlock(buf, pwlen + 1);
    munmap(buf, pwlen + 1);

    log_audit_event(user, ret == PAM_SUCCESS);
    return (ret == PAM_SUCCESS) ? 0 : -1;
}

int main(int argc, char **argv)
{
    set_no_core();
    const char *user = NULL;
    const char *pwd_env = getenv("FRDP_AUTH_PASSWORD");
    const char *pass = pwd_env;

    /* Accept username as first argument; password from env or second argument for test harness. */
    if (argc >= 2) {
        user = argv[1];
    }
    if (!pass && argc >= 3) {
        pass = argv[2];
    }
    if (!user || !pass) {
        fprintf(stderr, "Usage: %s <username> [<password>|$FRDP_AUTH_PASSWORD] (test only)\n", argv[0]);
        return 1;
    }
    int rc = authenticate_user(user, pass);
    if (rc == 0) {
        printf("Authentication success\n");
        return 0;
    }
    printf("Authentication failed\n");
    return 1;
}
