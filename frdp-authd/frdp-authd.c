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

/* Additional headers for hardening and account lookups */
#include <sys/resource.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <uuid/uuid.h>

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

/*
 * Disable core dumps for the process.  Running an authentication broker with
 * core dumps enabled risks leaking credentials.  We set RLIMIT_CORE to zero
 * early in the process lifetime.
 */
static void set_no_core(void)
{
    struct rlimit rl = {0};
    setrlimit(RLIMIT_CORE, &rl);
}

/*
 * Emit an audit event with a correlation identifier.  Logs are sent to
 * syslog using the AUTH facility.  In a real implementation this would
 * integrate with a structured logging framework and include additional
 * context such as remote IP, result, and reason codes.
 */
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
        /* Perform authentication.  This will prompt via our conversation
         * function but since the password is supplied in appdata_ptr no
         * interactive I/O occurs.  */
        ret = pam_authenticate(pamh, 0);
        if (ret == PAM_SUCCESS) {
            /* Check that the account is valid and not expired. */
            ret = pam_acct_mgmt(pamh, 0);
        }
        /* Regardless of authentication outcome close PAM context. */
        pam_end(pamh, ret);
    }

    /* Lookup the user’s UID/GID and supplementary groups to ensure the
     * account exists.  This is not strictly part of authentication but
     * provides early detection of unknown accounts. */
    struct passwd *pwd = getpwnam(user);
    if (!pwd) {
        ret = PAM_USER_UNKNOWN;
    } else {
        /* Initialise the group access list.  A real implementation would
         * propagate these groups to the session manager. */
        if (initgroups(user, pwd->pw_gid) != 0) {
            ret = PAM_PERM_DENIED;
        }
    }

    /* Zeroise and unlock password buffer. */
    memset(buf, 0, pwlen + 1);
    munlock(buf, pwlen + 1);
    munmap(buf, pwlen + 1);

    /* Emit an audit event. */
    log_audit_event(user, ret == PAM_SUCCESS);

    return (ret == PAM_SUCCESS) ? 0 : -1;
}

int main(int argc, char **argv)
{
    set_no_core();
    // Example usage for testing only.
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <username> <password>\n", argv[0]);
        return 1;
    }
    int rc = authenticate_user(argv[1], argv[2]);
    if (rc == 0) {
        printf("Authentication success\n");
        return 0;
    }
    printf("Authentication failed\n");
    return 1;
}
