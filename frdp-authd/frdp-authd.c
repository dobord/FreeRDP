/*
 * frdp-authd - Authentication broker for FreeRDP-based RDP server
 *
 * This component performs authentication for the RDP daemon using CredSSP,
 * Kerberos and PAM/SSSD. The code demonstrates secure handling of passwords
 * and integrates PAM. In production builds credentials must be supplied via
 * a secure IPC channel or protected file descriptor; command-line ingress
 * is provided only for development and testing.
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

/* IPC definitions */
#include "../ipc/frdp-ipc.h"
#include <sys/socket.h>
#include <sys/un.h>

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
        /* Hard fail if we cannot lock memory to protect secrets */
        memset(buf, 0, pwlen + 1);
        munmap(buf, pwlen + 1);
        return -1;
    }

    struct pam_conv conv = {pam_conversation, buf};
    pam_handle_t *pamh = NULL;
    int ret = pam_start("frdpd", user, &conv, &pamh);
    if (ret == PAM_SUCCESS) {
        ret = pam_authenticate(pamh, 0);
        if (ret == PAM_SUCCESS) {
            ret = pam_acct_mgmt(pamh, 0);
        }
        /* Establish credentials for the session */
        if (ret == PAM_SUCCESS) {
            ret = pam_setcred(pamh, PAM_ESTABLISH_CRED);
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

/* Run in IPC server mode listening on a UNIX domain socket and handling auth requests */
static int run_ipc_server(const char *socket_path)
{
    /* Ensure no leftover socket */
    unlink(socket_path);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    if (listen(fd, 5) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    printf("frdp-authd IPC server listening on %s\n", socket_path);
    while (1) {
        int cfd = accept(fd, NULL, NULL);
        if (cfd < 0) {
            perror("accept");
            continue;
        }
        frdpIpcHeader hdr;
        if (frdp_ipc_recv(cfd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
            close(cfd);
            continue;
        }
        if (hdr.type == FRDP_IPC_AUTH_REQUEST && hdr.payload_len == sizeof(frdpAuthRequest)) {
            frdpAuthRequest req;
            if (frdp_ipc_recv(cfd, &req, sizeof(req)) == (int)sizeof(req)) {
                frdpAuthResponse resp;
                resp.success = (authenticate_user(req.user, req.password) == 0);
                resp.error[0] = '\0';
                frdpIpcHeader rhdr;
                rhdr.type = FRDP_IPC_AUTH_RESPONSE;
                rhdr.payload_len = sizeof(resp);
                frdp_ipc_send(cfd, &rhdr, sizeof(rhdr));
                frdp_ipc_send(cfd, &resp, sizeof(resp));
            }
        }
        close(cfd);
    }
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    set_no_core();
    /* If invoked with --socket <path>, run as IPC server */
    if (argc == 3 && strcmp(argv[1], "--socket") == 0) {
        const char *sock = argv[2];
        return run_ipc_server(sock);
    }
    const char *user = NULL;
    const char *pass = NULL;
    /* Accept username and password as positional arguments for development only. */
    if (argc >= 3) {
        user = argv[1];
        pass = argv[2];
    }
    if (!user || !pass) {
        fprintf(stderr, "Usage: %s [--socket <path>] | <username> <password>\n", argv[0]);
        fprintf(stderr, "In production this service must be invoked via a secure IPC protocol.\n");
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
