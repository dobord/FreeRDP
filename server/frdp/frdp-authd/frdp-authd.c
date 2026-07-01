#define _GNU_SOURCE

/*
 * frdp-authd - Authentication broker for FreeRDP-based RDP server
 *
 * This component performs authentication for the RDP daemon using CredSSP,
 * Kerberos and PAM/SSSD. The code demonstrates secure handling of passwords
 * and integrates PAM. Credentials must be supplied via the local IPC server;
 * command-line password ingress is intentionally not supported.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <unistd.h>
#include <sys/mman.h>

/* Additional headers for hardening and account lookups */
#include <sys/resource.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <uuid/uuid.h>
#include <sys/types.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>

/* IPC definitions */
#include "../config/frdp-config.h"
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

static volatile sig_atomic_t g_stop_requested = 0;

static void authd_signal_handler(int signum)
{
    (void)signum;
    g_stop_requested = 1;
}

static int install_signal_handlers(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = authd_signal_handler;
    if (sigemptyset(&action.sa_mask) != 0)
        return -1;
    if (sigaction(SIGINT, &action, NULL) != 0)
        return -1;
    if (sigaction(SIGTERM, &action, NULL) != 0)
        return -1;
    return 0;
}

static int pam_conversation(int num_msg, const struct pam_message **msg,
                            struct pam_response **resp, void *appdata_ptr)
{
    const char *password = (const char *)appdata_ptr;
    struct pam_response *aresp = calloc(num_msg, sizeof(struct pam_response));
    if (!aresp)
        return PAM_BUF_ERR;
    for (int i = 0; i < num_msg; i++) {
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
            aresp[i].resp = strdup(password ? password : "");
            if (!aresp[i].resp) {
                for (int j = 0; j < i; j++)
                    free(aresp[j].resp);
                free(aresp);
                return PAM_BUF_ERR;
            }
        }
    }
    *resp = aresp;
    return PAM_SUCCESS;
}

/* Disable core dumps for the process. */
static int set_no_core(void)
{
    struct rlimit rl = {0};

    if (setrlimit(RLIMIT_CORE, &rl) != 0)
        return -1;
#ifdef __linux__
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
        return -1;
#endif
    return 0;
}

static char hex_digit(unsigned int value)
{
    return (value < 10U) ? (char)('0' + value) : (char)('a' + (value - 10U));
}

static int log_char_is_safe(unsigned char c)
{
    return ((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z')) ||
           ((c >= '0') && (c <= '9')) || (c == '.') || (c == '_') || (c == '-') ||
           (c == ':') || (c == '@') || (c == '/') || (c == '%') || (c == '+');
}

static void escape_log_field(const char *src, char *dst, size_t dst_size)
{
    size_t used = 0;

    if (!dst || dst_size == 0)
        return;
    dst[0] = '\0';
    if (!src)
        return;

    for (const unsigned char *p = (const unsigned char *)src; (*p != '\0') && (used + 1 < dst_size);
         p++) {
        if (log_char_is_safe(*p)) {
            dst[used++] = (char)*p;
            dst[used] = '\0';
        } else if ((*p == '\\') && (used + 2 < dst_size)) {
            dst[used++] = '\\';
            dst[used++] = '\\';
            dst[used] = '\0';
        } else if (used + 4 < dst_size) {
            dst[used++] = '\\';
            dst[used++] = 'x';
            dst[used++] = hex_digit((*p >> 4U) & 0x0fU);
            dst[used++] = hex_digit(*p & 0x0fU);
            dst[used] = '\0';
        } else {
            break;
        }
    }
}

static int is_uuid_hex_char(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int correlation_id_is_valid(const char *correlation_id)
{
    size_t x;

    if (!correlation_id)
        return 0;
    for (x = 0; x < 36; x++) {
        const char c = correlation_id[x];

        if (c == '\0')
            return 0;
        if (x == 8 || x == 13 || x == 18 || x == 23) {
            if (c != '-')
                return 0;
        } else if (!is_uuid_hex_char(c)) {
            return 0;
        }
    }

    return correlation_id[36] == '\0';
}

/* Emit an audit event with a correlation identifier. */
static void log_audit_event(const char *user, int success, const char *correlation_id)
{
    uuid_t id;
    char uuid_str[37];
    char escaped_user[256] = {0};

    if (!correlation_id_is_valid(correlation_id)) {
        uuid_generate(id);
        uuid_unparse_lower(id, uuid_str);
        correlation_id = uuid_str;
    }
    escape_log_field(user ? user : "unknown", escaped_user, sizeof(escaped_user));
    openlog("frdp-authd", LOG_PID | LOG_NDELAY, LOG_AUTH);
    syslog(success ? LOG_INFO : LOG_WARNING,
           "correlation_id=%s user=%s result=%s", correlation_id, escaped_user,
           success ? "success" : "failure");
    closelog();
}

static void clear_secret(char *secret, size_t length)
{
    volatile unsigned char *p = (volatile unsigned char *)secret;

    while (p && length-- > 0)
        *p++ = 0;
}

static int copy_ipc_string(char *dst, size_t dst_size, const char *src, size_t src_size)
{
    size_t len = 0;

    if (!dst || dst_size == 0 || !src)
        return -1;

    while (len < src_size && src[len] != '\0')
        len++;
    if (len == src_size || len >= dst_size)
        return -1;

    memcpy(dst, src, len);
    dst[len] = '\0';
    return 0;
}

static int send_auth_response(int fd, int success, const char *error)
{
    frdpAuthResponse resp;
    frdpIpcHeader rhdr;

    memset(&resp, 0, sizeof(resp));
    resp.success = success;
    if (error)
        snprintf(resp.error, sizeof(resp.error), "%s", error);

    rhdr.type = FRDP_IPC_AUTH_RESPONSE;
    rhdr.payload_len = sizeof(resp);
    if (frdp_ipc_send(fd, &rhdr, sizeof(rhdr)) < 0)
        return -1;
    return frdp_ipc_send(fd, &resp, sizeof(resp));
}

static int verify_peer(int fd)
{
#ifdef __linux__
    struct ucred cred;
    socklen_t len = sizeof(cred);

    memset(&cred, 0, sizeof(cred));
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0)
        return -1;
    if (cred.uid != geteuid())
        return -1;
#else
    (void)fd;
#endif
    return 0;
}

static int set_client_timeouts(int fd)
{
    struct timeval timeout;

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
        return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0)
        return -1;
    return 0;
}

/* Perform a PAM authentication for the given user and password. */
int authenticate_user(const char *service, const char *rhost, const char *correlation_id,
                      const char *user, const char *password)
{
    if (!service || !service[0] || !user || !password)
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
    int credentials_established = 0;
    int ret = pam_start(service, user, &conv, &pamh);
    if (ret == PAM_SUCCESS) {
        if (rhost && rhost[0]) {
            ret = pam_set_item(pamh, PAM_RHOST, rhost);
        }
        if (ret == PAM_SUCCESS) {
            ret = pam_set_item(pamh, PAM_TTY, "rdp");
        }
        if (ret == PAM_SUCCESS) {
            ret = pam_set_item(pamh, PAM_RUSER, user);
        }
        if (ret == PAM_SUCCESS) {
            ret = pam_set_item(pamh, PAM_AUTHTOK, buf);
        }
        if (ret == PAM_SUCCESS) {
            ret = pam_authenticate(pamh, 0);
        }
        if (ret == PAM_SUCCESS) {
            ret = pam_acct_mgmt(pamh, 0);
        }
        /* Establish credentials for the session */
        if (ret == PAM_SUCCESS) {
            ret = pam_setcred(pamh, PAM_ESTABLISH_CRED);
            credentials_established = (ret == PAM_SUCCESS);
        }
        if (credentials_established) {
            int cred_ret = pam_setcred(pamh, PAM_DELETE_CRED);
            if (ret == PAM_SUCCESS && cred_ret != PAM_SUCCESS)
                ret = cred_ret;
        }
        pam_set_item(pamh, PAM_AUTHTOK, "");
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

    log_audit_event(user, ret == PAM_SUCCESS, correlation_id);
    return (ret == PAM_SUCCESS) ? 0 : -1;
}

/* Run in IPC server mode listening on a UNIX domain socket and handling auth requests */
static int pam_service_is_valid(const char *service)
{
    size_t len = 0;

    if (!service || service[0] == '\0')
        return 0;
    for (len = 0; service[len] != '\0'; len++) {
        unsigned char c = (unsigned char)service[len];
        if (len >= 63)
            return 0;
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

static int load_configured_pam_service(const char *config_path, char *service, size_t service_size)
{
    frdpConfig config;
    int rc = 0;

    if (!config_path || !service || service_size == 0)
        return -1;
    if (frdp_config_load(config_path, &config) != 0)
        return -1;
    if (!pam_service_is_valid(config.pam_service))
        return -1;
    rc = snprintf(service, service_size, "%s", config.pam_service);
    return (rc >= 0 && (size_t)rc < service_size) ? 0 : -1;
}

static int set_cloexec(int fd)
{
    const int flags = fcntl(fd, F_GETFD);

    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static int create_cloexec_unix_socket(void)
{
    int fd = -1;

#ifdef SOCK_CLOEXEC
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if ((fd == -1) && (errno == EINVAL || errno == EPROTONOSUPPORT))
#endif
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    if (set_cloexec(fd) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

static int accept_cloexec(int fd)
{
    int cfd = -1;

#ifdef SOCK_CLOEXEC
    cfd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
    if ((cfd == -1) && (errno == EINVAL || errno == ENOSYS))
#endif
        cfd = accept(fd, NULL, NULL);
    if (cfd < 0)
        return -1;
    if (set_cloexec(cfd) != 0) {
        int saved = errno;
        close(cfd);
        errno = saved;
        return -1;
    }
    return cfd;
}

static int run_ipc_server(const char *socket_path, const char *pam_service, const char *config_path)
{
    mode_t old_umask;
    int fd = -1;
    char configured_service[64] = {0};

    if (config_path) {
        if (load_configured_pam_service(config_path, configured_service,
                                        sizeof(configured_service)) != 0) {
            fprintf(stderr, "failed to load frdp-authd config\n");
            return -1;
        }
        pam_service = configured_service;
    }
    if (!pam_service_is_valid(pam_service)) {
        fprintf(stderr, "invalid PAM service name\n");
        return -1;
    }
    if (install_signal_handlers() != 0) {
        fprintf(stderr, "failed to install signal handlers\n");
        return -1;
    }
    if (g_stop_requested)
        return 0;

    if (frdp_ipc_prepare_listener_socket_path(socket_path) != 0) {
        char escaped_socket[512] = {0};

        escape_log_field(socket_path ? socket_path : "(null)", escaped_socket, sizeof(escaped_socket));
        fprintf(stderr, "refusing unsafe socket path: %s\n", escaped_socket);
        return -1;
    }

    fd = create_cloexec_unix_socket();
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
    old_umask = umask(0177);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        umask(old_umask);
        perror("bind");
        close(fd);
        return -1;
    }
    umask(old_umask);
    if (chmod(socket_path, 0600) != 0) {
        perror("chmod");
        close(fd);
        unlink(socket_path);
        return -1;
    }
    if (listen(fd, 5) < 0) {
        perror("listen");
        close(fd);
        unlink(socket_path);
        return -1;
    }
    if (g_stop_requested) {
        close(fd);
        unlink(socket_path);
        return 0;
    }
    char escaped_socket[512] = {0};

    escape_log_field(socket_path, escaped_socket, sizeof(escaped_socket));
    printf("frdp-authd IPC server listening on %s\n", escaped_socket);
    while (!g_stop_requested) {
        struct pollfd pfd;

        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLIN;
        const int poll_status = poll(&pfd, 1, 1000);
        if (poll_status < 0) {
            if (errno == EINTR)
                continue;
            perror("poll");
            break;
        }
        if (poll_status == 0)
            continue;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            perror("poll");
            break;
        }
        if ((pfd.revents & POLLIN) == 0)
            continue;

        int cfd = accept_cloexec(fd);
        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            continue;
        }
        if (set_client_timeouts(cfd) != 0) {
            close(cfd);
            continue;
        }
        if (verify_peer(cfd) != 0) {
            send_auth_response(cfd, 0, "unauthorized IPC peer");
            close(cfd);
            continue;
        }
        frdpIpcHeader hdr;
        if (frdp_ipc_recv(cfd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
            close(cfd);
            continue;
        }
        if (hdr.type == FRDP_IPC_AUTH_REQUEST_V2 && hdr.payload_len == sizeof(frdpAuthRequest)) {
            frdpAuthRequest req;
            if (frdp_ipc_recv(cfd, &req, sizeof(req)) == (int)sizeof(req)) {
                char user[sizeof(req.user)] = {0};
                char correlation_id[sizeof(req.correlation_id)] = {0};
                char rhost[sizeof(req.rhost)] = {0};
                char password[sizeof(req.password)] = {0};
                if (copy_ipc_string(user, sizeof(user), req.user, sizeof(req.user)) != 0 ||
                    copy_ipc_string(correlation_id, sizeof(correlation_id), req.correlation_id,
                                    sizeof(req.correlation_id)) != 0 ||
                    copy_ipc_string(rhost, sizeof(rhost), req.rhost, sizeof(req.rhost)) != 0 ||
                    copy_ipc_string(password, sizeof(password), req.password, sizeof(req.password)) != 0) {
                    send_auth_response(cfd, 0, "invalid auth request");
                } else {
                    send_auth_response(cfd,
                                       authenticate_user(pam_service, rhost, correlation_id, user,
                                                         password) == 0,
                                       NULL);
                }
                clear_secret(password, sizeof(password));
                clear_secret(req.password, sizeof(req.password));
            }
        } else {
            send_auth_response(cfd, 0, "unsupported IPC request");
        }
        close(cfd);
    }
    close(fd);
    unlink(socket_path);
    return g_stop_requested ? 0 : -1;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [--pam-service <name> | --config <path>] --socket <absolute-socket-path>\n",
            argv0);
}

int main(int argc, char **argv)
{
    const char *pam_service = "frdpd";
    const char *socket_path = NULL;
    const char *config_path = NULL;
    int pam_service_set = 0;

    if (set_no_core() != 0) {
        fprintf(stderr, "failed to disable core dumps\n");
        return 1;
    }
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        usage(argv[0]);
        return 0;
    }
    for (int x = 1; x < argc; x++) {
        if (strcmp(argv[x], "--pam-service") == 0) {
            if (++x >= argc) {
                usage(argv[0]);
                return 2;
            }
            pam_service = argv[x];
            pam_service_set = 1;
        } else if (strcmp(argv[x], "--config") == 0) {
            if (++x >= argc) {
                usage(argv[0]);
                return 2;
            }
            config_path = argv[x];
        } else if (strcmp(argv[x], "--socket") == 0) {
            if (++x >= argc) {
                usage(argv[0]);
                return 2;
            }
            socket_path = argv[x];
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (!socket_path) {
        usage(argv[0]);
        return 2;
    }
    if (config_path && (!socket_path || pam_service_set)) {
        usage(argv[0]);
        return 2;
    }
    return (run_ipc_server(socket_path, pam_service, config_path) == 0) ? 0 : 1;
}
