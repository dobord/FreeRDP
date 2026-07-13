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
#include <stdint.h>
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
#include "../ipc/frdp-auth-token.h"
#include "../ipc/frdp-ipc.h"
#include "authd_pam.h"
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

static void clear_secret(char *secret, size_t length);

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

typedef struct
{
    char *secret;
    size_t length;
    int locked;
} lockedSecret;

static int lock_secret(char *secret, size_t length, lockedSecret *locked)
{
    if (!secret || length == 0 || !locked)
        return -1;

    memset(locked, 0, sizeof(*locked));
    locked->secret = secret;
    locked->length = length;
    if (mlock(secret, length) != 0)
        return -1;
    locked->locked = 1;
    return 0;
}

static void wipe_locked_secret(lockedSecret *locked)
{
    if (!locked || !locked->secret)
        return;

    clear_secret(locked->secret, locked->length);
}

static void unlock_locked_secret(lockedSecret *locked)
{
    if (!locked || !locked->secret)
        return;

    if (locked->locked)
        (void)munlock(locked->secret, locked->length);
    memset(locked, 0, sizeof(*locked));
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

static int compare_uint64(const void *a, const void *b)
{
    const uint64_t left = *(const uint64_t *)a;
    const uint64_t right = *(const uint64_t *)b;

    return (left > right) - (left < right);
}

static int lookup_posix_groups(const char *user, gid_t primary_gid, uint64_t *groups,
                               uint32_t *group_count)
{
    gid_t native_groups[FRDP_IPC_MAX_AUTH_GROUPS] = {0};
    int count = FRDP_IPC_MAX_AUTH_GROUPS;

    if (!user || !groups || !group_count)
        return -1;
    if (getgrouplist(user, primary_gid, native_groups, &count) < 0)
        return -1;
    if ((count < 0) || (count > (int)FRDP_IPC_MAX_AUTH_GROUPS))
        return -1;
    for (int x = 0; x < count; x++)
        groups[x] = (uint64_t)native_groups[x];
    qsort(groups, (size_t)count, sizeof(groups[0]), compare_uint64);
    *group_count = (uint32_t)count;
    return 0;
}

static int send_auth_response(int fd, int success, const char *error,
                              const char *authorization_id, uid_t uid, gid_t gid,
                              const uint64_t *groups, uint32_t group_count,
                              int has_posix_account)
{
    frdpAuthResponse resp;
    int rc = -1;

    memset(&resp, 0, sizeof(resp));
    resp.success = success;
    if (error)
        snprintf(resp.error, sizeof(resp.error), "%s", error);
    if (authorization_id)
        snprintf(resp.authorization_id, sizeof(resp.authorization_id), "%s", authorization_id);
    resp.uid = (uint64_t)uid;
    resp.gid = (uint64_t)gid;
    if (group_count > FRDP_IPC_MAX_AUTH_GROUPS)
        goto fail;
    if (groups && (group_count <= FRDP_IPC_MAX_AUTH_GROUPS)) {
        resp.group_count = group_count;
        memcpy(resp.groups, groups, group_count * sizeof(resp.groups[0]));
    }
    resp.has_posix_account = has_posix_account ? 1 : 0;

    rc = frdp_ipc_send_auth_response(fd, &resp);

fail:
    clear_secret((char *)&resp, sizeof(resp));
    return rc;
}

static int verify_peer(int fd)
{
    uint64_t peer_uid = 0;

    if (frdp_ipc_get_peer_uid(fd, &peer_uid) != 0)
        return -1;
    if (peer_uid != (uint64_t)geteuid())
        return -1;
    return 0;
}

static int set_client_timeouts(int fd)
{
    struct timeval timeout;
    unsigned long timeout_ms = 10000UL;
    const char *value = getenv("FRDP_HELPER_IPC_TIMEOUT_MS");

    if (value && value[0]) {
        char *end = NULL;

        errno = 0;
        timeout_ms = strtoul(value, &end, 10);
        if ((errno != 0) || !end || (*end != '\0') || (timeout_ms == 0) ||
            (timeout_ms > 600000UL))
            return -1;
    }

    timeout.tv_sec = (time_t)(timeout_ms / 1000UL);
    timeout.tv_usec = (suseconds_t)((timeout_ms % 1000UL) * 1000UL);
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
        return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0)
        return -1;
    return 0;
}

/* Perform a PAM authentication for the given user and password. */
static int authenticate_user(const char *service, const char *rhost, const char *correlation_id,
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
        clear_secret(buf, pwlen + 1);
        munmap(buf, pwlen + 1);
        return -1;
    }

    struct pam_conv conv = {frdp_authd_pam_conversation, buf};
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
        pam_end(pamh, ret);
    }

    /* Verify that the user exists. */
    struct passwd *pwd = getpwnam(user);
    if (!pwd) {
        ret = PAM_USER_UNKNOWN;
    }

    /* Clear and unlock secret data. */
    clear_secret(buf, pwlen + 1);
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
    frdpIpcRateLimiter rate_limiter = {0};
    frdpIpcRateLimiter health_rate_limiter = {0};
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
            send_auth_response(cfd, 0, "unauthorized IPC peer", NULL, (uid_t)-1, (gid_t)-1,
                               NULL, 0, 0);
            close(cfd);
            continue;
        }
        uint64_t peer_uid = 0;
        if (frdp_ipc_get_peer_uid(cfd, &peer_uid) != 0) {
            send_auth_response(cfd, 0, "unable to identify IPC peer", NULL, (uid_t)-1,
                               (gid_t)-1, NULL, 0, 0);
            close(cfd);
            continue;
        }
        frdpIpcHeader hdr;
        if (frdp_ipc_recv_header(cfd, &hdr) != (int)sizeof(hdr)) {
            close(cfd);
            continue;
        }
        if (!frdp_ipc_request_payload_len_is_bounded(hdr.payload_len)) {
            send_auth_response(cfd, 0, "IPC payload too large", NULL, (uid_t)-1, (gid_t)-1,
                               NULL, 0, 0);
            close(cfd);
            continue;
        }
        if ((hdr.type == FRDP_IPC_HELPER_HEALTH_REQUEST) && (hdr.payload_len == 0) &&
            !frdp_ipc_rate_limiter_allow(&health_rate_limiter, peer_uid)) {
            frdpControlResponse response = { 0 };

            snprintf(response.error, sizeof(response.error), "%s", "IPC health rate limit exceeded");
            (void)frdp_ipc_send_helper_health_response(cfd, &response);
            clear_secret((char *)&response, sizeof(response));
            close(cfd);
            continue;
        }
        if (!((hdr.type == FRDP_IPC_HELPER_HEALTH_REQUEST) && (hdr.payload_len == 0)) &&
            !frdp_ipc_rate_limiter_allow(&rate_limiter, peer_uid)) {
            send_auth_response(cfd, 0, "IPC rate limit exceeded", NULL, (uid_t)-1,
                               (gid_t)-1, NULL, 0, 0);
            close(cfd);
            continue;
        }
        if ((hdr.type == FRDP_IPC_HELPER_HEALTH_REQUEST) && (hdr.payload_len == 0)) {
            frdpControlResponse response = { .success = 1 };

            snprintf(response.message, sizeof(response.message), "%s", "frdp-authd");
            (void)frdp_ipc_send_helper_health_response(cfd, &response);
            clear_secret((char *)&response, sizeof(response));
        } else if ((hdr.type == FRDP_IPC_AUTH_REQUEST_V2) &&
            (hdr.payload_len == FRDP_IPC_AUTH_REQUEST_V2_WIRE_SIZE)) {
            frdpAuthRequest req = {0};
            if (frdp_ipc_recv_auth_request_v2_payload(cfd, &req, hdr.payload_len) == 0) {
                lockedSecret request_password_secret = {0};
                lockedSecret password_secret = {0};
                char user[sizeof(req.user)] = {0};
                char correlation_id[sizeof(req.correlation_id)] = {0};
                char rhost[sizeof(req.rhost)] = {0};
                char password[sizeof(req.password)] = {0};
                if (lock_secret(req.password, sizeof(req.password),
                                &request_password_secret) != 0 ||
                    lock_secret(password, sizeof(password), &password_secret) != 0 ||
                    copy_ipc_string(user, sizeof(user), req.user, sizeof(req.user)) != 0 ||
                    copy_ipc_string(correlation_id, sizeof(correlation_id), req.correlation_id,
                                    sizeof(req.correlation_id)) != 0 ||
                    copy_ipc_string(rhost, sizeof(rhost), req.rhost, sizeof(req.rhost)) != 0 ||
                    copy_ipc_string(password, sizeof(password), req.password, sizeof(req.password)) != 0) {
                    send_auth_response(cfd, 0, "invalid auth request", NULL, (uid_t)-1,
                                       (gid_t)-1, NULL, 0, 0);
                } else {
                    char authorization_id[sizeof(((frdpAuthResponse *)0)->authorization_id)] = {0};
                    uint64_t groups[FRDP_IPC_MAX_AUTH_GROUPS] = {0};
                    uint32_t group_count = 0;
                    const int authenticated =
                        authenticate_user(pam_service, rhost, correlation_id, user, password) == 0;
                    struct passwd *pwd = NULL;
                    if (authenticated)
                        pwd = getpwnam(user);
                    if (authenticated && !pwd)
                        send_auth_response(cfd, 0, "missing POSIX account", NULL, (uid_t)-1,
                                           (gid_t)-1, NULL, 0, 0);
                    else if (authenticated &&
                             lookup_posix_groups(user, pwd->pw_gid, groups, &group_count) != 0)
                        send_auth_response(cfd, 0, "POSIX group lookup failed", NULL, (uid_t)-1,
                                           (gid_t)-1, NULL, 0, 0);
                    else if (authenticated &&
                             frdp_auth_token_create(user, rhost, correlation_id,
                                                    (uint64_t)pwd->pw_uid,
                                                    (uint64_t)pwd->pw_gid, groups, group_count, 1,
                                                    authorization_id, sizeof(authorization_id)) != 0)
                        send_auth_response(cfd, 0, "authorization id generation failed", NULL,
                                           (uid_t)-1, (gid_t)-1, NULL, 0, 0);
                    else
                        send_auth_response(cfd, authenticated, NULL,
                                           authenticated ? authorization_id : NULL,
                                           authenticated ? pwd->pw_uid : (uid_t)-1,
                                           authenticated ? pwd->pw_gid : (gid_t)-1,
                                           authenticated ? groups : NULL,
                                           authenticated ? group_count : 0,
                                           authenticated ? 1 : 0);
                    clear_secret(authorization_id, sizeof(authorization_id));
                    clear_secret((char *)groups, sizeof(groups));
                }
                wipe_locked_secret(&password_secret);
                wipe_locked_secret(&request_password_secret);
                unlock_locked_secret(&password_secret);
                unlock_locked_secret(&request_password_secret);
            }
            clear_secret((char *)&req, sizeof(req));
        } else {
            send_auth_response(cfd, 0, "unsupported IPC request", NULL, (uid_t)-1, (gid_t)-1,
                               NULL, 0, 0);
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
