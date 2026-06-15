#define _GNU_SOURCE

/*
 * frdp-sesmand - Session manager for FreeRDP-based RDP server
 *
 * This process maintains a registry of active sessions, opens PAM sessions,
 * launches per-user session agents and supports reconnect and cleanup.  The
 * implementation here is intentionally minimal; error handling and
 * integration with systemd-logind/cgroups are elided for clarity.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <security/pam_appl.h>
#include <pwd.h>
#include <syslog.h>
#include <uuid/uuid.h>
#include <time.h>
#include <signal.h>
#include <grp.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include "../ipc/frdp-ipc.h"

/* Session registry entry.  Each session retains its PAM handle and the
 * process group of the launched agent/backend so that cleanup can terminate
 * all descendants.  A per-session display number is allocated for headless
 * X servers. */
typedef struct {
    char user[64];
    uuid_t id;
    pid_t agent_pid;
    pid_t pgid;
    time_t start_time;
    pam_handle_t *pamh;
    int credentials_established;
    int display_number;
} session;

#define MAX_SESSIONS 64
static session sessions[MAX_SESSIONS];
static int session_count = 0;
static int next_display = 100;
static const char *g_pam_service = "frdpd";

static unsigned int normalize_dimension(uint32_t value, unsigned int fallback)
{
    return (value > 0 && value <= 8192) ? value : fallback;
}

static unsigned int normalize_color_depth(uint32_t value)
{
    switch (value) {
        case 8:
        case 15:
        case 16:
        case 24:
        case 32:
            return value;
        default:
            return 24;
    }
}

static void child_exec_failed(int fd)
{
    const char marker = '!';

    if (fd >= 0) {
        const ssize_t rc = write(fd, &marker, sizeof(marker));
        (void)rc;
    }
    _exit(127);
}

static int wait_for_agent_exec(int fd, pid_t pid)
{
    struct pollfd pfd;
    char marker = 0;
    int status = 0;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLHUP;
    const int poll_status = poll(&pfd, 1, 10000);
    if (poll_status <= 0) {
        kill(pid, SIGKILL);
        for (int x = 0; x < 20; x++) {
            const pid_t rc = waitpid(pid, &status, WNOHANG);
            if (rc == pid || rc < 0)
                break;
            usleep(100000);
        }
        return -1;
    }

    const ssize_t rc = read(fd, &marker, sizeof(marker));
    if (rc == 0)
        return 0;

    for (int x = 0; x < 20; x++) {
        const pid_t wait_rc = waitpid(pid, &status, WNOHANG);
        if (wait_rc == pid || wait_rc < 0)
            break;
        usleep(100000);
    }
    return -1;
}

static int process_group_exists(pid_t pgid)
{
    if (pgid <= 0)
        return 0;
    if (kill(-pgid, 0) == 0)
        return 1;
    return errno == EPERM;
}

static void wait_for_agent_exit(pid_t pid, pid_t pgid)
{
    int status = 0;
    int agent_reaped = 0;

    for (int x = 0; x < 20; x++) {
        const pid_t rc = waitpid(pid, &status, WNOHANG);
        if (rc == pid || rc < 0) {
            agent_reaped = 1;
            break;
        }
        if (!process_group_exists(pgid))
            return;
        usleep(100000);
    }

    if (process_group_exists(pgid))
        kill(-pgid, SIGKILL);
    if (agent_reaped)
        return;
    for (int x = 0; x < 20; x++) {
        const pid_t rc = waitpid(pid, &status, WNOHANG);
        if (rc == pid || rc < 0)
            return;
        usleep(100000);
    }
}

/* Non-interactive PAM conversation. */
static int pam_conv_fn(int num_msg, const struct pam_message **msg,
                       struct pam_response **resp, void *appdata_ptr)
{
    (void)msg;
    (void)appdata_ptr;
    struct pam_response *aresp = calloc(num_msg, sizeof(struct pam_response));
    if (!aresp)
        return PAM_BUF_ERR;
    *resp = aresp;
    return PAM_SUCCESS;
}

static void session_id_to_string(const session *s, char *dst, size_t dst_size)
{
    char uuid_str[37];

    if (!s || !dst || dst_size == 0)
        return;
    uuid_unparse_lower(s->id, uuid_str);
    snprintf(dst, dst_size, "%s", uuid_str);
}

/* Open a session for the specified user.  This starts a PAM session, forks
 * a child to run the per-user agent and returns 0 on success. */
static int open_session(const char *user, const char *rhost, const char *correlation_id,
                        uint32_t desktop_width, uint32_t desktop_height, uint32_t color_depth,
                        char *session_id, size_t session_id_size,
                        char *display_out, size_t display_out_size)
{
    char geometry_str[32];
    int exec_pipe[2] = {-1, -1};

    if (session_count >= MAX_SESSIONS)
        return -1;
    struct pam_conv conv = {pam_conv_fn, NULL};
    pam_handle_t *pamh = NULL;
    int credentials_established = 0;
    int ret = pam_start(g_pam_service, user, &conv, &pamh);
    if (ret != PAM_SUCCESS)
        return -1;
    if (rhost && rhost[0])
        ret = pam_set_item(pamh, PAM_RHOST, rhost);
    if (ret == PAM_SUCCESS)
        ret = pam_set_item(pamh, PAM_TTY, "rdp");
    if (ret == PAM_SUCCESS)
        ret = pam_set_item(pamh, PAM_RUSER, user);
    if (ret != PAM_SUCCESS) {
        pam_end(pamh, ret);
        return -1;
    }
    ret = pam_acct_mgmt(pamh, 0);
    if (ret != PAM_SUCCESS) {
        pam_end(pamh, ret);
        return -1;
    }
    ret = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    if (ret != PAM_SUCCESS) {
        pam_end(pamh, ret);
        return -1;
    }
    credentials_established = 1;
    ret = pam_open_session(pamh, 0);
    if (ret != PAM_SUCCESS) {
        pam_setcred(pamh, PAM_DELETE_CRED);
        pam_end(pamh, ret);
        return -1;
    }

    /* Allocate display number and build display string */
    int display = next_display++;
    char display_str[16];
    snprintf(display_str, sizeof display_str, ":%d", display);
    snprintf(geometry_str, sizeof(geometry_str), "%ux%ux%u",
             normalize_dimension(desktop_width, 1024),
             normalize_dimension(desktop_height, 768), normalize_color_depth(color_depth));

    /* Retrieve user information for UID/GID drop. */
    struct passwd *pwd = getpwnam(user);
    if (!pwd) {
        pam_close_session(pamh, 0);
        pam_setcred(pamh, PAM_DELETE_CRED);
        pam_end(pamh, PAM_USER_UNKNOWN);
        return -1;
    }

    if (pipe(exec_pipe) != 0) {
        pam_close_session(pamh, 0);
        pam_setcred(pamh, PAM_DELETE_CRED);
        pam_end(pamh, PAM_SUCCESS);
        return -1;
    }
    if (fcntl(exec_pipe[1], F_SETFD, FD_CLOEXEC) != 0) {
        close(exec_pipe[0]);
        close(exec_pipe[1]);
        pam_close_session(pamh, 0);
        pam_setcred(pamh, PAM_DELETE_CRED);
        pam_end(pamh, PAM_SUCCESS);
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(exec_pipe[0]);
        close(exec_pipe[1]);
        pam_close_session(pamh, 0);
        pam_setcred(pamh, PAM_DELETE_CRED);
        pam_end(pamh, PAM_SUCCESS);
        return -1;
    }
    if (pid == 0) {
        close(exec_pipe[0]);
        /* Child: create a new process group for the session and drop privileges. */
        if (setpgid(0, 0) != 0)
            child_exec_failed(exec_pipe[1]);
        /* Set environment variables for the display */
        setenv("DISPLAY", display_str, 1);
        setenv("FRDP_DISPLAY", display_str, 1);
        setenv("FRDP_GEOMETRY", geometry_str, 1);
        /* Set groups and UID/GID */
        if (initgroups(user, pwd->pw_gid) != 0) {
            child_exec_failed(exec_pipe[1]);
        }
        if (setgid(pwd->pw_gid) != 0 || setuid(pwd->pw_uid) != 0) {
            child_exec_failed(exec_pipe[1]);
        }
        execlp("frdp-session-agent", "frdp-session-agent", (char *)NULL);
        /* If exec fails, exit with error. */
        child_exec_failed(exec_pipe[1]);
    }

    close(exec_pipe[1]);
    exec_pipe[1] = -1;
    if (wait_for_agent_exec(exec_pipe[0], pid) != 0) {
        close(exec_pipe[0]);
        pam_close_session(pamh, 0);
        pam_setcred(pamh, PAM_DELETE_CRED);
        pam_end(pamh, PAM_SUCCESS);
        return -1;
    }
    close(exec_pipe[0]);

    /* Parent: record session metadata. */
    session *s = &sessions[session_count++];
    strncpy(s->user, user, sizeof(s->user) - 1);
    s->user[sizeof(s->user) - 1] = '\0';
    uuid_generate(s->id);
    s->agent_pid = pid;
    s->pgid = pid; /* child's pgid equals pid since setpgid called with 0 */
    s->start_time = time(NULL);
    s->pamh = pamh;
    s->credentials_established = credentials_established;
    s->display_number = display;
    session_id_to_string(s, session_id, session_id_size);
    snprintf(display_out, display_out_size, "%s", display_str);
    syslog(LOG_INFO, "correlation_id=%s created session_id=%s user=%s display=%s geometry=%s",
           correlation_id && correlation_id[0] ? correlation_id : "unknown",
           session_id ? session_id : "unknown", user, display_str, geometry_str);
    return 0;
}

/* Clean up and remove a session from the registry. */
static void cleanup_session(int idx)
{
    session *s = &sessions[idx];
    /* Terminate the entire process group (agent + display backend). */
    if (s->pgid > 0) {
        kill(-s->pgid, SIGTERM);
        wait_for_agent_exit(s->agent_pid, s->pgid);
    }
    /* Close PAM session and end handle. */
    if (s->pamh) {
        int status = pam_close_session(s->pamh, 0);
        if (s->credentials_established) {
            int cred_status = pam_setcred(s->pamh, PAM_DELETE_CRED);
            if (status == PAM_SUCCESS && cred_status != PAM_SUCCESS)
                status = cred_status;
        }
        pam_end(s->pamh, status);
    }
    if (idx < session_count - 1) {
        sessions[idx] = sessions[session_count - 1];
    }
    session_count--;
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

static int send_session_response(int fd, int success, const char *session_id,
                                 const char *display, const char *error)
{
    frdpSessionResponse resp;
    frdpIpcHeader rhdr;

    memset(&resp, 0, sizeof(resp));
    resp.success = success;
    if (session_id)
        snprintf(resp.session_id, sizeof(resp.session_id), "%s", session_id);
    if (display)
        snprintf(resp.display, sizeof(resp.display), "%s", display);
    if (error)
        snprintf(resp.error, sizeof(resp.error), "%s", error);

    rhdr.type = FRDP_IPC_SESSION_RESPONSE;
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
    return -1;
#endif
    return 0;
}

static int prepare_socket_path(const char *socket_path)
{
    struct stat st;
    char parent[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};
    char *slash = NULL;

    if (!socket_path || strlen(socket_path) >= sizeof(((struct sockaddr_un *)0)->sun_path))
        return -1;
    if (socket_path[0] != '/')
        return -1;

    snprintf(parent, sizeof(parent), "%s", socket_path);
    slash = strrchr(parent, '/');
    if (!slash || slash == parent)
        return -1;
    *slash = '\0';

    if (lstat(parent, &st) != 0 || !S_ISDIR(st.st_mode))
        return -1;
    if (st.st_uid != 0 && st.st_uid != geteuid())
        return -1;
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        return -1;

    if (lstat(socket_path, &st) != 0)
        return (errno == ENOENT) ? 0 : -1;
    if (!S_ISSOCK(st.st_mode))
        return -1;
    if (st.st_uid != geteuid())
        return -1;
    return unlink(socket_path);
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

static int find_session_by_id(const char *session_id)
{
    char current[64];

    if (!session_id || session_id[0] == '\0')
        return -1;
    for (int x = 0; x < session_count; x++) {
        memset(current, 0, sizeof(current));
        session_id_to_string(&sessions[x], current, sizeof(current));
        if (strcmp(current, session_id) == 0)
            return x;
    }
    return -1;
}

static void reap_exited_sessions(void)
{
    int status = 0;
    pid_t pid = 0;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        for (int x = 0; x < session_count; x++) {
            if (sessions[x].agent_pid == pid) {
                cleanup_session(x);
                break;
            }
        }
    }
}

static int handle_session_request(int fd, frdpIpcMessageType type)
{
    frdpSessionRequest req;
    char correlation_id[sizeof(req.correlation_id)] = {0};
    char session_id[sizeof(req.session_id)] = {0};
    char user[sizeof(req.user)] = {0};
    char rhost[sizeof(req.rhost)] = {0};
    char response_session_id[64] = {0};
    char display[32] = {0};

    memset(&req, 0, sizeof(req));
    if (frdp_ipc_recv(fd, &req, sizeof(req)) != (int)sizeof(req))
        return -1;
    if (copy_ipc_string(correlation_id, sizeof(correlation_id), req.correlation_id,
                        sizeof(req.correlation_id)) != 0 ||
        copy_ipc_string(session_id, sizeof(session_id), req.session_id,
                        sizeof(req.session_id)) != 0 ||
        copy_ipc_string(user, sizeof(user), req.user, sizeof(req.user)) != 0 ||
        copy_ipc_string(rhost, sizeof(rhost), req.rhost, sizeof(req.rhost)) != 0) {
        return send_session_response(fd, 0, NULL, NULL, "invalid session request");
    }

    if (type == FRDP_IPC_SESSION_REQUEST) {
        if (user[0] == '\0')
            return send_session_response(fd, 0, NULL, NULL, "missing user");
        if (open_session(user, rhost, correlation_id, req.desktop_width, req.desktop_height,
                         req.color_depth, response_session_id, sizeof(response_session_id), display,
                         sizeof(display)) != 0) {
            syslog(LOG_ERR, "correlation_id=%s failed to create session for %s",
                   correlation_id[0] ? correlation_id : "unknown", user);
            return send_session_response(fd, 0, NULL, NULL, "session open failed");
        }
        const int send_status = send_session_response(fd, 1, response_session_id, display, NULL);
        if (send_status != 0) {
            const int idx = find_session_by_id(response_session_id);
            if (idx >= 0) {
                syslog(LOG_WARNING,
                       "correlation_id=%s rolling back session_id=%s after response failure",
                       correlation_id[0] ? correlation_id : "unknown", response_session_id);
                cleanup_session(idx);
            }
        }
        return send_status;
    }

    if (type == FRDP_IPC_SESSION_CLOSE_REQUEST) {
        const int idx = find_session_by_id(session_id);

        if (idx < 0)
            return send_session_response(fd, 0, NULL, NULL, "unknown session");
        syslog(LOG_INFO, "correlation_id=%s closing session_id=%s user=%s",
               correlation_id[0] ? correlation_id : "unknown", session_id, sessions[idx].user);
        cleanup_session(idx);
        return send_session_response(fd, 1, session_id, NULL, NULL);
    }

    return send_session_response(fd, 0, NULL, NULL, "unsupported session request");
}

static int run_ipc_server(const char *socket_path, const char *pam_service)
{
    int fd = -1;
    mode_t old_umask;
    struct sockaddr_un addr;

    if (!pam_service_is_valid(pam_service)) {
        fprintf(stderr, "invalid PAM service name\n");
        return -1;
    }
    g_pam_service = pam_service;

    if (prepare_socket_path(socket_path) != 0) {
        fprintf(stderr, "refusing unsafe socket path: %s\n", socket_path ? socket_path : "(null)");
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

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

    printf("frdp-sesmand IPC server listening on %s\n", socket_path);
    while (1) {
        struct pollfd pfd;
        int poll_status = 0;

        reap_exited_sessions();
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLIN;
        poll_status = poll(&pfd, 1, 1000);
        if (poll_status < 0) {
            if (errno == EINTR)
                continue;
            perror("poll");
            break;
        }
        if (poll_status == 0)
            continue;
        if ((pfd.revents & POLLIN) == 0)
            continue;

        int cfd = accept(fd, NULL, NULL);
        if (cfd < 0) {
            perror("accept");
            continue;
        }
        if (set_client_timeouts(cfd) != 0) {
            close(cfd);
            continue;
        }
        if (verify_peer(cfd) != 0) {
            send_session_response(cfd, 0, NULL, NULL, "unauthorized IPC peer");
            close(cfd);
            continue;
        }

        frdpIpcHeader hdr;
        if (frdp_ipc_recv(cfd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
            close(cfd);
            continue;
        }
        if ((hdr.payload_len == sizeof(frdpSessionRequest)) &&
            ((hdr.type == FRDP_IPC_SESSION_REQUEST) ||
             (hdr.type == FRDP_IPC_SESSION_CLOSE_REQUEST))) {
            (void)handle_session_request(cfd, hdr.type);
        } else {
            send_session_response(cfd, 0, NULL, NULL, "unsupported IPC request");
        }
        close(cfd);
    }

    close(fd);
    unlink(socket_path);
    return -1;
}

static void usage(const char *argv0)
{
    fprintf(stderr, "Usage: %s [--pam-service <name>] --socket <absolute-socket-path>\n", argv0);
    fprintf(stderr, "       %s [--pam-service <name>] --open-session <user>\n", argv0);
    fprintf(stderr, "Set FRDP_SESMAND_ALLOW_STANDALONE=1 to enable this development path.\n");
}

static int standalone_open_session_allowed(void)
{
    const char *value = getenv("FRDP_SESMAND_ALLOW_STANDALONE");

    return value && strcmp(value, "1") == 0;
}

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

int main(int argc, char **argv)
{
    const char *socket_path = NULL;
    const char *standalone_user = NULL;
    const char *pam_service = "frdpd";

    if (set_no_core() != 0) {
        fprintf(stderr, "failed to disable core dumps\n");
        return 1;
    }

    openlog("frdp-sesmand", LOG_PID, LOG_DAEMON);

    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        usage(argv[0]);
        closelog();
        return 0;
    }

    for (int x = 1; x < argc; x++) {
        if (strcmp(argv[x], "--pam-service") == 0) {
            if (++x >= argc) {
                usage(argv[0]);
                closelog();
                return 2;
            }
            pam_service = argv[x];
        } else if (strcmp(argv[x], "--socket") == 0) {
            if (++x >= argc) {
                usage(argv[0]);
                closelog();
                return 2;
            }
            socket_path = argv[x];
        } else if (strcmp(argv[x], "--open-session") == 0) {
            if (++x >= argc) {
                usage(argv[0]);
                closelog();
                return 2;
            }
            standalone_user = argv[x];
        } else {
            usage(argv[0]);
            closelog();
            return 2;
        }
    }

    if (socket_path && standalone_user) {
        usage(argv[0]);
        closelog();
        return 2;
    }
    if (socket_path) {
        const int rc = run_ipc_server(socket_path, pam_service);
        closelog();
        return (rc == 0) ? 0 : 1;
    }
    if (!standalone_user) {
        usage(argv[0]);
        closelog();
        return 2;
    }
    if (!pam_service_is_valid(pam_service)) {
        fprintf(stderr, "invalid PAM service name\n");
        closelog();
        return 2;
    }
    g_pam_service = pam_service;
    if (!standalone_open_session_allowed()) {
        fprintf(stderr, "standalone session opening is disabled by default\n");
        syslog(LOG_WARNING, "refused standalone session open without explicit development opt-in");
        closelog();
        return 2;
    }

    printf("frdp-sesmand: opening session for %s\n", standalone_user);

    char session_id[64] = {0};
    char display[32] = {0};
    if (open_session(standalone_user, NULL, "standalone", 1024, 768, 24, session_id,
                     sizeof(session_id), display, sizeof(display)) == 0) {
        syslog(LOG_INFO, "created session for %s", standalone_user);
    } else {
        syslog(LOG_ERR, "failed to create session for %s", standalone_user);
        closelog();
        return 1;
    }

    /* Monitor for agent exits and clean up sessions accordingly. */
    while (session_count > 0) {
        pid_t pid = wait(NULL);
        for (int i = 0; i < session_count; i++) {
            if (sessions[i].agent_pid == pid) {
                cleanup_session(i);
                break;
            }
        }
    }
    syslog(LOG_INFO, "no more sessions, shutting down");
    closelog();
    return 0;
}
