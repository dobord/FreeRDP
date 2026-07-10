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
#include <inttypes.h>
#include <poll.h>

#include <winpr/crt.h>
#include <winpr/platform.h>

#include "../config/frdp-config.h"
#include "../ipc/frdp-auth-token.h"
#include "../ipc/frdp-ipc.h"
#include "display_policy.h"
#include "sesmand_pam.h"
#include "session_cleanup.h"
#include "session_disconnect.h"
#include "session_reconnect.h"
#include "session_resources.h"
#include "session_state.h"

/* Session registry entry.  Each session retains its PAM handle and the
 * process group of the launched agent/backend so that cleanup can terminate
 * all descendants.  A per-session display number is allocated for headless
 * X servers. */
typedef struct {
    char user[64];
    uid_t uid;
    uuid_t id;
    pid_t agent_pid;
    pid_t pgid;
    time_t start_time;
    pam_handle_t *pamh;
    int credentials_established;
    frdpSesmandSessionState state;
    int display_number;
    int display_reservation_fd;
    char display_reservation[sizeof(((struct sockaddr_un *)0)->sun_path)];
    char agent_socket[sizeof(((struct sockaddr_un *)0)->sun_path)];
} session;

#define MAX_SESSIONS 64
#define FRDP_AGENT_READY_MARKER 'R'
static session sessions[MAX_SESSIONS];
static int session_count = 0;
static int next_display = FRDP_SESMAND_DISPLAY_MIN;
static char g_pam_service[64] = "frdpd";
static frdpSessionResourcePolicy g_session_resource_policy = {0};
static char g_config_path[1024] = {0};
static char g_agent_socket_dir[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};
static volatile sig_atomic_t g_stop_requested = 0;

#define MAX_CONSUMED_AUTH_TOKENS 128

typedef struct {
    char nonce[37];
    unsigned long long expires_at;
} consumedAuthToken;

static consumedAuthToken consumed_auth_tokens[MAX_CONSUMED_AUTH_TOKENS];

static int create_agent_socket(const char *socket_path);
static void destroy_agent_socket(int *fd, const char *socket_path);

static void sesmand_signal_handler(int signum)
{
    (void)signum;
    g_stop_requested = 1;
}

static int install_signal_handlers(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = sesmand_signal_handler;
    if (sigemptyset(&action.sa_mask) != 0)
        return -1;
    if (sigaction(SIGINT, &action, NULL) != 0)
        return -1;
    if (sigaction(SIGTERM, &action, NULL) != 0)
        return -1;
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

static int derive_parent_dir(const char *path, char *dst, size_t dst_size)
{
    char *slash = NULL;

    if (!path || path[0] != '/' || !dst || dst_size == 0 || strlen(path) >= dst_size)
        return -1;
    snprintf(dst, dst_size, "%s", path);
    slash = strrchr(dst, '/');
    if (!slash || slash == dst)
        return -1;
    *slash = '\0';
    return 0;
}

static int build_agent_socket_path(char *dst, size_t dst_size, const char *session_id)
{
    int rc = 0;

    if (!dst || dst_size == 0 || !session_id || session_id[0] == '\0')
        return -1;
    dst[0] = '\0';
    if (g_agent_socket_dir[0] == '\0')
        return 0;

    rc = snprintf(dst, dst_size, "%s/agent-%s.sock", g_agent_socket_dir, session_id);
    return (rc >= 0 && (size_t)rc < dst_size) ? 0 : -1;
}

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

WINPR_NORETURN(static void child_exec_failed(int fd))
{
    const char marker = '!';

    if (fd >= 0) {
        const ssize_t rc = write(fd, &marker, sizeof(marker));
        (void)rc;
    }
    _exit(127);
}

static void terminate_agent_start_failure(pid_t pid, pid_t pgid)
{
    int status = 0;

    if (pgid > 0) {
        if (kill(-pgid, SIGTERM) != 0 && errno == ESRCH)
            kill(pid, SIGTERM);
        usleep(200000);
        if (kill(-pgid, SIGKILL) != 0 && errno == ESRCH)
            kill(pid, SIGKILL);
    } else {
        kill(pid, SIGTERM);
        usleep(200000);
        kill(pid, SIGKILL);
    }
    for (int x = 0; x < 20; x++) {
        const pid_t rc = waitpid(pid, &status, WNOHANG);
        if (rc == pid || rc < 0)
            return;
        usleep(100000);
    }
}

static int wait_for_agent_ready(int fd, pid_t pid, pid_t pgid)
{
    struct pollfd pfd;
    char marker = 0;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLHUP;
    const int poll_status = poll(&pfd, 1, 20000);
    if (poll_status <= 0) {
        terminate_agent_start_failure(pid, pgid);
        return -1;
    }

    const ssize_t rc = read(fd, &marker, sizeof(marker));
    if (rc == (ssize_t)sizeof(marker) && marker == FRDP_AGENT_READY_MARKER)
        return 0;

    terminate_agent_start_failure(pid, pgid);
    return -1;
}

static void close_child_fds_except(int keep_a, int keep_b)
{
    long max_fd = sysconf(_SC_OPEN_MAX);

    if (max_fd < 0 || max_fd > 65536)
        max_fd = 65536;
    for (int fd = 3; fd < max_fd; fd++) {
        if (fd == keep_a || fd == keep_b)
            continue;
        close(fd);
    }
}

static int set_fd_cloexec(int fd, int enabled)
{
    int flags = fcntl(fd, F_GETFD);

    if (flags < 0)
        return -1;
    if (enabled)
        flags |= FD_CLOEXEC;
    else
        flags &= ~FD_CLOEXEC;
    return fcntl(fd, F_SETFD, flags);
}

static int create_cloexec_pipe(int pipefd[2])
{
    if (!pipefd)
        return -1;

#if defined(__linux__) && defined(O_CLOEXEC)
    if (pipe2(pipefd, O_CLOEXEC) == 0)
        return 0;
    if (errno != EINVAL && errno != ENOSYS)
        return -1;
#endif

    if (pipe(pipefd) != 0)
        return -1;
    if (set_fd_cloexec(pipefd[0], 1) != 0 || set_fd_cloexec(pipefd[1], 1) != 0) {
        int saved = errno;
        close(pipefd[0]);
        close(pipefd[1]);
        pipefd[0] = -1;
        pipefd[1] = -1;
        errno = saved;
        return -1;
    }
    return 0;
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

static void session_id_to_string(const session *s, char *dst, size_t dst_size)
{
    char uuid_str[37];

    if (!s || !dst || dst_size == 0)
        return;
    uuid_unparse_lower(s->id, uuid_str);
    snprintf(dst, dst_size, "%s", uuid_str);
}

static int path_exists_or_unknown(const char *path)
{
    struct stat st;

    if (!path || path[0] == '\0')
        return 1;
    if (lstat(path, &st) == 0)
        return 1;
    return (errno == ENOENT) ? 0 : 1;
}

static int display_number_in_use(int display)
{
    char lock_path[64] = {0};
    char socket_path[64] = {0};

    for (int x = 0; x < session_count; x++) {
        if (sessions[x].display_number == display)
            return 1;
    }

    if ((snprintf(lock_path, sizeof(lock_path), "/tmp/.X%d-lock", display) < 0) ||
        (snprintf(socket_path, sizeof(socket_path), "/tmp/.X11-unix/X%d", display) < 0))
        return 1;
    return path_exists_or_unknown(lock_path) || path_exists_or_unknown(socket_path);
}

static int allocate_display_number(int *display, int *reservation_fd, char *reservation_path,
                                   size_t reservation_path_size)
{
    if (!display || !reservation_fd || !reservation_path || reservation_path_size == 0)
        return -1;
    *reservation_fd = -1;
    reservation_path[0] = '\0';

    for (int attempts = 0; attempts <= (FRDP_SESMAND_DISPLAY_MAX - FRDP_SESMAND_DISPLAY_MIN);
         attempts++) {
        const int candidate = next_display;
        const char *dir = (g_agent_socket_dir[0] != '\0') ? g_agent_socket_dir : "/tmp";
        int fd = -1;

        next_display++;
        if (next_display > FRDP_SESMAND_DISPLAY_MAX)
            next_display = FRDP_SESMAND_DISPLAY_MIN;
        if (display_number_in_use(candidate))
            continue;
        if (frdp_sesmand_display_reservation_create(candidate, dir, &fd, reservation_path,
                                                    reservation_path_size) != 0) {
            if (errno == EEXIST) {
                if (frdp_sesmand_display_reservation_reconcile_stale(dir, candidate) > 0 &&
                    frdp_sesmand_display_reservation_create(candidate, dir, &fd,
                                                            reservation_path,
                                                            reservation_path_size) == 0) {
                    *display = candidate;
                    *reservation_fd = fd;
                    return 0;
                }
                continue;
            }
            return -1;
        }
        *display = candidate;
        *reservation_fd = fd;
        return 0;
    }
    return -1;
}

static void release_display_reservation(int *reservation_fd, const char *reservation_path)
{
    frdp_sesmand_display_reservation_release(reservation_fd, reservation_path);
}

static int copy_groups_to_native(const uint64_t *groups, uint32_t group_count,
                                 gid_t *native_groups, size_t native_group_count)
{
    if (!groups || !native_groups || (group_count == 0) ||
        (group_count > FRDP_IPC_MAX_AUTH_GROUPS) || (group_count > native_group_count))
        return -1;

    for (uint32_t x = 0; x < group_count; x++) {
        const gid_t native_group = (gid_t)groups[x];

        if ((uint64_t)native_group != groups[x])
            return -1;
        native_groups[x] = native_group;
    }
    return 0;
}

/* Open a session for the specified user.  This starts a PAM session, forks
 * a child to run the per-user agent and returns 0 on success. */
static int open_session(const char *user, uid_t uid, gid_t gid, const uint64_t *groups,
                        uint32_t group_count, const char *rhost, const char *correlation_id,
                        uint32_t desktop_width, uint32_t desktop_height, uint32_t color_depth,
                        char *session_id, size_t session_id_size, char *display_out,
                        size_t display_out_size, char *agent_socket_out, size_t agent_socket_out_size)
{
    char geometry_str[32];
    uuid_t new_id;
    char new_session_id[64] = {0};
    char agent_socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};
    char display_reservation_path[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};
    char agent_fd_str[16] = {0};
    char ready_fd_str[16] = {0};
    int exec_pipe[2] = {-1, -1};
    int agent_fd = -1;
    int display_reservation_fd = -1;
    gid_t native_groups[FRDP_IPC_MAX_AUTH_GROUPS] = {0};

    if (session_count >= MAX_SESSIONS)
        return -1;
    if (copy_groups_to_native(groups, group_count, native_groups,
                              sizeof(native_groups) / sizeof(native_groups[0])) != 0)
        return -1;
    struct pam_conv conv = {frdp_sesmand_pam_conversation, NULL};
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
    int display = 0;
    if (allocate_display_number(&display, &display_reservation_fd, display_reservation_path,
                                sizeof(display_reservation_path)) != 0) {
        pam_close_session(pamh, 0);
        pam_setcred(pamh, PAM_DELETE_CRED);
        pam_end(pamh, PAM_SUCCESS);
        return -1;
    }
    char display_str[16];
    snprintf(display_str, sizeof display_str, ":%d", display);
    uuid_generate(new_id);
    uuid_unparse_lower(new_id, new_session_id);
    if (build_agent_socket_path(agent_socket_path, sizeof(agent_socket_path), new_session_id) != 0) {
        release_display_reservation(&display_reservation_fd, display_reservation_path);
        pam_close_session(pamh, 0);
        pam_setcred(pamh, PAM_DELETE_CRED);
        pam_end(pamh, PAM_SUCCESS);
        return -1;
    }
    if (agent_socket_path[0] != '\0') {
        agent_fd = create_agent_socket(agent_socket_path);
        if (agent_fd < 0) {
            release_display_reservation(&display_reservation_fd, display_reservation_path);
            pam_close_session(pamh, 0);
            pam_setcred(pamh, PAM_DELETE_CRED);
            pam_end(pamh, PAM_SUCCESS);
            return -1;
        }
    }
    snprintf(geometry_str, sizeof(geometry_str), "%ux%ux%u",
             normalize_dimension(desktop_width, 1024),
             normalize_dimension(desktop_height, 768), normalize_color_depth(color_depth));

    if (create_cloexec_pipe(exec_pipe) != 0) {
        destroy_agent_socket(&agent_fd, agent_socket_path);
        release_display_reservation(&display_reservation_fd, display_reservation_path);
        pam_close_session(pamh, 0);
        pam_setcred(pamh, PAM_DELETE_CRED);
        pam_end(pamh, PAM_SUCCESS);
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(exec_pipe[0]);
        close(exec_pipe[1]);
        destroy_agent_socket(&agent_fd, agent_socket_path);
        release_display_reservation(&display_reservation_fd, display_reservation_path);
        pam_close_session(pamh, 0);
        pam_setcred(pamh, PAM_DELETE_CRED);
        pam_end(pamh, PAM_SUCCESS);
        return -1;
    }
    if (pid == 0) {
        close(exec_pipe[0]);
        close_child_fds_except(exec_pipe[1], agent_fd);
        if (set_fd_cloexec(exec_pipe[1], 0) != 0)
            child_exec_failed(exec_pipe[1]);
        /* Child: create a new process group for the session and drop privileges. */
        if (setpgid(0, 0) != 0)
            child_exec_failed(exec_pipe[1]);
        if (frdp_sesmand_apply_session_resource_policy(&g_session_resource_policy) != 0)
            child_exec_failed(exec_pipe[1]);
        /* Set environment variables for the display */
        setenv("DISPLAY", display_str, 1);
        setenv("FRDP_DISPLAY", display_str, 1);
        setenv("FRDP_GEOMETRY", geometry_str, 1);
        setenv("FRDP_SESSION_ID", new_session_id, 1);
        snprintf(ready_fd_str, sizeof(ready_fd_str), "%d", exec_pipe[1]);
        setenv("FRDP_AGENT_READY_FD", ready_fd_str, 1);
        if (correlation_id && correlation_id[0])
            setenv("FRDP_CORRELATION_ID", correlation_id, 1);
        if (rhost && rhost[0])
            setenv("FRDP_RHOST", rhost, 1);
        if (agent_fd >= 0) {
            snprintf(agent_fd_str, sizeof(agent_fd_str), "%d", agent_fd);
            setenv("FRDP_AGENT_CONTROL_FD", agent_fd_str, 1);
            setenv("FRDP_AGENT_SOCKET", agent_socket_path, 1);
        }
        /* Apply the verified group payload before dropping UID/GID. */
        if (setgroups((size_t)group_count, native_groups) != 0) {
            child_exec_failed(exec_pipe[1]);
        }
        if (setgid(gid) != 0 || setuid(uid) != 0) {
            child_exec_failed(exec_pipe[1]);
        }
        execlp("frdp-session-agent", "frdp-session-agent", (char *)NULL);
        /* If exec fails, exit with error. */
        child_exec_failed(exec_pipe[1]);
    }

    close(exec_pipe[1]);
    exec_pipe[1] = -1;
    if (agent_fd >= 0) {
        close(agent_fd);
        agent_fd = -1;
    }
    if (wait_for_agent_ready(exec_pipe[0], pid, pid) != 0) {
        close(exec_pipe[0]);
        destroy_agent_socket(&agent_fd, agent_socket_path);
        release_display_reservation(&display_reservation_fd, display_reservation_path);
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
    s->uid = uid;
    uuid_copy(s->id, new_id);
    s->agent_pid = pid;
    s->pgid = pid; /* child's pgid equals pid since setpgid called with 0 */
    s->start_time = time(NULL);
    s->pamh = pamh;
    s->credentials_established = credentials_established;
    s->state = FRDP_SESMAND_SESSION_ACTIVE;
    s->display_number = display;
    s->display_reservation_fd = display_reservation_fd;
    display_reservation_fd = -1;
    snprintf(s->display_reservation, sizeof(s->display_reservation), "%s",
             display_reservation_path);
    snprintf(s->agent_socket, sizeof(s->agent_socket), "%s", agent_socket_path);
    snprintf(session_id, session_id_size, "%s", new_session_id);
    snprintf(display_out, display_out_size, "%s", display_str);
    if (agent_socket_out && agent_socket_out_size > 0)
        snprintf(agent_socket_out, agent_socket_out_size, "%s", agent_socket_path);
    char escaped_correlation_id[256] = {0};
    char escaped_session_id[256] = {0};
    char escaped_user[256] = {0};
    char escaped_display[128] = {0};
    char escaped_geometry[128] = {0};
    char escaped_agent_socket[512] = {0};

    escape_log_field(correlation_id && correlation_id[0] ? correlation_id : "unknown",
                     escaped_correlation_id, sizeof(escaped_correlation_id));
    escape_log_field(session_id ? session_id : "unknown", escaped_session_id,
                     sizeof(escaped_session_id));
    escape_log_field(user, escaped_user, sizeof(escaped_user));
    escape_log_field(display_str, escaped_display, sizeof(escaped_display));
    escape_log_field(geometry_str, escaped_geometry, sizeof(escaped_geometry));
    escape_log_field(agent_socket_path[0] ? agent_socket_path : "none", escaped_agent_socket,
                     sizeof(escaped_agent_socket));
    syslog(LOG_INFO, "correlation_id=%s created session_id=%s user=%s display=%s geometry=%s agent_socket=%s",
           escaped_correlation_id, escaped_session_id, escaped_user, escaped_display,
           escaped_geometry, escaped_agent_socket);
    return 0;
}

/* Clean up and remove a session from the registry. */
static void cleanup_session(int idx)
{
    session *s = &sessions[idx];
    frdpSesmandSessionCleanupPlan cleanup = {0};
    frdpSesmandSessionCleanupContext cleanup_context = {
        .state = s->state,
        .has_process_group = s->pgid > 0,
        .has_pam_handle = s->pamh != NULL,
        .credentials_established = s->credentials_established,
        .has_agent_socket = s->agent_socket[0] != '\0',
        .has_display_reservation = (s->display_reservation_fd >= 0) ||
                                   (s->display_reservation[0] != '\0')
    };
    if (frdp_sesmand_session_cleanup_plan(&cleanup_context, &cleanup) != 0) {
        cleanup.terminate_process_group = cleanup_context.has_process_group;
        cleanup.close_pam_session = cleanup_context.has_pam_handle;
        cleanup.delete_pam_credentials = cleanup_context.has_pam_handle &&
                                         cleanup_context.credentials_established;
        cleanup.unlink_agent_socket = cleanup_context.has_agent_socket;
        cleanup.release_display_reservation = cleanup_context.has_display_reservation;
    }
    if (cleanup.mark_stopping)
        s->state = FRDP_SESMAND_SESSION_STOPPING;
    /* Terminate the entire process group (agent + display backend). */
    if (cleanup.terminate_process_group) {
        kill(-s->pgid, SIGTERM);
        wait_for_agent_exit(s->agent_pid, s->pgid);
    }
    /* Close PAM session and end handle. */
    if (cleanup.close_pam_session) {
        int status = pam_close_session(s->pamh, 0);
        if (cleanup.delete_pam_credentials) {
            int cred_status = pam_setcred(s->pamh, PAM_DELETE_CRED);
            if (status == PAM_SUCCESS && cred_status != PAM_SUCCESS)
                status = cred_status;
        }
        pam_end(s->pamh, status);
    }
    if (cleanup.unlink_agent_socket)
        unlink(s->agent_socket);
    if (cleanup.release_display_reservation)
        release_display_reservation(&s->display_reservation_fd, s->display_reservation);
    if (cleanup.mark_dead)
        s->state = FRDP_SESMAND_SESSION_DEAD;
    if (idx < session_count - 1) {
        sessions[idx] = sessions[session_count - 1];
    }
    session_count--;
}

static void cleanup_all_sessions(void)
{
    while (session_count > 0)
        cleanup_session(session_count - 1);
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
                                 const char *display, const char *agent_socket,
                                 const char *error)
{
    frdpSessionResponse resp;
    int rc = 0;

    memset(&resp, 0, sizeof(resp));
    resp.success = success;
    if (session_id)
        snprintf(resp.session_id, sizeof(resp.session_id), "%s", session_id);
    if (display)
        snprintf(resp.display, sizeof(resp.display), "%s", display);
    if (agent_socket)
        snprintf(resp.agent_socket, sizeof(resp.agent_socket), "%s", agent_socket);
    if (error)
        snprintf(resp.error, sizeof(resp.error), "%s", error);

    rc = frdp_ipc_send_session_response(fd, &resp);
    SecureZeroMemory(&resp, sizeof(resp));
    return rc;
}

static int send_session_list_response(int fd)
{
    frdpSessionListResponse resp;
    int rc = 0;

    memset(&resp, 0, sizeof(resp));

    resp.success = 1;
    resp.count = (session_count > 0) ? (uint32_t)session_count : 0;
    if (resp.count > FRDP_IPC_MAX_SESSION_LIST_ENTRIES)
        resp.count = FRDP_IPC_MAX_SESSION_LIST_ENTRIES;
    for (uint32_t i = 0; i < resp.count; i++) {
        session_id_to_string(&sessions[i], resp.entries[i].session_id,
                             sizeof(resp.entries[i].session_id));
        snprintf(resp.entries[i].user, sizeof(resp.entries[i].user), "%s", sessions[i].user);
        snprintf(resp.entries[i].display, sizeof(resp.entries[i].display), ":%d",
                 sessions[i].display_number);
        snprintf(resp.entries[i].state, sizeof(resp.entries[i].state), "%s",
                 frdp_sesmand_session_state_string(sessions[i].state));
        resp.entries[i].agent_pid = sessions[i].agent_pid;
    }

    rc = frdp_ipc_send_session_list_response(fd, &resp);
    SecureZeroMemory(&resp, sizeof(resp));
    return rc;
}

static int send_reload_response(int fd, int success, const char *message, const char *error)
{
    frdpControlResponse resp;
    int rc = 0;

    memset(&resp, 0, sizeof(resp));
    resp.success = success;
    if (message)
        snprintf(resp.message, sizeof(resp.message), "%s", message);
    if (error)
        snprintf(resp.error, sizeof(resp.error), "%s", error);

    rc = frdp_ipc_send_session_reload_response(fd, &resp);
    SecureZeroMemory(&resp, sizeof(resp));
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

static int create_agent_socket(const char *socket_path)
{
    int fd = -1;
    mode_t old_umask;
    struct sockaddr_un addr;

    if (!socket_path || socket_path[0] == '\0')
        return -1;
    if (frdp_ipc_prepare_listener_socket_path(socket_path) != 0)
        return -1;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    old_umask = umask(0177);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        umask(old_umask);
        close(fd);
        return -1;
    }
    umask(old_umask);

    if (chmod(socket_path, 0600) != 0 || listen(fd, 8) != 0) {
        close(fd);
        unlink(socket_path);
        return -1;
    }
    return fd;
}

static void destroy_agent_socket(int *fd, const char *socket_path)
{
    if (fd && *fd >= 0) {
        close(*fd);
        *fd = -1;
    }
    if (socket_path && socket_path[0] != '\0')
        unlink(socket_path);
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

static int set_pam_service_name(const char *service)
{
    int rc = 0;

    if (!pam_service_is_valid(service))
        return -1;
    rc = snprintf(g_pam_service, sizeof(g_pam_service), "%s", service);
    return (rc >= 0 && (size_t)rc < sizeof(g_pam_service)) ? 0 : -1;
}

static int copy_config_path(const char *path)
{
    int rc = 0;

    if (!path || path[0] == '\0')
        return -1;
    rc = snprintf(g_config_path, sizeof(g_config_path), "%s", path);
    return (rc >= 0 && (size_t)rc < sizeof(g_config_path)) ? 0 : -1;
}

static int load_configured_sesmand_policy(const char *config_path, char *service,
                                          size_t service_size,
                                          frdpSessionResourcePolicy *resource_policy)
{
    frdpConfig config;
    int rc = 0;

    if (!config_path || !service || service_size == 0 || !resource_policy)
        return -1;
    if (frdp_config_load(config_path, &config) != 0)
        return -1;
    if (config.kerberos || (config.clipboard.mode != FRDP_CLIPBOARD_MODE_DISABLED))
        return -1;
    if (!pam_service_is_valid(config.pam_service))
        return -1;
    rc = snprintf(service, service_size, "%s", config.pam_service);
    if (!(rc >= 0 && (size_t)rc < service_size))
        return -1;
    *resource_policy = config.session_resources;
    return 0;
}

static int apply_sesmand_policy(const char *pam_service,
                                const frdpSessionResourcePolicy *resource_policy)
{
    if (!resource_policy)
        return -1;
    if (set_pam_service_name(pam_service) != 0)
        return -1;
    g_session_resource_policy = *resource_policy;
    return 0;
}

static int reload_configured_sesmand_policy(char *error, size_t error_size)
{
    char pam_service[sizeof(g_pam_service)] = {0};
    frdpSessionResourcePolicy resource_policy = {0};

    if (g_config_path[0] == '\0') {
        if (error && error_size > 0)
            snprintf(error, error_size, "%s", "no config path configured");
        return -1;
    }
    if (load_configured_sesmand_policy(g_config_path, pam_service, sizeof(pam_service),
                                       &resource_policy) != 0) {
        if (error && error_size > 0)
            snprintf(error, error_size, "%s", "config reload failed");
        return -1;
    }
    if (apply_sesmand_policy(pam_service, &resource_policy) != 0) {
        if (error && error_size > 0)
            snprintf(error, error_size, "%s", "invalid session policy");
        return -1;
    }
    return 0;
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

static int reconnect_existing_session(int fd, const char *correlation_id,
                                      const char *requested_session_id, const char *user,
                                      uid_t uid)
{
    frdpSesmandReconnectCandidate candidates[MAX_SESSIONS];
    char candidate_ids[MAX_SESSIONS][64];
    size_t selected = 0;
    session *s = NULL;
    char response_session_id[64] = {0};
    char display[32] = {0};
    char escaped_correlation_id[256] = {0};
    char escaped_session_id[256] = {0};
    char escaped_user[256] = {0};
    frdpSesmandReconnectResult selection = FRDP_SESMAND_RECONNECT_ERROR;
    const int explicit_reconnect = requested_session_id && requested_session_id[0] != '\0';
    int rc = -1;

    if (session_count <= 0) {
        if (!explicit_reconnect)
            return FRDP_SESMAND_RECONNECT_NOT_FOUND;
        return send_session_response(fd, 0, NULL, NULL, NULL, "reconnect target not found");
    }

    memset(candidates, 0, sizeof(candidates));
    memset(candidate_ids, 0, sizeof(candidate_ids));
    for (int x = 0; x < session_count; x++) {
        session_id_to_string(&sessions[x], candidate_ids[x], sizeof(candidate_ids[x]));
        candidates[x].session_id = candidate_ids[x];
        candidates[x].user = sessions[x].user;
        candidates[x].uid = (uint64_t)sessions[x].uid;
        candidates[x].state = sessions[x].state;
        candidates[x].start_time = (unsigned long long)sessions[x].start_time;
    }

    selection = frdp_sesmand_reconnect_select(candidates, (size_t)session_count,
                                               requested_session_id, user, (uint64_t)uid,
                                               &selected);
    if (selection == FRDP_SESMAND_RECONNECT_NOT_FOUND) {
        if (!explicit_reconnect)
            return selection;
        return send_session_response(fd, 0, NULL, NULL, NULL, "reconnect target not found");
    }
    if (selection != FRDP_SESMAND_RECONNECT_SELECTED || selected >= (size_t)session_count)
        return send_session_response(fd, 0, NULL, NULL, NULL,
                                     "reconnect target is ambiguous");

    s = &sessions[selected];
    if ((s->state != FRDP_SESMAND_SESSION_DISCONNECTED) || (s->agent_socket[0] == '\0'))
        return send_session_response(fd, 0, NULL, NULL, NULL, "reconnect target not available");
    if (!frdp_sesmand_session_state_can_transition(s->state, FRDP_SESMAND_SESSION_ACTIVE))
        return send_session_response(fd, 0, NULL, NULL, NULL, "reconnect target not available");

    session_id_to_string(s, response_session_id, sizeof(response_session_id));
    snprintf(display, sizeof(display), ":%d", s->display_number);
    rc = send_session_response(fd, 1, response_session_id, display, s->agent_socket, NULL);
    if (rc != 0)
        return rc;
    s->state = FRDP_SESMAND_SESSION_ACTIVE;

    escape_log_field(correlation_id && correlation_id[0] ? correlation_id : "unknown",
                     escaped_correlation_id, sizeof(escaped_correlation_id));
    escape_log_field(response_session_id, escaped_session_id, sizeof(escaped_session_id));
    escape_log_field(user, escaped_user, sizeof(escaped_user));
    syslog(LOG_INFO, "correlation_id=%s reconnected session_id=%s user=%s",
           escaped_correlation_id, escaped_session_id, escaped_user);
    return 0;
}

static void prune_consumed_auth_tokens(unsigned long long now)
{
    for (size_t x = 0; x < MAX_CONSUMED_AUTH_TOKENS; x++) {
        if (consumed_auth_tokens[x].nonce[0] != '\0' &&
            consumed_auth_tokens[x].expires_at < now) {
            SecureZeroMemory(&consumed_auth_tokens[x], sizeof(consumed_auth_tokens[x]));
        }
    }
}

static int consume_auth_token_nonce(const char *nonce, unsigned long long expires_at)
{
    size_t free_slot = MAX_CONSUMED_AUTH_TOKENS;
    const unsigned long long now = (unsigned long long)time(NULL);

    if (!nonce || nonce[0] == '\0')
        return -1;
    prune_consumed_auth_tokens(now);
    for (size_t x = 0; x < MAX_CONSUMED_AUTH_TOKENS; x++) {
        if ((consumed_auth_tokens[x].nonce[0] != '\0') &&
            (strcmp(consumed_auth_tokens[x].nonce, nonce) == 0))
            return -1;
        if ((free_slot == MAX_CONSUMED_AUTH_TOKENS) &&
            (consumed_auth_tokens[x].nonce[0] == '\0'))
            free_slot = x;
    }
    if (free_slot == MAX_CONSUMED_AUTH_TOKENS)
        return -1;
    snprintf(consumed_auth_tokens[free_slot].nonce, sizeof(consumed_auth_tokens[free_slot].nonce),
             "%s", nonce);
    consumed_auth_tokens[free_slot].expires_at = expires_at;
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

static int posix_groups_match(const char *user, gid_t primary_gid, const uint64_t *groups,
                              uint32_t group_count)
{
    uint64_t current_groups[FRDP_IPC_MAX_AUTH_GROUPS] = {0};
    uint32_t current_group_count = 0;

    if ((group_count > FRDP_IPC_MAX_AUTH_GROUPS) || ((group_count > 0U) && !groups))
        return 0;
    if (lookup_posix_groups(user, primary_gid, current_groups, &current_group_count) != 0)
        return 0;
    return (current_group_count == group_count) &&
           (memcmp(current_groups, groups, group_count * sizeof(groups[0])) == 0);
}

static int validate_and_consume_authorization(const char *authorization_id, const char *user,
                                              const char *rhost, const char *correlation_id,
                                              uint64_t uid, uint64_t gid, const uint64_t *groups,
                                              uint32_t group_count, int has_posix_account)
{
    char nonce[37] = {0};
    unsigned long long expires_at = 0;
    int rc = -1;

    if (frdp_auth_token_verify(authorization_id, user, rhost, correlation_id, uid, gid,
                               groups, group_count, has_posix_account, nonce, sizeof(nonce),
                               &expires_at) != 0)
        goto cleanup;
    rc = consume_auth_token_nonce(nonce, expires_at);

cleanup:
    SecureZeroMemory(nonce, sizeof(nonce));
    return rc;
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

static int handle_session_request(int fd, frdpIpcMessageType type, uint32_t payload_len)
{
    frdpSessionRequest req;
    frdpSessionRequestV3 req_v3;
    char correlation_id[sizeof(req.correlation_id)] = {0};
    char session_id[sizeof(req.session_id)] = {0};
    char user[sizeof(req.user)] = {0};
    char rhost[sizeof(req.rhost)] = {0};
    char authorization_id[sizeof(req_v3.authorization_id)] = {0};
    char response_session_id[64] = {0};
    char display[32] = {0};
    char agent_socket[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};
    uid_t uid = (uid_t)-1;
    gid_t gid = (gid_t)-1;
    int has_posix_account = 0;
    int rc = -1;

    memset(&req, 0, sizeof(req));
    memset(&req_v3, 0, sizeof(req_v3));
    if (type == FRDP_IPC_SESSION_REQUEST_V3) {
        if (frdp_ipc_recv_session_request_v3_payload(fd, &req_v3, payload_len) != 0)
            goto cleanup;
        memcpy(req.correlation_id, req_v3.correlation_id, sizeof(req.correlation_id));
        memcpy(req.session_id, req_v3.session_id, sizeof(req.session_id));
        memcpy(req.user, req_v3.user, sizeof(req.user));
        memcpy(req.rhost, req_v3.rhost, sizeof(req.rhost));
        req.desktop_width = req_v3.desktop_width;
        req.desktop_height = req_v3.desktop_height;
        req.color_depth = req_v3.color_depth;
        uid = (uid_t)req_v3.uid;
        gid = (gid_t)req_v3.gid;
        has_posix_account = req_v3.has_posix_account;
    } else if ((type == FRDP_IPC_SESSION_CLOSE_REQUEST) ||
               (type == FRDP_IPC_SESSION_DISCONNECT_REQUEST)) {
        if (frdp_ipc_recv_session_close_request_payload(fd, &req, payload_len) != 0)
            goto cleanup;
    } else {
        goto cleanup;
    }
    if (copy_ipc_string(correlation_id, sizeof(correlation_id), req.correlation_id,
                        sizeof(req.correlation_id)) != 0 ||
        copy_ipc_string(session_id, sizeof(session_id), req.session_id,
                        sizeof(req.session_id)) != 0 ||
        copy_ipc_string(user, sizeof(user), req.user, sizeof(req.user)) != 0 ||
        copy_ipc_string(rhost, sizeof(rhost), req.rhost, sizeof(req.rhost)) != 0) {
        rc = send_session_response(fd, 0, NULL, NULL, NULL, "invalid session request");
        goto cleanup;
    }
    if ((type == FRDP_IPC_SESSION_REQUEST_V3) &&
        (copy_ipc_string(authorization_id, sizeof(authorization_id), req_v3.authorization_id,
                         sizeof(req_v3.authorization_id)) != 0)) {
        rc = send_session_response(fd, 0, NULL, NULL, NULL, "invalid authorization");
        goto cleanup;
    }

    if (type == FRDP_IPC_SESSION_REQUEST_V3) {
        struct passwd *pwd = NULL;

        if (user[0] == '\0') {
            rc = send_session_response(fd, 0, NULL, NULL, NULL, "missing user");
            goto cleanup;
        }
        if (authorization_id[0] == '\0') {
            rc = send_session_response(fd, 0, NULL, NULL, NULL, "missing authorization");
            goto cleanup;
        }
        if (req_v3.group_count > FRDP_IPC_MAX_AUTH_GROUPS) {
            rc = send_session_response(fd, 0, NULL, NULL, NULL, "missing POSIX account");
            goto cleanup;
        }
        if (validate_and_consume_authorization(authorization_id, user, rhost, correlation_id,
                                               req_v3.uid, req_v3.gid, req_v3.groups,
                                               req_v3.group_count,
                                               req_v3.has_posix_account) != 0) {
            rc = send_session_response(fd, 0, NULL, NULL, NULL, "invalid authorization");
            goto cleanup;
        }
        if (!has_posix_account || ((uint64_t)uid != req_v3.uid) || ((uint64_t)gid != req_v3.gid) ||
            (req_v3.group_count > FRDP_IPC_MAX_AUTH_GROUPS)) {
            rc = send_session_response(fd, 0, NULL, NULL, NULL, "missing POSIX account");
            goto cleanup;
        }
        pwd = getpwnam(user);
        if (!pwd || (pwd->pw_uid != uid) || (pwd->pw_gid != gid)) {
            rc = send_session_response(fd, 0, NULL, NULL, NULL, "POSIX account mismatch");
            goto cleanup;
        }
        if (!posix_groups_match(user, gid, req_v3.groups, req_v3.group_count)) {
            rc = send_session_response(fd, 0, NULL, NULL, NULL, "POSIX groups mismatch");
            goto cleanup;
        }
        if (session_id[0] != '\0') {
            rc = reconnect_existing_session(fd, correlation_id, session_id, user, uid);
            goto cleanup;
        }
        rc = reconnect_existing_session(fd, correlation_id, NULL, user, uid);
        if (rc != FRDP_SESMAND_RECONNECT_NOT_FOUND)
            goto cleanup;
        if (open_session(user, uid, gid, req_v3.groups, req_v3.group_count, rhost,
                         correlation_id, req.desktop_width, req.desktop_height, req.color_depth,
                         response_session_id, sizeof(response_session_id), display,
                         sizeof(display), agent_socket, sizeof(agent_socket)) != 0) {
            char escaped_correlation_id[256] = {0};
            char escaped_user[256] = {0};

            escape_log_field(correlation_id[0] ? correlation_id : "unknown", escaped_correlation_id,
                             sizeof(escaped_correlation_id));
            escape_log_field(user, escaped_user, sizeof(escaped_user));
            syslog(LOG_ERR, "correlation_id=%s failed to create session for %s",
                   escaped_correlation_id, escaped_user);
            rc = send_session_response(fd, 0, NULL, NULL, NULL, "session open failed");
            goto cleanup;
        }
        const int send_status = send_session_response(fd, 1, response_session_id, display,
                                                     agent_socket, NULL);
        if (send_status != 0) {
            const int idx = find_session_by_id(response_session_id);
            if (idx >= 0) {
                char escaped_correlation_id[256] = {0};
                char escaped_session_id[256] = {0};

                escape_log_field(correlation_id[0] ? correlation_id : "unknown",
                                 escaped_correlation_id, sizeof(escaped_correlation_id));
                escape_log_field(response_session_id, escaped_session_id, sizeof(escaped_session_id));
                syslog(LOG_WARNING,
                       "correlation_id=%s rolling back session_id=%s after response failure",
                       escaped_correlation_id, escaped_session_id);
                cleanup_session(idx);
            }
        }
        rc = send_status;
        goto cleanup;
    }

    if (type == FRDP_IPC_SESSION_DISCONNECT_REQUEST) {
        const int idx = find_session_by_id(session_id);
        int send_status = -1;

        if (idx < 0) {
            rc = send_session_response(fd, 0, NULL, NULL, NULL, "unknown session");
            goto cleanup;
        }
        if (frdp_sesmand_session_disconnect_begin(&sessions[idx].state,
                                                  sessions[idx].agent_socket[0] != '\0') != 0) {
            rc = send_session_response(fd, 0, NULL, NULL, NULL, "session not disconnectable");
            goto cleanup;
        }
        char escaped_correlation_id[256] = {0};
        char escaped_session_id[256] = {0};
        char escaped_user[256] = {0};

        send_status = send_session_response(fd, 1, session_id, NULL, sessions[idx].agent_socket,
                                            NULL);
        if (send_status != 0) {
            (void)frdp_sesmand_session_disconnect_rollback(&sessions[idx].state);
            rc = send_status;
            goto cleanup;
        }

        escape_log_field(correlation_id[0] ? correlation_id : "unknown", escaped_correlation_id,
                         sizeof(escaped_correlation_id));
        escape_log_field(session_id, escaped_session_id, sizeof(escaped_session_id));
        escape_log_field(sessions[idx].user, escaped_user, sizeof(escaped_user));
        syslog(LOG_INFO, "correlation_id=%s disconnected session_id=%s user=%s",
               escaped_correlation_id, escaped_session_id, escaped_user);
        rc = 0;
        goto cleanup;
    }

    if (type == FRDP_IPC_SESSION_CLOSE_REQUEST) {
        const int idx = find_session_by_id(session_id);

        if (idx < 0) {
            rc = send_session_response(fd, 0, NULL, NULL, NULL, "unknown session");
            goto cleanup;
        }
        char escaped_correlation_id[256] = {0};
        char escaped_session_id[256] = {0};
        char escaped_user[256] = {0};

        escape_log_field(correlation_id[0] ? correlation_id : "unknown", escaped_correlation_id,
                         sizeof(escaped_correlation_id));
        escape_log_field(session_id, escaped_session_id, sizeof(escaped_session_id));
        escape_log_field(sessions[idx].user, escaped_user, sizeof(escaped_user));
        syslog(LOG_INFO, "correlation_id=%s closing session_id=%s user=%s",
               escaped_correlation_id, escaped_session_id, escaped_user);
        cleanup_session(idx);
        rc = send_session_response(fd, 1, session_id, NULL, NULL, NULL);
        goto cleanup;
    }

    rc = send_session_response(fd, 0, NULL, NULL, NULL, "unsupported session request");

cleanup:
    SecureZeroMemory(&req, sizeof(req));
    SecureZeroMemory(&req_v3, sizeof(req_v3));
    SecureZeroMemory(authorization_id, sizeof(authorization_id));
    return rc;
}

static int run_ipc_server(const char *socket_path, const char *pam_service, const char *config_path)
{
    int fd = -1;
    mode_t old_umask;
    struct sockaddr_un addr;

    if (config_path) {
        char configured_service[sizeof(g_pam_service)] = {0};
        frdpSessionResourcePolicy resource_policy = {0};

        if (copy_config_path(config_path) != 0 ||
            load_configured_sesmand_policy(config_path, configured_service,
                                           sizeof(configured_service), &resource_policy) != 0 ||
            apply_sesmand_policy(configured_service, &resource_policy) != 0) {
            fprintf(stderr, "failed to load frdp-sesmand config\n");
            return -1;
        }
    } else {
        if (set_pam_service_name(pam_service) != 0) {
            fprintf(stderr, "invalid PAM service name\n");
            return -1;
        }
    }

    if (frdp_ipc_prepare_listener_socket_path(socket_path) != 0) {
        char escaped_socket[512] = {0};

        escape_log_field(socket_path ? socket_path : "(null)", escaped_socket, sizeof(escaped_socket));
        fprintf(stderr, "refusing unsafe socket path: %s\n", escaped_socket);
        return -1;
    }
    if (derive_parent_dir(socket_path, g_agent_socket_dir, sizeof(g_agent_socket_dir)) != 0) {
        char escaped_socket[512] = {0};

        escape_log_field(socket_path ? socket_path : "(null)", escaped_socket, sizeof(escaped_socket));
        fprintf(stderr, "unable to derive agent socket directory from: %s\n", escaped_socket);
        return -1;
    }

    fd = create_cloexec_unix_socket();
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

    char escaped_socket[512] = {0};

    escape_log_field(socket_path, escaped_socket, sizeof(escaped_socket));
    printf("frdp-sesmand IPC server listening on %s\n", escaped_socket);
    frdpIpcRateLimiter rate_limiter = {0};
    while (!g_stop_requested) {
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

        int cfd = accept_cloexec(fd);
        if (cfd < 0) {
            perror("accept");
            continue;
        }
        if (set_client_timeouts(cfd) != 0) {
            close(cfd);
            continue;
        }
        if (verify_peer(cfd) != 0) {
            send_session_response(cfd, 0, NULL, NULL, NULL, "unauthorized IPC peer");
            close(cfd);
            continue;
        }
        uint64_t peer_uid = 0;
        if ((frdp_ipc_get_peer_uid(cfd, &peer_uid) != 0) ||
            !frdp_ipc_rate_limiter_allow(&rate_limiter, peer_uid)) {
            send_session_response(cfd, 0, NULL, NULL, NULL, "IPC rate limit exceeded");
            close(cfd);
            continue;
        }

        frdpIpcHeader hdr;
        if (frdp_ipc_recv_header(cfd, &hdr) != (int)sizeof(hdr)) {
            close(cfd);
            continue;
        }
        if (!frdp_ipc_request_payload_len_is_bounded(hdr.payload_len)) {
            send_session_response(cfd, 0, NULL, NULL, NULL, "IPC payload too large");
            close(cfd);
            continue;
        }
        if ((hdr.type == FRDP_IPC_SESSION_LIST_REQUEST) && (hdr.payload_len == 0)) {
            (void)send_session_list_response(cfd);
        } else if ((hdr.type == FRDP_IPC_SESSION_RELOAD_REQUEST) && (hdr.payload_len == 0)) {
            if (g_config_path[0] != '\0') {
                char error[sizeof(((frdpControlResponse *)0)->error)] = {0};
                char message[sizeof(((frdpControlResponse *)0)->message)] = {0};

                if (reload_configured_sesmand_policy(error, sizeof(error)) == 0) {
                    snprintf(message, sizeof(message),
                             "pam_service=%s;max_processes=%" PRIu32 ";memory_max_mb=%" PRIu32,
                             g_pam_service, g_session_resource_policy.max_processes,
                             g_session_resource_policy.memory_max_mb);
                    (void)send_reload_response(cfd, 1, message, NULL);
                } else
                    (void)send_reload_response(cfd, 0, NULL, error);
            } else {
                (void)send_reload_response(cfd, 1, "accepted", NULL);
            }
        } else if (((hdr.type == FRDP_IPC_SESSION_REQUEST_V3) &&
                    (hdr.payload_len == FRDP_IPC_SESSION_REQUEST_V3_WIRE_SIZE)) ||
                   ((hdr.type == FRDP_IPC_SESSION_CLOSE_REQUEST) &&
                    (hdr.payload_len == FRDP_IPC_SESSION_CLOSE_REQUEST_WIRE_SIZE)) ||
                   ((hdr.type == FRDP_IPC_SESSION_DISCONNECT_REQUEST) &&
                    (hdr.payload_len == FRDP_IPC_SESSION_DISCONNECT_REQUEST_WIRE_SIZE))) {
            (void)handle_session_request(cfd, hdr.type, hdr.payload_len);
        } else {
            send_session_response(cfd, 0, NULL, NULL, NULL, "unsupported IPC request");
        }
        close(cfd);
    }

    cleanup_all_sessions();
    close(fd);
    unlink(socket_path);
    return g_stop_requested ? 0 : -1;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [--pam-service <name> | --config <path>] --socket <absolute-socket-path>\n",
            argv0);
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
    const char *config_path = NULL;
    int pam_service_set = 0;

    if (set_no_core() != 0) {
        fprintf(stderr, "failed to disable core dumps\n");
        return 1;
    }

    openlog("frdp-sesmand", LOG_PID, LOG_DAEMON);
    if (install_signal_handlers() != 0) {
        fprintf(stderr, "failed to install signal handlers\n");
        closelog();
        return 1;
    }

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
            pam_service_set = 1;
        } else if (strcmp(argv[x], "--config") == 0) {
            if (++x >= argc) {
                usage(argv[0]);
                closelog();
                return 2;
            }
            config_path = argv[x];
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
    if (config_path && (!socket_path || standalone_user || pam_service_set)) {
        usage(argv[0]);
        closelog();
        return 2;
    }
    if (socket_path) {
        const int rc = run_ipc_server(socket_path, pam_service, config_path);
        closelog();
        return (rc == 0) ? 0 : 1;
    }
    if (!standalone_user) {
        usage(argv[0]);
        closelog();
        return 2;
    }
    if (set_pam_service_name(pam_service) != 0) {
        fprintf(stderr, "invalid PAM service name\n");
        closelog();
        return 2;
    }
    if (!standalone_open_session_allowed()) {
        fprintf(stderr, "standalone session opening is disabled by default\n");
        syslog(LOG_WARNING, "refused standalone session open without explicit development opt-in");
        closelog();
        return 2;
    }

    char escaped_standalone_user[512] = {0};

    escape_log_field(standalone_user, escaped_standalone_user, sizeof(escaped_standalone_user));
    printf("frdp-sesmand: opening session for %s\n", escaped_standalone_user);

    char session_id[64] = {0};
    char display[32] = {0};
    char agent_socket[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};
    uint64_t standalone_groups[FRDP_IPC_MAX_AUTH_GROUPS] = {0};
    uint32_t standalone_group_count = 0;
    struct passwd *pwd = getpwnam(standalone_user);
    if (!pwd) {
        syslog(LOG_ERR, "unknown standalone session user %s", escaped_standalone_user);
        closelog();
        return 1;
    }
    if (lookup_posix_groups(standalone_user, pwd->pw_gid, standalone_groups,
                            &standalone_group_count) != 0) {
        syslog(LOG_ERR, "failed to lookup groups for standalone session user %s",
               escaped_standalone_user);
        closelog();
        return 1;
    }
    if (open_session(standalone_user, pwd->pw_uid, pwd->pw_gid, standalone_groups,
                     standalone_group_count, NULL, "standalone", 1024, 768, 24, session_id,
                     sizeof(session_id), display, sizeof(display), agent_socket,
                     sizeof(agent_socket)) == 0) {
        syslog(LOG_INFO, "created session for %s", escaped_standalone_user);
    } else {
        syslog(LOG_ERR, "failed to create session for %s", escaped_standalone_user);
        closelog();
        return 1;
    }

    /* Monitor for agent exits and clean up sessions accordingly. */
    int wait_error = 0;
    while ((session_count > 0) && !g_stop_requested) {
        int status = 0;
        pid_t pid = waitpid(-1, &status, WNOHANG);
        if (pid == 0) {
            usleep(200000);
            continue;
        }
        if (pid < 0) {
            if (errno == EINTR)
                continue;
            wait_error = 1;
            break;
        }
        for (int i = 0; i < session_count; i++) {
            if (sessions[i].agent_pid == pid) {
                cleanup_session(i);
                break;
            }
        }
    }
    if ((session_count > 0) && (g_stop_requested || wait_error))
        cleanup_all_sessions();
    syslog(LOG_INFO, "no more sessions, shutting down");
    closelog();
    return (wait_error && !g_stop_requested) ? 1 : 0;
}
