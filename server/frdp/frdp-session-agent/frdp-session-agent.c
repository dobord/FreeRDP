#define _GNU_SOURCE

/*
 * frdp-session-agent - Per-user agent for FreeRDP-based RDP server
 *
 * This component runs in the security context of an authenticated user.  It
 * launches the headless desktop backend (for example Xvfb or Wayland), sets
 * up graphics capture and input dispatch and enforces channel policy.  In this
 * minimal prototype launches the display server and receives validated input
 * metadata over a local control fd; backend input injection and framebuffer
 * capture are still TODO.  The display number, geometry and audit identifiers
 * are provided via environment variables from the session manager: DISPLAY or
 * FRDP_DISPLAY, FRDP_GEOMETRY, FRDP_SESSION_ID and FRDP_CORRELATION_ID.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <syslog.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "../ipc/frdp-ipc.h"

static int parse_control_fd(void)
{
    char *end = NULL;
    long value = -1;
    const char *env = getenv("FRDP_AGENT_CONTROL_FD");

    if (!env || env[0] == '\0')
        return -1;
    errno = 0;
    value = strtol(env, &end, 10);
    if (errno != 0 || !end || end[0] != '\0' || value < 0 || value > 1024 * 1024)
        return -1;
    return (int)value;
}

static int set_cloexec(int fd)
{
    const int flags = fcntl(fd, F_GETFD);

    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static int set_control_timeouts(int fd)
{
    struct timeval timeout;

    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
        return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0)
        return -1;
    return 0;
}

static int verify_control_peer(int fd)
{
#ifdef __linux__
    struct ucred cred;
    socklen_t len = sizeof(cred);

    memset(&cred, 0, sizeof(cred));
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0)
        return -1;
    return (cred.uid == 0) ? 0 : -1;
#else
    (void)fd;
    return -1;
#endif
}

static int recv_exact(int fd, void *buf, size_t len)
{
    char *p = (char *)buf;
    size_t total = 0;

    while (total < len) {
        const ssize_t rc = recv(fd, p + total, len - total, 0);
        if (rc <= 0)
            return -1;
        total += (size_t)rc;
    }
    return 0;
}

static int handle_control_client(int fd, const char *correlation_id, const char *session_id)
{
    frdpIpcHeader header;
    frdpAgentInputEvent event;

    memset(&header, 0, sizeof(header));
    memset(&event, 0, sizeof(event));

    if (set_control_timeouts(fd) != 0 || verify_control_peer(fd) != 0)
        return -1;
    if (recv_exact(fd, &header, sizeof(header)) != 0)
        return -1;
    if (header.type != FRDP_IPC_AGENT_INPUT || header.payload_len != sizeof(event))
        return -1;
    if (recv_exact(fd, &event, sizeof(event)) != 0)
        return -1;

    event.correlation_id[sizeof(event.correlation_id) - 1] = '\0';
    event.session_id[sizeof(event.session_id) - 1] = '\0';
    if (strcmp(event.session_id, session_id) != 0 ||
        (strcmp(correlation_id, "unknown") != 0 &&
         strcmp(event.correlation_id, correlation_id) != 0)) {
        syslog(LOG_WARNING, "correlation_id=%s session_id=%s rejected mismatched input event",
               correlation_id, session_id);
        return -1;
    }

    /* Backend input injection is the next layer; do not log key or text payload. */
    return 0;
}

static int wait_for_backend_exit(pid_t pid, int control_fd, const char *correlation_id,
                                 const char *session_id)
{
    int status = 0;

    while (1) {
        const pid_t rc = waitpid(pid, &status, WNOHANG);
        if (rc == pid)
            return status;
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            return status;
        }

        if (control_fd < 0) {
            usleep(200000);
            continue;
        }

        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = control_fd;
        pfd.events = POLLIN;
        const int poll_status = poll(&pfd, 1, 500);
        if (poll_status < 0) {
            if (errno == EINTR)
                continue;
            return status;
        }
        if (poll_status == 0 || (pfd.revents & POLLIN) == 0)
            continue;

        const int cfd = accept(control_fd, NULL, NULL);
        if (cfd < 0)
            continue;
        if (handle_control_client(cfd, correlation_id, session_id) != 0) {
            syslog(LOG_WARNING, "correlation_id=%s session_id=%s rejected agent control event",
                   correlation_id, session_id);
        }
        close(cfd);
    }
}

static void backend_exec_failed(int fd)
{
    const char marker = '!';

    if (fd >= 0) {
        const ssize_t rc = write(fd, &marker, sizeof(marker));
        (void)rc;
    }
    _exit(127);
}

static int wait_for_backend_exec(int fd, pid_t pid)
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

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    openlog("frdp-session-agent", LOG_PID, LOG_USER);

    const char *correlation_id = getenv("FRDP_CORRELATION_ID");
    if (!correlation_id) {
        correlation_id = "unknown";
    }
    const char *session_id = getenv("FRDP_SESSION_ID");
    if (!session_id) {
        session_id = "unknown";
    }
    int control_fd = parse_control_fd();
    if (control_fd >= 0 && set_cloexec(control_fd) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to mark control fd close-on-exec",
               correlation_id, session_id);
        closelog();
        return 1;
    }

    /* Determine display and geometry from environment. */
    const char *display = getenv("DISPLAY");
    if (!display) {
        display = getenv("FRDP_DISPLAY");
    }
    if (!display) {
        display = ":99";
    }
    const char *geometry = getenv("FRDP_GEOMETRY");
    if (!geometry) {
        geometry = "1024x768x24";
    }

    syslog(LOG_INFO, "correlation_id=%s session_id=%s display=%s geometry=%s session agent starting",
           correlation_id, session_id, display, geometry);

    int exec_pipe[2] = {-1, -1};
    if (pipe(exec_pipe) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to create backend exec pipe",
               correlation_id, session_id);
        closelog();
        return 1;
    }
    if (fcntl(exec_pipe[1], F_SETFD, FD_CLOEXEC) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to mark backend exec pipe",
               correlation_id, session_id);
        close(exec_pipe[0]);
        close(exec_pipe[1]);
        closelog();
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to fork for backend",
               correlation_id, session_id);
        close(exec_pipe[0]);
        close(exec_pipe[1]);
        closelog();
        return 1;
    }
    if (pid == 0) {
        close(exec_pipe[0]);
        if (control_fd >= 0)
            close(control_fd);
        /* Child: execute Xvfb.  Provide display and geometry. */
        execlp("Xvfb", "Xvfb", display, "-screen", "0", geometry, (char *)NULL);
        /* If exec fails, log to stderr and exit. */
        fprintf(stderr, "frdp-session-agent: failed to exec Xvfb\n");
        backend_exec_failed(exec_pipe[1]);
    }

    close(exec_pipe[1]);
    if (wait_for_backend_exec(exec_pipe[0], pid) != 0) {
        close(exec_pipe[0]);
        syslog(LOG_ERR, "correlation_id=%s session_id=%s backend failed to start",
               correlation_id, session_id);
        closelog();
        return 1;
    }
    close(exec_pipe[0]);

    syslog(LOG_INFO, "correlation_id=%s session_id=%s backend started", correlation_id,
           session_id);

    /* TODO: capture framebuffer updates and forward to the client via FreeRDP. */
    /* TODO: inject validated input events into the display backend. */
    /* TODO: process clipboard/audio channels. */

    /* Wait for the display server to exit. */
    int status = wait_for_backend_exit(pid, control_fd, correlation_id, session_id);
    if (control_fd >= 0)
        close(control_fd);
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s display server exited with status %d",
               correlation_id, session_id, WEXITSTATUS(status));
    }
    syslog(LOG_INFO, "correlation_id=%s session_id=%s display server exited, terminating agent",
           correlation_id, session_id);
    closelog();
    return 0;
}
