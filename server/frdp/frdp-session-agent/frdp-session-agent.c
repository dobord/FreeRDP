/*
 * frdp-session-agent - Per-user agent for FreeRDP-based RDP server
 *
 * This component runs in the security context of an authenticated user.  It
 * launches the headless desktop backend (for example Xvfb or Wayland), sets
 * up graphics capture and input dispatch and enforces channel policy.  In this
 * minimal prototype only the display server launch is implemented.  The
 * display number, geometry and audit identifiers are provided via environment
 * variables from the session manager: DISPLAY or FRDP_DISPLAY, FRDP_GEOMETRY,
 * FRDP_SESSION_ID and FRDP_CORRELATION_ID.
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
    /* TODO: process keyboard/mouse events and clipboard/audio channels. */

    /* Wait for the display server to exit. */
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s display server exited with status %d",
               correlation_id, session_id, WEXITSTATUS(status));
    }
    syslog(LOG_INFO, "correlation_id=%s session_id=%s display server exited, terminating agent",
           correlation_id, session_id);
    closelog();
    return 0;
}
