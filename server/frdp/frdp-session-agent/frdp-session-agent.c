#define _GNU_SOURCE

/*
 * frdp-session-agent - Per-user agent for FreeRDP-based RDP server
 *
 * This component runs in the security context of an authenticated user.  It
 * launches the headless desktop backend (for example Xvfb or Wayland), sets
 * up graphics capture and input dispatch and enforces channel policy.  In this
 * minimal prototype launches the display server and injects validated keyboard
 * scancode and mouse input over a local control fd; framebuffer capture and
 * Unicode/text input are still TODO.  The display number, geometry and audit
 * identifiers are provided via environment variables from the session manager:
 * DISPLAY or FRDP_DISPLAY, FRDP_GEOMETRY, FRDP_SESSION_ID and FRDP_CORRELATION_ID.
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

#include <X11/Xlib.h>
#include <X11/extensions/XTest.h>

#include <freerdp/input.h>

#include <winpr/input.h>

#include "../ipc/frdp-ipc.h"

#define FRDP_AGENT_READY_MARKER 'R'

static Display *open_backend_display(const char *display_name, const char *correlation_id,
                                     const char *session_id)
{
    Display *display = NULL;

    for (int attempt = 0; attempt < 50; attempt++) {
        display = XOpenDisplay(display_name);
        if (display)
            break;
        usleep(100000);
    }
    if (!display) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to open display %s",
               correlation_id, session_id, display_name ? display_name : "unknown");
        return NULL;
    }

    int event_base = 0;
    int error_base = 0;
    int major = 0;
    int minor = 0;
    if (!XTestQueryExtension(display, &event_base, &error_base, &major, &minor)) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s display %s lacks XTest",
               correlation_id, session_id, display_name ? display_name : "unknown");
        XCloseDisplay(display);
        return NULL;
    }
    return display;
}

static int inject_keyboard_event(Display *display, const frdpAgentInputEvent *event)
{
    DWORD scancode = (DWORD)(event->param1 & 0xFF);
    DWORD vkcode = 0;
    DWORD keycode = 0;

    if (event->flags & KBD_FLAGS_EXTENDED)
        scancode |= KBDEXT;

    vkcode = GetVirtualKeyCodeFromVirtualScanCode(scancode, WINPR_KBD_TYPE_IBM_ENHANCED);
    if (event->flags & KBD_FLAGS_EXTENDED)
        vkcode |= KBDEXT;

    keycode = GetKeycodeFromVirtualKeyCode(vkcode, WINPR_KEYCODE_TYPE_XKB);
    if (keycode == 0)
        return -1;

    XTestFakeKeyEvent(display, keycode, (event->flags & KBD_FLAGS_RELEASE) ? False : True,
                      CurrentTime);
    return 0;
}

static void inject_button_event(Display *display, unsigned int button, Bool down)
{
    if (button)
        XTestFakeButtonEvent(display, button, down, CurrentTime);
}

static int inject_mouse_event(Display *display, const frdpAgentInputEvent *event)
{
    const uint32_t flags = event->flags;
    const int x = event->param1;
    const int y = event->param2;
    unsigned int button = 0;
    Bool down = (flags & PTR_FLAGS_DOWN) ? True : False;

    if (flags & PTR_FLAGS_WHEEL) {
        button = (flags & PTR_FLAGS_WHEEL_NEGATIVE) ? 5 : 4;
        XTestFakeButtonEvent(display, button, True, CurrentTime);
        XTestFakeButtonEvent(display, button, False, CurrentTime);
        return 0;
    }
    if (flags & PTR_FLAGS_HWHEEL) {
        button = (flags & PTR_FLAGS_WHEEL_NEGATIVE) ? 7 : 6;
        XTestFakeButtonEvent(display, button, True, CurrentTime);
        XTestFakeButtonEvent(display, button, False, CurrentTime);
        return 0;
    }
    if (flags & PTR_FLAGS_MOVE)
        XTestFakeMotionEvent(display, 0, x, y, CurrentTime);

    if (flags & PTR_FLAGS_BUTTON1)
        button = 1;
    else if (flags & PTR_FLAGS_BUTTON2)
        button = 3;
    else if (flags & PTR_FLAGS_BUTTON3)
        button = 2;
    inject_button_event(display, button, down);
    return 0;
}

static int inject_rel_mouse_event(Display *display, const frdpAgentInputEvent *event)
{
    const uint32_t flags = event->flags;
    unsigned int button = 0;
    Bool down = (flags & PTR_FLAGS_DOWN) ? True : False;

    if (flags & PTR_FLAGS_MOVE)
        XTestFakeRelativeMotionEvent(display, event->param1, event->param2, CurrentTime);

    if (flags & PTR_FLAGS_BUTTON1)
        button = 1;
    else if (flags & PTR_FLAGS_BUTTON2)
        button = 3;
    else if (flags & PTR_FLAGS_BUTTON3)
        button = 2;
    else if (flags & PTR_XFLAGS_BUTTON1)
        button = 8;
    else if (flags & PTR_XFLAGS_BUTTON2)
        button = 9;
    inject_button_event(display, button, down);
    return 0;
}

static int inject_extended_mouse_event(Display *display, const frdpAgentInputEvent *event)
{
    const uint32_t flags = event->flags;
    unsigned int button = 0;
    Bool down = (flags & PTR_XFLAGS_DOWN) ? True : False;

    XTestFakeMotionEvent(display, 0, event->param1, event->param2, CurrentTime);
    if (flags & PTR_XFLAGS_BUTTON1)
        button = 8;
    else if (flags & PTR_XFLAGS_BUTTON2)
        button = 9;
    inject_button_event(display, button, down);
    return 0;
}

static int inject_input_event(Display *display, const frdpAgentInputEvent *event)
{
    int rc = 0;

    if (!display || !event)
        return -1;
    XLockDisplay(display);
    XTestGrabControl(display, True);
    switch (event->event_type) {
        case FRDP_AGENT_INPUT_SYNC:
            rc = 0;
            break;
        case FRDP_AGENT_INPUT_KEYBOARD:
            rc = inject_keyboard_event(display, event);
            break;
        case FRDP_AGENT_INPUT_UNICODE:
            rc = 0;
            break;
        case FRDP_AGENT_INPUT_MOUSE:
            rc = inject_mouse_event(display, event);
            break;
        case FRDP_AGENT_INPUT_REL_MOUSE:
            rc = inject_rel_mouse_event(display, event);
            break;
        case FRDP_AGENT_INPUT_EXT_MOUSE:
            rc = inject_extended_mouse_event(display, event);
            break;
        default:
            rc = -1;
            break;
    }
    XTestGrabControl(display, False);
    XFlush(display);
    XUnlockDisplay(display);
    return rc;
}

static int parse_env_fd(const char *name)
{
    char *end = NULL;
    long value = -1;
    const char *env = getenv(name);

    if (!env || env[0] == '\0')
        return -1;
    errno = 0;
    value = strtol(env, &end, 10);
    if (errno != 0 || !end || end[0] != '\0' || value < 0 || value > 1024 * 1024)
        return -1;
    return (int)value;
}

static int parse_control_fd(void)
{
    return parse_env_fd("FRDP_AGENT_CONTROL_FD");
}

static int parse_ready_fd(void)
{
    return parse_env_fd("FRDP_AGENT_READY_FD");
}

static int notify_agent_ready(int *fd)
{
    if (!fd || *fd < 0)
        return 0;

    const char marker = FRDP_AGENT_READY_MARKER;
    const ssize_t rc = write(*fd, &marker, sizeof(marker));
    close(*fd);
    *fd = -1;
    return (rc == (ssize_t)sizeof(marker)) ? 0 : -1;
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

static int handle_control_client(int fd, Display *display, const char *correlation_id,
                                 const char *session_id)
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

    return inject_input_event(display, &event);
}

static int wait_for_backend_exit(pid_t pid, int control_fd, Display *display,
                                 const char *correlation_id,
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
        if (handle_control_client(cfd, display, correlation_id, session_id) != 0) {
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
    XInitThreads();

    const char *correlation_id = getenv("FRDP_CORRELATION_ID");
    if (!correlation_id) {
        correlation_id = "unknown";
    }
    const char *session_id = getenv("FRDP_SESSION_ID");
    if (!session_id) {
        session_id = "unknown";
    }
    int ready_fd = parse_ready_fd();
    if (ready_fd >= 0 && set_cloexec(ready_fd) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to mark ready fd close-on-exec",
               correlation_id, session_id);
        close(ready_fd);
        closelog();
        return 1;
    }
    int control_fd = parse_control_fd();
    if (control_fd >= 0 && set_cloexec(control_fd) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to mark control fd close-on-exec",
               correlation_id, session_id);
        if (ready_fd >= 0)
            close(ready_fd);
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
        if (ready_fd >= 0)
            close(ready_fd);
        if (control_fd >= 0)
            close(control_fd);
        closelog();
        return 1;
    }
    if (fcntl(exec_pipe[1], F_SETFD, FD_CLOEXEC) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to mark backend exec pipe",
               correlation_id, session_id);
        close(exec_pipe[0]);
        close(exec_pipe[1]);
        if (ready_fd >= 0)
            close(ready_fd);
        if (control_fd >= 0)
            close(control_fd);
        closelog();
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to fork for backend",
               correlation_id, session_id);
        close(exec_pipe[0]);
        close(exec_pipe[1]);
        if (ready_fd >= 0)
            close(ready_fd);
        if (control_fd >= 0)
            close(control_fd);
        closelog();
        return 1;
    }
    if (pid == 0) {
        close(exec_pipe[0]);
        if (control_fd >= 0)
            close(control_fd);
        if (ready_fd >= 0)
            close(ready_fd);
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
        if (ready_fd >= 0)
            close(ready_fd);
        if (control_fd >= 0)
            close(control_fd);
        closelog();
        return 1;
    }
    close(exec_pipe[0]);

    syslog(LOG_INFO, "correlation_id=%s session_id=%s backend started", correlation_id,
           session_id);

    Display *xdisplay = open_backend_display(display, correlation_id, session_id);
    if (!xdisplay) {
        kill(pid, SIGTERM);
        usleep(200000);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        if (ready_fd >= 0)
            close(ready_fd);
        if (control_fd >= 0)
            close(control_fd);
        closelog();
        return 1;
    }
    if (notify_agent_ready(&ready_fd) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to report agent readiness",
               correlation_id, session_id);
        XCloseDisplay(xdisplay);
        kill(pid, SIGTERM);
        usleep(200000);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        if (control_fd >= 0)
            close(control_fd);
        closelog();
        return 1;
    }

    /* TODO: capture framebuffer updates and forward to the client via FreeRDP. */
    /* TODO: add Unicode/text input injection with explicit layout handling. */
    /* TODO: process clipboard/audio channels. */

    /* Wait for the display server to exit. */
    int status = wait_for_backend_exit(pid, control_fd, xdisplay, correlation_id, session_id);
    XCloseDisplay(xdisplay);
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
