/*
 * frdp-session-agent - Per-user agent for FreeRDP-based RDP server
 *
 * This component runs in the security context of an authenticated user.  It
 * launches the headless desktop backend (for example Xvfb or Wayland), sets
 * up graphics capture and input dispatch and enforces channel policy.  In this
 * minimal prototype only the display server launch is implemented.  The
 * display number and geometry are provided via environment variables from
 * the session manager: DISPLAY or FRDP_DISPLAY and FRDP_GEOMETRY.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <syslog.h>
#include <signal.h>
#include <string.h>

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    openlog("frdp-session-agent", LOG_PID, LOG_USER);
    syslog(LOG_INFO, "session agent starting");

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

    pid_t pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "failed to fork for backend");
        closelog();
        return 1;
    }
    if (pid == 0) {
        /* Child: execute Xvfb.  Provide display and geometry. */
        execlp("Xvfb", "Xvfb", display, "-screen", "0", geometry, (char *)NULL);
        /* If exec fails, log to stderr and exit. */
        fprintf(stderr, "frdp-session-agent: failed to exec Xvfb\n");
        _exit(127);
    }

    /* TODO: capture framebuffer updates and forward to the client via FreeRDP. */
    /* TODO: process keyboard/mouse events and clipboard/audio channels. */

    /* Wait for the display server to exit. */
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        syslog(LOG_ERR, "display server exited with status %d", WEXITSTATUS(status));
    }
    syslog(LOG_INFO, "display server exited, terminating agent");
    closelog();
    return 0;
}
