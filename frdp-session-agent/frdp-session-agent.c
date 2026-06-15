/*
 * frdp-session-agent - Per-user agent for FreeRDP-based RDP server
 *
 * This component runs in the security context of an authenticated user.  It
 * launches the headless desktop backend (for example Xvfb or Wayland), sets
 * up graphics capture and input dispatch and enforces channel policy.  In this
 * minimal prototype only the display server launch is implemented.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <syslog.h>
#include <signal.h>

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    openlog("frdp-session-agent", LOG_PID, LOG_USER);
    syslog(LOG_INFO, "session agent starting");

    /* Fork and start a headless Xorg (Xvfb) server.  The display number and
     * screen geometry are hard-coded for demonstration purposes. */
    pid_t pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "failed to fork");
        closelog();
        return 1;
    }
    if (pid == 0) {
        execlp("Xvfb", "Xvfb", ":99", "-screen", "0", "1024x768x24", (char *)NULL);
        /* If Xvfb is unavailable fall back to a sleep loop to keep the agent
         * process alive until it is terminated by the session manager. */
        while (1) {
            sleep(60);
        }
    }

    /* TODO: capture framebuffer updates and forward to the client via FreeRDP. */
    /* TODO: process keyboard/mouse events and clipboard/audio channels. */

    /* Wait until the display server terminates. */
    waitpid(pid, NULL, 0);
    syslog(LOG_INFO, "display server exited, terminating agent");
    closelog();
    return 0;
}
