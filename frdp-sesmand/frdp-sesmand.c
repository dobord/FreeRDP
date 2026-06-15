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
#include <security/pam_appl.h>
#include <pwd.h>
#include <syslog.h>
#include <uuid/uuid.h>
#include <time.h>
#include <signal.h>
#include <grp.h>

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
    int display_number;
} session;

#define MAX_SESSIONS 64
static session sessions[MAX_SESSIONS];
static int session_count = 0;
static int next_display = 100;

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

/* Open a session for the specified user.  This starts a PAM session, forks
 * a child to run the per-user agent and returns 0 on success. */
static int open_session(const char *user)
{
    if (session_count >= MAX_SESSIONS)
        return -1;
    struct pam_conv conv = {pam_conv_fn, NULL};
    pam_handle_t *pamh = NULL;
    int ret = pam_start("frdpd", user, &conv, &pamh);
    if (ret != PAM_SUCCESS)
        return -1;
    ret = pam_open_session(pamh, 0);
    if (ret != PAM_SUCCESS) {
        pam_end(pamh, ret);
        return -1;
    }

    /* Allocate display number and build display string */
    int display = next_display++;
    char display_str[16];
    snprintf(display_str, sizeof display_str, ":%d", display);

    /* Retrieve user information for UID/GID drop. */
    struct passwd *pwd = getpwnam(user);
    if (!pwd) {
        pam_close_session(pamh, 0);
        pam_end(pamh, PAM_USER_UNKNOWN);
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        pam_close_session(pamh, 0);
        pam_end(pamh, PAM_SUCCESS);
        return -1;
    }
    if (pid == 0) {
        /* Child: create a new process group for the session and drop privileges. */
        setpgid(0, 0);
        /* Set environment variables for the display */
        setenv("DISPLAY", display_str, 1);
        setenv("FRDP_DISPLAY", display_str, 1);
        /* Set groups and UID/GID */
        if (initgroups(user, pwd->pw_gid) != 0) {
            _exit(127);
        }
        if (setgid(pwd->pw_gid) != 0 || setuid(pwd->pw_uid) != 0) {
            _exit(127);
        }
        execlp("frdp-session-agent", "frdp-session-agent", (char *)NULL);
        /* If exec fails, exit with error. */
        _exit(127);
    }

    /* Parent: record session metadata. */
    session *s = &sessions[session_count++];
    strncpy(s->user, user, sizeof(s->user) - 1);
    s->user[sizeof(s->user) - 1] = '\0';
    uuid_generate(s->id);
    s->agent_pid = pid;
    s->pgid = pid; /* child's pgid equals pid since setpgid called with 0 */
    s->start_time = time(NULL);
    s->pamh = pamh;
    s->display_number = display;
    return 0;
}

/* Clean up and remove a session from the registry. */
static void cleanup_session(int idx)
{
    session *s = &sessions[idx];
    /* Terminate the entire process group (agent + display backend). */
    if (s->pgid > 0) {
        kill(-s->pgid, SIGTERM);
        /* Wait for the agent PID to exit */
        waitpid(s->agent_pid, NULL, 0);
    }
    /* Close PAM session and end handle. */
    if (s->pamh) {
        pam_close_session(s->pamh, 0);
        pam_end(s->pamh, PAM_SUCCESS);
    }
    if (idx < session_count - 1) {
        sessions[idx] = sessions[session_count - 1];
    }
    session_count--;
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    openlog("frdp-sesmand", LOG_PID, LOG_DAEMON);
    printf("frdp-sesmand: session manager starting\n");

    /* Demonstration: create a test session for the nobody account. */
    if (open_session("nobody") == 0) {
        syslog(LOG_INFO, "created test session");
    } else {
        syslog(LOG_ERR, "failed to create test session");
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
