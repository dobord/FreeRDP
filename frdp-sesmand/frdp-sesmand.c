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

/* Session registry entry. */
typedef struct {
    char user[64];
    uuid_t id;
    pid_t agent_pid;
    time_t start_time;
} session;

#define MAX_SESSIONS 64
static session sessions[MAX_SESSIONS];
static int session_count = 0;

/* Non-interactive PAM conversation.  frdp-sesmand should not prompt. */
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

/* Open a session for the specified user.  This starts a PAM session and
 * launches the per-user session agent under the same UID/GID as the user.
 */
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
    pam_end(pamh, ret);
    if (ret != PAM_SUCCESS)
        return -1;

    /* Fork and exec the session agent.  In a complete implementation this
     * would switch UID/GID to the user and preserve environment variables. */
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execlp("frdp-session-agent", "frdp-session-agent", (char *)NULL);
        _exit(127);
    }
    session *s = &sessions[session_count++];
    strncpy(s->user, user, sizeof(s->user) - 1);
    s->user[sizeof(s->user) - 1] = '\0';
    uuid_generate(s->id);
    s->agent_pid = pid;
    s->start_time = time(NULL);
    return 0;
}

/* Clean up and remove a session from the registry. */
static void cleanup_session(int idx)
{
    session *s = &sessions[idx];
    if (s->agent_pid > 0) {
        kill(s->agent_pid, SIGTERM);
        waitpid(s->agent_pid, NULL, 0);
    }
    struct pam_conv conv = {pam_conv_fn, NULL};
    pam_handle_t *pamh = NULL;
    pam_start("frdpd", s->user, &conv, &pamh);
    pam_close_session(pamh, 0);
    pam_end(pamh, PAM_SUCCESS);
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

    /* Demonstration: create a test session for the nobody account.  In a real
     * server sessions would be created upon successful authentication by
     * frdp-authd. */
    if (open_session("nobody") == 0) {
        syslog(LOG_INFO, "created test session");
    } else {
        syslog(LOG_ERR, "failed to create test session");
    }

    /* Monitor for child exits and clean up sessions accordingly. */
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
