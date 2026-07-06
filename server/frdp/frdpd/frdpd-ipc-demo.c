/*
 * frdpd IPC demo client
 *
 * This simple program demonstrates how the RDP daemon could authenticate a user
 * via the frdp-authd broker using the IPC protocol defined in frdp-ipc.h.
 * It loads the daemon configuration to obtain defaults and sends an
 * FRDP_IPC_AUTH_REQUEST_V2 to the auth daemon.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../config/frdp-config.h"
#include "../ipc/frdp-ipc.h"

static void clear_secret(void *secret, size_t length)
{
    volatile unsigned char *p = (volatile unsigned char *)secret;

    while (p && length-- > 0)
        *p++ = 0;
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <config.toml> <socket-path> <username> <password>\n", argv[0]);
        return 1;
    }
    const char *cfg_path = argv[1];
    const char *sock = argv[2];
    const char *user = argv[3];
    const char *pass = argv[4];
    int rc = 1;
    int fd = -1;
    frdpAuthRequest req = {0};
    frdpAuthResponse resp = {0};

    frdpConfig cfg;
    if (frdp_config_load(cfg_path, &cfg) != 0) {
        fprintf(stderr, "Failed to load configuration from %s\n", cfg_path);
        goto cleanup;
    }
    fd = frdp_ipc_connect(sock);
    if (fd < 0) {
        perror("frdp_ipc_connect");
        goto cleanup;
    }
    strncpy(req.correlation_id, "11111111-1111-4111-8111-111111111111",
            sizeof(req.correlation_id) - 1);
    strncpy(req.user, user, sizeof(req.user) - 1);
    strncpy(req.password, pass, sizeof(req.password) - 1);
    clear_secret(argv[4], strlen(argv[4]));
    if (frdp_ipc_send_auth_request_v2(fd, &req) != 0) {
        perror("frdp_ipc_send");
        goto cleanup;
    }
    if (frdp_ipc_recv_auth_response(fd, &resp) != 0) {
        fprintf(stderr, "Failed to read response\n");
        goto cleanup;
    }
    printf("Authentication result: %s\n", resp.success ? "success" : "failure");
    if (!resp.success && resp.error[0] != '\0') {
        printf("Error: %s\n", resp.error);
    }
    rc = resp.success ? 0 : 1;

cleanup:
    clear_secret(&req, sizeof(req));
    clear_secret(&resp, sizeof(resp));
    if (fd >= 0)
        frdp_ipc_close(fd);
    clear_secret(argv[4], strlen(argv[4]));
    return rc;
}
