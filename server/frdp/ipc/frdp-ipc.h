#ifndef FRDP_IPC_H
#define FRDP_IPC_H

#include <stdint.h>
#include <stddef.h>

/* Message types for interprocess communication */
typedef enum {
    FRDP_IPC_AUTH_REQUEST = 1,
    FRDP_IPC_AUTH_RESPONSE = 2,
    FRDP_IPC_SESSION_REQUEST = 3,
    FRDP_IPC_SESSION_RESPONSE = 4,
    FRDP_IPC_AUTH_REQUEST_V2 = 5,
    FRDP_IPC_SESSION_CLOSE_REQUEST = 6
} frdpIpcMessageType;

/* Common header prepended to each IPC message */
typedef struct {
    frdpIpcMessageType type;
    uint32_t payload_len;
} frdpIpcHeader;

/* Authentication request structure */
typedef struct {
    char correlation_id[64];
    char user[64];
    char rhost[128];
    char password[256];
} frdpAuthRequest;

/* Authentication response structure */
typedef struct {
    int success;
    char error[128];
} frdpAuthResponse;

/* Session open/close request structure */
typedef struct {
    char correlation_id[64];
    char session_id[64];
    char user[64];
    char rhost[128];
    uint32_t desktop_width;
    uint32_t desktop_height;
    uint32_t color_depth;
} frdpSessionRequest;

/* Session open/close response structure */
typedef struct {
    int success;
    char session_id[64];
    char display[32];
    char error[128];
} frdpSessionResponse;

/* Connect to a UNIX domain socket at socket_path and return the fd, or -1 on error */
int frdp_ipc_connect(const char *socket_path);

/* Send len bytes of data on fd. Returns 0 on success, -1 on error */
int frdp_ipc_send(int fd, const void *buf, size_t len);

/* Receive up to len bytes of data on fd. Returns number of bytes read or -1 on error */
int frdp_ipc_recv(int fd, void *buf, size_t len);

/* Close a previously opened fd */
int frdp_ipc_close(int fd);

#endif /* FRDP_IPC_H */
