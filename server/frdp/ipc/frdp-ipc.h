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
    FRDP_IPC_SESSION_CLOSE_REQUEST = 6,
    FRDP_IPC_AGENT_INPUT = 7,
    FRDP_IPC_AGENT_FRAME_REQUEST = 8,
    FRDP_IPC_AGENT_FRAME_RESPONSE = 9
} frdpIpcMessageType;

typedef enum {
    FRDP_AGENT_INPUT_SYNC = 1,
    FRDP_AGENT_INPUT_KEYBOARD = 2,
    FRDP_AGENT_INPUT_UNICODE = 3,
    FRDP_AGENT_INPUT_MOUSE = 4,
    FRDP_AGENT_INPUT_REL_MOUSE = 5,
    FRDP_AGENT_INPUT_EXT_MOUSE = 6
} frdpAgentInputType;

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
    char agent_socket[108];
    char error[128];
} frdpSessionResponse;

typedef struct {
    char correlation_id[64];
    char session_id[64];
    uint32_t event_type;
    uint32_t flags;
    int32_t param1;
    int32_t param2;
} frdpAgentInputEvent;

typedef struct {
    char correlation_id[64];
    char session_id[64];
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
} frdpAgentFrameRequest;

typedef struct {
    char correlation_id[64];
    char session_id[64];
    int success;
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
    uint32_t stride;
    uint32_t bpp;
    uint32_t data_length;
    char error[128];
} frdpAgentFrameResponse;

/* Connect to a UNIX domain socket at socket_path and return the fd, or -1 on error */
int frdp_ipc_connect(const char *socket_path);

/* Send len bytes of data on fd. Returns 0 on success, -1 on error */
int frdp_ipc_send(int fd, const void *buf, size_t len);

/* Receive exactly len bytes of data on fd. Returns number of bytes read or -1 on error */
int frdp_ipc_recv(int fd, void *buf, size_t len);

/* Close a previously opened fd */
int frdp_ipc_close(int fd);

#endif /* FRDP_IPC_H */
