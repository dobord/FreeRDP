#ifndef FRDP_IPC_H
#define FRDP_IPC_H

#include <stdint.h>
#include <stddef.h>

#include "frdp-auth-token.h"

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
    FRDP_IPC_AGENT_FRAME_RESPONSE = 9,
    FRDP_IPC_AGENT_RESIZE_REQUEST = 10,
    FRDP_IPC_AGENT_RESIZE_RESPONSE = 11,
    FRDP_IPC_SESSION_LIST_REQUEST = 12,
    FRDP_IPC_SESSION_LIST_RESPONSE = 13,
    FRDP_IPC_SESSION_REQUEST_V2 = 14,
    FRDP_IPC_SESSION_RELOAD_REQUEST = 15,
    FRDP_IPC_SESSION_RELOAD_RESPONSE = 16,
    FRDP_IPC_SESSION_REQUEST_V3 = 17
} frdpIpcMessageType;

typedef enum {
    FRDP_AGENT_INPUT_SYNC = 1,
    FRDP_AGENT_INPUT_KEYBOARD = 2,
    FRDP_AGENT_INPUT_UNICODE = 3,
    FRDP_AGENT_INPUT_MOUSE = 4,
    FRDP_AGENT_INPUT_REL_MOUSE = 5,
    FRDP_AGENT_INPUT_EXT_MOUSE = 6
} frdpAgentInputType;

enum {
    FRDP_AGENT_FRAME_REQUEST_FORCE = 0x00000001U,
    FRDP_AGENT_FRAME_REQUEST_DIRTY_ONLY = 0x00000002U,
    FRDP_AGENT_FRAME_RESPONSE_UNCHANGED = 0x00000001U
};

/* Common header prepended to each IPC message */
typedef struct {
    frdpIpcMessageType type;
    uint32_t payload_len;
} frdpIpcHeader;

#define FRDP_IPC_MAX_REQUEST_PAYLOAD_LEN 4096U
#define FRDP_IPC_MAX_AUTH_GROUPS FRDP_AUTH_TOKEN_MAX_GROUPS
#define FRDP_IPC_AUTH_REQUEST_V2_WIRE_SIZE (64U + 64U + 128U + 256U)
#define FRDP_IPC_AUTH_RESPONSE_WIRE_SIZE \
    (4U + 128U + 192U + 8U + 8U + 4U + (FRDP_IPC_MAX_AUTH_GROUPS * 8U) + 4U)
#define FRDP_IPC_RATE_LIMIT_WINDOW_SECONDS 10U
#define FRDP_IPC_RATE_LIMIT_MAX_REQUESTS 64U
#define FRDP_IPC_RATE_LIMIT_MAX_PEERS 16U

typedef struct {
    uint64_t uid;
    uint32_t requests;
    unsigned long window_start;
    int in_use;
} frdpIpcRateLimitEntry;

typedef struct {
    frdpIpcRateLimitEntry entries[FRDP_IPC_RATE_LIMIT_MAX_PEERS];
} frdpIpcRateLimiter;

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
    char authorization_id[192];
    uint64_t uid;
    uint64_t gid;
    uint32_t group_count;
    uint64_t groups[FRDP_IPC_MAX_AUTH_GROUPS];
    int has_posix_account;
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

typedef struct {
    char correlation_id[64];
    char session_id[64];
    char user[64];
    char rhost[128];
    uint64_t uid;
    uint64_t gid;
    int has_posix_account;
    uint32_t desktop_width;
    uint32_t desktop_height;
    uint32_t color_depth;
} frdpSessionRequestV2;

typedef struct {
    char correlation_id[64];
    char session_id[64];
    char user[64];
    char rhost[128];
    char authorization_id[192];
    uint64_t uid;
    uint64_t gid;
    uint32_t group_count;
    uint64_t groups[FRDP_IPC_MAX_AUTH_GROUPS];
    int has_posix_account;
    uint32_t desktop_width;
    uint32_t desktop_height;
    uint32_t color_depth;
} frdpSessionRequestV3;

/* Session open/close response structure */
typedef struct {
    int success;
    char session_id[64];
    char display[32];
    char agent_socket[108];
    char error[128];
} frdpSessionResponse;

#define FRDP_IPC_MAX_SESSION_LIST_ENTRIES 64U

typedef struct {
    char session_id[64];
    char user[64];
    char display[32];
    int32_t agent_pid;
} frdpSessionListEntry;

typedef struct {
    int success;
    uint32_t count;
    frdpSessionListEntry entries[FRDP_IPC_MAX_SESSION_LIST_ENTRIES];
    char error[128];
} frdpSessionListResponse;

typedef struct {
    int success;
    char message[128];
    char error[128];
} frdpControlResponse;

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
    uint32_t flags;
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
    uint32_t flags;
    uint32_t data_length;
    char error[128];
} frdpAgentFrameResponse;

typedef struct {
    char correlation_id[64];
    char session_id[64];
    uint32_t width;
    uint32_t height;
    uint32_t color_depth;
} frdpAgentResizeRequest;

typedef struct {
    char correlation_id[64];
    char session_id[64];
    int success;
    uint32_t width;
    uint32_t height;
    char error[128];
} frdpAgentResizeResponse;

/* Connect to a UNIX domain socket at socket_path and return the fd, or -1 on error */
int frdp_ipc_connect(const char *socket_path);

/* Send len bytes of data on fd. Returns 0 on success, -1 on error */
int frdp_ipc_send(int fd, const void *buf, size_t len);

/* Receive exactly len bytes of data on fd. Returns number of bytes read or -1 on error */
int frdp_ipc_recv(int fd, void *buf, size_t len);

/* Send/receive an IPC header using the fixed little-endian wire format */
int frdp_ipc_send_header(int fd, frdpIpcMessageType type, uint32_t payload_len);
int frdp_ipc_recv_header(int fd, frdpIpcHeader *header);

int frdp_ipc_send_auth_request_v2(int fd, const frdpAuthRequest *request);
int frdp_ipc_recv_auth_request_v2_payload(int fd, frdpAuthRequest *request, uint32_t payload_len);
int frdp_ipc_send_auth_response(int fd, const frdpAuthResponse *response);
int frdp_ipc_recv_auth_response(int fd, frdpAuthResponse *response);

/* Close a previously opened fd */
int frdp_ipc_close(int fd);

/*
 * Validate a listener socket pathname before bind().
 * Existing live sockets are rejected without unlinking; stale same-owner
 * socket nodes are removed so the caller can bind a fresh listener.
 */
int frdp_ipc_prepare_listener_socket_path(const char *socket_path);

/* Return non-zero when an inbound request payload is within the supported bound. */
int frdp_ipc_request_payload_len_is_bounded(uint32_t payload_len);

/* Return the peer uid for rate-limit/accounting decisions when supported. */
int frdp_ipc_get_peer_uid(int fd, uint64_t *uid);

/* Return non-zero when peer_uid is still within the fixed-window request limit. */
int frdp_ipc_rate_limiter_allow(frdpIpcRateLimiter *limiter, uint64_t peer_uid);

#endif /* FRDP_IPC_H */
