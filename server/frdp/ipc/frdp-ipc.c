#define _GNU_SOURCE

#include "frdp-ipc.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>

static int frdp_ipc_validate_socket_path(const char *socket_path)
{
    struct stat st;
    char parent[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};
    char *slash = NULL;

    if (!socket_path || strlen(socket_path) >= sizeof(((struct sockaddr_un *)0)->sun_path))
        return -1;
    if (socket_path[0] != '/')
        return -1;

    snprintf(parent, sizeof(parent), "%s", socket_path);
    slash = strrchr(parent, '/');
    if (!slash || slash == parent)
        return -1;
    *slash = '\0';

    if (lstat(parent, &st) != 0 || !S_ISDIR(st.st_mode))
        return -1;
    if (st.st_uid != 0 && st.st_uid != geteuid())
        return -1;
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        return -1;

    if (lstat(socket_path, &st) != 0 || !S_ISSOCK(st.st_mode))
        return -1;
    if (st.st_uid != 0 && st.st_uid != geteuid())
        return -1;
    if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0)
        return -1;

    return 0;
}

static int frdp_ipc_validate_peer(int fd)
{
#if defined(__linux__) && defined(SO_PEERCRED)
    struct ucred cred;
    socklen_t length = sizeof(cred);

    memset(&cred, 0, sizeof(cred));
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &length) != 0)
        return -1;
    if (length != sizeof(cred)) {
        errno = EIO;
        return -1;
    }
    if ((cred.uid != 0) && (cred.uid != geteuid())) {
        errno = EACCES;
        return -1;
    }
#else
    (void)fd;
#endif
    return 0;
}

static int frdp_ipc_set_timeouts(int fd, uint32_t timeout_ms)
{
    struct timeval timeout;

    timeout.tv_sec = (time_t)(timeout_ms / 1000U);
    timeout.tv_usec = (suseconds_t)((timeout_ms % 1000U) * 1000U);
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
        return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0)
        return -1;
    return 0;
}

static int frdp_ipc_set_cloexec(int fd)
{
    const int flags = fcntl(fd, F_GETFD);

    if (flags < 0)
        return -1;
    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0)
        return -1;
    return 0;
}

static int frdp_ipc_create_cloexec_unix_socket(void)
{
    int fd = -1;

#ifdef SOCK_CLOEXEC
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if ((fd == -1) && (errno == EINVAL || errno == EPROTONOSUPPORT))
#endif
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    if (frdp_ipc_set_cloexec(fd) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

static int frdp_ipc_set_nonblock(int fd)
{
    const int flags = fcntl(fd, F_GETFL);

    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int frdp_ipc_socket_path_has_live_listener(const char *socket_path)
{
    int fd = -1;
    int saved = 0;
    struct sockaddr_un addr;

    fd = frdp_ipc_create_cloexec_unix_socket();
    if (fd < 0)
        return -1;
    if (frdp_ipc_set_nonblock(fd) != 0) {
        saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        close(fd);
        errno = EADDRINUSE;
        return 1;
    }

    saved = errno;
    close(fd);
    errno = saved;
    if (saved == EAGAIN || saved == EINPROGRESS || saved == EALREADY) {
        errno = EADDRINUSE;
        return 1;
    }
    if (saved == ECONNREFUSED || saved == ENOENT)
        return 0;
    return -1;
}

int frdp_ipc_prepare_listener_socket_path(const char *socket_path)
{
    struct stat st;
    struct stat current;
    char parent[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};
    char *slash = NULL;
    int live_status = 0;

    if (!socket_path || strlen(socket_path) >= sizeof(((struct sockaddr_un *)0)->sun_path))
        return -1;
    if (socket_path[0] != '/')
        return -1;

    snprintf(parent, sizeof(parent), "%s", socket_path);
    slash = strrchr(parent, '/');
    if (!slash || slash == parent)
        return -1;
    *slash = '\0';

    if (lstat(parent, &st) != 0 || !S_ISDIR(st.st_mode))
        return -1;
    if (st.st_uid != 0 && st.st_uid != geteuid())
        return -1;
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        return -1;

    if (lstat(socket_path, &st) != 0)
        return (errno == ENOENT) ? 0 : -1;
    if (!S_ISSOCK(st.st_mode))
        return -1;
    if (st.st_uid != geteuid())
        return -1;

    live_status = frdp_ipc_socket_path_has_live_listener(socket_path);
    if (live_status != 0)
        return -1;

    if (lstat(socket_path, &current) != 0)
        return (errno == ENOENT) ? 0 : -1;
    if (!S_ISSOCK(current.st_mode))
        return -1;
    if (current.st_dev != st.st_dev || current.st_ino != st.st_ino) {
        errno = EADDRINUSE;
        return -1;
    }

    return unlink(socket_path);
}

int frdp_ipc_request_payload_len_is_bounded(uint32_t payload_len)
{
    return payload_len <= FRDP_IPC_MAX_REQUEST_PAYLOAD_LEN;
}

int frdp_ipc_get_peer_uid(int fd, uint64_t *uid)
{
    if (!uid) {
        errno = EINVAL;
        return -1;
    }
#if defined(__linux__) && defined(SO_PEERCRED)
    struct ucred cred;
    socklen_t length = sizeof(cred);

    memset(&cred, 0, sizeof(cred));
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &length) != 0)
        return -1;
    if (length != sizeof(cred)) {
        errno = EIO;
        return -1;
    }
    *uid = (uint64_t)cred.uid;
#else
    (void)fd;
    *uid = (uint64_t)geteuid();
#endif
    return 0;
}

int frdp_ipc_rate_limiter_allow(frdpIpcRateLimiter *limiter, uint64_t peer_uid)
{
    frdpIpcRateLimitEntry *free_entry = NULL;
    const unsigned long now = (unsigned long)time(NULL);

    if (!limiter) {
        errno = EINVAL;
        return 0;
    }

    for (size_t x = 0; x < FRDP_IPC_RATE_LIMIT_MAX_PEERS; x++) {
        frdpIpcRateLimitEntry *entry = &limiter->entries[x];

        if (entry->in_use &&
            ((now < entry->window_start) ||
             (now - entry->window_start >= FRDP_IPC_RATE_LIMIT_WINDOW_SECONDS))) {
            memset(entry, 0, sizeof(*entry));
        }
        if (!entry->in_use) {
            if (!free_entry)
                free_entry = entry;
            continue;
        }
        if (entry->uid != peer_uid)
            continue;
        if (entry->requests >= FRDP_IPC_RATE_LIMIT_MAX_REQUESTS)
            return 0;
        entry->requests++;
        return 1;
    }

    if (!free_entry)
        return 0;
    free_entry->in_use = 1;
    free_entry->uid = peer_uid;
    free_entry->requests = 1;
    free_entry->window_start = now;
    return 1;
}

/* Connect to a UNIX domain socket and return a file descriptor */
int frdp_ipc_connect(const char *socket_path)
{
    return frdp_ipc_connect_timeout(socket_path, 10000U);
}

static int frdp_ipc_monotonic_ms(uint64_t *value)
{
    struct timespec now = {0};

    if (!value) {
        errno = EINVAL;
        return -1;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -1;
    *value = ((uint64_t)now.tv_sec * 1000U) + ((uint64_t)now.tv_nsec / 1000000U);
    return 0;
}

int frdp_ipc_connect_timeout(const char *socket_path, uint32_t timeout_ms)
{
    uint64_t deadline_ms = 0;

    if ((timeout_ms == 0) || (timeout_ms > 600000U)) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_validate_socket_path(socket_path) != 0) {
        errno = EACCES;
        return -1;
    }
    if (frdp_ipc_monotonic_ms(&deadline_ms) != 0)
        return -1;
    deadline_ms += timeout_ms;

    int fd = -1;
    int status_flags = -1;

#ifdef SOCK_CLOEXEC
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if ((fd == -1) && (errno == EINVAL || errno == EPROTONOSUPPORT))
#endif
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
        return -1;
    if (frdp_ipc_set_cloexec(fd) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    status_flags = fcntl(fd, F_GETFL);
    if ((status_flags < 0) || (fcntl(fd, F_SETFL, status_flags | O_NONBLOCK) != 0)) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        if ((errno != EINPROGRESS) && (errno != EAGAIN)) {
            int saved = errno;
            close(fd);
            errno = saved;
            return -1;
        }
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        int poll_status = 0;

        do {
            uint64_t now_ms = 0;
            int remaining_ms = 0;

            if (frdp_ipc_monotonic_ms(&now_ms) != 0) {
                int saved = errno;
                close(fd);
                errno = saved;
                return -1;
            }
            if (now_ms >= deadline_ms) {
                close(fd);
                errno = ETIMEDOUT;
                return -1;
            }
            remaining_ms = (int)(deadline_ms - now_ms);
            poll_status = poll(&pfd, 1, remaining_ms);
        } while ((poll_status < 0) && (errno == EINTR));
        if (poll_status <= 0) {
            int saved = (poll_status == 0) ? ETIMEDOUT : errno;
            close(fd);
            errno = saved;
            return -1;
        }
        int socket_error = 0;
        socklen_t socket_error_size = sizeof(socket_error);

        if ((getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_size) != 0) ||
            (socket_error != 0)) {
            int saved = (socket_error != 0) ? socket_error : errno;
            close(fd);
            errno = saved;
            return -1;
        }
    }
    if ((fcntl(fd, F_SETFL, status_flags) != 0) ||
        (frdp_ipc_set_timeouts(fd, timeout_ms) != 0)) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    if (frdp_ipc_validate_peer(fd) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

/* Send the given buffer over a socket */
int frdp_ipc_send(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t total = 0;

    if (!buf && (len > 0)) {
        errno = EINVAL;
        return -1;
    }
#ifdef MSG_NOSIGNAL
    const int flags = MSG_NOSIGNAL;
#else
    const int flags = 0;
#endif
    while (total < len) {
        ssize_t n = send(fd, p + total, len - total, flags);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        total += (size_t)n;
    }
    return 0;
}

/* Receive exactly len bytes into buf. Returns number of bytes read or -1 */
int frdp_ipc_recv(int fd, void *buf, size_t len)
{
    char *p = (char *)buf;
    size_t total = 0;

    if (!buf && (len > 0)) {
        errno = EINVAL;
        return -1;
    }
    while (total < len) {
        ssize_t n = recv(fd, p + total, len - total, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        total += (size_t)n;
    }
    return (int)total;
}

static void frdp_ipc_write_u32_le(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)(value & 0xffU);
    dst[1] = (uint8_t)((value >> 8U) & 0xffU);
    dst[2] = (uint8_t)((value >> 16U) & 0xffU);
    dst[3] = (uint8_t)((value >> 24U) & 0xffU);
}

static uint32_t frdp_ipc_read_u32_le(const uint8_t *src)
{
    return ((uint32_t)src[0]) | ((uint32_t)src[1] << 8U) | ((uint32_t)src[2] << 16U) |
           ((uint32_t)src[3] << 24U);
}

static void frdp_ipc_write_u64_le(uint8_t *dst, uint64_t value)
{
    for (size_t x = 0; x < 8U; x++)
        dst[x] = (uint8_t)((value >> (x * 8U)) & 0xffU);
}

static uint64_t frdp_ipc_read_u64_le(const uint8_t *src)
{
    uint64_t value = 0;

    for (size_t x = 0; x < 8U; x++)
        value |= ((uint64_t)src[x]) << (x * 8U);
    return value;
}

static void frdp_ipc_clear_secret(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;

    while (len-- > 0U)
        *p++ = 0;
}

int frdp_ipc_send_header(int fd, frdpIpcMessageType type, uint32_t payload_len)
{
    uint8_t wire[8] = {0};

    frdp_ipc_write_u32_le(&wire[0], (uint32_t)type);
    frdp_ipc_write_u32_le(&wire[4], payload_len);
    return frdp_ipc_send(fd, wire, sizeof(wire));
}

int frdp_ipc_recv_header(int fd, frdpIpcHeader *header)
{
    uint8_t wire[8] = {0};

    if (!header) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv(fd, wire, sizeof(wire)) != (int)sizeof(wire))
        return -1;
    header->type = (frdpIpcMessageType)(uint32_t)frdp_ipc_read_u32_le(&wire[0]);
    header->payload_len = frdp_ipc_read_u32_le(&wire[4]);
    return (int)sizeof(wire);
}

int frdp_ipc_send_auth_request_v2(int fd, const frdpAuthRequest *request)
{
    uint8_t wire[FRDP_IPC_AUTH_REQUEST_V2_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!request) {
        errno = EINVAL;
        return -1;
    }
    memcpy(&wire[offset], request->correlation_id, sizeof(request->correlation_id));
    offset += sizeof(request->correlation_id);
    memcpy(&wire[offset], request->user, sizeof(request->user));
    offset += sizeof(request->user);
    memcpy(&wire[offset], request->rhost, sizeof(request->rhost));
    offset += sizeof(request->rhost);
    memcpy(&wire[offset], request->password, sizeof(request->password));

    if (frdp_ipc_send_header(fd, FRDP_IPC_AUTH_REQUEST_V2, sizeof(wire)) != 0)
        goto cleanup;
    rc = frdp_ipc_send(fd, wire, sizeof(wire));

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_recv_auth_request_v2_payload(int fd, frdpAuthRequest *request, uint32_t payload_len)
{
    uint8_t wire[FRDP_IPC_AUTH_REQUEST_V2_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!request || (payload_len != sizeof(wire))) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv(fd, wire, sizeof(wire)) != (int)sizeof(wire))
        goto cleanup;
    memset(request, 0, sizeof(*request));
    memcpy(request->correlation_id, &wire[offset], sizeof(request->correlation_id));
    offset += sizeof(request->correlation_id);
    memcpy(request->user, &wire[offset], sizeof(request->user));
    offset += sizeof(request->user);
    memcpy(request->rhost, &wire[offset], sizeof(request->rhost));
    offset += sizeof(request->rhost);
    memcpy(request->password, &wire[offset], sizeof(request->password));
    rc = 0;

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_send_auth_response(int fd, const frdpAuthResponse *response)
{
    uint8_t wire[FRDP_IPC_AUTH_RESPONSE_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!response || (response->group_count > FRDP_IPC_MAX_AUTH_GROUPS)) {
        errno = EINVAL;
        return -1;
    }
    frdp_ipc_write_u32_le(&wire[offset], response->success ? 1U : 0U);
    offset += 4U;
    memcpy(&wire[offset], response->error, sizeof(response->error));
    offset += sizeof(response->error);
    memcpy(&wire[offset], response->authorization_id, sizeof(response->authorization_id));
    offset += sizeof(response->authorization_id);
    frdp_ipc_write_u64_le(&wire[offset], response->uid);
    offset += 8U;
    frdp_ipc_write_u64_le(&wire[offset], response->gid);
    offset += 8U;
    frdp_ipc_write_u32_le(&wire[offset], response->group_count);
    offset += 4U;
    for (uint32_t x = 0; x < FRDP_IPC_MAX_AUTH_GROUPS; x++) {
        const uint64_t group = (x < response->group_count) ? response->groups[x] : 0U;

        frdp_ipc_write_u64_le(&wire[offset], group);
        offset += 8U;
    }
    frdp_ipc_write_u32_le(&wire[offset], response->has_posix_account ? 1U : 0U);

    if (frdp_ipc_send_header(fd, FRDP_IPC_AUTH_RESPONSE, sizeof(wire)) != 0)
        goto cleanup;
    rc = frdp_ipc_send(fd, wire, sizeof(wire));

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_recv_auth_response(int fd, frdpAuthResponse *response)
{
    frdpIpcHeader header = { .type = FRDP_IPC_INVALID, .payload_len = 0 };
    uint8_t wire[FRDP_IPC_AUTH_RESPONSE_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!response) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv_header(fd, &header) != (int)sizeof(header))
        return -1;
    if ((header.type != FRDP_IPC_AUTH_RESPONSE) || (header.payload_len != sizeof(wire))) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv(fd, wire, sizeof(wire)) != (int)sizeof(wire))
        goto cleanup;
    memset(response, 0, sizeof(*response));
    response->success = frdp_ipc_read_u32_le(&wire[offset]) ? 1 : 0;
    offset += 4U;
    memcpy(response->error, &wire[offset], sizeof(response->error));
    offset += sizeof(response->error);
    memcpy(response->authorization_id, &wire[offset], sizeof(response->authorization_id));
    offset += sizeof(response->authorization_id);
    response->uid = frdp_ipc_read_u64_le(&wire[offset]);
    offset += 8U;
    response->gid = frdp_ipc_read_u64_le(&wire[offset]);
    offset += 8U;
    response->group_count = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    if (response->group_count > FRDP_IPC_MAX_AUTH_GROUPS) {
        errno = EINVAL;
        memset(response, 0, sizeof(*response));
        goto cleanup;
    }
    for (uint32_t x = 0; x < FRDP_IPC_MAX_AUTH_GROUPS; x++) {
        const uint64_t group = frdp_ipc_read_u64_le(&wire[offset]);

        if (x < response->group_count)
            response->groups[x] = group;
        offset += 8U;
    }
    response->has_posix_account = frdp_ipc_read_u32_le(&wire[offset]) ? 1 : 0;
    rc = 0;

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_send_session_request_v3(int fd, const frdpSessionRequestV3 *request)
{
    uint8_t wire[FRDP_IPC_SESSION_REQUEST_V3_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!request || (request->group_count > FRDP_IPC_MAX_AUTH_GROUPS)) {
        errno = EINVAL;
        return -1;
    }
    memcpy(&wire[offset], request->correlation_id, sizeof(request->correlation_id));
    offset += sizeof(request->correlation_id);
    memcpy(&wire[offset], request->session_id, sizeof(request->session_id));
    offset += sizeof(request->session_id);
    memcpy(&wire[offset], request->user, sizeof(request->user));
    offset += sizeof(request->user);
    memcpy(&wire[offset], request->rhost, sizeof(request->rhost));
    offset += sizeof(request->rhost);
    memcpy(&wire[offset], request->authorization_id, sizeof(request->authorization_id));
    offset += sizeof(request->authorization_id);
    frdp_ipc_write_u64_le(&wire[offset], request->uid);
    offset += 8U;
    frdp_ipc_write_u64_le(&wire[offset], request->gid);
    offset += 8U;
    frdp_ipc_write_u32_le(&wire[offset], request->group_count);
    offset += 4U;
    for (uint32_t x = 0; x < FRDP_IPC_MAX_AUTH_GROUPS; x++) {
        const uint64_t group = (x < request->group_count) ? request->groups[x] : 0U;

        frdp_ipc_write_u64_le(&wire[offset], group);
        offset += 8U;
    }
    frdp_ipc_write_u32_le(&wire[offset], request->has_posix_account ? 1U : 0U);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], request->desktop_width);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], request->desktop_height);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], request->color_depth);

    if (frdp_ipc_send_header(fd, FRDP_IPC_SESSION_REQUEST_V3, sizeof(wire)) != 0)
        goto cleanup;
    rc = frdp_ipc_send(fd, wire, sizeof(wire));

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_recv_session_request_v3_payload(int fd, frdpSessionRequestV3 *request,
                                             uint32_t payload_len)
{
    uint8_t wire[FRDP_IPC_SESSION_REQUEST_V3_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!request || (payload_len != sizeof(wire))) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv(fd, wire, sizeof(wire)) != (int)sizeof(wire))
        goto cleanup;
    memset(request, 0, sizeof(*request));
    memcpy(request->correlation_id, &wire[offset], sizeof(request->correlation_id));
    offset += sizeof(request->correlation_id);
    memcpy(request->session_id, &wire[offset], sizeof(request->session_id));
    offset += sizeof(request->session_id);
    memcpy(request->user, &wire[offset], sizeof(request->user));
    offset += sizeof(request->user);
    memcpy(request->rhost, &wire[offset], sizeof(request->rhost));
    offset += sizeof(request->rhost);
    memcpy(request->authorization_id, &wire[offset], sizeof(request->authorization_id));
    offset += sizeof(request->authorization_id);
    request->uid = frdp_ipc_read_u64_le(&wire[offset]);
    offset += 8U;
    request->gid = frdp_ipc_read_u64_le(&wire[offset]);
    offset += 8U;
    request->group_count = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    if (request->group_count > FRDP_IPC_MAX_AUTH_GROUPS) {
        errno = EINVAL;
        memset(request, 0, sizeof(*request));
        goto cleanup;
    }
    for (uint32_t x = 0; x < FRDP_IPC_MAX_AUTH_GROUPS; x++) {
        const uint64_t group = frdp_ipc_read_u64_le(&wire[offset]);

        if (x < request->group_count)
            request->groups[x] = group;
        offset += 8U;
    }
    request->has_posix_account = frdp_ipc_read_u32_le(&wire[offset]) ? 1 : 0;
    offset += 4U;
    request->desktop_width = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    request->desktop_height = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    request->color_depth = frdp_ipc_read_u32_le(&wire[offset]);
    rc = 0;

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

static int frdp_ipc_send_session_control_request(int fd, frdpIpcMessageType type,
                                                 const frdpSessionRequest *request)
{
    uint8_t wire[FRDP_IPC_SESSION_CLOSE_REQUEST_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!request) {
        errno = EINVAL;
        return -1;
    }
    memcpy(&wire[offset], request->correlation_id, sizeof(request->correlation_id));
    offset += sizeof(request->correlation_id);
    memcpy(&wire[offset], request->session_id, sizeof(request->session_id));
    offset += sizeof(request->session_id);
    memcpy(&wire[offset], request->user, sizeof(request->user));
    offset += sizeof(request->user);
    memcpy(&wire[offset], request->rhost, sizeof(request->rhost));
    offset += sizeof(request->rhost);
    frdp_ipc_write_u32_le(&wire[offset], request->desktop_width);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], request->desktop_height);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], request->color_depth);

    if (frdp_ipc_send_header(fd, type, sizeof(wire)) != 0)
        goto cleanup;
    rc = frdp_ipc_send(fd, wire, sizeof(wire));

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_send_session_close_request(int fd, const frdpSessionRequest *request)
{
    return frdp_ipc_send_session_control_request(fd, FRDP_IPC_SESSION_CLOSE_REQUEST, request);
}

int frdp_ipc_send_session_disconnect_request(int fd, const frdpSessionRequest *request)
{
    return frdp_ipc_send_session_control_request(fd, FRDP_IPC_SESSION_DISCONNECT_REQUEST, request);
}

int frdp_ipc_recv_session_close_request_payload(int fd, frdpSessionRequest *request,
                                                uint32_t payload_len)
{
    uint8_t wire[FRDP_IPC_SESSION_CLOSE_REQUEST_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!request || (payload_len != sizeof(wire))) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv(fd, wire, sizeof(wire)) != (int)sizeof(wire))
        goto cleanup;
    memset(request, 0, sizeof(*request));
    memcpy(request->correlation_id, &wire[offset], sizeof(request->correlation_id));
    offset += sizeof(request->correlation_id);
    memcpy(request->session_id, &wire[offset], sizeof(request->session_id));
    offset += sizeof(request->session_id);
    memcpy(request->user, &wire[offset], sizeof(request->user));
    offset += sizeof(request->user);
    memcpy(request->rhost, &wire[offset], sizeof(request->rhost));
    offset += sizeof(request->rhost);
    request->desktop_width = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    request->desktop_height = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    request->color_depth = frdp_ipc_read_u32_le(&wire[offset]);
    rc = 0;

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_send_session_response(int fd, const frdpSessionResponse *response)
{
    uint8_t wire[FRDP_IPC_SESSION_RESPONSE_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!response) {
        errno = EINVAL;
        return -1;
    }
    frdp_ipc_write_u32_le(&wire[offset], response->success ? 1U : 0U);
    offset += 4U;
    memcpy(&wire[offset], response->session_id, sizeof(response->session_id));
    offset += sizeof(response->session_id);
    memcpy(&wire[offset], response->display, sizeof(response->display));
    offset += sizeof(response->display);
    memcpy(&wire[offset], response->agent_socket, sizeof(response->agent_socket));
    offset += sizeof(response->agent_socket);
    memcpy(&wire[offset], response->error, sizeof(response->error));

    if (frdp_ipc_send_header(fd, FRDP_IPC_SESSION_RESPONSE, sizeof(wire)) != 0)
        goto cleanup;
    rc = frdp_ipc_send(fd, wire, sizeof(wire));

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_recv_session_response(int fd, frdpSessionResponse *response)
{
    frdpIpcHeader header = { .type = FRDP_IPC_INVALID, .payload_len = 0 };
    uint8_t wire[FRDP_IPC_SESSION_RESPONSE_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!response) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv_header(fd, &header) != (int)sizeof(header))
        return -1;
    if ((header.type != FRDP_IPC_SESSION_RESPONSE) || (header.payload_len != sizeof(wire))) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv(fd, wire, sizeof(wire)) != (int)sizeof(wire))
        goto cleanup;
    memset(response, 0, sizeof(*response));
    response->success = frdp_ipc_read_u32_le(&wire[offset]) ? 1 : 0;
    offset += 4U;
    memcpy(response->session_id, &wire[offset], sizeof(response->session_id));
    offset += sizeof(response->session_id);
    memcpy(response->display, &wire[offset], sizeof(response->display));
    offset += sizeof(response->display);
    memcpy(response->agent_socket, &wire[offset], sizeof(response->agent_socket));
    offset += sizeof(response->agent_socket);
    memcpy(response->error, &wire[offset], sizeof(response->error));
    rc = 0;

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_send_session_list_response(int fd, const frdpSessionListResponse *response)
{
    uint8_t wire[FRDP_IPC_SESSION_LIST_RESPONSE_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!response || (response->count > FRDP_IPC_MAX_SESSION_LIST_ENTRIES)) {
        errno = EINVAL;
        return -1;
    }
    frdp_ipc_write_u32_le(&wire[offset], response->success ? 1U : 0U);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], response->count);
    offset += 4U;
    for (uint32_t x = 0; x < FRDP_IPC_MAX_SESSION_LIST_ENTRIES; x++) {
        if (x < response->count) {
            memcpy(&wire[offset], response->entries[x].session_id,
                   sizeof(response->entries[x].session_id));
            offset += sizeof(response->entries[x].session_id);
            memcpy(&wire[offset], response->entries[x].user, sizeof(response->entries[x].user));
            offset += sizeof(response->entries[x].user);
            memcpy(&wire[offset], response->entries[x].display,
                   sizeof(response->entries[x].display));
            offset += sizeof(response->entries[x].display);
            memcpy(&wire[offset], response->entries[x].state, sizeof(response->entries[x].state));
            offset += sizeof(response->entries[x].state);
            frdp_ipc_write_u32_le(&wire[offset], (uint32_t)response->entries[x].agent_pid);
            offset += 4U;
        } else {
            offset += FRDP_IPC_SESSION_LIST_ENTRY_WIRE_SIZE;
        }
    }
    memcpy(&wire[offset], response->error, sizeof(response->error));

    if (frdp_ipc_send_header(fd, FRDP_IPC_SESSION_LIST_RESPONSE, sizeof(wire)) != 0)
        goto cleanup;
    rc = frdp_ipc_send(fd, wire, sizeof(wire));

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_recv_session_list_response(int fd, frdpSessionListResponse *response)
{
    frdpIpcHeader header = { .type = FRDP_IPC_INVALID, .payload_len = 0 };
    uint8_t wire[FRDP_IPC_SESSION_LIST_RESPONSE_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!response) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv_header(fd, &header) != (int)sizeof(header))
        return -1;
    if ((header.type != FRDP_IPC_SESSION_LIST_RESPONSE) || (header.payload_len != sizeof(wire))) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv(fd, wire, sizeof(wire)) != (int)sizeof(wire))
        goto cleanup;
    memset(response, 0, sizeof(*response));
    response->success = frdp_ipc_read_u32_le(&wire[offset]) ? 1 : 0;
    offset += 4U;
    response->count = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    if (response->count > FRDP_IPC_MAX_SESSION_LIST_ENTRIES) {
        errno = EINVAL;
        memset(response, 0, sizeof(*response));
        goto cleanup;
    }
    for (uint32_t x = 0; x < FRDP_IPC_MAX_SESSION_LIST_ENTRIES; x++) {
        if (x < response->count) {
            memcpy(response->entries[x].session_id, &wire[offset],
                   sizeof(response->entries[x].session_id));
            offset += sizeof(response->entries[x].session_id);
            memcpy(response->entries[x].user, &wire[offset], sizeof(response->entries[x].user));
            offset += sizeof(response->entries[x].user);
            memcpy(response->entries[x].display, &wire[offset],
                   sizeof(response->entries[x].display));
            offset += sizeof(response->entries[x].display);
            memcpy(response->entries[x].state, &wire[offset], sizeof(response->entries[x].state));
            offset += sizeof(response->entries[x].state);
            response->entries[x].agent_pid = (int32_t)frdp_ipc_read_u32_le(&wire[offset]);
            offset += 4U;
        } else {
            offset += FRDP_IPC_SESSION_LIST_ENTRY_WIRE_SIZE;
        }
    }
    memcpy(response->error, &wire[offset], sizeof(response->error));
    rc = 0;

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

static int frdp_ipc_send_control_response(int fd, frdpIpcMessageType type,
                                          const frdpControlResponse *response)
{
    uint8_t wire[FRDP_IPC_SESSION_RELOAD_RESPONSE_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!response) {
        errno = EINVAL;
        return -1;
    }
    frdp_ipc_write_u32_le(&wire[offset], response->success ? 1U : 0U);
    offset += 4U;
    memcpy(&wire[offset], response->message, sizeof(response->message));
    offset += sizeof(response->message);
    memcpy(&wire[offset], response->error, sizeof(response->error));

    if (frdp_ipc_send_header(fd, type, sizeof(wire)) != 0)
        goto cleanup;
    rc = frdp_ipc_send(fd, wire, sizeof(wire));

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

static int frdp_ipc_recv_control_response(int fd, frdpIpcMessageType expected_type,
                                          frdpControlResponse *response)
{
    frdpIpcHeader header = { .type = FRDP_IPC_INVALID, .payload_len = 0 };
    uint8_t wire[FRDP_IPC_SESSION_RELOAD_RESPONSE_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!response) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv_header(fd, &header) != (int)sizeof(header))
        return -1;
    if ((header.type != expected_type) || (header.payload_len != sizeof(wire))) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv(fd, wire, sizeof(wire)) != (int)sizeof(wire))
        goto cleanup;
    memset(response, 0, sizeof(*response));
    response->success = frdp_ipc_read_u32_le(&wire[offset]) ? 1 : 0;
    offset += 4U;
    memcpy(response->message, &wire[offset], sizeof(response->message));
    offset += sizeof(response->message);
    memcpy(response->error, &wire[offset], sizeof(response->error));
    rc = 0;

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_send_session_reload_response(int fd, const frdpControlResponse *response)
{
    return frdp_ipc_send_control_response(fd, FRDP_IPC_SESSION_RELOAD_RESPONSE, response);
}

int frdp_ipc_recv_session_reload_response(int fd, frdpControlResponse *response)
{
    return frdp_ipc_recv_control_response(fd, FRDP_IPC_SESSION_RELOAD_RESPONSE, response);
}

int frdp_ipc_send_helper_health_request(int fd)
{
    return frdp_ipc_send_header(fd, FRDP_IPC_HELPER_HEALTH_REQUEST, 0);
}

int frdp_ipc_send_helper_health_response(int fd, const frdpControlResponse *response)
{
    return frdp_ipc_send_control_response(fd, FRDP_IPC_HELPER_HEALTH_RESPONSE, response);
}

int frdp_ipc_recv_helper_health_response(int fd, frdpControlResponse *response)
{
    return frdp_ipc_recv_control_response(fd, FRDP_IPC_HELPER_HEALTH_RESPONSE, response);
}

int frdp_ipc_send_agent_input_event(int fd, const frdpAgentInputEvent *event)
{
    uint8_t wire[FRDP_IPC_AGENT_INPUT_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!event) {
        errno = EINVAL;
        return -1;
    }
    memcpy(&wire[offset], event->correlation_id, sizeof(event->correlation_id));
    offset += sizeof(event->correlation_id);
    memcpy(&wire[offset], event->session_id, sizeof(event->session_id));
    offset += sizeof(event->session_id);
    frdp_ipc_write_u32_le(&wire[offset], event->event_type);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], event->flags);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], (uint32_t)event->param1);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], (uint32_t)event->param2);

    if (frdp_ipc_send_header(fd, FRDP_IPC_AGENT_INPUT, sizeof(wire)) != 0)
        goto cleanup;
    rc = frdp_ipc_send(fd, wire, sizeof(wire));

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_recv_agent_input_event_payload(int fd, frdpAgentInputEvent *event,
                                            uint32_t payload_len)
{
    uint8_t wire[FRDP_IPC_AGENT_INPUT_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!event) {
        errno = EINVAL;
        return -1;
    }
    if (payload_len != sizeof(wire)) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv(fd, wire, sizeof(wire)) != (int)sizeof(wire))
        goto cleanup;
    memset(event, 0, sizeof(*event));
    memcpy(event->correlation_id, &wire[offset], sizeof(event->correlation_id));
    offset += sizeof(event->correlation_id);
    memcpy(event->session_id, &wire[offset], sizeof(event->session_id));
    offset += sizeof(event->session_id);
    event->event_type = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    event->flags = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    event->param1 = (int32_t)frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    event->param2 = (int32_t)frdp_ipc_read_u32_le(&wire[offset]);
    rc = 0;

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_send_agent_frame_request(int fd, const frdpAgentFrameRequest *request)
{
    uint8_t wire[FRDP_IPC_AGENT_FRAME_REQUEST_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!request) {
        errno = EINVAL;
        return -1;
    }
    memcpy(&wire[offset], request->correlation_id, sizeof(request->correlation_id));
    offset += sizeof(request->correlation_id);
    memcpy(&wire[offset], request->session_id, sizeof(request->session_id));
    offset += sizeof(request->session_id);
    frdp_ipc_write_u32_le(&wire[offset], request->x);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], request->y);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], request->width);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], request->height);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], request->flags);

    if (frdp_ipc_send_header(fd, FRDP_IPC_AGENT_FRAME_REQUEST, sizeof(wire)) != 0)
        goto cleanup;
    rc = frdp_ipc_send(fd, wire, sizeof(wire));

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_recv_agent_frame_request_payload(int fd, frdpAgentFrameRequest *request,
                                              uint32_t payload_len)
{
    uint8_t wire[FRDP_IPC_AGENT_FRAME_REQUEST_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!request) {
        errno = EINVAL;
        return -1;
    }
    if (payload_len != sizeof(wire)) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv(fd, wire, sizeof(wire)) != (int)sizeof(wire))
        goto cleanup;
    memset(request, 0, sizeof(*request));
    memcpy(request->correlation_id, &wire[offset], sizeof(request->correlation_id));
    offset += sizeof(request->correlation_id);
    memcpy(request->session_id, &wire[offset], sizeof(request->session_id));
    offset += sizeof(request->session_id);
    request->x = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    request->y = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    request->width = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    request->height = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    request->flags = frdp_ipc_read_u32_le(&wire[offset]);
    rc = 0;

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_send_agent_frame_response(int fd, const frdpAgentFrameResponse *response)
{
    uint8_t wire[FRDP_IPC_AGENT_FRAME_RESPONSE_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!response) {
        errno = EINVAL;
        return -1;
    }
    memcpy(&wire[offset], response->correlation_id, sizeof(response->correlation_id));
    offset += sizeof(response->correlation_id);
    memcpy(&wire[offset], response->session_id, sizeof(response->session_id));
    offset += sizeof(response->session_id);
    frdp_ipc_write_u32_le(&wire[offset], response->success ? 1U : 0U);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], response->x);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], response->y);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], response->width);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], response->height);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], response->stride);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], response->bpp);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], response->flags);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], response->data_length);
    offset += 4U;
    memcpy(&wire[offset], response->error, sizeof(response->error));

    if (frdp_ipc_send_header(fd, FRDP_IPC_AGENT_FRAME_RESPONSE, sizeof(wire)) != 0)
        goto cleanup;
    rc = frdp_ipc_send(fd, wire, sizeof(wire));

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_recv_agent_frame_response(int fd, frdpAgentFrameResponse *response)
{
    frdpIpcHeader header = { .type = FRDP_IPC_INVALID, .payload_len = 0 };
    uint8_t wire[FRDP_IPC_AGENT_FRAME_RESPONSE_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!response) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv_header(fd, &header) != (int)sizeof(header))
        return -1;
    if ((header.type != FRDP_IPC_AGENT_FRAME_RESPONSE) || (header.payload_len != sizeof(wire))) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv(fd, wire, sizeof(wire)) != (int)sizeof(wire))
        goto cleanup;
    memset(response, 0, sizeof(*response));
    memcpy(response->correlation_id, &wire[offset], sizeof(response->correlation_id));
    offset += sizeof(response->correlation_id);
    memcpy(response->session_id, &wire[offset], sizeof(response->session_id));
    offset += sizeof(response->session_id);
    response->success = frdp_ipc_read_u32_le(&wire[offset]) ? 1 : 0;
    offset += 4U;
    response->x = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    response->y = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    response->width = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    response->height = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    response->stride = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    response->bpp = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    response->flags = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    response->data_length = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    memcpy(response->error, &wire[offset], sizeof(response->error));
    rc = 0;

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_send_agent_resize_request(int fd, const frdpAgentResizeRequest *request)
{
    uint8_t wire[FRDP_IPC_AGENT_RESIZE_REQUEST_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!request) {
        errno = EINVAL;
        return -1;
    }
    memcpy(&wire[offset], request->correlation_id, sizeof(request->correlation_id));
    offset += sizeof(request->correlation_id);
    memcpy(&wire[offset], request->session_id, sizeof(request->session_id));
    offset += sizeof(request->session_id);
    frdp_ipc_write_u32_le(&wire[offset], request->width);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], request->height);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], request->color_depth);

    if (frdp_ipc_send_header(fd, FRDP_IPC_AGENT_RESIZE_REQUEST, sizeof(wire)) != 0)
        goto cleanup;
    rc = frdp_ipc_send(fd, wire, sizeof(wire));

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_recv_agent_resize_request_payload(int fd, frdpAgentResizeRequest *request,
                                               uint32_t payload_len)
{
    uint8_t wire[FRDP_IPC_AGENT_RESIZE_REQUEST_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!request) {
        errno = EINVAL;
        return -1;
    }
    if (payload_len != sizeof(wire)) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv(fd, wire, sizeof(wire)) != (int)sizeof(wire))
        goto cleanup;
    memset(request, 0, sizeof(*request));
    memcpy(request->correlation_id, &wire[offset], sizeof(request->correlation_id));
    offset += sizeof(request->correlation_id);
    memcpy(request->session_id, &wire[offset], sizeof(request->session_id));
    offset += sizeof(request->session_id);
    request->width = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    request->height = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    request->color_depth = frdp_ipc_read_u32_le(&wire[offset]);
    rc = 0;

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_send_agent_resize_response(int fd, const frdpAgentResizeResponse *response)
{
    uint8_t wire[FRDP_IPC_AGENT_RESIZE_RESPONSE_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!response) {
        errno = EINVAL;
        return -1;
    }
    memcpy(&wire[offset], response->correlation_id, sizeof(response->correlation_id));
    offset += sizeof(response->correlation_id);
    memcpy(&wire[offset], response->session_id, sizeof(response->session_id));
    offset += sizeof(response->session_id);
    frdp_ipc_write_u32_le(&wire[offset], response->success ? 1U : 0U);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], response->width);
    offset += 4U;
    frdp_ipc_write_u32_le(&wire[offset], response->height);
    offset += 4U;
    memcpy(&wire[offset], response->error, sizeof(response->error));

    if (frdp_ipc_send_header(fd, FRDP_IPC_AGENT_RESIZE_RESPONSE, sizeof(wire)) != 0)
        goto cleanup;
    rc = frdp_ipc_send(fd, wire, sizeof(wire));

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

int frdp_ipc_recv_agent_resize_response(int fd, frdpAgentResizeResponse *response)
{
    frdpIpcHeader header = { .type = FRDP_IPC_INVALID, .payload_len = 0 };
    uint8_t wire[FRDP_IPC_AGENT_RESIZE_RESPONSE_WIRE_SIZE] = {0};
    size_t offset = 0;
    int rc = -1;

    if (!response) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv_header(fd, &header) != (int)sizeof(header))
        return -1;
    if ((header.type != FRDP_IPC_AGENT_RESIZE_RESPONSE) || (header.payload_len != sizeof(wire))) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv(fd, wire, sizeof(wire)) != (int)sizeof(wire))
        goto cleanup;
    memset(response, 0, sizeof(*response));
    memcpy(response->correlation_id, &wire[offset], sizeof(response->correlation_id));
    offset += sizeof(response->correlation_id);
    memcpy(response->session_id, &wire[offset], sizeof(response->session_id));
    offset += sizeof(response->session_id);
    response->success = frdp_ipc_read_u32_le(&wire[offset]) ? 1 : 0;
    offset += 4U;
    response->width = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    response->height = frdp_ipc_read_u32_le(&wire[offset]);
    offset += 4U;
    memcpy(response->error, &wire[offset], sizeof(response->error));
    rc = 0;

cleanup:
    frdp_ipc_clear_secret(wire, sizeof(wire));
    return rc;
}

static int frdp_ipc_send_agent_heartbeat(int fd, frdpIpcMessageType type,
                                         const frdpAgentHeartbeat *heartbeat)
{
    uint8_t wire[FRDP_IPC_AGENT_HEARTBEAT_WIRE_SIZE] = {0};

    if (!heartbeat) {
        errno = EINVAL;
        return -1;
    }
    memcpy(wire, heartbeat->session_id, sizeof(heartbeat->session_id));
    frdp_ipc_write_u64_le(&wire[sizeof(heartbeat->session_id)], heartbeat->nonce);
    if (frdp_ipc_send_header(fd, type, sizeof(wire)) != 0)
        return -1;
    return frdp_ipc_send(fd, wire, sizeof(wire));
}

static int frdp_ipc_recv_agent_heartbeat_payload(int fd, frdpAgentHeartbeat *heartbeat,
                                                 uint32_t payload_len)
{
    uint8_t wire[FRDP_IPC_AGENT_HEARTBEAT_WIRE_SIZE] = {0};

    if (!heartbeat || (payload_len != sizeof(wire))) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv(fd, wire, sizeof(wire)) != (int)sizeof(wire))
        return -1;
    memset(heartbeat, 0, sizeof(*heartbeat));
    memcpy(heartbeat->session_id, wire, sizeof(heartbeat->session_id));
    heartbeat->nonce = frdp_ipc_read_u64_le(&wire[sizeof(heartbeat->session_id)]);
    return 0;
}

int frdp_ipc_send_agent_heartbeat_request(int fd, const frdpAgentHeartbeat *heartbeat)
{
    return frdp_ipc_send_agent_heartbeat(fd, FRDP_IPC_AGENT_HEARTBEAT_REQUEST, heartbeat);
}

int frdp_ipc_recv_agent_heartbeat_request_payload(int fd, frdpAgentHeartbeat *heartbeat,
                                                  uint32_t payload_len)
{
    return frdp_ipc_recv_agent_heartbeat_payload(fd, heartbeat, payload_len);
}

int frdp_ipc_send_agent_heartbeat_response(int fd, const frdpAgentHeartbeat *heartbeat)
{
    return frdp_ipc_send_agent_heartbeat(fd, FRDP_IPC_AGENT_HEARTBEAT_RESPONSE, heartbeat);
}

int frdp_ipc_recv_agent_heartbeat_response(int fd, frdpAgentHeartbeat *heartbeat)
{
    frdpIpcHeader header = { .type = FRDP_IPC_INVALID, .payload_len = 0 };

    if (!heartbeat) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_recv_header(fd, &header) != (int)sizeof(header))
        return -1;
    if ((header.type != FRDP_IPC_AGENT_HEARTBEAT_RESPONSE) ||
        (header.payload_len != FRDP_IPC_AGENT_HEARTBEAT_WIRE_SIZE)) {
        errno = EINVAL;
        return -1;
    }
    return frdp_ipc_recv_agent_heartbeat_payload(fd, heartbeat, header.payload_len);
}

static int frdp_ipc_wait_deadline(int fd, short events, uint64_t deadline_ms)
{
    struct pollfd pfd = { .fd = fd, .events = events };

    for (;;) {
        uint64_t now_ms = 0;
        int poll_status = 0;

        if (frdp_ipc_monotonic_ms(&now_ms) != 0)
            return -1;
        if (now_ms >= deadline_ms) {
            errno = ETIMEDOUT;
            return -1;
        }
        poll_status = poll(&pfd, 1, (int)(deadline_ms - now_ms));
        if (poll_status < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (poll_status == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if ((pfd.revents & events) != 0)
            return 0;
        errno = ECONNRESET;
        return -1;
    }
}

static int frdp_ipc_stream_transfer_deadline(int fd, uint8_t *wire, size_t wire_size, int sending,
                                              uint64_t deadline_ms)
{
    size_t offset = 0;

    while (offset < wire_size) {
        ssize_t count = 0;

        if (frdp_ipc_wait_deadline(fd, sending ? POLLOUT : POLLIN, deadline_ms) != 0)
            return -1;
        if (sending) {
#ifdef MSG_NOSIGNAL
            count = send(fd, &wire[offset], wire_size - offset, MSG_NOSIGNAL);
#else
            count = send(fd, &wire[offset], wire_size - offset, 0);
#endif
        } else
            count = recv(fd, &wire[offset], wire_size - offset, 0);
        if (count < 0) {
            if ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))
                continue;
            return -1;
        }
        if (count == 0) {
            errno = ECONNRESET;
            return -1;
        }
        offset += (size_t)count;
    }
    return 0;
}

int frdp_ipc_exchange_helper_health(int fd, frdpControlResponse *response, uint32_t timeout_ms)
{
    uint8_t request_wire[8] = {0};
    uint8_t response_wire[8U + FRDP_IPC_SESSION_RELOAD_RESPONSE_WIRE_SIZE] = {0};
    uint64_t deadline_ms = 0;
    size_t offset = 8U;
    int status_flags = -1;
    int rc = -1;
    int saved = 0;

    if (!response || (timeout_ms == 0) || (timeout_ms > 600000U)) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_monotonic_ms(&deadline_ms) != 0)
        return -1;
    deadline_ms += timeout_ms;
    status_flags = fcntl(fd, F_GETFL);
    if ((status_flags < 0) || (fcntl(fd, F_SETFL, status_flags | O_NONBLOCK) != 0))
        return -1;
    frdp_ipc_write_u32_le(&request_wire[0], FRDP_IPC_HELPER_HEALTH_REQUEST);
    frdp_ipc_write_u32_le(&request_wire[4], 0);
    if ((frdp_ipc_stream_transfer_deadline(fd, request_wire, sizeof(request_wire), 1,
                                           deadline_ms) != 0) ||
        (frdp_ipc_stream_transfer_deadline(fd, response_wire, sizeof(response_wire), 0,
                                           deadline_ms) != 0))
        goto cleanup;
    if ((frdp_ipc_read_u32_le(&response_wire[0]) != FRDP_IPC_HELPER_HEALTH_RESPONSE) ||
        (frdp_ipc_read_u32_le(&response_wire[4]) !=
         FRDP_IPC_SESSION_RELOAD_RESPONSE_WIRE_SIZE)) {
        errno = EINVAL;
        goto cleanup;
    }
    memset(response, 0, sizeof(*response));
    response->success = frdp_ipc_read_u32_le(&response_wire[offset]) ? 1 : 0;
    offset += 4U;
    memcpy(response->message, &response_wire[offset], sizeof(response->message));
    offset += sizeof(response->message);
    memcpy(response->error, &response_wire[offset], sizeof(response->error));
    rc = 0;

cleanup:
    saved = errno;
    if (fcntl(fd, F_SETFL, status_flags) != 0) {
        if (rc == 0)
            saved = errno;
        rc = -1;
    }
    errno = saved;
    return rc;
}

static void frdp_ipc_encode_agent_heartbeat_packet(uint8_t *wire, frdpIpcMessageType type,
                                                   const frdpAgentHeartbeat *heartbeat)
{
    memset(wire, 0, 8U + FRDP_IPC_AGENT_HEARTBEAT_WIRE_SIZE);
    frdp_ipc_write_u32_le(&wire[0], (uint32_t)type);
    frdp_ipc_write_u32_le(&wire[4], FRDP_IPC_AGENT_HEARTBEAT_WIRE_SIZE);
    memcpy(&wire[8], heartbeat->session_id, sizeof(heartbeat->session_id));
    frdp_ipc_write_u64_le(&wire[8U + sizeof(heartbeat->session_id)], heartbeat->nonce);
}

static int frdp_ipc_decode_agent_heartbeat_packet(const uint8_t *wire, size_t wire_size,
                                                   frdpIpcMessageType expected_type,
                                                   frdpAgentHeartbeat *heartbeat)
{
    if (!wire || !heartbeat || (wire_size != (8U + FRDP_IPC_AGENT_HEARTBEAT_WIRE_SIZE)) ||
        (frdp_ipc_read_u32_le(&wire[0]) != (uint32_t)expected_type) ||
        (frdp_ipc_read_u32_le(&wire[4]) != FRDP_IPC_AGENT_HEARTBEAT_WIRE_SIZE)) {
        errno = EINVAL;
        return -1;
    }
    memset(heartbeat, 0, sizeof(*heartbeat));
    memcpy(heartbeat->session_id, &wire[8], sizeof(heartbeat->session_id));
    heartbeat->nonce = frdp_ipc_read_u64_le(&wire[8U + sizeof(heartbeat->session_id)]);
    return 0;
}

static int frdp_ipc_send_agent_heartbeat_packet(int fd, frdpIpcMessageType type,
                                                 const frdpAgentHeartbeat *heartbeat)
{
    uint8_t wire[8U + FRDP_IPC_AGENT_HEARTBEAT_WIRE_SIZE] = {0};
    ssize_t count = 0;

    if (!heartbeat) {
        errno = EINVAL;
        return -1;
    }
    frdp_ipc_encode_agent_heartbeat_packet(wire, type, heartbeat);
#ifdef MSG_NOSIGNAL
    count = send(fd, wire, sizeof(wire), MSG_NOSIGNAL);
#else
    count = send(fd, wire, sizeof(wire), 0);
#endif
    if (count != (ssize_t)sizeof(wire)) {
        if (count >= 0)
            errno = EIO;
        return -1;
    }
    return 0;
}

static int frdp_ipc_recv_agent_heartbeat_packet(int fd, frdpIpcMessageType expected_type,
                                                 frdpAgentHeartbeat *heartbeat)
{
    uint8_t wire[8U + FRDP_IPC_AGENT_HEARTBEAT_WIRE_SIZE + 1U] = {0};
    const ssize_t count = recv(fd, wire, sizeof(wire), 0);

    if (count < 0)
        return -1;
    if (count != (ssize_t)(8U + FRDP_IPC_AGENT_HEARTBEAT_WIRE_SIZE)) {
        errno = EINVAL;
        return -1;
    }
    return frdp_ipc_decode_agent_heartbeat_packet(wire, (size_t)count, expected_type, heartbeat);
}

int frdp_ipc_recv_agent_heartbeat_request_packet(int fd, frdpAgentHeartbeat *heartbeat)
{
    return frdp_ipc_recv_agent_heartbeat_packet(fd, FRDP_IPC_AGENT_HEARTBEAT_REQUEST, heartbeat);
}

int frdp_ipc_send_agent_heartbeat_response_packet(int fd, const frdpAgentHeartbeat *heartbeat)
{
    return frdp_ipc_send_agent_heartbeat_packet(fd, FRDP_IPC_AGENT_HEARTBEAT_RESPONSE, heartbeat);
}

int frdp_ipc_exchange_agent_heartbeat(int fd, const frdpAgentHeartbeat *request,
                                      frdpAgentHeartbeat *response, uint32_t timeout_ms)
{
    uint64_t deadline_ms = 0;
    int status_flags = -1;
    int rc = -1;
    int saved = 0;

    if (!request || !response || (timeout_ms == 0) || (timeout_ms > 600000U)) {
        errno = EINVAL;
        return -1;
    }
    if (frdp_ipc_monotonic_ms(&deadline_ms) != 0)
        return -1;
    deadline_ms += timeout_ms;
    status_flags = fcntl(fd, F_GETFL);
    if ((status_flags < 0) || (fcntl(fd, F_SETFL, status_flags | O_NONBLOCK) != 0))
        return -1;

    if ((frdp_ipc_wait_deadline(fd, POLLOUT, deadline_ms) != 0) ||
        (frdp_ipc_send_agent_heartbeat_packet(fd, FRDP_IPC_AGENT_HEARTBEAT_REQUEST, request) != 0))
        goto cleanup;
    for (;;) {
        if (frdp_ipc_wait_deadline(fd, POLLIN, deadline_ms) != 0)
            goto cleanup;
        if (frdp_ipc_recv_agent_heartbeat_packet(fd, FRDP_IPC_AGENT_HEARTBEAT_RESPONSE,
                                                  response) != 0)
            goto cleanup;
        if ((response->nonce == request->nonce) &&
            (memcmp(response->session_id, request->session_id, sizeof(response->session_id)) == 0))
            break;
    }
    rc = 0;

cleanup:
    saved = errno;
    if (fcntl(fd, F_SETFL, status_flags) != 0) {
        if (rc == 0)
            saved = errno;
        rc = -1;
    }
    errno = saved;
    return rc;
}

/* Close a socket */
int frdp_ipc_close(int fd)
{
    return close(fd);
}
