#include "frdp-ipc.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

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

static int frdp_ipc_set_timeouts(int fd)
{
    struct timeval timeout;

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
        return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0)
        return -1;
    return 0;
}

/* Connect to a UNIX domain socket and return a file descriptor */
int frdp_ipc_connect(const char *socket_path)
{
    if (frdp_ipc_validate_socket_path(socket_path) != 0) {
        errno = EACCES;
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
        return -1;
    if (frdp_ipc_set_timeouts(fd) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
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
        total += n;
    }
    return 0;
}

/* Receive exactly len bytes into buf. Returns number of bytes read or -1 */
int frdp_ipc_recv(int fd, void *buf, size_t len)
{
    char *p = (char *)buf;
    size_t total = 0;
    while (total < len) {
        ssize_t n = recv(fd, p + total, len - total, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        total += n;
    }
    return (int)total;
}

/* Close a socket */
int frdp_ipc_close(int fd)
{
    return close(fd);
}
