#include "frdp-ipc.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

/* Connect to a UNIX domain socket and return a file descriptor */
int frdp_ipc_connect(const char *socket_path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
        return -1;
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
    while (total < len) {
        ssize_t n = send(fd, p + total, len - total, 0);
        if (n <= 0)
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
        if (n <= 0)
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
