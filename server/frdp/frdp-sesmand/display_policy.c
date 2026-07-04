#include "display_policy.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

int frdp_sesmand_display_number_is_valid(int display)
{
    return (display >= FRDP_SESMAND_DISPLAY_MIN) && (display <= FRDP_SESMAND_DISPLAY_MAX);
}

int frdp_sesmand_display_reservation_path(char *dst, size_t dst_size, const char *dir,
                                          int display)
{
    int rc = 0;

    if (!dst || dst_size == 0 || !dir || dir[0] != '/' ||
        !frdp_sesmand_display_number_is_valid(display))
        return -1;
    rc = snprintf(dst, dst_size, "%s/frdp-display-%d.lock", dir, display);
    return (rc >= 0 && (size_t)rc < dst_size) ? 0 : -1;
}

int frdp_sesmand_display_reservation_create(int display, const char *dir, int *reservation_fd,
                                            char *reservation_path,
                                            size_t reservation_path_size)
{
    char candidate_reservation[sizeof(((struct sockaddr_un *)0)->sun_path)] = { 0 };
    int open_flags = O_WRONLY | O_CREAT | O_EXCL;
    int fd = -1;

    if (!reservation_fd || !reservation_path || reservation_path_size == 0)
        return -1;
    *reservation_fd = -1;
    reservation_path[0] = '\0';
    if (frdp_sesmand_display_reservation_path(candidate_reservation,
                                              sizeof(candidate_reservation), dir,
                                              display) != 0)
        return -1;

#ifdef O_CLOEXEC
    open_flags |= O_CLOEXEC;
#endif
    fd = open(candidate_reservation, open_flags, 0600);
    if (fd < 0)
        return -1;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        const int saved_errno = errno;

        close(fd);
        unlink(candidate_reservation);
        errno = saved_errno;
        return -1;
    }
    if (dprintf(fd, "%ld\n", (long)getpid()) < 0) {
        const int saved_errno = errno;

        close(fd);
        unlink(candidate_reservation);
        errno = saved_errno;
        return -1;
    }
    if (snprintf(reservation_path, reservation_path_size, "%s", candidate_reservation) >=
        (int)reservation_path_size) {
        close(fd);
        unlink(candidate_reservation);
        errno = ENAMETOOLONG;
        return -1;
    }
    *reservation_fd = fd;
    return 0;
}

int frdp_sesmand_display_reservation_reconcile_stale(const char *dir, int display)
{
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)] = { 0 };
    char pid_text[64] = { 0 };
    char *end = NULL;
    struct stat fd_stat;
    struct stat path_stat;
    ssize_t bytes = 0;
    long pid = 0;
    int fd = -1;

    if (frdp_sesmand_display_reservation_path(path, sizeof(path), dir, display) != 0)
        return -1;

#ifdef O_NOFOLLOW
    fd = open(path, O_RDONLY | O_NOFOLLOW);
#else
    fd = open(path, O_RDONLY);
#endif
    if (fd < 0)
        return (errno == ENOENT) ? 0 : -1;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        close(fd);
        return -1;
    }
    if (fstat(fd, &fd_stat) != 0 || !S_ISREG(fd_stat.st_mode)) {
        close(fd);
        return -1;
    }
    bytes = read(fd, pid_text, sizeof(pid_text) - 1);
    if (bytes <= 0) {
        close(fd);
        return -1;
    }
    pid_text[bytes] = '\0';
    errno = 0;
    pid = strtol(pid_text, &end, 10);
    while (end && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t'))
        end++;
    if ((errno != 0) || !end || (*end != '\0') || (pid <= 1) ||
        ((long)(pid_t)pid != pid)) {
        close(fd);
        return -1;
    }
    if (kill((pid_t)pid, 0) == 0 || errno == EPERM) {
        close(fd);
        return 0;
    }
    if (errno != ESRCH) {
        close(fd);
        return -1;
    }
    if ((lstat(path, &path_stat) != 0) || (fd_stat.st_dev != path_stat.st_dev) ||
        (fd_stat.st_ino != path_stat.st_ino)) {
        close(fd);
        return 0;
    }
    close(fd);
    return (unlink(path) == 0) ? 1 : -1;
}

void frdp_sesmand_display_reservation_release(int *reservation_fd, const char *reservation_path)
{
    if (!reservation_fd || *reservation_fd < 0)
        return;
    if (reservation_path && reservation_path[0] != '\0') {
        struct stat fd_stat;
        struct stat path_stat;

        if ((fstat(*reservation_fd, &fd_stat) == 0) &&
            (lstat(reservation_path, &path_stat) == 0) &&
            (fd_stat.st_dev == path_stat.st_dev) && (fd_stat.st_ino == path_stat.st_ino))
            unlink(reservation_path);
    }
    close(*reservation_fd);
    *reservation_fd = -1;
}
