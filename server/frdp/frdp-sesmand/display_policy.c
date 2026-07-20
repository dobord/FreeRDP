#include "display_policy.h"
#include "process_identity.h"

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
#ifdef __linux__
    unsigned long long start_ticks = 0;
#endif

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
#ifdef __linux__
    if (frdp_sesmand_process_identity_read(getpid(), &start_ticks, NULL) !=
            FRDP_SESMAND_PROCESS_IDENTITY_OK ||
        dprintf(fd, "v2 %ld %llu\n", (long)getpid(), start_ticks) < 0 || fsync(fd) != 0) {
#else
    if (dprintf(fd, "%ld\n", (long)getpid()) < 0 || fsync(fd) != 0) {
#endif
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

int frdp_sesmand_display_reservation_open(int display, const char *dir, uint64_t expected_dev,
                                          uint64_t expected_ino, int *reservation_fd,
                                          char *reservation_path,
                                          size_t reservation_path_size)
{
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)] = { 0 };
    struct stat opened = { 0 };
    struct stat current = { 0 };
    int flags = O_RDONLY;
    int fd = -1;

    if (!reservation_fd || !reservation_path || (reservation_path_size == 0) ||
        (expected_dev == 0) || (expected_ino == 0) ||
        (frdp_sesmand_display_reservation_path(path, sizeof(path), dir, display) != 0))
        return -1;
    *reservation_fd = -1;
    reservation_path[0] = '\0';
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    fd = open(path, flags);
    if (fd < 0)
        return -1;
    if ((fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) || (fstat(fd, &opened) != 0) ||
        !S_ISREG(opened.st_mode) || (opened.st_uid != geteuid()) ||
        ((opened.st_mode & 0777) != 0600) || (opened.st_nlink != 1) ||
        ((uint64_t)opened.st_dev != expected_dev) || ((uint64_t)opened.st_ino != expected_ino) ||
        (lstat(path, &current) != 0) || (current.st_dev != opened.st_dev) ||
        (current.st_ino != opened.st_ino) ||
        (snprintf(reservation_path, reservation_path_size, "%s", path) >=
         (int)reservation_path_size))
    {
        close(fd);
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
    char extra = 0;
    long pid = 0;
    int fd = -1;
    int stale = 0;
    int version = 1;
    unsigned long long recorded_start_ticks = 0;

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
    if (read(fd, &extra, sizeof(extra)) != 0) {
        close(fd);
        return -1;
    }
    pid_text[bytes] = '\0';
    errno = 0;
    if (strncmp(pid_text, "v2 ", 3) == 0) {
        version = 2;
        pid = strtol(pid_text + 3, &end, 10);
        if (end) {
            char *start_end = NULL;

            while (*end == ' ' || *end == '\t')
                end++;
            if (*end < '0' || *end > '9') {
                close(fd);
                return -1;
            }
            recorded_start_ticks = strtoull(end, &start_end, 10);
            end = start_end;
        }
    } else {
        pid = strtol(pid_text, &end, 10);
    }
    while (end && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t'))
        end++;
    if ((errno != 0) || !end || (*end != '\0') || (pid <= 0) ||
        (version == 1 && pid <= 1) || ((long)(pid_t)pid != pid) ||
        (version == 2 && recorded_start_ticks == 0)) {
        close(fd);
        return -1;
    }
    if (version == 2) {
        unsigned long long current_start_ticks = 0;
        const frdpSesmandProcessIdentityResult process_status =
            frdp_sesmand_process_identity_read((pid_t)pid, &current_start_ticks, NULL);

        if (process_status == FRDP_SESMAND_PROCESS_IDENTITY_ERROR) {
            close(fd);
            return 0;
        }
        stale = (process_status == FRDP_SESMAND_PROCESS_IDENTITY_MISSING) ||
                (current_start_ticks != recorded_start_ticks);
    } else {
        if (kill((pid_t)pid, 0) == 0 || errno == EPERM) {
            close(fd);
            return 0;
        }
        if (errno != ESRCH) {
            close(fd);
            return -1;
        }
        stale = 1;
    }
    if (!stale) {
        close(fd);
        return 0;
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
