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

static int process_start_ticks(pid_t pid, unsigned long long *start_ticks)
{
#ifdef __linux__
    char path[64] = {0};
    char stat_text[4096] = {0};
    char *cursor = NULL;
    char *comm_end = NULL;
    ssize_t bytes = 0;
    int fd = -1;

    if (pid <= 0 || !start_ticks ||
        snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid) >= (int)sizeof(path))
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return (errno == ENOENT || errno == ESRCH) ? 1 : -1;
    bytes = read(fd, stat_text, sizeof(stat_text) - 1U);
    close(fd);
    if (bytes <= 0)
        return -1;
    stat_text[bytes] = '\0';
    comm_end = strrchr(stat_text, ')');
    if (!comm_end || comm_end[1] != ' ')
        return -1;
    cursor = comm_end + 2;
    for (unsigned int field = 3; field <= 22; field++) {
        char *token_end = NULL;

        while (*cursor == ' ')
            cursor++;
        if (*cursor == '\0')
            return -1;
        token_end = cursor;
        while (*token_end != '\0' && *token_end != ' ' && *token_end != '\n')
            token_end++;
        if (field == 22) {
            char *parsed_end = NULL;
            unsigned long long value = 0;
            const char saved = *token_end;

            *token_end = '\0';
            errno = 0;
            value = strtoull(cursor, &parsed_end, 10);
            *token_end = saved;
            if (errno != 0 || !parsed_end || parsed_end != token_end || value == 0)
                return -1;
            *start_ticks = value;
            return 0;
        }
        cursor = token_end;
    }
    return -1;
#else
    (void)pid;
    (void)start_ticks;
    return -1;
#endif
}

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
    if (process_start_ticks(getpid(), &start_ticks) != 0 ||
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
        const int process_status = process_start_ticks((pid_t)pid, &current_start_ticks);

        if (process_status < 0) {
            close(fd);
            return 0;
        }
        stale = (process_status > 0) || (current_start_ticks != recorded_start_ticks);
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
