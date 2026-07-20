#include "frdp-sesmand/display_policy.h"
#include "frdp-sesmand/process_identity.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int make_test_dir(char *dir, size_t dir_size)
{
    const int rc = snprintf(dir, dir_size, "/tmp/frdp-display-policy-XXXXXX");

    if ((rc < 0) || ((size_t)rc >= dir_size))
        return -1;
    if (!mkdtemp(dir))
        return -1;
    return 0;
}

static int test_display_bounds_and_paths(void)
{
    char path[128] = { 0 };

    if (frdp_sesmand_display_number_is_valid(FRDP_SESMAND_DISPLAY_MIN - 1))
        return -1;
    if (!frdp_sesmand_display_number_is_valid(FRDP_SESMAND_DISPLAY_MIN))
        return -1;
    if (!frdp_sesmand_display_number_is_valid(FRDP_SESMAND_DISPLAY_MAX))
        return -1;
    if (frdp_sesmand_display_number_is_valid(FRDP_SESMAND_DISPLAY_MAX + 1))
        return -1;
    if (frdp_sesmand_display_reservation_path(path, sizeof(path), "relative",
                                              FRDP_SESMAND_DISPLAY_MIN) == 0)
        return -1;
    if (frdp_sesmand_display_reservation_path(path, 8, "/tmp",
                                              FRDP_SESMAND_DISPLAY_MIN) == 0)
        return -1;
    if (frdp_sesmand_display_reservation_path(path, sizeof(path), "/tmp",
                                              FRDP_SESMAND_DISPLAY_MIN) != 0)
        return -1;
    return strcmp(path, "/tmp/frdp-display-100.lock") == 0 ? 0 : -1;
}

static int test_reservation_create_rejects_collision(void)
{
    char dir[128] = { 0 };
    char path[128] = { 0 };
    char original_path[128] = { 0 };
    int fd = -1;
    int second_fd = -1;
    int rc = -1;

    if (make_test_dir(dir, sizeof(dir)) != 0)
        return -1;
    if (frdp_sesmand_display_reservation_create(FRDP_SESMAND_DISPLAY_MIN, dir, &fd, path,
                                                sizeof(path)) != 0)
        goto cleanup;
    snprintf(original_path, sizeof(original_path), "%s", path);
    if (access(path, F_OK) != 0)
        goto cleanup;
    errno = 0;
    if (frdp_sesmand_display_reservation_create(FRDP_SESMAND_DISPLAY_MIN, dir, &second_fd,
                                                path, sizeof(path)) == 0)
        goto cleanup;
    if (errno != EEXIST)
        goto cleanup;
    frdp_sesmand_display_reservation_release(&fd, original_path);
    if (access(original_path, F_OK) == 0 || errno != ENOENT)
        goto cleanup;
    rc = 0;

cleanup:
    if (second_fd >= 0)
        frdp_sesmand_display_reservation_release(&second_fd, path);
    frdp_sesmand_display_reservation_release(&fd, original_path);
    if (original_path[0] != '\0')
        unlink(original_path);
    if (dir[0] != '\0')
        rmdir(dir);
    return rc;
}

static int test_reservation_records_process_identity(void)
{
    char dir[128] = { 0 };
    char path[128] = { 0 };
    char text[128] = { 0 };
    long pid = 0;
    unsigned long long start_ticks = 0;
    int fd = -1;
    int read_fd = -1;
    int rc = -1;

    if (make_test_dir(dir, sizeof(dir)) != 0)
        return -1;
    if (frdp_sesmand_display_reservation_create(FRDP_SESMAND_DISPLAY_MIN, dir, &fd, path,
                                                sizeof(path)) != 0)
        goto cleanup;
    read_fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (read_fd < 0 || read(read_fd, text, sizeof(text) - 1U) <= 0)
        goto cleanup;
#ifdef __linux__
    if (sscanf(text, "v2 %ld %llu", &pid, &start_ticks) != 2 || pid != (long)getpid() ||
        start_ticks == 0)
        goto cleanup;
#else
    if (sscanf(text, "%ld", &pid) != 1 || pid != (long)getpid())
        goto cleanup;
#endif
    rc = 0;

cleanup:
    if (read_fd >= 0)
        close(read_fd);
    frdp_sesmand_display_reservation_release(&fd, path);
    if (path[0] != '\0')
        unlink(path);
    if (dir[0] != '\0')
        rmdir(dir);
    return rc;
}

static int test_reservation_release_keeps_replaced_path(void)
{
    char dir[128] = { 0 };
    char path[128] = { 0 };
    int fd = -1;
    int replacement_fd = -1;
    int rc = -1;

    if (make_test_dir(dir, sizeof(dir)) != 0)
        return -1;
    if (frdp_sesmand_display_reservation_create(FRDP_SESMAND_DISPLAY_MIN, dir, &fd, path,
                                                sizeof(path)) != 0)
        goto cleanup;
    if (unlink(path) != 0)
        goto cleanup;
    replacement_fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (replacement_fd < 0)
        goto cleanup;
    close(replacement_fd);
    replacement_fd = -1;

    frdp_sesmand_display_reservation_release(&fd, path);
    if (access(path, F_OK) != 0)
        goto cleanup;
    rc = 0;

cleanup:
    if (replacement_fd >= 0)
        close(replacement_fd);
    frdp_sesmand_display_reservation_release(&fd, path);
    if (path[0] != '\0')
        unlink(path);
    if (dir[0] != '\0')
        rmdir(dir);
    return rc;
}

static int test_reservation_open_pins_existing_inode(void)
{
    char dir[128] = { 0 };
    char path[128] = { 0 };
    char reopened_path[128] = { 0 };
    struct stat st = { 0 };
    int fd = -1;
    int reopened_fd = -1;
    int rejected_fd = -1;
    char rejected_path[128] = { 0 };
    int rc = -1;

    if ((make_test_dir(dir, sizeof(dir)) != 0) ||
        (frdp_sesmand_display_reservation_create(FRDP_SESMAND_DISPLAY_MIN, dir, &fd, path,
                                                 sizeof(path)) != 0) ||
        (fstat(fd, &st) != 0))
        goto cleanup;
    close(fd);
    fd = -1;
    if ((frdp_sesmand_display_reservation_open(
             FRDP_SESMAND_DISPLAY_MIN, dir, (uint64_t)st.st_dev, (uint64_t)st.st_ino,
             &reopened_fd, reopened_path, sizeof(reopened_path)) != 0) ||
        (strcmp(path, reopened_path) != 0))
        goto cleanup;
    errno = 0;
    if ((frdp_sesmand_display_reservation_open(
             FRDP_SESMAND_DISPLAY_MIN, dir, (uint64_t)st.st_dev,
             (uint64_t)st.st_ino + 1U, &rejected_fd, rejected_path,
             sizeof(rejected_path)) == 0) ||
        (rejected_fd >= 0))
        goto cleanup;
    frdp_sesmand_display_reservation_release(&reopened_fd, reopened_path);
    if ((access(path, F_OK) == 0) || (errno != ENOENT))
        goto cleanup;
    rc = 0;

cleanup:
    if (rejected_fd >= 0)
        close(rejected_fd);
    frdp_sesmand_display_reservation_release(&reopened_fd, reopened_path);
    frdp_sesmand_display_reservation_release(&fd, path);
    if (path[0] != '\0')
        unlink(path);
    if (dir[0] != '\0')
        rmdir(dir);
    return rc;
}

static int write_pid_file(const char *path, long pid)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0)
        return -1;
    if (dprintf(fd, "%ld\n", pid) < 0) {
        close(fd);
        return -1;
    }
    return close(fd);
}

static int write_text_file(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0)
        return -1;
    if (dprintf(fd, "%s", text) < 0) {
        close(fd);
        return -1;
    }
    return close(fd);
}

static int write_identity_file(const char* path, pid_t pid, unsigned long long start_ticks)
{
    char text[128] = { 0 };

    if (snprintf(text, sizeof(text), "v2 %ld %llu\n", (long)pid, start_ticks) >=
        (int)sizeof(text))
        return -1;
    return write_text_file(path, text);
}

static int expect_malformed_reservation_kept(const char *dir, const char *path, const char *text)
{
    if (write_text_file(path, text) != 0)
        return -1;
    if (frdp_sesmand_display_reservation_reconcile_stale(dir, FRDP_SESMAND_DISPLAY_MIN) != -1)
        return -1;
    if (access(path, F_OK) != 0)
        return -1;
    return unlink(path);
}

static int test_reconcile_removes_stale_reservation(void)
{
    char dir[128] = { 0 };
    char path[128] = { 0 };
    pid_t child = -1;
    pid_t dead_pid = -1;
    int status = 0;
    int fd = -1;
    int rc = -1;

    if (make_test_dir(dir, sizeof(dir)) != 0)
        return -1;
    if (frdp_sesmand_display_reservation_path(path, sizeof(path), dir,
                                              FRDP_SESMAND_DISPLAY_MIN) != 0)
        goto cleanup;
    child = fork();
    if (child < 0)
        goto cleanup;
    if (child == 0)
        _exit(0);
    if (waitpid(child, &status, 0) != child)
        goto cleanup;
    dead_pid = child;
    child = -1;
    if (write_pid_file(path, (long)dead_pid) != 0)
        goto cleanup;
    if (frdp_sesmand_display_reservation_reconcile_stale(dir, FRDP_SESMAND_DISPLAY_MIN) != 1)
        goto cleanup;
    if (access(path, F_OK) == 0 || errno != ENOENT)
        goto cleanup;
    if (frdp_sesmand_display_reservation_create(FRDP_SESMAND_DISPLAY_MIN, dir, &fd, path,
                                                sizeof(path)) != 0)
        goto cleanup;
    rc = 0;

cleanup:
    if (child > 0)
        waitpid(child, &status, 0);
    frdp_sesmand_display_reservation_release(&fd, path);
    if (path[0] != '\0')
        unlink(path);
    if (dir[0] != '\0')
        rmdir(dir);
    return rc;
}

static int test_reconcile_keeps_malformed_reservation(void)
{
    char dir[128] = { 0 };
    char path[128] = { 0 };
    char text[160] = { 0 };
    size_t used = 0;
    int rc = -1;

    if (make_test_dir(dir, sizeof(dir)) != 0)
        return -1;
    if (frdp_sesmand_display_reservation_path(path, sizeof(path), dir,
                                              FRDP_SESMAND_DISPLAY_MIN) != 0)
        goto cleanup;
    if (expect_malformed_reservation_kept(dir, path, "not-a-pid\n") != 0)
        goto cleanup;
    if (snprintf(text, sizeof(text), "v2 %ld -1\n", (long)getpid()) >= (int)sizeof(text) ||
        expect_malformed_reservation_kept(dir, path, text) != 0)
        goto cleanup;
    if (snprintf(text, sizeof(text), "v2 %ld 18446744073709551616\n", (long)getpid()) >=
            (int)sizeof(text) ||
        expect_malformed_reservation_kept(dir, path, text) != 0)
        goto cleanup;
    used = (size_t)snprintf(text, sizeof(text), "v2 %ld 1", (long)getpid());
    if (used >= sizeof(text) - 2U)
        goto cleanup;
    memset(&text[used], ' ', sizeof(text) - used - 2U);
    text[sizeof(text) - 2U] = 'x';
    text[sizeof(text) - 1U] = '\0';
    if (expect_malformed_reservation_kept(dir, path, text) != 0)
        goto cleanup;
    rc = 0;

cleanup:
    if (path[0] != '\0')
        unlink(path);
    if (dir[0] != '\0')
        rmdir(dir);
    return rc;
}

static int test_reconcile_keeps_live_reservation(void)
{
    char dir[128] = { 0 };
    char path[128] = { 0 };
    int rc = -1;

    if (make_test_dir(dir, sizeof(dir)) != 0)
        return -1;
    if (frdp_sesmand_display_reservation_path(path, sizeof(path), dir,
                                              FRDP_SESMAND_DISPLAY_MIN) != 0)
        goto cleanup;
    if (write_pid_file(path, (long)getpid()) != 0)
        goto cleanup;
    if (frdp_sesmand_display_reservation_reconcile_stale(dir, FRDP_SESMAND_DISPLAY_MIN) != 0)
        goto cleanup;
    if (access(path, F_OK) != 0)
        goto cleanup;
    rc = 0;

cleanup:
    if (path[0] != '\0')
        unlink(path);
    if (dir[0] != '\0')
        rmdir(dir);
    return rc;
}

static int test_reconcile_keeps_live_identity_reservation(void)
{
#ifdef __linux__
    char dir[128] = { 0 };
    char path[128] = { 0 };
    unsigned long long start_ticks = 0;
    int rc = -1;

    if (make_test_dir(dir, sizeof(dir)) != 0)
        return -1;
    if (frdp_sesmand_display_reservation_path(path, sizeof(path), dir,
                                              FRDP_SESMAND_DISPLAY_MIN) != 0)
        goto cleanup;
    if (frdp_sesmand_process_identity_read(getpid(), &start_ticks, NULL) !=
        FRDP_SESMAND_PROCESS_IDENTITY_OK)
        goto cleanup;
    if (write_identity_file(path, getpid(), start_ticks) != 0)
        goto cleanup;
    if (frdp_sesmand_display_reservation_reconcile_stale(dir, FRDP_SESMAND_DISPLAY_MIN) != 0)
        goto cleanup;
    if (access(path, F_OK) != 0)
        goto cleanup;
    rc = 0;

cleanup:
    if (path[0] != '\0')
        unlink(path);
    if (dir[0] != '\0')
        rmdir(dir);
    return rc;
#else
    return 0;
#endif
}

static int test_reconcile_removes_dead_identity_reservation(void)
{
#ifdef __linux__
    char dir[128] = { 0 };
    char path[128] = { 0 };
    unsigned long long start_ticks = 0;
    pid_t child = -1;
    pid_t dead_pid = -1;
    int child_pipe[2] = { -1, -1 };
    int status = 0;
    int rc = -1;

    if (make_test_dir(dir, sizeof(dir)) != 0)
        return -1;
    if (frdp_sesmand_display_reservation_path(path, sizeof(path), dir,
                                              FRDP_SESMAND_DISPLAY_MIN) != 0)
        goto cleanup;
    if (pipe(child_pipe) != 0)
        goto cleanup;
    child = fork();
    if (child < 0)
        goto cleanup;
    if (child == 0) {
        char byte = 0;

        close(child_pipe[1]);
        (void)read(child_pipe[0], &byte, sizeof(byte));
        close(child_pipe[0]);
        _exit(0);
    }
    close(child_pipe[0]);
    child_pipe[0] = -1;
    if (frdp_sesmand_process_identity_read(child, &start_ticks, NULL) !=
        FRDP_SESMAND_PROCESS_IDENTITY_OK)
        goto cleanup;
    dead_pid = child;
    close(child_pipe[1]);
    child_pipe[1] = -1;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        goto cleanup;
    child = -1;
    if (write_identity_file(path, dead_pid, start_ticks) != 0)
        goto cleanup;
    if (frdp_sesmand_display_reservation_reconcile_stale(dir, FRDP_SESMAND_DISPLAY_MIN) != 1)
        goto cleanup;
    if (access(path, F_OK) == 0 || errno != ENOENT)
        goto cleanup;
    rc = 0;

cleanup:
    if (child_pipe[0] >= 0)
        close(child_pipe[0]);
    if (child_pipe[1] >= 0)
        close(child_pipe[1]);
    if (child > 0)
        waitpid(child, &status, 0);
    if (path[0] != '\0')
        unlink(path);
    if (dir[0] != '\0')
        rmdir(dir);
    return rc;
#else
    return 0;
#endif
}

static int test_reconcile_pid_one_policy(void)
{
    char dir[128] = { 0 };
    char path[128] = { 0 };
    int rc = -1;

    if (make_test_dir(dir, sizeof(dir)) != 0)
        return -1;
    if (frdp_sesmand_display_reservation_path(path, sizeof(path), dir,
                                              FRDP_SESMAND_DISPLAY_MIN) != 0)
        goto cleanup;
#ifdef __linux__
    {
        unsigned long long start_ticks = 0;
        const frdpSesmandProcessIdentityResult identity_result =
            frdp_sesmand_process_identity_read((pid_t)1, &start_ticks, NULL);

        if (identity_result == FRDP_SESMAND_PROCESS_IDENTITY_OK) {
            if (write_identity_file(path, (pid_t)1, start_ticks) != 0)
                goto cleanup;
            if (frdp_sesmand_display_reservation_reconcile_stale(
                    dir, FRDP_SESMAND_DISPLAY_MIN) != 0 ||
                access(path, F_OK) != 0)
                goto cleanup;
            if (unlink(path) != 0)
                goto cleanup;
        }
    }
#endif
    if (write_pid_file(path, 1) != 0)
        goto cleanup;
    if (frdp_sesmand_display_reservation_reconcile_stale(dir, FRDP_SESMAND_DISPLAY_MIN) != -1)
        goto cleanup;
    if (access(path, F_OK) != 0)
        goto cleanup;
    rc = 0;

cleanup:
    if (path[0] != '\0')
        unlink(path);
    if (dir[0] != '\0')
        rmdir(dir);
    return rc;
}

static int test_reconcile_removes_reused_pid_reservation(void)
{
#ifdef __linux__
    char dir[128] = { 0 };
    char path[128] = { 0 };
    char text[128] = { 0 };
    int rc = -1;

    if (make_test_dir(dir, sizeof(dir)) != 0)
        return -1;
    if (frdp_sesmand_display_reservation_path(path, sizeof(path), dir,
                                              FRDP_SESMAND_DISPLAY_MIN) != 0)
        goto cleanup;
    if (snprintf(text, sizeof(text), "v2 %ld %llu\n", (long)getpid(), ULLONG_MAX) >=
        (int)sizeof(text))
        goto cleanup;
    if (write_text_file(path, text) != 0)
        goto cleanup;
    if (frdp_sesmand_display_reservation_reconcile_stale(dir, FRDP_SESMAND_DISPLAY_MIN) != 1)
        goto cleanup;
    if (access(path, F_OK) == 0 || errno != ENOENT)
        goto cleanup;
    rc = 0;

cleanup:
    if (path[0] != '\0')
        unlink(path);
    if (dir[0] != '\0')
        rmdir(dir);
    return rc;
#else
    return 0;
#endif
}

int TestFreeRDPFrdpDisplayPolicy(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    if (test_display_bounds_and_paths() != 0) {
        fprintf(stderr, "display bounds/path validation failed\n");
        return -1;
    }
    if (test_reservation_create_rejects_collision() != 0) {
        fprintf(stderr, "display reservation collision handling failed\n");
        return -1;
    }
    if (test_reservation_records_process_identity() != 0) {
        fprintf(stderr, "display reservation process identity recording failed\n");
        return -1;
    }
    if (test_reservation_release_keeps_replaced_path() != 0) {
        fprintf(stderr, "display reservation release unlinked a replacement path\n");
        return -1;
    }
    if (test_reservation_open_pins_existing_inode() != 0) {
        fprintf(stderr, "display reservation existing-inode open failed\n");
        return -1;
    }
    if (test_reconcile_removes_stale_reservation() != 0) {
        fprintf(stderr, "display reservation stale reconciliation failed\n");
        return -1;
    }
    if (test_reconcile_keeps_malformed_reservation() != 0) {
        fprintf(stderr, "display reservation malformed reconciliation failed\n");
        return -1;
    }
    if (test_reconcile_keeps_live_reservation() != 0) {
        fprintf(stderr, "display reservation live reconciliation failed\n");
        return -1;
    }
    if (test_reconcile_keeps_live_identity_reservation() != 0) {
        fprintf(stderr, "display v2 reservation live reconciliation failed\n");
        return -1;
    }
    if (test_reconcile_removes_dead_identity_reservation() != 0) {
        fprintf(stderr, "display v2 reservation dead reconciliation failed\n");
        return -1;
    }
    if (test_reconcile_pid_one_policy() != 0) {
        fprintf(stderr, "display reservation PID 1 policy failed\n");
        return -1;
    }
    if (test_reconcile_removes_reused_pid_reservation() != 0) {
        fprintf(stderr, "display reservation PID reuse reconciliation failed\n");
        return -1;
    }
    return 0;
}
