#include "frdp-sesmand/display_policy.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
    if (test_reservation_release_keeps_replaced_path() != 0) {
        fprintf(stderr, "display reservation release unlinked a replacement path\n");
        return -1;
    }
    return 0;
}
