#define _GNU_SOURCE

#include "frdp-sesmand/session_metadata.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct
{
	const frdpSesmandSessionMetadata* expected;
	uint64_t file_dev;
	uint64_t file_ino;
	int count;
} metadataVisitContext;

static int make_test_dir(char* dir, size_t dir_size)
{
	const int rc = snprintf(dir, dir_size, "/tmp/frdp-session-metadata-XXXXXX");

	if ((rc < 0) || ((size_t)rc >= dir_size) || !mkdtemp(dir) || (chmod(dir, 0700) != 0))
		return -1;
	return 0;
}

static int metadata_matches(const frdpSesmandSessionMetadata* left,
                            const frdpSesmandSessionMetadata* right)
{
	return left && right && (strcmp(left->session_id, right->session_id) == 0) &&
	       (strcmp(left->user, right->user) == 0) &&
	       (left->uid == right->uid) && (left->agent_pid == right->agent_pid) &&
	       (left->pgid == right->pgid) && (left->agent_start_ticks == right->agent_start_ticks) &&
	       (left->start_time == right->start_time) &&
	       (left->state == right->state) && (left->display_number == right->display_number) &&
	       (left->agent_socket_dev == right->agent_socket_dev) &&
	       (left->agent_socket_ino == right->agent_socket_ino) &&
	       (left->display_reservation_dev == right->display_reservation_dev) &&
	       (left->display_reservation_ino == right->display_reservation_ino) &&
	       (left->systemd_scope == right->systemd_scope) && (left->pam_owner == right->pam_owner) &&
	       (left->logind_session == right->logind_session);
}

static int visit_metadata(const frdpSesmandSessionMetadata* metadata, uint64_t file_dev,
                          uint64_t file_ino, void* context)
{
	metadataVisitContext* visit = (metadataVisitContext*)context;

	if (!visit || !metadata_matches(metadata, visit->expected) || (file_dev == 0) ||
	    (file_ino == 0))
		return -1;
	visit->file_dev = file_dev;
	visit->file_ino = file_ino;
	visit->count++;
	return 0;
}

static int write_file(const char* path, const void* data, size_t size)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	ssize_t written = 0;
	int close_status = 0;

	if (fd < 0)
		return -1;
	written = write(fd, data, size);
	close_status = close(fd);
	return ((written == (ssize_t)size) && (close_status == 0)) ? 0 : -1;
}

static int test_metadata_store(void)
{
	static const char session_id[] = "01234567-89ab-cdef-0123-456789abcdef";
	frdpSesmandSessionMetadata metadata = { 0 };
	metadataVisitContext visit = { 0 };
	char dir[128] = { 0 };
	char filename[96] = { 0 };
	char path[256] = { 0 };
	char temp_path[256] = { 0 };
	uint64_t first_dev = 0;
	uint64_t first_ino = 0;
	uint64_t provisional_dev = 0;
	uint64_t provisional_ino = 0;
	uint64_t second_dev = 0;
	uint64_t second_ino = 0;
	int metadata_fd = -1;
	int rc = -1;

	if (make_test_dir(dir, sizeof(dir)) != 0)
		return -1;
	if (snprintf(metadata.session_id, sizeof(metadata.session_id), "%s", session_id) >=
	        (int)sizeof(metadata.session_id) ||
	    (snprintf(metadata.user, sizeof(metadata.user), "%s", "metadata-user") >=
	     (int)sizeof(metadata.user)))
		goto out;
	metadata.uid = geteuid();
	metadata.agent_pid = (pid_t)1234;
	metadata.pgid = metadata.agent_pid;
	metadata.agent_start_ticks = 5678;
	metadata.start_time = 123456;
	metadata.state = FRDP_SESMAND_SESSION_ACTIVE;
	metadata.display_number = 100;
	metadata.agent_socket_dev = 11;
	metadata.agent_socket_ino = 12;
	metadata.display_reservation_dev = 13;
	metadata.display_reservation_ino = 14;
	metadata.systemd_scope = 1;
	metadata.pam_owner = 1;
	metadata.logind_session = 1;
	{
		frdpSesmandSessionMetadata missing_user = metadata;

		memset(missing_user.user, 0, sizeof(missing_user.user));
		if (frdp_sesmand_session_metadata_save(dir, &missing_user, &first_dev, &first_ino) !=
		    FRDP_SESMAND_SESSION_METADATA_SAVE_ERROR)
			goto out;
	}
	if (!frdp_sesmand_session_metadata_is_valid(&metadata) ||
	    (frdp_sesmand_session_metadata_filename(filename, sizeof(filename), session_id) != 0) ||
	    (snprintf(path, sizeof(path), "%s/%s", dir, filename) >= (int)sizeof(path)))
		goto out;
	{
		frdpSesmandSessionMetadata provisional = metadata;

		provisional.agent_pid = 0;
		provisional.pgid = 0;
		provisional.agent_start_ticks = 0;
		provisional.state = FRDP_SESMAND_SESSION_STARTING;
		visit.expected = &provisional;
		if (!frdp_sesmand_session_metadata_is_valid(&provisional) ||
		    (frdp_sesmand_session_metadata_save(dir, &provisional, &provisional_dev,
		                                        &provisional_ino) !=
		     FRDP_SESMAND_SESSION_METADATA_SAVE_COMMITTED) ||
		    (frdp_sesmand_session_metadata_visit(dir, visit_metadata, &visit) != 0) ||
		    (visit.count != 1) || (visit.file_dev != provisional_dev) ||
		    (visit.file_ino != provisional_ino))
			goto out;
		provisional.state = FRDP_SESMAND_SESSION_ACTIVE;
		if (frdp_sesmand_session_metadata_is_valid(&provisional))
			goto out;
	}
	memset(&visit, 0, sizeof(visit));
	if (frdp_sesmand_session_metadata_save(dir, &metadata, &first_dev, &first_ino) !=
	    FRDP_SESMAND_SESSION_METADATA_SAVE_COMMITTED)
		goto out;
	visit.expected = &metadata;
	if ((frdp_sesmand_session_metadata_visit(dir, visit_metadata, &visit) != 0) ||
	    (visit.count != 1) || (visit.file_dev != first_dev) || (visit.file_ino != first_ino))
		goto out;
	metadata_fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
	if ((metadata_fd < 0) || (pwrite(metadata_fd, "\1\0\0\0", 4U, 8) != 4) ||
	    (pwrite(metadata_fd, "\200\0\0\0", 4U, 12) != 4) ||
	    (pwrite(metadata_fd, "\0\0\0", 3U, 53) != 3) || (fsync(metadata_fd) != 0) ||
	    (ftruncate(metadata_fd, 128) != 0) ||
	    (close(metadata_fd) != 0))
		goto out;
	metadata_fd = -1;
	metadata.systemd_scope = 0;
	metadata.pam_owner = 0;
	metadata.logind_session = 0;
	metadata.start_time = 1;
	memset(metadata.user, 0, sizeof(metadata.user));
	memset(&visit, 0, sizeof(visit));
	visit.expected = &metadata;
	if ((frdp_sesmand_session_metadata_visit(dir, visit_metadata, &visit) != 0) ||
	    (visit.count != 1) || (visit.file_dev != first_dev) || (visit.file_ino != first_ino))
		goto out;
	metadata_fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
	if ((metadata_fd < 0) || (pwrite(metadata_fd, "\2\0\0\0", 4U, 8) != 4) ||
	    (pwrite(metadata_fd, "\1", 1U, 53) != 1) || (fsync(metadata_fd) != 0) ||
	    (close(metadata_fd) != 0))
		goto out;
	metadata_fd = -1;
	metadata.systemd_scope = 1;
	memset(&visit, 0, sizeof(visit));
	visit.expected = &metadata;
	if ((frdp_sesmand_session_metadata_visit(dir, visit_metadata, &visit) != 0) ||
	    (visit.count != 1) || (visit.file_dev != first_dev) || (visit.file_ino != first_ino))
		goto out;
	metadata_fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
	if ((metadata_fd < 0) || (pwrite(metadata_fd, "\3\0\0\0", 4U, 8) != 4) ||
	    (pwrite(metadata_fd, "\1", 1U, 54) != 1) || (fsync(metadata_fd) != 0) ||
	    (close(metadata_fd) != 0))
		goto out;
	metadata_fd = -1;
	metadata.pam_owner = 1;
	memset(&visit, 0, sizeof(visit));
	visit.expected = &metadata;
	if ((frdp_sesmand_session_metadata_visit(dir, visit_metadata, &visit) != 0) ||
	    (visit.count != 1) || (visit.file_dev != first_dev) || (visit.file_ino != first_ino))
		goto out;

	metadata.state = FRDP_SESMAND_SESSION_DISCONNECTED;
	metadata.start_time = 123456;
	snprintf(metadata.user, sizeof(metadata.user), "%s", "metadata-user");
	if (frdp_sesmand_session_metadata_save(dir, &metadata, &second_dev, &second_ino) !=
	        FRDP_SESMAND_SESSION_METADATA_SAVE_COMMITTED ||
	    ((first_dev == second_dev) && (first_ino == second_ino)))
		goto out;
	if ((frdp_sesmand_session_metadata_remove(dir, session_id, first_dev, first_ino) == 0) ||
	    (access(path, F_OK) != 0))
		goto out;
	memset(&visit, 0, sizeof(visit));
	visit.expected = &metadata;
	if ((frdp_sesmand_session_metadata_visit(dir, visit_metadata, &visit) != 0) ||
	    (visit.count != 1) || (visit.file_dev != second_dev) || (visit.file_ino != second_ino))
		goto out;

	if (snprintf(temp_path, sizeof(temp_path), "%s/.frdp-session-tmp-stale", dir) >=
	        (int)sizeof(temp_path) ||
	    (write_file(temp_path, "stale", 5) != 0) ||
	    (frdp_sesmand_session_metadata_visit(dir, visit_metadata, &visit) != 0) ||
	    (access(temp_path, F_OK) == 0) || (errno != ENOENT))
		goto out;
	if (frdp_sesmand_session_metadata_remove(dir, session_id, second_dev, second_ino) != 0 ||
	    (access(path, F_OK) == 0) || (errno != ENOENT))
		goto out;
	if ((write_file(path, "bad", 3) != 0) ||
	    (frdp_sesmand_session_metadata_visit(dir, visit_metadata, &visit) == 0) ||
	    (access(path, F_OK) != 0))
		goto out;
	unlink(path);
	if ((symlink("/dev/null", path) != 0) ||
	    (frdp_sesmand_session_metadata_visit(dir, visit_metadata, &visit) == 0) ||
	    (lstat(path, &(struct stat){ 0 }) != 0))
		goto out;
	unlink(path);
	if ((chmod(dir, 0770) != 0) ||
	    (frdp_sesmand_session_metadata_save(dir, &metadata, &second_dev, &second_ino) !=
	     FRDP_SESMAND_SESSION_METADATA_SAVE_ERROR) ||
	    (chmod(dir, 0700) != 0))
		goto out;
	rc = 0;

out:
	if (metadata_fd >= 0)
		close(metadata_fd);
	unlink(temp_path);
	unlink(path);
	if (dir[0] != '\0')
	{
		chmod(dir, 0700);
		rmdir(dir);
	}
	return rc;
}

int TestFreeRDPFrdpSessionMetadata(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_metadata_store() != 0)
	{
		fprintf(stderr, "session metadata store test failed\n");
		return -1;
	}
	return 0;
}
