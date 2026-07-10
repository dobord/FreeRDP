#define _GNU_SOURCE

#include "frdp-sesmand/session_recovery.h"
#include "frdp-sesmand/session_metadata.h"

#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int create_regular_file(const char* path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);

	if (fd < 0)
		return -1;
	return close(fd);
}

static int test_same_inode_artifact_cleanup(void)
{
	char dir[128] = "/tmp/frdp-session-recovery-XXXXXX";
	char regular_path[256] = { 0 };
	char socket_path[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	struct sockaddr_un address = { 0 };
	struct stat original = { 0 };
	struct stat replacement = { 0 };
	struct stat socket_stat = { 0 };
	int socket_fd = -1;
	int rc = -1;

	if (!mkdtemp(dir) || (chmod(dir, 0700) != 0) ||
	    (snprintf(regular_path, sizeof(regular_path), "%s/artifact", dir) >=
	     (int)sizeof(regular_path)) ||
	    (snprintf(socket_path, sizeof(socket_path), "%s/agent.sock", dir) >=
	     (int)sizeof(socket_path)))
		goto out;
	if ((create_regular_file(regular_path) != 0) || (lstat(regular_path, &original) != 0) ||
	    (unlink(regular_path) != 0) || (create_regular_file(regular_path) != 0) ||
	    (lstat(regular_path, &replacement) != 0))
		goto out;
	if ((frdp_sesmand_session_unlink_artifact(
	         regular_path, (uint64_t)original.st_dev, (uint64_t)original.st_ino, S_IFREG) == 0) ||
	    (access(regular_path, F_OK) != 0))
		goto out;
	if (frdp_sesmand_session_unlink_artifact(
	        regular_path, (uint64_t)replacement.st_dev, (uint64_t)replacement.st_ino, S_IFREG) != 0)
		goto out;

	socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (socket_fd < 0)
		goto out;
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, sizeof(address.sun_path), "%s", socket_path);
	if ((bind(socket_fd, (struct sockaddr*)&address, sizeof(address)) != 0) ||
	    (chmod(socket_path, 0600) != 0) || (lstat(socket_path, &socket_stat) != 0) ||
	    (frdp_sesmand_session_unlink_artifact(
	         socket_path, (uint64_t)socket_stat.st_dev, (uint64_t)socket_stat.st_ino, S_IFSOCK) != 0))
		goto out;
	rc = 0;

out:
	if (socket_fd >= 0)
		close(socket_fd);
	unlink(socket_path);
	unlink(regular_path);
	rmdir(dir);
	return rc;
}

static int test_reused_pid_metadata_does_not_signal_current_process(void)
{
	static const char session_id[] = "fedcba98-7654-3210-fedc-ba9876543210";
	frdpSesmandSessionMetadata metadata = { 0 };
	char dir[128] = "/tmp/frdp-session-reused-pid-XXXXXX";
	char metadata_name[96] = { 0 };
	char metadata_path[256] = { 0 };
	char reservation_path[256] = { 0 };
	char socket_path[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	struct sockaddr_un address = { 0 };
	struct stat reservation_stat = { 0 };
	struct stat socket_stat = { 0 };
	uint64_t metadata_dev = 0;
	uint64_t metadata_ino = 0;
	int socket_fd = -1;
	int rc = -1;

	if (!mkdtemp(dir) || (chmod(dir, 0700) != 0) ||
	    (snprintf(socket_path, sizeof(socket_path), "%s/agent-%s.sock", dir, session_id) >=
	     (int)sizeof(socket_path)) ||
	    (snprintf(reservation_path, sizeof(reservation_path), "%s/frdp-display-100.lock", dir) >=
	     (int)sizeof(reservation_path)) ||
	    (frdp_sesmand_session_metadata_filename(metadata_name, sizeof(metadata_name), session_id) !=
	     0) ||
	    (snprintf(metadata_path, sizeof(metadata_path), "%s/%s", dir, metadata_name) >=
	     (int)sizeof(metadata_path)))
		goto out;
	socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (socket_fd < 0)
		goto out;
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, sizeof(address.sun_path), "%s", socket_path);
	if ((bind(socket_fd, (struct sockaddr*)&address, sizeof(address)) != 0) ||
	    (chmod(socket_path, 0600) != 0) || (create_regular_file(reservation_path) != 0) ||
	    (lstat(socket_path, &socket_stat) != 0) ||
	    (lstat(reservation_path, &reservation_stat) != 0))
		goto out;
	snprintf(metadata.session_id, sizeof(metadata.session_id), "%s", session_id);
	metadata.uid = geteuid();
	metadata.agent_pid = getpid();
	metadata.pgid = getpid();
	metadata.agent_start_ticks = ULLONG_MAX;
	metadata.state = FRDP_SESMAND_SESSION_ACTIVE;
	metadata.display_number = 100;
	metadata.agent_socket_dev = (uint64_t)socket_stat.st_dev;
	metadata.agent_socket_ino = (uint64_t)socket_stat.st_ino;
	metadata.display_reservation_dev = (uint64_t)reservation_stat.st_dev;
	metadata.display_reservation_ino = (uint64_t)reservation_stat.st_ino;
	if ((frdp_sesmand_session_metadata_save(dir, &metadata, &metadata_dev, &metadata_ino) !=
	     FRDP_SESMAND_SESSION_METADATA_SAVE_COMMITTED) ||
	    (frdp_sesmand_session_reconcile_all(dir) != 0) || (kill(getpid(), 0) != 0) ||
	    (access(socket_path, F_OK) == 0) || (access(reservation_path, F_OK) == 0) ||
	    (access(metadata_path, F_OK) == 0))
		goto out;
	rc = 0;

out:
	if (socket_fd >= 0)
		close(socket_fd);
	unlink(metadata_path);
	unlink(socket_path);
	unlink(reservation_path);
	rmdir(dir);
	return rc;
}

int TestFreeRDPFrdpSessionRecovery(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_same_inode_artifact_cleanup() != 0)
	{
		fprintf(stderr, "session recovery artifact cleanup test failed\n");
		return -1;
	}
	if (test_reused_pid_metadata_does_not_signal_current_process() != 0)
	{
		fprintf(stderr, "session recovery PID reuse test failed\n");
		return -1;
	}
	return 0;
}
