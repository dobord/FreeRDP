#define _GNU_SOURCE

#include "session_recovery.h"

#include "display_policy.h"
#include "process_identity.h"
#include "session_metadata.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

static int process_group_exists(pid_t pgid)
{
	if (pgid <= 1)
		return 0;
	if (kill(-pgid, 0) == 0)
		return 1;
	return errno == EPERM;
}

static int open_process_pidfd(pid_t pid)
{
#if defined(__linux__) && defined(SYS_pidfd_open)
	return (int)syscall(SYS_pidfd_open, pid, 0U);
#else
	(void)pid;
	errno = ENOSYS;
	return -1;
#endif
}

static int signal_process_pidfd(int pidfd, int signal_number)
{
#if defined(__linux__) && defined(SYS_pidfd_send_signal)
	return (int)syscall(SYS_pidfd_send_signal, pidfd, signal_number, NULL, 0U);
#else
	(void)pidfd;
	(void)signal_number;
	errno = ENOSYS;
	return -1;
#endif
}

int frdp_sesmand_session_recovery_supported(void)
{
	int pidfd = open_process_pidfd(getpid());
	int supported = 0;

	if (pidfd < 0)
		return 0;
	supported = signal_process_pidfd(pidfd, 0) == 0;
	close(pidfd);
	return supported;
}

static int wait_process_pidfd(int pidfd, int timeout_ms)
{
	struct pollfd descriptor = { .fd = pidfd, .events = POLLIN };
	int status = 0;

	do
	{
		status = poll(&descriptor, 1, timeout_ms);
	} while ((status < 0) && (errno == EINTR));
	return (status == 1) && ((descriptor.revents & POLLIN) != 0) ? 0 : -1;
}

static int wait_process_group_gone(pid_t pgid)
{
	for (unsigned int attempt = 0; attempt < 50U; attempt++)
	{
		if (!process_group_exists(pgid))
			return 0;
		usleep(100000);
	}
	return -1;
}

static int process_identity_matches(const frdpSesmandSessionMetadata* metadata, int* matches)
{
	unsigned long long start_ticks = 0;
	uid_t effective_uid = (uid_t)-1;
	pid_t current_pgid = -1;
	frdpSesmandProcessIdentityResult result = FRDP_SESMAND_PROCESS_IDENTITY_ERROR;

	if (!metadata || !matches)
		return -1;
	*matches = 0;
	result = frdp_sesmand_process_identity_read(metadata->agent_pid, &start_ticks, &effective_uid);
	if (result == FRDP_SESMAND_PROCESS_IDENTITY_MISSING)
		return 0;
	if (result != FRDP_SESMAND_PROCESS_IDENTITY_OK)
		return -1;
	if (start_ticks != metadata->agent_start_ticks)
		return 0;
	if (effective_uid != metadata->uid)
		return -1;
	current_pgid = getpgid(metadata->agent_pid);
	if (current_pgid < 0)
	{
		if (errno == ESRCH)
		{
			result = frdp_sesmand_process_identity_read(metadata->agent_pid, &start_ticks, NULL);
			if (result == FRDP_SESMAND_PROCESS_IDENTITY_MISSING)
				return 0;
		}
		return -1;
	}
	if (current_pgid != metadata->pgid)
		return -1;
	*matches = 1;
	return 0;
}

static int stop_matching_process_group(const frdpSesmandSessionMetadata* metadata)
{
	int matches = 0;
	int pidfd = -1;
	int rc = -1;

	pidfd = open_process_pidfd(metadata->agent_pid);
	if (pidfd < 0)
	{
		if ((errno == ESRCH) || (errno == ENOENT))
			return process_group_exists(metadata->pgid) ? -1 : 0;
		return -1;
	}
	if (process_identity_matches(metadata, &matches) != 0)
		goto out;
	if (!matches)
	{
		unsigned long long start_ticks = 0;
		const frdpSesmandProcessIdentityResult status = frdp_sesmand_process_identity_read(
		    metadata->agent_pid, &start_ticks, NULL);

		if ((status == FRDP_SESMAND_PROCESS_IDENTITY_MISSING) &&
		    process_group_exists(metadata->pgid))
			goto out;
		rc = (status == FRDP_SESMAND_PROCESS_IDENTITY_ERROR) ? -1 : 0;
		goto out;
	}
	if ((signal_process_pidfd(pidfd, SIGTERM) != 0) || (wait_process_pidfd(pidfd, 5000) != 0) ||
	    (wait_process_group_gone(metadata->pgid) != 0))
		goto out;
	rc = 0;
out:
	close(pidfd);
	return rc;
}

int frdp_sesmand_session_unlink_artifact(const char* path, uint64_t expected_dev,
                                         uint64_t expected_ino, mode_t expected_type)
{
	struct stat first = { 0 };
	struct stat current = { 0 };

	if (!path || (path[0] != '/') || (expected_dev == 0) || (expected_ino == 0))
		return -1;
	if (lstat(path, &first) != 0)
		return (errno == ENOENT) ? 0 : -1;
	if (((first.st_mode & S_IFMT) != expected_type) || (first.st_uid != geteuid()) ||
	    ((uint64_t)first.st_dev != expected_dev) || ((uint64_t)first.st_ino != expected_ino))
		return -1;
	if ((lstat(path, &current) != 0) || (current.st_dev != first.st_dev) ||
	    (current.st_ino != first.st_ino) ||
	    ((current.st_mode & S_IFMT) != (first.st_mode & S_IFMT)))
		return -1;
	return unlink(path);
}

static int sync_directory(const char* dir)
{
	int fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	int rc = -1;

	if (fd < 0)
		return -1;
	rc = fsync(fd);
	close(fd);
	return rc;
}

static int reconcile_session(const frdpSesmandSessionMetadata* metadata, uint64_t file_dev,
                             uint64_t file_ino, void* context)
{
	char agent_socket[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	char display_reservation[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	const char* dir = *(const char* const*)context;

	if (!metadata || !dir ||
	    (snprintf(agent_socket, sizeof(agent_socket), "%s/agent-%s.sock", dir,
	              metadata->session_id) >= (int)sizeof(agent_socket)) ||
	    (frdp_sesmand_display_reservation_path(display_reservation,
	                                           sizeof(display_reservation), dir,
	                                           metadata->display_number) != 0))
		return -1;
	if (stop_matching_process_group(metadata) != 0)
		return -1;
	if ((frdp_sesmand_session_unlink_artifact(agent_socket, metadata->agent_socket_dev,
	                                          metadata->agent_socket_ino, S_IFSOCK) != 0) ||
	    (frdp_sesmand_session_unlink_artifact(display_reservation,
	                                          metadata->display_reservation_dev,
	                                          metadata->display_reservation_ino, S_IFREG) != 0) ||
	    (sync_directory(dir) != 0))
		return -1;
	return frdp_sesmand_session_metadata_remove(dir, metadata->session_id, file_dev, file_ino);
}

int frdp_sesmand_session_reconcile_all(const char* dir)
{
	const char* context = dir;

	return frdp_sesmand_session_metadata_visit(dir, reconcile_session, &context);
}
