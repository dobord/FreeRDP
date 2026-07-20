#define _GNU_SOURCE

#include "session_pam_owner.h"

#include "sesmand_pam.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <security/pam_appl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <time.h>
#include <unistd.h>

#define FRDP_PAM_OWNER_MAGIC 0x4f4d4150U
#define FRDP_PAM_OWNER_BIND 1U
#define FRDP_PAM_OWNER_CLOSE 2U
#define FRDP_PAM_OWNER_RESPONSE 3U
#define FRDP_PAM_OWNER_BIND_LOGIND 4U
#define FRDP_PAM_OWNER_TAKEOVER 5U
#define FRDP_PAM_OWNER_GET_LOGIND 6U
#define FRDP_PAM_OWNER_WIRE_SIZE 24U
#define FRDP_PAM_OWNER_START_TIMEOUT_MS 20000
#define FRDP_PAM_OWNER_COMMAND_TIMEOUT_MS 10000
#define FRDP_PAM_OWNER_ORPHAN_GRACE_MS 30000U
#define FRDP_PAM_OWNER_TAKEOVER_GRACE_MS 10000U
#define FRDP_PAM_OWNER_RECEIPT "FRDP-PAM-CLOSED-1\n"
#define FRDP_PAM_OWNER_FAILURE "FRDP-PAM-CLOSE-FAILED-1\n"

static volatile sig_atomic_t g_owner_stop_requested = 0;

static void owner_stop_handler(int signal_number)
{
	(void)signal_number;
	g_owner_stop_requested = 1;
}

static uint64_t monotonic_ms(void)
{
	struct timespec now = { 0 };

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return 0;
	return ((uint64_t)now.tv_sec * 1000U) + ((uint64_t)now.tv_nsec / 1000000U);
}

static void write_u32_le(unsigned char* dst, uint32_t value)
{
	dst[0] = (unsigned char)(value & 0xffU);
	dst[1] = (unsigned char)((value >> 8U) & 0xffU);
	dst[2] = (unsigned char)((value >> 16U) & 0xffU);
	dst[3] = (unsigned char)((value >> 24U) & 0xffU);
}

static void write_u64_le(unsigned char* dst, uint64_t value)
{
	for (unsigned int x = 0; x < 8U; x++)
		dst[x] = (unsigned char)((value >> (x * 8U)) & 0xffU);
}

static uint32_t read_u32_le(const unsigned char* src)
{
	return ((uint32_t)src[0]) | ((uint32_t)src[1] << 8U) | ((uint32_t)src[2] << 16U) |
	       ((uint32_t)src[3] << 24U);
}

static uint64_t read_u64_le(const unsigned char* src)
{
	uint64_t value = 0;

	for (unsigned int x = 0; x < 8U; x++)
		value |= (uint64_t)src[x] << (x * 8U);
	return value;
}

static int session_id_is_valid(const char* session_id)
{
	if (!session_id || (strlen(session_id) != 36U))
		return 0;
	for (size_t x = 0; x < 36U; x++)
	{
		const char c = session_id[x];

		if ((x == 8U) || (x == 13U) || (x == 18U) || (x == 23U))
		{
			if (c != '-')
				return 0;
		}
		else if (!(((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f'))))
			return 0;
	}
	return 1;
}

int frdp_sesmand_pam_owner_endpoint(char* dst, size_t dst_size, const char* runtime_dir,
                                    const char* session_id)
{
	int rc = 0;

	if (!dst || (dst_size == 0U) || !runtime_dir || (runtime_dir[0] != '/') ||
	    !session_id_is_valid(session_id))
		return -1;
	rc = snprintf(dst, dst_size, "%s/pam-%s.sock", runtime_dir, session_id);
	return ((rc > 0) && ((size_t)rc < dst_size)) ? 0 : -1;
}

static int marker_path(char* dst, size_t dst_size, const char* runtime_dir, const char* session_id,
                       const char* suffix)
{
	int rc = 0;

	if (!dst || (dst_size == 0U) || !runtime_dir || (runtime_dir[0] != '/') ||
	    !session_id_is_valid(session_id) || !suffix || !suffix[0])
		return -1;
	rc = snprintf(dst, dst_size, "%s/pam-%s.%s", runtime_dir, session_id, suffix);
	return ((rc > 0) && ((size_t)rc < dst_size)) ? 0 : -1;
}

static int receipt_path(char* dst, size_t dst_size, const char* runtime_dir, const char* session_id)
{
	return marker_path(dst, dst_size, runtime_dir, session_id, "closed");
}

static int sync_runtime_dir(const char* runtime_dir)
{
	int fd = -1;
	int rc = -1;

	fd = open(runtime_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return -1;
	rc = fsync(fd);
	if (close(fd) != 0)
		rc = -1;
	return rc;
}

static int write_all(int fd, const void* data, size_t size)
{
	const unsigned char* bytes = (const unsigned char*)data;
	size_t offset = 0;

	while (offset < size)
	{
		const ssize_t count = write(fd, &bytes[offset], size - offset);

		if (count > 0)
		{
			offset += (size_t)count;
			continue;
		}
		if ((count < 0) && (errno == EINTR))
			continue;
		return -1;
	}
	return 0;
}

static int write_close_marker(const char* runtime_dir, const char* session_id, const char* suffix,
                              const char* content)
{
	char path[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	int fd = -1;
	int rc = -1;

	if (!content || (marker_path(path, sizeof(path), runtime_dir, session_id, suffix) != 0))
		return -1;
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;
	if ((fchmod(fd, 0600) == 0) && (write_all(fd, content, strlen(content)) == 0) &&
	    (fsync(fd) == 0))
		rc = 0;
	if (close(fd) != 0)
		rc = -1;
	if ((rc == 0) && (sync_runtime_dir(runtime_dir) != 0))
		rc = -1;
	if (rc != 0)
		unlink(path);
	return rc;
}

static int write_receipt(const char* runtime_dir, const char* session_id)
{
	return write_close_marker(runtime_dir, session_id, "closed", FRDP_PAM_OWNER_RECEIPT);
}

static int write_failure_marker(const char* runtime_dir, const char* session_id)
{
	return write_close_marker(runtime_dir, session_id, "failed", FRDP_PAM_OWNER_FAILURE);
}

static int remove_matching_artifact(int dirfd, const char* name, const struct stat* expected)
{
	struct stat current = { 0 };

	if ((fstatat(dirfd, name, &current, AT_SYMLINK_NOFOLLOW) != 0) ||
	    (current.st_dev != expected->st_dev) || (current.st_ino != expected->st_ino) ||
	    ((current.st_mode & S_IFMT) != (expected->st_mode & S_IFMT)) ||
	    (unlinkat(dirfd, name, 0) != 0))
		return -1;
	return 0;
}

static int check_close_marker(const char* runtime_dir, const char* session_id, const char* suffix,
                              const char* expected, int consume)
{
	char name[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	char content[64] = { 0 };
	struct stat st = { 0 };
	int dirfd = -1;
	int fd = -1;
	ssize_t count = 0;
	int rc = -1;

	const size_t expected_size = expected ? strlen(expected) : 0;

	if (!runtime_dir || (runtime_dir[0] != '/') || !session_id_is_valid(session_id) || !suffix ||
	    !expected || (expected_size == 0) || (expected_size >= sizeof(content)) ||
	    (snprintf(name, sizeof(name), "pam-%s.%s", session_id, suffix) >= (int)sizeof(name)))
		return -1;
	dirfd = open(runtime_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (dirfd < 0)
		return -1;
	fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		goto cleanup;
	count = read(fd, content, sizeof(content));
	if ((fstat(fd, &st) != 0) || !S_ISREG(st.st_mode) || (st.st_uid != geteuid()) ||
	    ((st.st_mode & 0777) != 0600) || (st.st_nlink != 1) || (count != (ssize_t)expected_size) ||
	    (memcmp(content, expected, expected_size) != 0))
		goto cleanup;
	if (consume && ((remove_matching_artifact(dirfd, name, &st) != 0) || (fsync(dirfd) != 0)))
		goto cleanup;
	rc = 0;

cleanup:
	if ((fd >= 0) && (close(fd) != 0))
		rc = -1;
	if (close(dirfd) != 0)
		rc = -1;
	return rc;
}

static int check_receipt(const char* runtime_dir, const char* session_id, int consume)
{
	return check_close_marker(runtime_dir, session_id, "closed", FRDP_PAM_OWNER_RECEIPT, consume);
}

static int check_failure_marker(const char* runtime_dir, const char* session_id)
{
	return check_close_marker(runtime_dir, session_id, "failed", FRDP_PAM_OWNER_FAILURE, 0);
}

static int set_socket_timeout_ms(int fd, uint64_t timeout_ms)
{
	struct timeval timeout = { 0 };

	if ((timeout_ms == 0) || (timeout_ms > FRDP_PAM_OWNER_COMMAND_TIMEOUT_MS))
		timeout_ms = FRDP_PAM_OWNER_COMMAND_TIMEOUT_MS;
	timeout.tv_sec = (time_t)(timeout_ms / 1000U);
	timeout.tv_usec = (suseconds_t)((timeout_ms % 1000U) * 1000U);

	return (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0) &&
	               (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0)
	           ? 0
	           : -1;
}

static int peer_is_manager(int fd, pid_t* pid)
{
#if defined(__linux__) && defined(SO_PEERCRED)
	struct ucred credentials = { 0 };
	socklen_t size = sizeof(credentials);

	if ((getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &size) != 0) ||
	    (size != sizeof(credentials)) || (credentials.pid <= 1) || (credentials.uid != geteuid()))
		return 0;
	if (pid)
		*pid = credentials.pid;
	return 1;
#else
	uid_t uid = (uid_t)-1;
	gid_t gid = (gid_t)-1;

	(void)pid;
	return (getpeereid(fd, &uid, &gid) == 0) && (uid == geteuid());
#endif
}

static int encode_message(unsigned char wire[FRDP_PAM_OWNER_WIRE_SIZE], uint32_t type, pid_t pid,
                          pid_t pgid, int status)
{
	if (!wire || (pid < 0) || (pgid < 0))
		return -1;
	memset(wire, 0, FRDP_PAM_OWNER_WIRE_SIZE);
	write_u32_le(&wire[0], FRDP_PAM_OWNER_MAGIC);
	write_u32_le(&wire[4], type);
	write_u64_le(&wire[8], (uint64_t)pid);
	write_u32_le(&wire[16], (uint32_t)pgid);
	write_u32_le(&wire[20], (uint32_t)status);
	return 0;
}

static int decode_message(const unsigned char wire[FRDP_PAM_OWNER_WIRE_SIZE], uint32_t* type,
                          pid_t* pid, pid_t* pgid, int* status)
{
	uint64_t pid_value = 0;
	uint32_t pgid_value = 0;
	pid_t native_pid = -1;
	pid_t native_pgid = -1;

	if (!wire || !type || !pid || !pgid || !status)
		return -1;
	pid_value = read_u64_le(&wire[8]);
	pgid_value = read_u32_le(&wire[16]);
	native_pid = (pid_t)pid_value;
	native_pgid = (pid_t)pgid_value;
	if ((read_u32_le(&wire[0]) != FRDP_PAM_OWNER_MAGIC) || ((uint64_t)native_pid != pid_value) ||
	    ((uint32_t)native_pgid != pgid_value))
		return -1;
	*type = read_u32_le(&wire[4]);
	*pid = native_pid;
	*pgid = native_pgid;
	*status = (int32_t)read_u32_le(&wire[20]);
	return 0;
}

static int send_message(int fd, uint32_t type, pid_t pid, pid_t pgid, int status)
{
	unsigned char wire[FRDP_PAM_OWNER_WIRE_SIZE] = { 0 };

	if (encode_message(wire, type, pid, pgid, status) != 0)
		return -1;
	return send(fd, wire, sizeof(wire), MSG_NOSIGNAL) == (ssize_t)sizeof(wire) ? 0 : -1;
}

static int send_message_fd(int fd, uint32_t type, int passed_fd)
{
	unsigned char wire[FRDP_PAM_OWNER_WIRE_SIZE] = { 0 };
	unsigned char control[CMSG_SPACE(sizeof(int))] = { 0 };
	struct iovec iov = { .iov_base = wire, .iov_len = sizeof(wire) };
	struct msghdr message = { 0 };
	struct cmsghdr* cmsg = NULL;

	if ((passed_fd < 0) || (encode_message(wire, type, 0, 0, 0) != 0))
		return -1;
	message.msg_iov = &iov;
	message.msg_iovlen = 1U;
	message.msg_control = control;
	message.msg_controllen = sizeof(control);
	cmsg = CMSG_FIRSTHDR(&message);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &passed_fd, sizeof(passed_fd));
	return sendmsg(fd, &message, MSG_NOSIGNAL) == (ssize_t)sizeof(wire) ? 0 : -1;
}

static int receive_message_fd(int fd, uint32_t* type, pid_t* pid, pid_t* pgid, int* status,
                              int* passed_fd)
{
	unsigned char wire[FRDP_PAM_OWNER_WIRE_SIZE] = { 0 };
	unsigned char control[CMSG_SPACE(sizeof(int))] = { 0 };
	struct iovec iov = { .iov_base = wire, .iov_len = sizeof(wire) };
	struct msghdr message = { 0 };
	struct cmsghdr* cmsg = NULL;
	int received_fd = -1;

	if (!passed_fd)
		return -1;
	*passed_fd = -1;
	message.msg_iov = &iov;
	message.msg_iovlen = 1U;
	message.msg_control = control;
	message.msg_controllen = sizeof(control);
	const ssize_t count = recvmsg(fd, &message, MSG_CMSG_CLOEXEC);

	if ((count != (ssize_t)sizeof(wire)) || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)))
		return -1;
	cmsg = CMSG_FIRSTHDR(&message);
	if (cmsg)
	{
		if ((cmsg->cmsg_level == SOL_SOCKET) && (cmsg->cmsg_type == SCM_RIGHTS) &&
		    (cmsg->cmsg_len >= CMSG_LEN(sizeof(int))))
			memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(received_fd));
		if ((received_fd < 0) || (cmsg->cmsg_len != CMSG_LEN(sizeof(int))) ||
		    CMSG_NXTHDR(&message, cmsg))
		{
			if (received_fd >= 0)
				close(received_fd);
			return -1;
		}
	}
	if (decode_message(wire, type, pid, pgid, status) != 0)
	{
		if (received_fd >= 0)
			close(received_fd);
		return -1;
	}
	*passed_fd = received_fd;
	return 0;
}

static int receive_message(int fd, uint32_t* type, pid_t* pid, pid_t* pgid, int* status)
{
	int passed_fd = -1;
	const int rc = receive_message_fd(fd, type, pid, pgid, status, &passed_fd);

	if (passed_fd >= 0)
	{
		close(passed_fd);
		return -1;
	}
	return rc;
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

static int create_listener(const char* endpoint, struct stat* endpoint_stat)
{
	struct sockaddr_un address = { 0 };
	mode_t previous_umask = 0;
	int fd = -1;

	if (!endpoint || !endpoint_stat || (strlen(endpoint) >= sizeof(address.sun_path)) ||
	    (lstat(endpoint, endpoint_stat) == 0) || (errno != ENOENT))
		return -1;
	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, sizeof(address.sun_path), "%s", endpoint);
	previous_umask = umask(0077);
	const int bind_status = bind(fd, (struct sockaddr*)&address, sizeof(address));
	umask(previous_umask);
	if ((bind_status != 0) || (chmod(endpoint, 0600) != 0) || (listen(fd, 4) != 0) ||
	    (lstat(endpoint, endpoint_stat) != 0) || !S_ISSOCK(endpoint_stat->st_mode) ||
	    (endpoint_stat->st_uid != geteuid()) || ((endpoint_stat->st_mode & 0777) != 0600))
	{
		close(fd);
		unlink(endpoint);
		return -1;
	}
	return fd;
}

static void remove_listener(const char* endpoint, const struct stat* expected)
{
	struct stat current = { 0 };

	if (!endpoint || !expected || (lstat(endpoint, &current) != 0) ||
	    (current.st_dev != expected->st_dev) || (current.st_ino != expected->st_ino) ||
	    !S_ISSOCK(current.st_mode))
		return;
	(void)unlink(endpoint);
}

static void close_unneeded_fds(int keep_a, int keep_b, int keep_c)
{
	long maximum = sysconf(_SC_OPEN_MAX);

	if ((maximum < 0) || (maximum > 65536))
		maximum = 65536;
	for (int fd = 3; fd < maximum; fd++)
	{
		if ((fd != keep_a) && (fd != keep_b) && (fd != keep_c))
			close(fd);
	}
}

static int install_owner_signal_handlers(void)
{
	struct sigaction action = { 0 };

	action.sa_handler = owner_stop_handler;
	sigemptyset(&action.sa_mask);
	return (sigaction(SIGTERM, &action, NULL) == 0) && (sigaction(SIGINT, &action, NULL) == 0) &&
	               (sigaction(SIGHUP, &action, NULL) == 0)
	           ? 0
	           : -1;
}

static int protect_startup_from_parent_death(pid_t manager_pid, int enabled)
{
#ifdef __linux__
	if (prctl(PR_SET_PDEATHSIG, enabled ? SIGKILL : 0) != 0)
		return -1;
	if (enabled && (getppid() != manager_pid))
		return -1;
	return 0;
#else
	(void)manager_pid;
	(void)enabled;
	return 0;
#endif
}

static int finish_pam_session(pam_handle_t* pamh, int credentials_established, int session_open)
{
	int status = PAM_SUCCESS;

	if (!pamh)
		return -1;
	if (session_open)
		status = pam_close_session(pamh, 0);
	if (credentials_established)
	{
		const int credential_status = pam_setcred(pamh, PAM_DELETE_CRED);

		if ((status == PAM_SUCCESS) && (credential_status != PAM_SUCCESS))
			status = credential_status;
	}
	if (pam_end(pamh, status) != PAM_SUCCESS)
		status = PAM_SYSTEM_ERR;
	return status == PAM_SUCCESS ? 0 : -1;
}

static int process_group_exists(pid_t pgid)
{
	if (pgid <= 1)
		return 0;
#ifdef __linux__
	DIR* directory = opendir("/proc");
	struct dirent* entry = NULL;
	int scan_error = 0;

	if (!directory)
		return 1;
	for (;;)
	{
		errno = 0;
		entry = readdir(directory);
		if (!entry)
		{
			if (errno != 0)
				scan_error = 1;
			break;
		}
		char* end = NULL;
		const long pid = strtol(entry->d_name, &end, 10);
		char path[64] = { 0 };
		char stat_line[4096] = { 0 };
		char* fields = NULL;
		char state = 0;
		long parent = 0;
		long group = 0;
		FILE* stream = NULL;

		if ((pid <= 0) || !end || (*end != '\0') ||
		    (snprintf(path, sizeof(path), "/proc/%ld/stat", pid) >= (int)sizeof(path)))
			continue;
		stream = fopen(path, "re");
		if (!stream)
		{
			if (kill((pid_t)pid, 0) == 0)
				scan_error = 1;
			continue;
		}
		if (!fgets(stat_line, sizeof(stat_line), stream))
		{
			fclose(stream);
			if (kill((pid_t)pid, 0) == 0)
				scan_error = 1;
			continue;
		}
		fclose(stream);
		fields = strrchr(stat_line, ')');
		if (!fields || (sscanf(fields + 1, " %c %ld %ld", &state, &parent, &group) != 3))
		{
			scan_error = 1;
			continue;
		}
		(void)parent;
		if ((group == (long)pgid) && (state != 'Z') && (state != 'X'))
		{
			closedir(directory);
			return 1;
		}
	}
	closedir(directory);
	return scan_error;
#else
	if (kill(-pgid, 0) == 0)
		return 1;
	return errno == EPERM;
#endif
}

static int read_process_state(pid_t pid, char* state)
{
#ifdef __linux__
	char path[64] = { 0 };
	char stat_line[4096] = { 0 };
	char* fields = NULL;
	FILE* stream = NULL;

	if (!state || (pid <= 1) ||
	    (snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid) >= (int)sizeof(path)))
		return -1;
	stream = fopen(path, "re");
	if (!stream)
		return -1;
	if (!fgets(stat_line, sizeof(stat_line), stream))
	{
		fclose(stream);
		return -1;
	}
	fclose(stream);
	fields = strrchr(stat_line, ')');
	return fields && (sscanf(fields + 1, " %c", state) == 1) ? 0 : -1;
#else
	(void)pid;
	(void)state;
	return -1;
#endif
}

static int wait_for_process_stopped(pid_t pid, int pidfd)
{
	struct pollfd descriptor = { .fd = pidfd, .events = POLLIN };

	for (unsigned int attempt = 0; attempt < 100U; attempt++)
	{
		char state = 0;

		if (poll(&descriptor, 1, 0) != 0)
			return -1;
		if ((read_process_state(pid, &state) == 0) && ((state == 'T') || (state == 't')))
			return 0;
		usleep(1000);
	}
	return -1;
}

static int wait_for_process_group_gone(pid_t pgid)
{
	for (unsigned int attempt = 0; attempt < 200U; attempt++)
	{
		if (!process_group_exists(pgid))
			return 0;
		usleep(10000);
	}
	return -1;
}

static int terminate_agent_group(pid_t agent_pid, pid_t pgid, int agent_pidfd)
{
	struct pollfd descriptor = { .fd = agent_pidfd, .events = POLLIN };

	if (pgid <= 1)
		return 0;
	if ((agent_pid <= 1) || (agent_pidfd < 0))
		return process_group_exists(pgid) ? -1 : 0;
	if (signal_process_pidfd(agent_pidfd, SIGSTOP) != 0)
		return process_group_exists(pgid) ? -1 : 0;
	if ((wait_for_process_stopped(agent_pid, agent_pidfd) != 0) || (getpgid(agent_pid) != pgid))
	{
		(void)signal_process_pidfd(agent_pidfd, SIGCONT);
		return -1;
	}
	if (kill(-pgid, SIGSTOP) != 0)
	{
		(void)signal_process_pidfd(agent_pidfd, SIGCONT);
		return -1;
	}
	for (unsigned int attempt = 0; attempt < 100U; attempt++)
	{
		usleep(1000);
		if ((poll(&descriptor, 1, 0) != 0) || (getpgid(agent_pid) != pgid))
			return -1;
		(void)kill(-pgid, SIGSTOP);
	}
	if (kill(-pgid, SIGTERM) != 0)
	{
		(void)signal_process_pidfd(agent_pidfd, SIGCONT);
		return -1;
	}
	for (unsigned int attempt = 0; attempt < 200U; attempt++)
	{
		usleep(10000);
		if ((poll(&descriptor, 1, 0) != 0) || (getpgid(agent_pid) != pgid))
			return -1;
	}
	if (kill(-pgid, SIGKILL) != 0)
	{
		(void)signal_process_pidfd(agent_pidfd, SIGCONT);
		return -1;
	}
	(void)poll(&descriptor, 1, 2000);
	return wait_for_process_group_gone(pgid);
}

static int run_owner(const char* runtime_dir, const char* endpoint, const char* session_id,
                     const char* pam_service, const char* user, const char* rhost, int startup_fd,
                     pid_t manager_pid)
{
	struct pam_conv conversation = { frdp_sesmand_pam_conversation, NULL };
	struct stat endpoint_stat = { 0 };
	pam_handle_t* pamh = NULL;
	int listener = -1;
	int manager_pidfd = -1;
	int agent_pidfd = -1;
	int logind_fifo_fd = -1;
	pid_t agent_pid = -1;
	pid_t agent_pgid = -1;
	int credentials_established = 0;
	int session_open = 0;
	int close_status = -1;
	int close_evidence = 1;
	int startup_sent = 0;
	uint64_t agent_gone_at = 0;
	uint64_t manager_gone_at = 0;
	uint64_t cleanup_retry_at = 0;
	pid_t current_manager_pid = manager_pid;
	int takeover_consumed = 0;

	g_owner_stop_requested = 0;
	if ((protect_startup_from_parent_death(manager_pid, 1) != 0) ||
	    (install_owner_signal_handlers() != 0) ||
	    ((listener = create_listener(endpoint, &endpoint_stat)) < 0))
		goto cleanup;
	close_unneeded_fds(listener, startup_fd, -1);
	manager_pidfd = open_process_pidfd(manager_pid);
	if (manager_pidfd < 0)
		goto cleanup;
	if (pam_start(pam_service, user, &conversation, &pamh) != PAM_SUCCESS)
		goto cleanup;
	int status = PAM_SUCCESS;

	if (rhost && rhost[0])
		status = pam_set_item(pamh, PAM_RHOST, rhost);
	if (status == PAM_SUCCESS)
		status = pam_set_item(pamh, PAM_TTY, "rdp");
	if (status == PAM_SUCCESS)
		status = pam_set_item(pamh, PAM_RUSER, user);
	if (status == PAM_SUCCESS)
		status = pam_acct_mgmt(pamh, 0);
	if (status == PAM_SUCCESS)
		status = pam_setcred(pamh, PAM_ESTABLISH_CRED);
	if (status == PAM_SUCCESS)
		credentials_established = 1;
	if (status == PAM_SUCCESS)
		status = pam_open_session(pamh, 0);
	if (status != PAM_SUCCESS)
		goto cleanup;
	session_open = 1;
	if (protect_startup_from_parent_death(manager_pid, 0) != 0)
		goto cleanup;
	if (send(startup_fd, "R", 1U, MSG_NOSIGNAL) != 1)
		goto cleanup;
	startup_sent = 1;
	close(startup_fd);
	startup_fd = -1;

	for (;;)
	{
		struct pollfd descriptors[3] = {
			{ .fd = listener, .events = POLLIN },
			{ .fd = manager_pidfd, .events = POLLIN },
			{ .fd = agent_pidfd, .events = POLLIN },
		};
		int count = 1;
		int manager_index = -1;
		int agent_index = -1;

		if (manager_pidfd >= 0)
		{
			manager_index = count;
			descriptors[count++] = descriptors[1];
		}
		if (agent_pidfd >= 0)
		{
			agent_index = count;
			descriptors[count++] = descriptors[2];
		}
		const int poll_status = poll(descriptors, (nfds_t)count, 250);

		if ((poll_status < 0) && (errno != EINTR))
			break;
		const int manager_gone =
		    (manager_index >= 0) && (descriptors[manager_index].revents & POLLIN);
		if (manager_gone)
		{
			close(manager_pidfd);
			manager_pidfd = -1;
			if (takeover_consumed)
				g_owner_stop_requested = 1;
			else
			{
				manager_gone_at = monotonic_ms();
				if (manager_gone_at == 0)
					g_owner_stop_requested = 1;
			}
		}
		const uint64_t now = monotonic_ms();
		const int cleanup_due =
		    g_owner_stop_requested ||
		    ((manager_gone_at != 0) && (now >= manager_gone_at) &&
		     ((now - manager_gone_at) >= FRDP_PAM_OWNER_TAKEOVER_GRACE_MS));

		if (cleanup_due && ((cleanup_retry_at == 0) || (now >= cleanup_retry_at)))
		{
			if (terminate_agent_group(agent_pid, agent_pgid, agent_pidfd) == 0)
				break;
			cleanup_retry_at = now + 250U;
		}
		if ((agent_index >= 0) && (descriptors[agent_index].revents & POLLIN) &&
		    (agent_gone_at == 0))
			agent_gone_at = monotonic_ms();
		if ((agent_gone_at != 0) &&
		    ((monotonic_ms() - agent_gone_at) >= FRDP_PAM_OWNER_ORPHAN_GRACE_MS) &&
		    !process_group_exists(agent_pgid))
			break;
		if ((poll_status <= 0) || !(descriptors[0].revents & POLLIN))
			continue;
		int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
		uint32_t type = 0;
		pid_t requested_pid = -1;
		pid_t requested_pgid = -1;
		int requested_status = 0;
		int passed_fd = -1;

		if (client < 0)
			continue;
		pid_t peer_pid = -1;
		uint64_t command_timeout_ms = 250U;
		if (manager_gone_at != 0)
		{
			const uint64_t command_now = monotonic_ms();
			const uint64_t elapsed =
			    (command_now >= manager_gone_at) ? command_now - manager_gone_at : UINT64_MAX;

			if ((command_now == 0) || (elapsed >= FRDP_PAM_OWNER_TAKEOVER_GRACE_MS))
			{
				close(client);
				continue;
			}
			const uint64_t remaining = FRDP_PAM_OWNER_TAKEOVER_GRACE_MS - elapsed;
			if (remaining < command_timeout_ms)
				command_timeout_ms = remaining;
		}
		if (set_socket_timeout_ms(client, command_timeout_ms) != 0)
		{
			close(client);
			continue;
		}

		if (!peer_is_manager(client, &peer_pid) ||
		    (receive_message_fd(client, &type, &requested_pid, &requested_pgid, &requested_status,
		                        &passed_fd) != 0))
		{
			close(client);
			continue;
		}
		if ((type == FRDP_PAM_OWNER_TAKEOVER) && (passed_fd < 0) &&
		    (requested_pid == 0) && (requested_pgid == 0) && (requested_status == 0))
		{
			if ((manager_pidfd >= 0) && (peer_pid == current_manager_pid))
				(void)send_message(client, FRDP_PAM_OWNER_RESPONSE, 0, 0, 0);
			else if ((manager_pidfd < 0) && (manager_gone_at != 0) && (agent_pidfd >= 0))
			{
				const uint64_t takeover_now = monotonic_ms();
				const int replacement_pidfd =
				    ((takeover_now != 0) && (takeover_now >= manager_gone_at) &&
				     ((takeover_now - manager_gone_at) < FRDP_PAM_OWNER_TAKEOVER_GRACE_MS))
				        ? open_process_pidfd(peer_pid)
				        : -1;

				if (replacement_pidfd >= 0)
				{
					manager_pidfd = replacement_pidfd;
					current_manager_pid = peer_pid;
					takeover_consumed = 1;
					manager_gone_at = 0;
					cleanup_retry_at = 0;
					(void)send_message(client, FRDP_PAM_OWNER_RESPONSE, 0, 0, 0);
				}
				else
					(void)send_message(client, FRDP_PAM_OWNER_RESPONSE, 0, 0, -1);
			}
			else
				(void)send_message(client, FRDP_PAM_OWNER_RESPONSE, 0, 0, -1);
			close(client);
			continue;
		}
		if (peer_pid != current_manager_pid)
		{
			if (passed_fd >= 0)
				close(passed_fd);
			(void)send_message(client, FRDP_PAM_OWNER_RESPONSE, 0, 0, -1);
			close(client);
			continue;
		}
		if ((type == FRDP_PAM_OWNER_BIND) && (agent_pidfd < 0) && (requested_pid > 1) &&
		    (passed_fd < 0) && (requested_pgid == requested_pid) &&
		    (getpgid(requested_pid) == requested_pgid))
		{
			agent_pidfd = open_process_pidfd(requested_pid);
			if (agent_pidfd >= 0)
			{
				agent_pid = requested_pid;
				agent_pgid = requested_pgid;
				(void)send_message(client, FRDP_PAM_OWNER_RESPONSE, 0, 0, 0);
			}
			else
				(void)send_message(client, FRDP_PAM_OWNER_RESPONSE, 0, 0, -1);
			close(client);
			continue;
		}
		if ((type == FRDP_PAM_OWNER_BIND_LOGIND) && (passed_fd >= 0) &&
		    (logind_fifo_fd < 0) && (requested_pid == 0) && (requested_pgid == 0))
		{
			struct stat fifo_stat = { 0 };

			if ((fstat(passed_fd, &fifo_stat) == 0) && S_ISFIFO(fifo_stat.st_mode) &&
			    (fcntl(passed_fd, F_SETFD, FD_CLOEXEC) == 0))
			{
				logind_fifo_fd = passed_fd;
				passed_fd = -1;
				(void)send_message(client, FRDP_PAM_OWNER_RESPONSE, 0, 0, 0);
			}
			else
				(void)send_message(client, FRDP_PAM_OWNER_RESPONSE, 0, 0, -1);
			if (passed_fd >= 0)
				close(passed_fd);
			close(client);
			continue;
		}
		if ((type == FRDP_PAM_OWNER_GET_LOGIND) && (passed_fd < 0) &&
		    (logind_fifo_fd >= 0) && (requested_pid == 0) && (requested_pgid == 0) &&
		    (requested_status == 0))
		{
			(void)send_message_fd(client, FRDP_PAM_OWNER_RESPONSE, logind_fifo_fd);
			close(client);
			continue;
		}
		if ((type == FRDP_PAM_OWNER_CLOSE) && (passed_fd < 0))
		{
			if (process_group_exists(agent_pgid))
			{
				(void)send_message(client, FRDP_PAM_OWNER_RESPONSE, 0, 0, -1);
				close(client);
				continue;
			}
			const int was_open = session_open;

			if (logind_fifo_fd >= 0)
			{
				close(logind_fifo_fd);
				logind_fifo_fd = -1;
			}
			close_status = finish_pam_session(pamh, credentials_established, session_open);
			pamh = NULL;
			credentials_established = 0;
			session_open = 0;
			if (was_open)
			{
				close_evidence =
				    ((close_status == 0) ? write_receipt(runtime_dir, session_id)
				                         : write_failure_marker(runtime_dir, session_id)) == 0;
				if (!close_evidence)
					close_status = -1;
			}
			(void)send_message(client, FRDP_PAM_OWNER_RESPONSE, 0, 0, close_status);
			close(client);
			goto cleanup;
		}
		if (passed_fd >= 0)
			close(passed_fd);
		(void)send_message(client, FRDP_PAM_OWNER_RESPONSE, 0, 0, -1);
		close(client);
	}

cleanup:
	if (logind_fifo_fd >= 0)
		close(logind_fifo_fd);
	if (pamh)
	{
		const int was_open = session_open;

		close_status = finish_pam_session(pamh, credentials_established, session_open);
		if (was_open)
			close_evidence =
			    ((close_status == 0) ? write_receipt(runtime_dir, session_id)
			                         : write_failure_marker(runtime_dir, session_id)) == 0;
	}
	if (!startup_sent && (startup_fd >= 0))
		(void)send(startup_fd, "!", 1U, MSG_NOSIGNAL);
	if (startup_fd >= 0)
		close(startup_fd);
	if (agent_pidfd >= 0)
		close(agent_pidfd);
	if (manager_pidfd >= 0)
		close(manager_pidfd);
	if (listener >= 0)
		close(listener);
	if (close_evidence)
		remove_listener(endpoint, &endpoint_stat);
	return close_status;
}

static int wait_startup(int fd)
{
	struct pollfd descriptor = { .fd = fd, .events = POLLIN | POLLHUP };
	char marker = 0;

	if ((poll(&descriptor, 1, FRDP_PAM_OWNER_START_TIMEOUT_MS) != 1) ||
	    (recv(fd, &marker, 1U, 0) != 1) || (marker != 'R'))
		return -1;
	return 0;
}

int frdp_sesmand_pam_owner_start(const char* runtime_dir, const char* session_id,
                                 const char* pam_service, const char* user, const char* rhost,
                                 frdpSesmandPamOwner* owner)
{
	char endpoint[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	char closed[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	char failed[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	int startup[2] = { -1, -1 };
	pid_t pid = -1;

	if (!pam_service || !pam_service[0] || !user || !user[0] || !owner ||
	    (frdp_sesmand_pam_owner_endpoint(endpoint, sizeof(endpoint), runtime_dir, session_id) !=
	     0) ||
	    (receipt_path(closed, sizeof(closed), runtime_dir, session_id) != 0) ||
	    (marker_path(failed, sizeof(failed), runtime_dir, session_id, "failed") != 0) ||
	    (access(closed, F_OK) == 0) || (errno != ENOENT) || (access(failed, F_OK) == 0) ||
	    (errno != ENOENT) || (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, startup) != 0))
		return -1;
	owner->pid = -1;
	owner->active = 0;
	pid = fork();
	if (pid < 0)
	{
		close(startup[0]);
		close(startup[1]);
		return -1;
	}
	if (pid == 0)
	{
		close(startup[0]);
		_exit(run_owner(runtime_dir, endpoint, session_id, pam_service, user, rhost, startup[1],
		                getppid()) == 0
		          ? 0
		          : 1);
	}
	close(startup[1]);
	if (wait_startup(startup[0]) != 0)
	{
		close(startup[0]);
		(void)kill(pid, SIGKILL);
		(void)waitpid(pid, NULL, 0);
		return -1;
	}
	close(startup[0]);
	owner->pid = pid;
	owner->active = 1;
	return 0;
}

static int connect_owner_timeout(const char* runtime_dir, const char* session_id, int* fd,
                                 pid_t* owner_pid, uint64_t timeout_ms)
{
	char endpoint[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	struct sockaddr_un address = { 0 };
	struct stat st = { 0 };
	int client = -1;

	if (!fd ||
	    (frdp_sesmand_pam_owner_endpoint(endpoint, sizeof(endpoint), runtime_dir, session_id) !=
	     0) ||
	    (lstat(endpoint, &st) != 0) || !S_ISSOCK(st.st_mode) || (st.st_uid != geteuid()) ||
	    ((st.st_mode & 0777) != 0600) || (st.st_nlink != 1))
		return -1;
	client = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (client < 0)
		return -1;
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, sizeof(address.sun_path), "%s", endpoint);
	if ((set_socket_timeout_ms(client, timeout_ms) != 0) ||
	    (connect(client, (struct sockaddr*)&address, sizeof(address)) != 0) ||
	    !peer_is_manager(client, owner_pid))
	{
		close(client);
		return -1;
	}
	*fd = client;
	return 0;
}

static int connect_owner(const char* runtime_dir, const char* session_id, int* fd, pid_t* owner_pid)
{
	return connect_owner_timeout(runtime_dir, session_id, fd, owner_pid,
	                             FRDP_PAM_OWNER_COMMAND_TIMEOUT_MS);
}

static int request_owner(const char* runtime_dir, const char* session_id, uint32_t type, pid_t pid,
                         pid_t pgid)
{
	uint32_t response_type = 0;
	pid_t response_pid = -1;
	pid_t response_pgid = -1;
	int response_status = -1;
	int fd = -1;
	int rc = -1;

	if ((connect_owner(runtime_dir, session_id, &fd, NULL) != 0) ||
	    (send_message(fd, type, pid, pgid, 0) != 0) ||
	    (receive_message(fd, &response_type, &response_pid, &response_pgid, &response_status) !=
	     0) ||
	    (response_type != FRDP_PAM_OWNER_RESPONSE) || (response_pid != 0) || (response_pgid != 0) ||
	    (response_status != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (fd >= 0)
		close(fd);
	return rc;
}

static int takeover_owner(const char* runtime_dir, const char* session_id,
                          frdpSesmandPamOwner* owner, uint64_t timeout_ms,
                          unsigned int attempts)
{
	if (!owner || owner->active || (timeout_ms == 0) || (attempts == 0))
		return -1;
	for (unsigned int attempt = 0; attempt < attempts; attempt++)
	{
		uint32_t response_type = 0;
		pid_t response_pid = -1;
		pid_t response_pgid = -1;
		pid_t owner_pid = -1;
		int response_status = -1;
		int fd = -1;

		if ((connect_owner_timeout(runtime_dir, session_id, &fd, &owner_pid, timeout_ms) == 0) &&
		    (set_socket_timeout_ms(fd, timeout_ms) == 0) &&
		    (send_message(fd, FRDP_PAM_OWNER_TAKEOVER, 0, 0, 0) == 0) &&
		    (receive_message(fd, &response_type, &response_pid, &response_pgid,
		                     &response_status) == 0) &&
		    (response_type == FRDP_PAM_OWNER_RESPONSE) && (response_pid == 0) &&
		    (response_pgid == 0) && (response_status == 0) && (owner_pid > 1))
		{
			close(fd);
			owner->pid = owner_pid;
			owner->active = 1;
			return 0;
		}
		if (fd >= 0)
			close(fd);
	}
	return -1;
}

int frdp_sesmand_pam_owner_takeover(const char* runtime_dir, const char* session_id,
                                    frdpSesmandPamOwner* owner)
{
	return takeover_owner(runtime_dir, session_id, owner, 1000U, 2U);
}

int frdp_sesmand_pam_owner_takeover_fast(const char* runtime_dir, const char* session_id,
                                         frdpSesmandPamOwner* owner)
{
	return takeover_owner(runtime_dir, session_id, owner, 100U, 1U);
}

int frdp_sesmand_pam_owner_bind_agent(const char* runtime_dir, const char* session_id,
                                      frdpSesmandPamOwner* owner, pid_t agent_pid, pid_t pgid)
{
	if (!owner || !owner->active || (owner->pid <= 1) || (agent_pid <= 1) || (pgid != agent_pid))
		return -1;
	return request_owner(runtime_dir, session_id, FRDP_PAM_OWNER_BIND, agent_pid, pgid);
}

int frdp_sesmand_pam_owner_bind_logind(const char* runtime_dir, const char* session_id,
                                       frdpSesmandPamOwner* owner, int fifo_fd)
{
	uint32_t response_type = 0;
	pid_t response_pid = -1;
	pid_t response_pgid = -1;
	int response_status = -1;
	int fd = -1;
	int rc = -1;

	if (!owner || !owner->active || (owner->pid <= 1) || (fifo_fd < 0) ||
	    (connect_owner(runtime_dir, session_id, &fd, NULL) != 0) ||
	    (send_message_fd(fd, FRDP_PAM_OWNER_BIND_LOGIND, fifo_fd) != 0) ||
	    (receive_message(fd, &response_type, &response_pid, &response_pgid, &response_status) !=
	     0) ||
	    (response_type != FRDP_PAM_OWNER_RESPONSE) || (response_pid != 0) ||
	    (response_pgid != 0) || (response_status != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (fd >= 0)
		close(fd);
	return rc;
}

int frdp_sesmand_pam_owner_get_logind(const char* runtime_dir, const char* session_id,
                                      frdpSesmandPamOwner* owner, int* fifo_fd)
{
	uint32_t response_type = 0;
	pid_t response_pid = -1;
	pid_t response_pgid = -1;
	struct stat fifo_stat = { 0 };
	int response_status = -1;
	int received_fd = -1;
	int fd = -1;
	int rc = -1;

	if (fifo_fd)
		*fifo_fd = -1;
	if (!owner || !owner->active || (owner->pid <= 1) || !fifo_fd ||
	    (connect_owner(runtime_dir, session_id, &fd, NULL) != 0) ||
	    (send_message(fd, FRDP_PAM_OWNER_GET_LOGIND, 0, 0, 0) != 0) ||
	    (receive_message_fd(fd, &response_type, &response_pid, &response_pgid, &response_status,
	                        &received_fd) != 0) ||
	    (response_type != FRDP_PAM_OWNER_RESPONSE) || (response_pid != 0) ||
	    (response_pgid != 0) || (response_status != 0) || (received_fd < 0) ||
	    (fstat(received_fd, &fifo_stat) != 0) || !S_ISFIFO(fifo_stat.st_mode) ||
	    (fcntl(received_fd, F_SETFD, FD_CLOEXEC) != 0))
		goto cleanup;
	*fifo_fd = received_fd;
	received_fd = -1;
	rc = 0;

cleanup:
	if (received_fd >= 0)
		close(received_fd);
	if (fd >= 0)
		close(fd);
	return rc;
}

static int wait_owner_child(pid_t pid)
{
	int status = 0;

	for (unsigned int attempt = 0; attempt < 100U; attempt++)
	{
		const pid_t result = waitpid(pid, &status, WNOHANG);

		if (result == pid)
			return WIFEXITED(status) && (WEXITSTATUS(status) == 0) ? 0 : -1;
		if ((result < 0) && (errno == ECHILD))
			return 0;
		if (result < 0)
			return -1;
		usleep(10000);
	}
	return -1;
}

static int close_owner_common(const char* runtime_dir, const char* session_id,
                              frdpSesmandPamOwner* owner, int consume_receipt)
{
	int rc = -1;

	(void)request_owner(runtime_dir, session_id, FRDP_PAM_OWNER_CLOSE, 0, 0);
	rc = check_receipt(runtime_dir, session_id, consume_receipt);
	if (owner && owner->active)
	{
		if ((owner->pid > 1) && (wait_owner_child(owner->pid) != 0))
			rc = -1;
		owner->pid = -1;
		owner->active = 0;
	}
	return rc;
}

int frdp_sesmand_pam_owner_close(const char* runtime_dir, const char* session_id,
                                 frdpSesmandPamOwner* owner)
{
	if (!owner || !owner->active)
		return -1;
	return close_owner_common(runtime_dir, session_id, owner, 1);
}

int frdp_sesmand_pam_owner_prepare_close(const char* runtime_dir, const char* session_id,
                                         frdpSesmandPamOwner* owner)
{
	if (!owner || !owner->active)
		return -1;
	return close_owner_common(runtime_dir, session_id, owner, 0);
}

int frdp_sesmand_pam_owner_recover(const char* runtime_dir, const char* session_id)
{
	frdpSesmandPamOwner owner = { .pid = -1, .active = 0 };

	if (frdp_sesmand_pam_owner_takeover(runtime_dir, session_id, &owner) == 0)
		return close_owner_common(runtime_dir, session_id, &owner, 0);
	return close_owner_common(runtime_dir, session_id, NULL, 0);
}

int frdp_sesmand_pam_owner_finalize(const char* runtime_dir, const char* session_id)
{
	return check_receipt(runtime_dir, session_id, 1);
}

static int artifact_session_id(const char* name, const char* suffix, char session_id[37])
{
	static const char prefix[] = "pam-";
	const size_t prefix_length = sizeof(prefix) - 1U;
	const size_t suffix_length = strlen(suffix);

	if (!name || !suffix || (strlen(name) != (prefix_length + 36U + suffix_length)) ||
	    (memcmp(name, prefix, prefix_length) != 0) ||
	    (memcmp(&name[prefix_length + 36U], suffix, suffix_length) != 0))
		return -1;
	memcpy(session_id, &name[prefix_length], 36U);
	session_id[36] = '\0';
	return session_id_is_valid(session_id) ? 0 : -1;
}

static int remove_stale_endpoint(int dirfd, const char* runtime_dir, const char* name,
                                 const struct stat* expected)
{
	char endpoint[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	struct sockaddr_un address = { 0 };
	int client = -1;
	int connect_error = 0;

	if (!S_ISSOCK(expected->st_mode) || (expected->st_uid != geteuid()) ||
	    ((expected->st_mode & 0777) != 0600) || (expected->st_nlink != 1) ||
	    (snprintf(endpoint, sizeof(endpoint), "%s/%s", runtime_dir, name) >= (int)sizeof(endpoint)))
		return -1;
	client = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (client < 0)
		return -1;
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, sizeof(address.sun_path), "%s", endpoint);
	if (connect(client, (struct sockaddr*)&address, sizeof(address)) == 0)
	{
		close(client);
		return -1;
	}
	connect_error = errno;
	close(client);
	if ((connect_error != ECONNREFUSED) && (connect_error != ENOENT))
		return -1;
	return remove_matching_artifact(dirfd, name, expected);
}

static int remove_stale_agent_socket(int dirfd, const char* runtime_dir, const char* session_id)
{
	char name[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	char path[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	struct sockaddr_un address = { 0 };
	struct stat st = { 0 };
	int client = -1;
	int connect_error = 0;

	if ((snprintf(name, sizeof(name), "agent-%s.sock", session_id) >= (int)sizeof(name)) ||
	    (snprintf(path, sizeof(path), "%s/%s", runtime_dir, name) >= (int)sizeof(path)))
		return -1;
	if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
		return errno == ENOENT ? 0 : -1;
	if (!S_ISSOCK(st.st_mode) || (st.st_uid != geteuid()) || ((st.st_mode & 0777) != 0600) ||
	    (st.st_nlink != 1))
		return -1;
	client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (client < 0)
		return -1;
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
	if (connect(client, (struct sockaddr*)&address, sizeof(address)) == 0)
	{
		close(client);
		return -1;
	}
	connect_error = errno;
	close(client);
	if ((connect_error != ECONNREFUSED) && (connect_error != ENOENT))
		return -1;
	return remove_matching_artifact(dirfd, name, &st);
}

int frdp_sesmand_pam_owner_reconcile_stale_except(const char* runtime_dir,
                                                  frdpSesmandPamOwnerKeepCallback keep,
                                                  void* context)
{
	struct stat directory_stat = { 0 };
	DIR* directory = NULL;
	struct dirent* entry = NULL;
	int dirfd = -1;
	int scanfd = -1;
	int rc = -1;

	if (!runtime_dir || (runtime_dir[0] != '/'))
		return -1;
	dirfd = open(runtime_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if ((dirfd < 0) || (fstat(dirfd, &directory_stat) != 0) || !S_ISDIR(directory_stat.st_mode) ||
	    (directory_stat.st_uid != geteuid()))
		goto cleanup;
	scanfd = dup(dirfd);
	if ((scanfd < 0) || !(directory = fdopendir(scanfd)))
		goto cleanup;
	scanfd = -1;
	for (;;)
	{
		errno = 0;
		entry = readdir(directory);
		if (!entry)
		{
			if (errno != 0)
				goto cleanup;
			break;
		}
		char session_id[37] = { 0 };
		struct stat st = { 0 };
		const int live_endpoint = artifact_session_id(entry->d_name, ".sock", session_id) == 0;

		if (live_endpoint && keep && keep(session_id, context))
			continue;

		if (artifact_session_id(entry->d_name, ".sock", session_id) == 0)
		{
			if (fstatat(dirfd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
			{
				if (errno == ENOENT)
					continue;
				goto cleanup;
			}
			if ((check_receipt(runtime_dir, session_id, 0) != 0) ||
			    (remove_stale_endpoint(dirfd, runtime_dir, entry->d_name, &st) != 0))
				goto cleanup;
		}
		else if (artifact_session_id(entry->d_name, ".closed", session_id) == 0)
		{
			char endpoint_name[64] = { 0 };

			if ((check_receipt(runtime_dir, session_id, 0) != 0) ||
			    (snprintf(endpoint_name, sizeof(endpoint_name), "pam-%s.sock", session_id) >=
			     (int)sizeof(endpoint_name)))
				goto cleanup;
			if (fstatat(dirfd, endpoint_name, &st, AT_SYMLINK_NOFOLLOW) == 0)
			{
				if (remove_stale_endpoint(dirfd, runtime_dir, endpoint_name, &st) != 0)
					goto cleanup;
			}
			else if (errno != ENOENT)
				goto cleanup;
			if ((remove_stale_agent_socket(dirfd, runtime_dir, session_id) != 0) ||
			    (frdp_sesmand_pam_owner_finalize(runtime_dir, session_id) != 0))
				goto cleanup;
		}
		else if (artifact_session_id(entry->d_name, ".failed", session_id) == 0)
		{
			(void)check_failure_marker(runtime_dir, session_id);
			goto cleanup;
		}
	}
	if (fsync(dirfd) != 0)
		goto cleanup;
	rc = 0;

cleanup:
	if (directory)
		closedir(directory);
	else if (scanfd >= 0)
		close(scanfd);
	if (dirfd >= 0)
		close(dirfd);
	return rc;
}

int frdp_sesmand_pam_owner_reconcile_stale(const char* runtime_dir)
{
	return frdp_sesmand_pam_owner_reconcile_stale_except(runtime_dir, NULL, NULL);
}
