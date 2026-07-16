#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ipc/frdp-ipc.h"
#include "frdp-sesmand/display_policy.h"
#include "frdp-sesmand/process_identity.h"
#include "frdp-sesmand/session_metadata.h"
#include "frdp-sesmand/session_recovery.h"
#include "frdp-sesmand/session_scope.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include <systemd/sd-bus.h>
#include <winpr/crt.h>

#ifndef FRDP_AUTHD_BINARY
#error "FRDP_AUTHD_BINARY is not defined"
#endif
#ifndef FRDP_SESMAND_BINARY
#error "FRDP_SESMAND_BINARY is not defined"
#endif
#ifndef FRDP_SYSTEMD_RUN_BINARY
#error "FRDP_SYSTEMD_RUN_BINARY is not defined"
#endif
#ifndef FRDP_SYSTEMCTL_BINARY
#error "FRDP_SYSTEMCTL_BINARY is not defined"
#endif

#define FRDP_SYSTEMD_COMMAND_TIMEOUT_MS 3000U
#define FRDP_SYSTEMD_HEALTH_TIMEOUT_MS 100U
#define FRDP_SYSTEMD_SKIP 77

static uint64_t monotonic_ms(void)
{
	struct timespec now = { 0 };

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return 0;
	return ((uint64_t)now.tv_sec * 1000U) + ((uint64_t)now.tv_nsec / 1000000U);
}

static int run_command(char* const argv[], char* output, size_t output_size)
{
	pid_t child = -1;
	uint64_t deadline = 0;
	int output_pipe[2] = { -1, -1 };
	int status = 0;

	if (!argv || !argv[0] || (!!output != (output_size > 0)))
		return -1;
	if (output && (pipe(output_pipe) != 0))
		return -1;
	if (output)
		output[0] = '\0';
	child = fork();
	if (child < 0)
		goto fail;
	if (child == 0)
	{
		const int null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);

		if (output)
		{
			close(output_pipe[0]);
			if (dup2(output_pipe[1], STDOUT_FILENO) < 0)
				_exit(127);
		}
		else if ((null_fd < 0) || (dup2(null_fd, STDOUT_FILENO) < 0))
			_exit(127);
		if ((null_fd < 0) || (dup2(null_fd, STDERR_FILENO) < 0))
			_exit(127);
		if (output_pipe[1] >= 0)
			close(output_pipe[1]);
		if (null_fd > STDERR_FILENO)
			close(null_fd);
		execv(argv[0], argv);
		_exit(127);
	}
	if (output)
		close(output_pipe[1]);
	output_pipe[1] = -1;
	if (output && (fcntl(output_pipe[0], F_SETFL, O_NONBLOCK) != 0))
		goto timeout;
	deadline = monotonic_ms();
	if (deadline == 0)
		goto timeout;
	deadline += FRDP_SYSTEMD_COMMAND_TIMEOUT_MS;
	for (;;)
	{
		const pid_t waited = waitpid(child, &status, WNOHANG);

		if (waited == child)
			break;
		if ((waited < 0) && (errno != EINTR))
			goto timeout;
		if (monotonic_ms() >= deadline)
			goto timeout;
		usleep(10000);
	}
	if (output)
	{
		ssize_t count = 0;
		size_t offset = 0;

		while ((offset + 1U) < output_size)
		{
			count = read(output_pipe[0], &output[offset], output_size - offset - 1U);
			if (count > 0)
			{
				offset += (size_t)count;
				continue;
			}
			if ((count < 0) && (errno == EINTR))
				continue;
			break;
		}
		output[offset] = '\0';
	}
	if (output_pipe[0] >= 0)
		close(output_pipe[0]);
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;

timeout:
	kill(child, SIGKILL);
	while ((waitpid(child, NULL, 0) < 0) && (errno == EINTR))
	{
	}
fail:
	if (output_pipe[0] >= 0)
		close(output_pipe[0]);
	if (output_pipe[1] >= 0)
		close(output_pipe[1]);
	return -1;
}

static int helper_health(const char* socket_path, const char* expected_role)
{
	frdpControlResponse response = { 0 };
	int fd = -1;
	int rc = -1;

	if (!socket_path || !expected_role)
		return -1;
	fd = frdp_ipc_connect_timeout(socket_path, FRDP_SYSTEMD_HEALTH_TIMEOUT_MS);
	if ((fd < 0) ||
	    (frdp_ipc_exchange_helper_health(fd, &response, FRDP_SYSTEMD_HEALTH_TIMEOUT_MS) != 0) ||
	    !response.success || !memchr(response.message, '\0', sizeof(response.message)) ||
	    !memchr(response.error, '\0', sizeof(response.error)) || (response.error[0] != '\0') ||
	    (strcmp(response.message, expected_role) != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (fd >= 0)
		frdp_ipc_close(fd);
	SecureZeroMemory(&response, sizeof(response));
	return rc;
}

static int wait_for_initial_health(const char* socket_path, const char* expected_role,
                                   int* socket_fd)
{
	for (int attempt = 0; attempt < 30; attempt++)
	{
		struct stat current = { 0 };
		struct stat pinned = { 0 };
		int fd = -1;

		if ((lstat(socket_path, &current) == 0) && S_ISSOCK(current.st_mode) &&
		    ((current.st_mode & 0777) == 0600) &&
		    (helper_health(socket_path, expected_role) == 0) &&
		    ((fd = open(socket_path, O_PATH | O_CLOEXEC | O_NOFOLLOW)) >= 0) &&
		    (fstat(fd, &pinned) == 0) && (pinned.st_dev == current.st_dev) &&
		    (pinned.st_ino == current.st_ino))
		{
			*socket_fd = fd;
			return 0;
		}
		if (fd >= 0)
			close(fd);
		usleep(100000);
	}
	return -1;
}

static int wait_for_restarted_health(const char* socket_path, const char* expected_role,
                                     int previous_fd)
{
	struct stat previous = { 0 };

	if ((previous_fd < 0) || (fstat(previous_fd, &previous) != 0))
		return -1;
	for (int attempt = 0; attempt < 30; attempt++)
	{
		struct stat current = { 0 };

		if ((lstat(socket_path, &current) == 0) && S_ISSOCK(current.st_mode) &&
		    ((current.st_dev != previous.st_dev) || (current.st_ino != previous.st_ino)) &&
		    (helper_health(socket_path, expected_role) == 0))
			return 0;
		usleep(100000);
	}
	return -1;
}

static int output_has_line(const char* output, const char* expected)
{
	const size_t expected_len = expected ? strlen(expected) : 0;
	const char* current = output;

	if (!output || !expected || (expected_len == 0))
		return 0;
	while ((current = strstr(current, expected)) != NULL)
	{
		if (((current == output) || (current[-1] == '\n')) &&
		    ((current[expected_len] == '\0') || (current[expected_len] == '\n')))
			return 1;
		current += expected_len;
	}
	return 0;
}

static int wait_for_unit_stopped(char* const show_argv[])
{
	for (int attempt = 0; attempt < 3; attempt++)
	{
		char output[256] = { 0 };
		const int status = run_command(show_argv, output, sizeof(output));

		if (status == 4)
			return 0;
		if ((status == 0) && output_has_line(output, "Job=") &&
		    (output_has_line(output, "LoadState=not-found") ||
		     (output_has_line(output, "MainPID=0") &&
		      output_has_line(output, "ActiveState=inactive") &&
		      output_has_line(output, "SubState=dead"))))
			return 0;
		usleep(100000);
	}
	return -1;
}

static int wait_for_child_exit(pid_t child)
{
	const uint64_t start = monotonic_ms();
	int status = 0;

	if ((child <= 0) || (start == 0))
		return -1;
	for (;;)
	{
		const pid_t waited = waitpid(child, &status, WNOHANG);

		if (waited == child)
		{
			if (WIFSIGNALED(status) || (WIFEXITED(status) && (WEXITSTATUS(status) == 0)))
				return 0;
			return -1;
		}
		if ((waited < 0) && (errno != EINTR))
			return -1;
		if ((monotonic_ms() - start) >= FRDP_SYSTEMD_COMMAND_TIMEOUT_MS)
			return -1;
		usleep(10000);
	}
}

static int process_is_in_scope(pid_t pid, const char* scope_name)
{
	char cgroup_path[64] = { 0 };
	char content[4096] = { 0 };
	FILE* fp = NULL;
	size_t count = 0;

	if ((pid <= 0) || !scope_name ||
	    (snprintf(cgroup_path, sizeof(cgroup_path), "/proc/%ld/cgroup", (long)pid) >=
	     (int)sizeof(cgroup_path)))
		return 0;
	fp = fopen(cgroup_path, "r");
	if (!fp)
		return 0;
	count = fread(content, 1, sizeof(content) - 1U, fp);
	fclose(fp);
	content[count] = '\0';
	return strstr(content, scope_name) != NULL;
}

static int test_write_exact(int fd, const void* data, size_t size)
{
	const unsigned char* bytes = (const unsigned char*)data;
	size_t offset = 0;

	while (offset < size)
	{
		const ssize_t count = write(fd, bytes + offset, size - offset);

		if ((count < 0) && (errno == EINTR))
			continue;
		if (count <= 0)
			return -1;
		offset += (size_t)count;
	}
	return 0;
}

static int test_read_exact(int fd, void* data, size_t size)
{
	unsigned char* bytes = (unsigned char*)data;
	size_t offset = 0;

	while (offset < size)
	{
		const ssize_t count = read(fd, bytes + offset, size - offset);

		if ((count < 0) && (errno == EINTR))
			continue;
		if (count <= 0)
			return -1;
		offset += (size_t)count;
	}
	return 0;
}

static int wait_for_process_gone(pid_t pid)
{
	for (int attempt = 0; attempt < 300; attempt++)
	{
		if ((kill(pid, 0) != 0) && (errno == ESRCH))
			return 0;
		usleep(10000);
	}
	return -1;
}

static int test_session_scope(void)
{
	frdpSesmandScopeManager manager = { 0 };
	frdpSessionResourcePolicy policy = {
		.max_processes = 17,
		.memory_max_mb = 64,
		.cpu_quota_percent = 25,
		.systemd_scope = 1,
	};
	uuid_t session_uuid = { 0 };
	char session_id[37] = { 0 };
	char scope_name[FRDP_SESMAND_SCOPE_NAME_SIZE] = { 0 };
	char expected_cgroup[FRDP_SESMAND_SCOPE_NAME_SIZE + 32U] = { 0 };
	char properties[512] = { 0 };
	char runtime_dir[128] = "/tmp/frdp-scope-recovery-XXXXXX";
	char agent_socket_path[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	char reservation_path[256] = { 0 };
	char metadata_name[96] = { 0 };
	char metadata_path[256] = { 0 };
	char launch_marker = 'G';
	char ready_marker = 0;
	frdpSesmandSessionMetadata metadata = { 0 };
	struct sockaddr_un address = { 0 };
	struct stat socket_stat = { 0 };
	struct stat reservation_stat = { 0 };
	uint64_t metadata_dev = 0;
	uint64_t metadata_ino = 0;
	int launch_pipe[2] = { -1, -1 };
	int status_pipe[2] = { -1, -1 };
	int agent_socket_fd = -1;
	int reservation_fd = -1;
	pid_t child = -1;
	pid_t detached_child = -1;
	int scope_started = 0;
	int child_reaped = 0;
	int metadata_saved = 0;
	int rc = -1;
	const char* stage = "fork";
	char* show_argv[] = { (char*)FRDP_SYSTEMCTL_BINARY,
		                  "show",
		                  "--property=ControlGroup",
		                  "--property=TasksMax",
		                  "--property=MemoryMax",
		                  "--property=CPUQuotaPerSecUSec",
		                  scope_name,
		                  NULL };
	char* stopped_argv[] = { (char*)FRDP_SYSTEMCTL_BINARY,
		                     "show",
		                     "--property=LoadState",
		                     "--property=ActiveState",
		                     "--property=SubState",
		                     "--property=Job",
		                     "--property=MainPID",
		                     scope_name,
		                     NULL };

	uuid_generate_random(session_uuid);
	uuid_unparse_lower(session_uuid, session_id);
	if ((pipe2(launch_pipe, O_CLOEXEC) != 0) || (pipe2(status_pipe, O_CLOEXEC) != 0))
		goto cleanup;
	child = fork();
	if (child < 0)
		goto cleanup;
	if (child == 0)
	{
		pid_t descendant = -1;

		close(launch_pipe[1]);
		close(status_pipe[0]);
		if ((setpgid(0, 0) != 0) || (test_write_exact(status_pipe[1], "R", 1U) != 0) ||
		    (test_read_exact(launch_pipe[0], &ready_marker, 1U) != 0) || (ready_marker != 'G'))
			_exit(2);
		descendant = fork();
		if (descendant < 0)
			_exit(3);
		if (descendant == 0)
		{
			if (setsid() < 0)
				_exit(4);
			for (;;)
				pause();
		}
		if (test_write_exact(status_pipe[1], &descendant, sizeof(descendant)) != 0)
			_exit(5);
		for (;;)
			pause();
	}
	close(launch_pipe[0]);
	launch_pipe[0] = -1;
	close(status_pipe[1]);
	status_pipe[1] = -1;
	if ((test_read_exact(status_pipe[0], &ready_marker, 1U) != 0) || (ready_marker != 'R'))
		goto cleanup;
	stage = "manager init";
	if (frdp_sesmand_scope_manager_init(&manager) != 0)
		goto cleanup;
	stage = "manager reconnect";
	sd_bus_close((sd_bus*)manager.bus);
	if (frdp_sesmand_scope_manager_init(&manager) != 0)
		goto cleanup;
	stage = "scope start";
	if (frdp_sesmand_scope_start(&manager, session_id, child, &policy, scope_name,
	                             sizeof(scope_name)) != 0)
		goto cleanup;
	scope_started = 1;
	stage = "properties";
	if ((snprintf(expected_cgroup, sizeof(expected_cgroup), "ControlGroup=/system.slice/%s",
	              scope_name) >= (int)sizeof(expected_cgroup)) ||
	    (run_command(show_argv, properties, sizeof(properties)) != 0) ||
	    !output_has_line(properties, expected_cgroup) ||
	    !output_has_line(properties, "TasksMax=17") ||
	    !output_has_line(properties, "MemoryMax=67108864") ||
	    !output_has_line(properties, "CPUQuotaPerSecUSec=250ms") ||
	    !process_is_in_scope(child, scope_name))
		goto cleanup;
	stage = "detached descendant";
	if ((test_write_exact(launch_pipe[1], &launch_marker, 1U) != 0) ||
	    (test_read_exact(status_pipe[0], &detached_child, sizeof(detached_child)) != 0) ||
	    (detached_child <= 1))
		goto cleanup;
	for (int attempt = 0; attempt < 100; attempt++)
	{
		if ((getpgid(detached_child) == detached_child) &&
		    process_is_in_scope(detached_child, scope_name))
			break;
		if (attempt == 99)
			goto cleanup;
		usleep(10000);
	}
	stage = "recovery metadata";
	if (!mkdtemp(runtime_dir) || (chmod(runtime_dir, 0700) != 0) ||
	    (snprintf(agent_socket_path, sizeof(agent_socket_path), "%s/agent-%s.sock", runtime_dir,
	              session_id) >= (int)sizeof(agent_socket_path)) ||
	    (frdp_sesmand_display_reservation_path(reservation_path, sizeof(reservation_path),
	                                           runtime_dir, 100) != 0) ||
	    (frdp_sesmand_session_metadata_filename(metadata_name, sizeof(metadata_name), session_id) !=
	     0) ||
	    (snprintf(metadata_path, sizeof(metadata_path), "%s/%s", runtime_dir, metadata_name) >=
	     (int)sizeof(metadata_path)))
		goto cleanup;
	agent_socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	reservation_fd = open(reservation_path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, sizeof(address.sun_path), "%s", agent_socket_path);
	if ((agent_socket_fd < 0) || (reservation_fd < 0) ||
	    (bind(agent_socket_fd, (struct sockaddr*)&address, sizeof(address)) != 0) ||
	    (chmod(agent_socket_path, 0600) != 0) || (lstat(agent_socket_path, &socket_stat) != 0) ||
	    (lstat(reservation_path, &reservation_stat) != 0))
		goto cleanup;
	snprintf(metadata.session_id, sizeof(metadata.session_id), "%s", session_id);
	metadata.uid = geteuid();
	metadata.agent_pid = child;
	metadata.pgid = child;
	metadata.state = FRDP_SESMAND_SESSION_ACTIVE;
	metadata.display_number = 100;
	metadata.agent_socket_dev = (uint64_t)socket_stat.st_dev;
	metadata.agent_socket_ino = (uint64_t)socket_stat.st_ino;
	metadata.display_reservation_dev = (uint64_t)reservation_stat.st_dev;
	metadata.display_reservation_ino = (uint64_t)reservation_stat.st_ino;
	metadata.systemd_scope = 1;
	if ((frdp_sesmand_process_identity_read(child, &metadata.agent_start_ticks, NULL) !=
	     FRDP_SESMAND_PROCESS_IDENTITY_OK) ||
	    (frdp_sesmand_session_metadata_save(runtime_dir, &metadata, &metadata_dev, &metadata_ino) !=
	     FRDP_SESMAND_SESSION_METADATA_SAVE_COMMITTED))
		goto cleanup;
	metadata_saved = 1;
	stage = "scope recovery";
	if (frdp_sesmand_session_reconcile_all(runtime_dir, &manager) != 0)
		goto cleanup;
	metadata_saved = 0;
	scope_started = 0;
	stage = "child exit";
	if ((wait_for_child_exit(child) != 0) || (wait_for_process_gone(detached_child) != 0))
		goto cleanup;
	child_reaped = 1;
	if ((access(agent_socket_path, F_OK) == 0) || (access(reservation_path, F_OK) == 0) ||
	    (access(metadata_path, F_OK) == 0))
		goto cleanup;
	stage = "unit collection";
	if (wait_for_unit_stopped(stopped_argv) != 0)
		goto cleanup;
	rc = 0;

cleanup:
	if (scope_started)
		(void)frdp_sesmand_scope_stop(&manager, scope_name);
	if (launch_pipe[0] >= 0)
		close(launch_pipe[0]);
	if (launch_pipe[1] >= 0)
		close(launch_pipe[1]);
	if (status_pipe[0] >= 0)
		close(status_pipe[0]);
	if (status_pipe[1] >= 0)
		close(status_pipe[1]);
	if (!child_reaped && (child > 0))
	{
		(void)kill(child, SIGKILL);
		while ((waitpid(child, NULL, 0) < 0) && (errno == EINTR))
		{
		}
	}
	if ((detached_child > 1) && (kill(detached_child, 0) == 0))
		(void)kill(detached_child, SIGKILL);
	if (agent_socket_fd >= 0)
		close(agent_socket_fd);
	if (reservation_fd >= 0)
		close(reservation_fd);
	if (metadata_saved)
		unlink(metadata_path);
	unlink(agent_socket_path);
	unlink(reservation_path);
	if (runtime_dir[0] != '\0')
		rmdir(runtime_dir);
	frdp_sesmand_scope_manager_uninit(&manager);
	if (rc != 0)
		fprintf(stderr, "session systemd scope failed at stage: %s\n", stage);
	return rc;
}

static int test_systemd_restart(const char* binary, const char* role, const char* suffix)
{
	char runtime_dir[256] = { 0 };
	char socket_path[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	char unit[128] = { 0 };
	char* start_argv[] = { (char*)FRDP_SYSTEMD_RUN_BINARY,
		                   "--quiet",
		                   "--collect",
		                   "--unit",
		                   unit,
		                   "--property=Type=simple",
		                   "--property=Restart=on-failure",
		                   "--property=RestartSec=100ms",
		                   "--property=TimeoutStopSec=2s",
		                   (char*)binary,
		                   "--socket",
		                   socket_path,
		                   NULL };
	char* kill_argv[] = {
		(char*)FRDP_SYSTEMCTL_BINARY, "kill", "--kill-whom=main", "--signal=KILL", unit, NULL
	};
	char* active_argv[] = { (char*)FRDP_SYSTEMCTL_BINARY, "is-active", "--quiet", unit, NULL };
	char* stop_argv[] = { (char*)FRDP_SYSTEMCTL_BINARY, "stop", unit, NULL };
	char* kill_all_argv[] = {
		(char*)FRDP_SYSTEMCTL_BINARY, "kill", "--kill-whom=all", "--signal=KILL", unit, NULL
	};
	char* show_argv[] = { (char*)FRDP_SYSTEMCTL_BINARY,
		                  "show",
		                  "--property=LoadState",
		                  "--property=ActiveState",
		                  "--property=SubState",
		                  "--property=Job",
		                  "--property=MainPID",
		                  unit,
		                  NULL };
	int attempted = 0;
	int old_socket_fd = -1;
	int stopped = 0;
	int rc = -1;
	const char* stage = "fixture";

	if (!binary || !role || !suffix ||
	    (snprintf(runtime_dir, sizeof(runtime_dir), "/tmp/frdp-systemd-%s-XXXXXX", suffix) >=
	     (int)sizeof(runtime_dir)) ||
	    !mkdtemp(runtime_dir) || (chmod(runtime_dir, 0700) != 0) ||
	    (snprintf(socket_path, sizeof(socket_path), "%s/helper.sock", runtime_dir) >=
	     (int)sizeof(socket_path)) ||
	    (snprintf(unit, sizeof(unit), "frdp-test-%s-%ld.service", suffix, (long)getpid()) >=
	     (int)sizeof(unit)))
		goto cleanup;
	attempted = 1;
	stage = "start";
	if (run_command(start_argv, NULL, 0) != 0)
		goto cleanup;
	stage = "initial-health";
	if (wait_for_initial_health(socket_path, role, &old_socket_fd) != 0)
		goto cleanup;
	stage = "sigkill";
	if (run_command(kill_argv, NULL, 0) != 0)
		goto cleanup;
	stage = "restarted-health";
	if (wait_for_restarted_health(socket_path, role, old_socket_fd) != 0)
		goto cleanup;
	stage = "active";
	if (run_command(active_argv, NULL, 0) != 0)
		goto cleanup;
	rc = 0;

cleanup:
	if (old_socket_fd >= 0)
		close(old_socket_fd);
	if (attempted)
	{
		(void)run_command(stop_argv, NULL, 0);
		stopped = wait_for_unit_stopped(show_argv) == 0;
		if (!stopped)
		{
			(void)run_command(kill_all_argv, NULL, 0);
			(void)run_command(stop_argv, NULL, 0);
			stopped = wait_for_unit_stopped(show_argv) == 0;
		}
		if (!stopped)
			rc = -1;
	}
	if (!attempted || stopped)
	{
		unlink(socket_path);
		if (runtime_dir[0] != '\0')
			rmdir(runtime_dir);
	}
	if (rc != 0)
		fprintf(stderr, "%s systemd recovery failed at stage: %s\n", role, stage);
	return rc;
}

int TestFreeRDPFrdpSystemdRecovery(int argc, char* argv[])
{
	char manager_version[64] = { 0 };
	char* running_argv[] = { (char*)FRDP_SYSTEMCTL_BINARY, "show", "--property=Version", "--value",
		                     NULL };

	(void)argc;
	(void)argv;
	if (geteuid() != 0)
	{
		printf("systemd helper recovery skipped: root required\n");
		return FRDP_SYSTEMD_SKIP;
	}
	if ((run_command(running_argv, manager_version, sizeof(manager_version)) != 0) ||
	    (manager_version[0] == '\0'))
	{
		printf("systemd helper recovery skipped: system manager unavailable\n");
		return FRDP_SYSTEMD_SKIP;
	}
	if (test_session_scope() != 0)
	{
		printf("session systemd scope lifecycle failed\n");
		return -1;
	}
	if (test_systemd_restart(FRDP_AUTHD_BINARY, "frdp-authd", "authd") != 0)
	{
		printf("frdp-authd systemd restart recovery failed\n");
		return -1;
	}
	if (test_systemd_restart(FRDP_SESMAND_BINARY, "frdp-sesmand", "sesmand") != 0)
	{
		printf("frdp-sesmand systemd restart recovery failed\n");
		return -1;
	}
	return 0;
}
