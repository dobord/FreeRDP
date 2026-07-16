#include "session_scope.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <systemd/sd-bus.h>

#define FRDP_SYSTEMD_BUS_TIMEOUT_USEC 5000000ULL
#define FRDP_SYSTEMD_STATE_POLL_USEC 10000U
#define FRDP_SYSTEMD_CGROUP_ROOT "/sys/fs/cgroup/system.slice"

static uint64_t monotonic_usec(void)
{
	struct timespec now = { 0 };

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return 0;
	return ((uint64_t)now.tv_sec * 1000000ULL) + ((uint64_t)now.tv_nsec / 1000ULL);
}

static int scope_name_component_is_valid(const char* session_id)
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
		else if (!((c >= '0') && (c <= '9')) && !((c >= 'a') && (c <= 'f')))
			return 0;
	}
	return 1;
}

int frdp_sesmand_scope_name(const char* session_id, char* name, size_t name_size)
{
	int rc = 0;

	if (!scope_name_component_is_valid(session_id) || !name || (name_size == 0U))
		return -1;
	rc = snprintf(name, name_size, "frdp-session-%s.scope", session_id);
	return ((rc > 0) && ((size_t)rc < name_size)) ? 0 : -1;
}

static int scope_name_is_valid(const char* name)
{
	char expected[FRDP_SESMAND_SCOPE_NAME_SIZE] = { 0 };
	char session_id[37] = { 0 };
	static const char prefix[] = "frdp-session-";

	if (!name || (strlen(name) != (sizeof(prefix) - 1U + 36U + sizeof(".scope") - 1U)))
		return 0;
	memcpy(session_id, name + sizeof(prefix) - 1U, sizeof(session_id) - 1U);
	return (frdp_sesmand_scope_name(session_id, expected, sizeof(expected)) == 0) &&
	       (strcmp(name, expected) == 0);
}

int frdp_sesmand_scope_limits(const frdpSessionResourcePolicy* policy, uint64_t* tasks_max,
                              uint64_t* memory_max, uint64_t* cpu_quota_per_sec_usec)
{
	const uint64_t mb = 1024ULL * 1024ULL;
	const uint64_t percent_usec = 10000ULL;

	if (!policy || !tasks_max || !memory_max || !cpu_quota_per_sec_usec)
		return -1;
	*tasks_max = policy->max_processes;
	*memory_max = (uint64_t)policy->memory_max_mb * mb;
	*cpu_quota_per_sec_usec = (uint64_t)policy->cpu_quota_percent * percent_usec;
	if ((*memory_max / mb) != policy->memory_max_mb)
		return -1;
	if ((*cpu_quota_per_sec_usec / percent_usec) != policy->cpu_quota_percent)
		return -1;
	return 0;
}

void frdp_sesmand_scope_manager_uninit(frdpSesmandScopeManager* manager)
{
	if (!manager)
		return;
	manager->bus = sd_bus_unref((sd_bus*)manager->bus);
}

static int manager_ping(frdpSesmandScopeManager* manager)
{
	sd_bus_error error = SD_BUS_ERROR_NULL;
	int rc = -1;

	if (!manager || !manager->bus)
		return -1;
	rc = sd_bus_call_method((sd_bus*)manager->bus, "org.freedesktop.systemd1",
	                        "/org/freedesktop/systemd1", "org.freedesktop.DBus.Peer", "Ping",
	                        &error, NULL, NULL);
	sd_bus_error_free(&error);
	return (rc < 0) ? -1 : 0;
}

int frdp_sesmand_scope_manager_init(frdpSesmandScopeManager* manager)
{
	sd_bus* bus = NULL;

	if (!manager)
		return -1;
	if (manager->bus && (manager_ping(manager) == 0))
		return 0;
	frdp_sesmand_scope_manager_uninit(manager);
	if ((sd_bus_open_system(&bus) < 0) ||
	    (sd_bus_set_method_call_timeout(bus, FRDP_SYSTEMD_BUS_TIMEOUT_USEC) < 0))
	{
		sd_bus_unref(bus);
		return -1;
	}
	manager->bus = bus;
	if (manager_ping(manager) != 0)
	{
		frdp_sesmand_scope_manager_uninit(manager);
		return -1;
	}
	return 0;
}

static int append_string_property(sd_bus_message* message, const char* name, const char* value)
{
	int rc = sd_bus_message_open_container(message, SD_BUS_TYPE_STRUCT, "sv");

	if (rc < 0)
		return rc;
	if ((rc = sd_bus_message_append(message, "s", name)) < 0)
		return rc;
	if ((rc = sd_bus_message_open_container(message, SD_BUS_TYPE_VARIANT, "s")) < 0)
		return rc;
	if ((rc = sd_bus_message_append(message, "s", value)) < 0)
		return rc;
	if ((rc = sd_bus_message_close_container(message)) < 0)
		return rc;
	return sd_bus_message_close_container(message);
}

static int append_boolean_property(sd_bus_message* message, const char* name, int value)
{
	int rc = sd_bus_message_open_container(message, SD_BUS_TYPE_STRUCT, "sv");

	if (rc < 0)
		return rc;
	if ((rc = sd_bus_message_append(message, "s", name)) < 0)
		return rc;
	if ((rc = sd_bus_message_open_container(message, SD_BUS_TYPE_VARIANT, "b")) < 0)
		return rc;
	if ((rc = sd_bus_message_append(message, "b", value)) < 0)
		return rc;
	if ((rc = sd_bus_message_close_container(message)) < 0)
		return rc;
	return sd_bus_message_close_container(message);
}

static int append_uint64_property(sd_bus_message* message, const char* name, uint64_t value)
{
	int rc = sd_bus_message_open_container(message, SD_BUS_TYPE_STRUCT, "sv");

	if (rc < 0)
		return rc;
	if ((rc = sd_bus_message_append(message, "s", name)) < 0)
		return rc;
	if ((rc = sd_bus_message_open_container(message, SD_BUS_TYPE_VARIANT, "t")) < 0)
		return rc;
	if ((rc = sd_bus_message_append(message, "t", value)) < 0)
		return rc;
	if ((rc = sd_bus_message_close_container(message)) < 0)
		return rc;
	return sd_bus_message_close_container(message);
}

static int append_pid_property(sd_bus_message* message, uint32_t pid)
{
	int rc = sd_bus_message_open_container(message, SD_BUS_TYPE_STRUCT, "sv");

	if (rc < 0)
		return rc;
	if ((rc = sd_bus_message_append(message, "s", "PIDs")) < 0)
		return rc;
	if ((rc = sd_bus_message_open_container(message, SD_BUS_TYPE_VARIANT, "au")) < 0)
		return rc;
	if ((rc = sd_bus_message_open_container(message, SD_BUS_TYPE_ARRAY, "u")) < 0)
		return rc;
	if ((rc = sd_bus_message_append(message, "u", pid)) < 0)
		return rc;
	if ((rc = sd_bus_message_close_container(message)) < 0)
		return rc;
	if ((rc = sd_bus_message_close_container(message)) < 0)
		return rc;
	return sd_bus_message_close_container(message);
}

static int get_unit_active_state(frdpSesmandScopeManager* manager, const char* name, char* state,
                                 size_t state_size, int* missing)
{
	sd_bus_error error = SD_BUS_ERROR_NULL;
	sd_bus_message* reply = NULL;
	char object_path[256] = { 0 };
	char* value = NULL;
	const char* returned_path = NULL;
	int rc = -1;

	if (!manager || !manager->bus || !scope_name_is_valid(name) || !state || (state_size == 0U) ||
	    !missing)
		return -1;
	*missing = 0;
	rc = sd_bus_call_method((sd_bus*)manager->bus, "org.freedesktop.systemd1",
	                        "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager",
	                        "GetUnit", &error, &reply, "s", name);
	if ((rc < 0) && sd_bus_error_has_name(&error, "org.freedesktop.systemd1.NoSuchUnit"))
	{
		*missing = 1;
		rc = 0;
		goto cleanup;
	}
	if ((rc < 0) || (sd_bus_message_read(reply, "o", &returned_path) < 0) || !returned_path ||
	    (snprintf(object_path, sizeof(object_path), "%s", returned_path) >=
	     (int)sizeof(object_path)))
		goto cleanup;
	sd_bus_message_unref(reply);
	reply = NULL;
	sd_bus_error_free(&error);
	rc = sd_bus_get_property_string((sd_bus*)manager->bus, "org.freedesktop.systemd1", object_path,
	                                "org.freedesktop.systemd1.Unit", "ActiveState", &error, &value);
	if ((rc < 0) || !value || (snprintf(state, state_size, "%s", value) >= (int)state_size))
		goto cleanup;
	rc = 0;

cleanup:
	free(value);
	sd_bus_error_free(&error);
	sd_bus_message_unref(reply);
	return (rc < 0) ? -1 : 0;
}

static int wait_for_scope_state(frdpSesmandScopeManager* manager, const char* name, int starting)
{
	const uint64_t start = monotonic_usec();
	const uint64_t deadline = start + FRDP_SYSTEMD_BUS_TIMEOUT_USEC;

	if (start == 0)
		return -1;
	for (;;)
	{
		char state[32] = { 0 };
		int missing = 0;

		if (get_unit_active_state(manager, name, state, sizeof(state), &missing) != 0)
			return -1;
		if (starting)
		{
			if (!missing && (strcmp(state, "active") == 0))
				return 0;
			if (!missing && (strcmp(state, "failed") == 0))
				return -1;
		}
		else if (missing || (strcmp(state, "inactive") == 0) || (strcmp(state, "failed") == 0))
			return 0;
		if (monotonic_usec() >= deadline)
			return -1;
		usleep(FRDP_SYSTEMD_STATE_POLL_USEC);
	}
}

int frdp_sesmand_scope_start(frdpSesmandScopeManager* manager, const char* session_id, pid_t pid,
                             const frdpSessionResourcePolicy* policy, char* name, size_t name_size)
{
	sd_bus_error error = SD_BUS_ERROR_NULL;
	sd_bus_message* message = NULL;
	sd_bus_message* reply = NULL;
	uint64_t tasks_max = 0;
	uint64_t memory_max = 0;
	uint64_t cpu_quota_per_sec_usec = 0;
	int rc = -1;

	if (!manager || (pid <= 0) || ((uint64_t)pid > UINT32_MAX) ||
	    (frdp_sesmand_scope_name(session_id, name, name_size) != 0) ||
	    (frdp_sesmand_scope_limits(policy, &tasks_max, &memory_max, &cpu_quota_per_sec_usec) !=
	     0) ||
	    (frdp_sesmand_scope_manager_init(manager) != 0))
		return -1;
	rc = sd_bus_message_new_method_call((sd_bus*)manager->bus, &message, "org.freedesktop.systemd1",
	                                    "/org/freedesktop/systemd1",
	                                    "org.freedesktop.systemd1.Manager", "StartTransientUnit");
	if (rc < 0)
		goto cleanup;
	if ((rc = sd_bus_message_append(message, "ss", name, "fail")) < 0 ||
	    (rc = sd_bus_message_open_container(message, SD_BUS_TYPE_ARRAY, "(sv)")) < 0 ||
	    (rc = append_string_property(message, "Description", "FreeRDP managed desktop session")) <
	        0 ||
	    (rc = append_string_property(message, "Slice", "system.slice")) < 0 ||
	    (rc = append_string_property(message, "CollectMode", "inactive-or-failed")) < 0 ||
	    (rc = append_string_property(message, "KillMode", "control-group")) < 0 ||
	    (rc = append_boolean_property(message, "TasksAccounting", 1)) < 0 ||
	    (rc = append_boolean_property(message, "MemoryAccounting", 1)) < 0 ||
	    (rc = append_pid_property(message, (uint32_t)pid)) < 0)
		goto cleanup;
	if ((tasks_max > 0U) && ((rc = append_uint64_property(message, "TasksMax", tasks_max)) < 0))
		goto cleanup;
	if ((memory_max > 0U) && ((rc = append_uint64_property(message, "MemoryMax", memory_max)) < 0))
		goto cleanup;
	if ((cpu_quota_per_sec_usec > 0U) &&
	    ((rc = append_uint64_property(message, "CPUQuotaPerSecUSec", cpu_quota_per_sec_usec)) < 0))
		goto cleanup;
	if ((rc = sd_bus_message_close_container(message)) < 0 ||
	    (rc = sd_bus_message_open_container(message, SD_BUS_TYPE_ARRAY, "(sa(sv))")) < 0 ||
	    (rc = sd_bus_message_close_container(message)) < 0)
		goto cleanup;
	rc = sd_bus_call((sd_bus*)manager->bus, message, FRDP_SYSTEMD_BUS_TIMEOUT_USEC, &error, &reply);
	if ((rc >= 0) && (wait_for_scope_state(manager, name, 1) != 0))
		rc = -1;

cleanup:
	sd_bus_error_free(&error);
	sd_bus_message_unref(reply);
	sd_bus_message_unref(message);
	if (rc < 0)
		frdp_sesmand_scope_manager_uninit(manager);
	return (rc < 0) ? -1 : 0;
}

static int cgroup_is_empty_or_missing(const char* path)
{
	char events_path[PATH_MAX] = { 0 };
	char content[256] = { 0 };
	int fd = -1;
	ssize_t count = 0;

	if (!path || (snprintf(events_path, sizeof(events_path), "%s/cgroup.events", path) >=
	              (int)sizeof(events_path)))
		return -1;
	fd = open(events_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return (errno == ENOENT) ? 1 : -1;
	do
	{
		count = read(fd, content, sizeof(content) - 1U);
	} while ((count < 0) && (errno == EINTR));
	close(fd);
	if (count < 0)
		return -1;
	content[count] = '\0';
	return strstr(content, "populated 0\n") ? 1 : 0;
}

static int force_kill_scope_cgroup(const char* name)
{
	const uint64_t start = monotonic_usec();
	const uint64_t deadline = start + FRDP_SYSTEMD_BUS_TIMEOUT_USEC;
	char cgroup_path[PATH_MAX] = { 0 };
	char kill_path[PATH_MAX] = { 0 };
	int fd = -1;
	ssize_t count = 0;

	if ((start == 0) || !scope_name_is_valid(name) ||
	    (snprintf(cgroup_path, sizeof(cgroup_path), FRDP_SYSTEMD_CGROUP_ROOT "/%s", name) >=
	     (int)sizeof(cgroup_path)) ||
	    (snprintf(kill_path, sizeof(kill_path), "%s/cgroup.kill", cgroup_path) >=
	     (int)sizeof(kill_path)))
		return -1;
	fd = open(kill_path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
	{
		if (errno != ENOENT)
			return -1;
		return (access(cgroup_path, F_OK) != 0) && (errno == ENOENT) ? 0 : -1;
	}
	do
	{
		count = write(fd, "1\n", 2U);
	} while ((count < 0) && (errno == EINTR));
	close(fd);
	if (count != 2)
		return -1;
	for (;;)
	{
		const int empty = cgroup_is_empty_or_missing(cgroup_path);

		if (empty > 0)
			return 0;
		if ((empty < 0) || (monotonic_usec() >= deadline))
			return -1;
		usleep(FRDP_SYSTEMD_STATE_POLL_USEC);
	}
}

int frdp_sesmand_scope_stop(frdpSesmandScopeManager* manager, const char* name)
{
	sd_bus_error error = SD_BUS_ERROR_NULL;
	sd_bus_message* message = NULL;
	sd_bus_message* reply = NULL;
	int rc = -1;

	if (!manager || !scope_name_is_valid(name))
		return -1;
	if (frdp_sesmand_scope_manager_init(manager) == 0)
	{
		rc = sd_bus_message_new_method_call((sd_bus*)manager->bus, &message,
		                                    "org.freedesktop.systemd1",
		                                    "/org/freedesktop/systemd1",
		                                    "org.freedesktop.systemd1.Manager", "StopUnit");
		if ((rc >= 0) && ((rc = sd_bus_message_append(message, "ss", name, "replace")) >= 0))
			rc = sd_bus_call((sd_bus*)manager->bus, message, FRDP_SYSTEMD_BUS_TIMEOUT_USEC, &error,
			                 &reply);
		if ((rc < 0) && sd_bus_error_has_name(&error, "org.freedesktop.systemd1.NoSuchUnit"))
			rc = 0;
		else if ((rc >= 0) && (wait_for_scope_state(manager, name, 0) != 0))
			rc = -1;
	}
	sd_bus_error_free(&error);
	sd_bus_message_unref(reply);
	sd_bus_message_unref(message);
	if (rc >= 0)
		return force_kill_scope_cgroup(name);
	frdp_sesmand_scope_manager_uninit(manager);
	return force_kill_scope_cgroup(name);
}
