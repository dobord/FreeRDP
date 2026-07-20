#include "session_logind.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-login.h>

#define FRDP_LOGIND_BUS_TIMEOUT_USEC 5000000ULL
#define FRDP_LOGIND_DESTINATION "org.freedesktop.login1"
#define FRDP_LOGIND_PATH "/org/freedesktop/login1"
#define FRDP_LOGIND_INTERFACE "org.freedesktop.login1.Manager"

static int manager_ping(frdpSesmandLogindManager* manager)
{
	sd_bus_error error = SD_BUS_ERROR_NULL;
	int rc = -1;

	if (!manager || !manager->bus)
		return -1;
	rc = sd_bus_call_method((sd_bus*)manager->bus, FRDP_LOGIND_DESTINATION, FRDP_LOGIND_PATH,
	                        "org.freedesktop.DBus.Peer", "Ping", &error, NULL, NULL);
	sd_bus_error_free(&error);
	return (rc < 0) ? -1 : 0;
}

void frdp_sesmand_logind_manager_uninit(frdpSesmandLogindManager* manager)
{
	if (manager)
		manager->bus = sd_bus_unref((sd_bus*)manager->bus);
}

int frdp_sesmand_logind_manager_init(frdpSesmandLogindManager* manager)
{
	sd_bus* bus = NULL;

	if (!manager)
		return -1;
	if (manager->bus && (manager_ping(manager) == 0))
		return 0;
	frdp_sesmand_logind_manager_uninit(manager);
	if ((sd_bus_open_system(&bus) < 0) ||
	    (sd_bus_set_method_call_timeout(bus, FRDP_LOGIND_BUS_TIMEOUT_USEC) < 0))
	{
		sd_bus_unref(bus);
		return -1;
	}
	manager->bus = bus;
	if (manager_ping(manager) != 0)
	{
		frdp_sesmand_logind_manager_uninit(manager);
		return -1;
	}
	return 0;
}

void frdp_sesmand_logind_session_close(frdpSesmandLogindSession* session)
{
	if (!session)
		return;
	if (session->fifo_fd >= 0)
		close(session->fifo_fd);
	memset(session, 0, sizeof(*session));
	session->fifo_fd = -1;
}

static int copy_reply_string(char* dst, size_t dst_size, const char* value)
{
	const int rc = value ? snprintf(dst, dst_size, "%s", value) : -1;

	return ((rc > 0) && ((size_t)rc < dst_size)) ? 0 : -1;
}

static int open_pidfd(pid_t pid)
{
#ifdef SYS_pidfd_open
	int fd = -1;

	do
	{
		fd = (int)syscall(SYS_pidfd_open, pid, 0U);
	} while ((fd < 0) && (errno == EINTR));
	if ((fd >= 0) && (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0))
	{
		close(fd);
		return -1;
	}
	return fd;
#else
	(void)pid;
	errno = ENOSYS;
	return -1;
#endif
}

static int pidfd_fallback_allowed(int error)
{
	return (error == ENOSYS) || (error == EINVAL) || (error == EPERM) || (error == EACCES);
}

static int append_create_arguments(sd_bus_message* message, uid_t uid, pid_t pid, int pidfd,
                                   const char* service, const char* user, const char* remote_host,
                                   const char* display)
{
	int rc = -1;

	if (pidfd >= 0)
		rc = sd_bus_message_append(message, "uhsssssussbsst", (uint32_t)uid, pidfd, service, "x11",
		                           "user", "freerdp", "", 0U, "", display, 1, user, remote_host,
		                           0ULL);
	else
		rc = sd_bus_message_append(message, "uusssssussbss", (uint32_t)uid, (uint32_t)pid, service,
		                           "x11", "user", "freerdp", "", 0U, "", display, 1, user,
		                           remote_host);
	if ((rc < 0) ||
	    ((rc = sd_bus_message_open_container(message, SD_BUS_TYPE_ARRAY, "(sv)")) < 0) ||
	    ((rc = sd_bus_message_close_container(message)) < 0))
		return -1;
	return 0;
}

int frdp_sesmand_logind_create(frdpSesmandLogindManager* manager, uid_t uid, pid_t pid,
                               const char* service, const char* user, const char* remote_host,
                               const char* display, frdpSesmandLogindSession* session)
{
	sd_bus_error error = SD_BUS_ERROR_NULL;
	sd_bus_message* message = NULL;
	sd_bus_message* reply = NULL;
	const char* returned_id = NULL;
	const char* object_path = NULL;
	const char* runtime_path = NULL;
	const char* seat = NULL;
	const char* create_method = NULL;
	struct stat fifo_stat = { 0 };
	uint32_t returned_uid = 0;
	uint32_t vtnr = 0;
	int borrowed_fifo_fd = -1;
	int existing = 0;
	int pidfd = -1;
	int pidfd_error = 0;
	int rc = -1;
	int success = 0;

	if (!session || !manager || !service || (service[0] == '\0') || !user || (user[0] == '\0') ||
	    !remote_host || !display || (display[0] == '\0') || (pid <= 1) ||
	    ((uint64_t)uid > UINT32_MAX) || ((uint64_t)pid > UINT32_MAX))
		return -1;
	memset(session, 0, sizeof(*session));
	session->fifo_fd = -1;
	if (frdp_sesmand_logind_manager_init(manager) != 0)
		return -1;
	pidfd = open_pidfd(pid);
	pidfd_error = errno;
	if ((pidfd < 0) && !pidfd_fallback_allowed(pidfd_error))
		goto cleanup;
	create_method = (pidfd >= 0) ? "CreateSessionWithPIDFD" : "CreateSession";
	rc = sd_bus_message_new_method_call((sd_bus*)manager->bus, &message, FRDP_LOGIND_DESTINATION,
	                                    FRDP_LOGIND_PATH, FRDP_LOGIND_INTERFACE, create_method);
	if ((rc < 0) || (append_create_arguments(message, uid, pid, pidfd, service, user, remote_host,
	                                         display) != 0))
		goto cleanup;
	rc = sd_bus_call((sd_bus*)manager->bus, message, FRDP_LOGIND_BUS_TIMEOUT_USEC, &error, &reply);
	if ((pidfd >= 0) && (rc < 0) && sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD))
	{
		sd_bus_error_free(&error);
		sd_bus_message_unref(reply);
		reply = NULL;
		sd_bus_message_unref(message);
		message = NULL;
		rc = sd_bus_message_new_method_call((sd_bus*)manager->bus, &message,
		                                    FRDP_LOGIND_DESTINATION, FRDP_LOGIND_PATH,
		                                    FRDP_LOGIND_INTERFACE, "CreateSession");
		if ((rc < 0) || (append_create_arguments(message, uid, pid, -1, service, user, remote_host,
		                                         display) != 0))
			goto cleanup;
		rc = sd_bus_call((sd_bus*)manager->bus, message, FRDP_LOGIND_BUS_TIMEOUT_USEC, &error,
		                 &reply);
	}
	if ((rc < 0) ||
	    ((rc = sd_bus_message_read(reply, "soshusub", &returned_id, &object_path, &runtime_path,
	                               &borrowed_fifo_fd, &returned_uid, &seat, &vtnr, &existing)) <
	     0) ||
	    !object_path || (object_path[0] != '/') || !seat || (returned_uid != (uint32_t)uid) ||
	    existing || (vtnr != 0U) ||
	    (copy_reply_string(session->id, sizeof(session->id), returned_id) != 0) ||
	    (copy_reply_string(session->runtime_path, sizeof(session->runtime_path), runtime_path) !=
	     0) ||
	    (session->runtime_path[0] != '/') || (borrowed_fifo_fd < 0))
		goto cleanup;
	session->fifo_fd = fcntl(borrowed_fifo_fd, F_DUPFD_CLOEXEC, 3);
	if ((session->fifo_fd < 0) || (fstat(session->fifo_fd, &fifo_stat) != 0) ||
	    !S_ISFIFO(fifo_stat.st_mode))
		goto cleanup;
	success = 1;

cleanup:
	if (!success && sd_bus_error_is_set(&error))
		fprintf(stderr, "login1 %s failed: %s: %s\n", create_method ? create_method : "request",
		        error.name ? error.name : "unknown error",
		        error.message ? error.message : "no details");
	else if (!success)
		fprintf(stderr, "login1 %s returned an invalid response\n",
		        create_method ? create_method : "request");
	if (pidfd >= 0)
		close(pidfd);
	sd_bus_error_free(&error);
	sd_bus_message_unref(reply);
	sd_bus_message_unref(message);
	if (!success)
	{
		frdp_sesmand_logind_session_close(session);
		frdp_sesmand_logind_manager_uninit(manager);
		return -1;
	}
	return 0;
}

int frdp_sesmand_logind_recover(frdpSesmandLogindManager* manager, uid_t uid, pid_t pid,
                                const char* service, const char* user, const char* display,
                                int fifo_fd, frdpSesmandLogindSession* session)
{
	sd_bus_error error = SD_BUS_ERROR_NULL;
	sd_bus_message* reply = NULL;
	sd_bus_message* user_reply = NULL;
	char object_path[256] = { 0 };
	char* id = NULL;
	char* returned_user = NULL;
	char* returned_service = NULL;
	char* type = NULL;
	char* session_class = NULL;
	char* returned_display = NULL;
	char* runtime_path = NULL;
	char* pid_session = NULL;
	const char* returned_path = NULL;
	const char* user_path = NULL;
	struct stat fifo_stat = { 0 };
	uint32_t returned_uid = 0;
	uint32_t leader = 0;
	int remote = 0;
	int rc = -1;

	if (!manager || !session || !service || (service[0] == '\0') || !user ||
	    (user[0] == '\0') || !display || (display[0] == '\0') || (pid <= 1) ||
	    ((uint64_t)uid > UINT32_MAX) || ((uint64_t)pid > UINT32_MAX) || (fifo_fd < 0) ||
	    (fstat(fifo_fd, &fifo_stat) != 0) || !S_ISFIFO(fifo_stat.st_mode) ||
	    (fcntl(fifo_fd, F_SETFD, FD_CLOEXEC) != 0) ||
	    (frdp_sesmand_logind_manager_init(manager) != 0))
		return -1;
	memset(session, 0, sizeof(*session));
	session->fifo_fd = -1;
	if ((sd_bus_call_method((sd_bus*)manager->bus, FRDP_LOGIND_DESTINATION, FRDP_LOGIND_PATH,
	                        FRDP_LOGIND_INTERFACE, "GetSessionByPID", &error, &reply, "u",
	                        (uint32_t)pid) < 0) ||
	    (sd_bus_message_read(reply, "o", &returned_path) < 0) || !returned_path ||
	    (snprintf(object_path, sizeof(object_path), "%s", returned_path) >=
	     (int)sizeof(object_path)))
		goto cleanup;
	sd_bus_message_unref(reply);
	reply = NULL;
	sd_bus_error_free(&error);
	if ((sd_bus_get_property_string((sd_bus*)manager->bus, FRDP_LOGIND_DESTINATION, object_path,
	                                "org.freedesktop.login1.Session", "Id", &error, &id) < 0) ||
	    (sd_bus_get_property_string((sd_bus*)manager->bus, FRDP_LOGIND_DESTINATION, object_path,
	                                "org.freedesktop.login1.Session", "Name", &error,
	                                &returned_user) < 0) ||
	    (sd_bus_get_property_string((sd_bus*)manager->bus, FRDP_LOGIND_DESTINATION, object_path,
	                                "org.freedesktop.login1.Session", "Service", &error,
	                                &returned_service) < 0) ||
	    (sd_bus_get_property_string((sd_bus*)manager->bus, FRDP_LOGIND_DESTINATION, object_path,
	                                "org.freedesktop.login1.Session", "Type", &error, &type) < 0) ||
	    (sd_bus_get_property_string((sd_bus*)manager->bus, FRDP_LOGIND_DESTINATION, object_path,
	                                "org.freedesktop.login1.Session", "Class", &error,
	                                &session_class) < 0) ||
	    (sd_bus_get_property_string((sd_bus*)manager->bus, FRDP_LOGIND_DESTINATION, object_path,
	                                "org.freedesktop.login1.Session", "Display", &error,
	                                &returned_display) < 0) ||
	    (sd_bus_get_property_trivial((sd_bus*)manager->bus, FRDP_LOGIND_DESTINATION, object_path,
	                                 "org.freedesktop.login1.Session", "Leader", &error, 'u',
	                                 &leader) < 0) ||
	    (sd_bus_get_property_trivial((sd_bus*)manager->bus, FRDP_LOGIND_DESTINATION, object_path,
	                                 "org.freedesktop.login1.Session", "Remote", &error, 'b',
	                                 &remote) < 0) ||
	    (sd_bus_get_property((sd_bus*)manager->bus, FRDP_LOGIND_DESTINATION, object_path,
	                         "org.freedesktop.login1.Session", "User", &error, &user_reply,
	                         "(uo)") < 0) ||
	    (sd_bus_message_read(user_reply, "(uo)", &returned_uid, &user_path) < 0) || !user_path ||
	    (sd_bus_get_property_string((sd_bus*)manager->bus, FRDP_LOGIND_DESTINATION, user_path,
	                                "org.freedesktop.login1.User", "RuntimePath", &error,
	                                &runtime_path) < 0) ||
	    (sd_pid_get_session(pid, &pid_session) < 0) || !id || !returned_user ||
	    !returned_service || !type || !session_class || !returned_display || !runtime_path ||
	    !pid_session || (strcmp(id, pid_session) != 0) || (strcmp(returned_user, user) != 0) ||
	    (strcmp(returned_service, service) != 0) || (strcmp(type, "x11") != 0) ||
	    (strcmp(session_class, "user") != 0) || (strcmp(returned_display, display) != 0) ||
	    (runtime_path[0] != '/') || (returned_uid != (uint32_t)uid) ||
	    (leader != (uint32_t)pid) || !remote ||
	    (copy_reply_string(session->id, sizeof(session->id), id) != 0) ||
	    (copy_reply_string(session->runtime_path, sizeof(session->runtime_path), runtime_path) != 0))
		goto cleanup;
	session->fifo_fd = fifo_fd;
	rc = 0;

cleanup:
	free(pid_session);
	free(runtime_path);
	free(returned_display);
	free(session_class);
	free(type);
	free(returned_service);
	free(returned_user);
	free(id);
	sd_bus_message_unref(user_reply);
	sd_bus_message_unref(reply);
	sd_bus_error_free(&error);
	if (rc != 0)
	{
		frdp_sesmand_logind_session_close(session);
		frdp_sesmand_logind_manager_uninit(manager);
	}
	return rc;
}

int frdp_sesmand_logind_release(frdpSesmandLogindManager* manager,
                                frdpSesmandLogindSession* session)
{
	sd_bus_error error = SD_BUS_ERROR_NULL;
	int rc = -1;

	if (!manager || !session || (session->id[0] == '\0') || (session->fifo_fd < 0) ||
	    (frdp_sesmand_logind_manager_init(manager) != 0))
		return -1;
	rc =
	    sd_bus_call_method((sd_bus*)manager->bus, FRDP_LOGIND_DESTINATION, FRDP_LOGIND_PATH,
	                       FRDP_LOGIND_INTERFACE, "ReleaseSession", &error, NULL, "s", session->id);
	if ((rc < 0) && sd_bus_error_has_name(&error, "org.freedesktop.login1.NoSuchSession"))
		rc = 0;
	sd_bus_error_free(&error);
	if (rc < 0)
	{
		frdp_sesmand_logind_manager_uninit(manager);
		return -1;
	}
	frdp_sesmand_logind_session_close(session);
	return 0;
}
