#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(HAVE_PAM_PAM_APPL_H)
#include <pam/pam_modules.h>
#else
#include <security/pam_modules.h>
#endif

#define FRDP_PAM_TEST_AUDIT_ENV "FRDP_PAM_TEST_AUDIT_FILE"
#define FRDP_PAM_TEST_BLOCK_AUTH_ENV "FRDP_PAM_TEST_BLOCK_AUTH"

static int append_audit_record(const char* record)
{
	const char* path = getenv(FRDP_PAM_TEST_AUDIT_ENV);
	const size_t length = record ? strlen(record) : 0;
	size_t offset = 0;
	int fd = -1;

	if (!path || !path[0] || !record || (length == 0))
		return -1;
	fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -1;
	while (offset < length)
	{
		const ssize_t written = write(fd, record + offset, length - offset);

		if (written > 0)
		{
			offset += (size_t)written;
			continue;
		}
		if ((written < 0) && (errno == EINTR))
			continue;
		close(fd);
		return -1;
	}
	return close(fd);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	if (append_audit_record("authenticate-start\n") != 0)
		return PAM_SYSTEM_ERR;
	if (getenv(FRDP_PAM_TEST_BLOCK_AUTH_ENV))
	{
		for (;;)
			pause();
	}
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
	const char* record = (flags & PAM_DELETE_CRED) ? "setcred-delete\n" : "setcred-establish\n";

	(void)pamh;
	(void)argc;
	(void)argv;
	return append_audit_record(record) == 0 ? PAM_SUCCESS : PAM_SYSTEM_ERR;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return append_audit_record("account\n") == 0 ? PAM_SUCCESS : PAM_SYSTEM_ERR;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	if (append_audit_record("open-session-start\n") != 0)
		return PAM_SYSTEM_ERR;
#if defined(FRDP_PAM_TEST_ALWAYS_BLOCK_SESSION)
	{
		for (;;)
			pause();
	}
#endif
#if defined(FRDP_PAM_TEST_ALLOW_SESSION_OPEN)
	return PAM_SUCCESS;
#else
	if (append_audit_record("open-session-denied\n") != 0)
		return PAM_SYSTEM_ERR;
	return PAM_SESSION_ERR;
#endif
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	if (append_audit_record("close-session-start\n") != 0)
		return PAM_SYSTEM_ERR;
#if defined(FRDP_PAM_TEST_ALWAYS_BLOCK_SESSION_CLOSE)
	for (;;)
		pause();
#endif
	return append_audit_record("close-session\n") == 0 ? PAM_SUCCESS : PAM_SYSTEM_ERR;
}
