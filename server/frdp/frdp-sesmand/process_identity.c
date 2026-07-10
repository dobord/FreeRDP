#include "process_identity.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __linux__
static frdpSesmandProcessIdentityResult process_identity_open_error(void)
{
	return ((errno == ENOENT) || (errno == ESRCH)) ? FRDP_SESMAND_PROCESS_IDENTITY_MISSING
	                                              : FRDP_SESMAND_PROCESS_IDENTITY_ERROR;
}

static int process_identity_parse_stat(char* text, pid_t expected_pid,
                                       unsigned long long* start_ticks)
{
	char* comm_end = NULL;
	char* cursor = NULL;
	char* pid_end = NULL;
	long parsed_pid = 0;

	errno = 0;
	parsed_pid = strtol(text, &pid_end, 10);
	if ((errno != 0) || !pid_end || (pid_end == text) || (pid_end[0] != ' ') ||
	    (pid_end[1] != '(') || (parsed_pid <= 0) || ((long)(pid_t)parsed_pid != parsed_pid) ||
	    ((pid_t)parsed_pid != expected_pid))
		return -1;

	comm_end = strrchr(pid_end + 1, ')');
	if (!comm_end || (comm_end[1] != ' '))
		return -1;
	cursor = comm_end + 2;
	for (unsigned int field = 3; field <= 22; field++)
	{
		char* token_end = NULL;

		while (*cursor == ' ')
			cursor++;
		if (*cursor == '\0')
			return -1;
		token_end = cursor;
		while ((*token_end != '\0') && (*token_end != ' ') && (*token_end != '\n'))
			token_end++;
		if (field == 22)
		{
			char* parsed_end = NULL;
			unsigned long long value = 0;
			const char saved = *token_end;

			if ((*cursor < '0') || (*cursor > '9'))
				return -1;
			*token_end = '\0';
			errno = 0;
			value = strtoull(cursor, &parsed_end, 10);
			*token_end = saved;
			if ((errno != 0) || !parsed_end || (parsed_end != token_end) || (value == 0))
				return -1;
			*start_ticks = value;
			return 0;
		}
		cursor = token_end;
	}
	return -1;
}
#endif

frdpSesmandProcessIdentityResult frdp_sesmand_process_identity_read(
    pid_t pid, unsigned long long* start_ticks, uid_t* owner_uid)
{
#ifdef __linux__
	char pid_name[32] = { 0 };
	char stat_text[4096] = { 0 };
	struct stat process_stat = { 0 };
	ssize_t bytes = 0;
	int process_fd = -1;
	int proc_fd = -1;
	int stat_fd = -1;
	frdpSesmandProcessIdentityResult result = FRDP_SESMAND_PROCESS_IDENTITY_ERROR;

	if ((pid <= 0) || !start_ticks ||
	    (snprintf(pid_name, sizeof(pid_name), "%ld", (long)pid) >= (int)sizeof(pid_name)))
		return FRDP_SESMAND_PROCESS_IDENTITY_ERROR;
	proc_fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (proc_fd < 0)
		return FRDP_SESMAND_PROCESS_IDENTITY_ERROR;
	process_fd = openat(proc_fd, pid_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (process_fd < 0)
	{
		result = process_identity_open_error();
		goto out;
	}
	if ((fstat(process_fd, &process_stat) != 0) || !S_ISDIR(process_stat.st_mode))
		goto out;
	stat_fd = openat(process_fd, "stat", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (stat_fd < 0)
	{
		result = process_identity_open_error();
		goto out;
	}
	do
	{
		bytes = read(stat_fd, stat_text, sizeof(stat_text) - 1U);
	} while ((bytes < 0) && (errno == EINTR));
	if (bytes <= 0)
		goto out;
	stat_text[bytes] = '\0';
	if (process_identity_parse_stat(stat_text, pid, start_ticks) != 0)
		goto out;
	if (owner_uid)
		*owner_uid = process_stat.st_uid;
	result = FRDP_SESMAND_PROCESS_IDENTITY_OK;

out:
	if (stat_fd >= 0)
		close(stat_fd);
	if (process_fd >= 0)
		close(process_fd);
	close(proc_fd);
	return result;
#else
	(void)pid;
	(void)start_ticks;
	(void)owner_uid;
	return FRDP_SESMAND_PROCESS_IDENTITY_ERROR;
#endif
}
