#include "trusted-path.h"

#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int trusted_stat(const struct stat* st, int directory)
{
	if (!st || st->st_uid != 0 || (st->st_mode & (S_IWGRP | S_IWOTH)) != 0)
		return 0;
	return directory ? S_ISDIR(st->st_mode) : (S_ISREG(st->st_mode) && st->st_nlink == 1);
}

int frdp_trusted_root_file(const char* path, int executable)
{
	char current[PATH_MAX] = "/";
	const char* component = NULL;
	struct stat st;
	size_t used = 1;

	if (!path || path[0] != '/' || path[1] == '\0' || strlen(path) >= sizeof(current) ||
	    lstat("/", &st) != 0 || !trusted_stat(&st, 1))
		return 0;

	component = path + 1;
	while (*component != '\0')
	{
		const char* slash = strchr(component, '/');
		const size_t length = slash ? (size_t)(slash - component) : strlen(component);
		const int final = slash == NULL;

		if (length == 0 || (length == 1 && component[0] == '.') ||
		    (length == 2 && component[0] == '.' && component[1] == '.') ||
		    used + length + (used > 1 ? 1U : 0U) >= sizeof(current))
			return 0;
		if (used > 1)
			current[used++] = '/';
		memcpy(current + used, component, length);
		used += length;
		current[used] = '\0';
		if (lstat(current, &st) != 0 || !trusted_stat(&st, !final))
			return 0;
		if (final)
			break;
		component = slash + 1;
	}

	return access(path, executable ? X_OK : R_OK) == 0;
}
