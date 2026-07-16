#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config/trusted-path.h"

int TestFreeRDPFrdpTrustedPath(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	char directory[] = "/run/frdp-trusted-path-XXXXXX";
	char file[256] = { 0 };
	char link[256] = { 0 };
	FILE* fp = NULL;
	int rc = -1;

	if (!frdp_trusted_root_file("/etc/passwd", 0) ||
	    frdp_trusted_root_file("/etc/../etc/passwd", 0))
		return -1;
	if (geteuid() != 0)
		return 0;
	if (!mkdtemp(directory) || chmod(directory, 0700) != 0)
		return -1;
	snprintf(file, sizeof(file), "%s/config", directory);
	snprintf(link, sizeof(link), "%s/link", directory);
	fp = fopen(file, "w");
	if (!fp || fputs("test\n", fp) == EOF)
		goto cleanup;
	if (fclose(fp) != 0)
	{
		fp = NULL;
		goto cleanup;
	}
	fp = NULL;
	if (chmod(file, 0600) != 0 || !frdp_trusted_root_file(file, 0))
		goto cleanup;
	if (chmod(directory, 0770) != 0 || frdp_trusted_root_file(file, 0) ||
	    chmod(directory, 0700) != 0)
		goto cleanup;
	if (chmod(file, 0660) != 0 || frdp_trusted_root_file(file, 0) || chmod(file, 0600) != 0)
		goto cleanup;
	if (symlink(directory, link) != 0)
		goto cleanup;
	char linked_file[256] = { 0 };
	snprintf(linked_file, sizeof(linked_file), "%s/config", link);
	if (frdp_trusted_root_file(linked_file, 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (fp)
		fclose(fp);
	if (link[0] != '\0')
		unlink(link);
	if (file[0] != '\0')
		unlink(file);
	if (directory[0] != '\0')
		rmdir(directory);
	return rc;
}
