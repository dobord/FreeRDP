#include "frdp-sesmand/session_pam_owner.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int create_listener(const char* path)
{
	struct sockaddr_un address = { 0 };
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);

	if ((fd < 0) || (strlen(path) >= sizeof(address.sun_path)))
		return -1;
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
	if ((bind(fd, (struct sockaddr*)&address, sizeof(address)) != 0) || (chmod(path, 0600) != 0) ||
	    (listen(fd, 1) != 0))
	{
		close(fd);
		unlink(path);
		return -1;
	}
	return fd;
}

int TestFreeRDPFrdpSessionPamOwner(int argc, char* argv[])
{
	static const char session_id[] = "01234567-89ab-cdef-0123-456789abcdef";
	static const char receipt[] = "FRDP-PAM-CLOSED-1\n";
	static const char failure[] = "FRDP-PAM-CLOSE-FAILED-1\n";
	char dir[] = "/tmp/frdp-pam-owner-XXXXXX";
	char path[128] = { 0 };
	char closed[128] = { 0 };
	char agent[128] = { 0 };
	char failed[128] = { 0 };
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	int listener = -1;
	int agent_listener = -1;
	int fd = -1;

	(void)argc;
	(void)argv;
	if ((frdp_sesmand_pam_owner_endpoint(path, sizeof(path), "/run/frdp-sesmand", session_id) !=
	     0) ||
	    (strcmp(path, "/run/frdp-sesmand/pam-01234567-89ab-cdef-0123-456789abcdef.sock") != 0))
		return -1;
	if ((frdp_sesmand_pam_owner_endpoint(NULL, sizeof(path), "/run/frdp-sesmand", session_id) ==
	     0) ||
	    (frdp_sesmand_pam_owner_endpoint(path, 8U, "/run/frdp-sesmand", session_id) == 0) ||
	    (frdp_sesmand_pam_owner_endpoint(path, sizeof(path), "relative", session_id) == 0) ||
	    (frdp_sesmand_pam_owner_endpoint(path, sizeof(path), "/run/frdp-sesmand", "../invalid") ==
	     0))
		return -1;
	if (!mkdtemp(dir) || (chmod(dir, 0700) != 0) ||
	    (frdp_sesmand_pam_owner_endpoint(path, sizeof(path), dir, session_id) != 0) ||
	    ((listener = create_listener(path)) < 0) ||
	    (frdp_sesmand_pam_owner_reconcile_stale(dir) == 0) || (access(path, F_OK) != 0))
		goto fail;
	close(listener);
	listener = -1;
	if ((frdp_sesmand_pam_owner_reconcile_stale(dir) == 0) || (access(path, F_OK) != 0) ||
	    (snprintf(closed, sizeof(closed), "%s/pam-%s.closed", dir, session_id) >=
	     (int)sizeof(closed)) ||
	    (snprintf(failed, sizeof(failed), "%s/pam-%s.failed", dir, session_id) >=
	     (int)sizeof(failed)) ||
	    (snprintf(agent, sizeof(agent), "%s/agent-%s.sock", dir, session_id) >=
	     (int)sizeof(agent)) ||
	    ((agent_listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0) ||
	    (snprintf((address.sun_path), sizeof(address.sun_path), "%s", agent) >=
	     (int)sizeof(address.sun_path)) ||
	    (bind(agent_listener, (struct sockaddr*)&address, sizeof(address)) != 0) ||
	    (chmod(agent, 0600) != 0) ||
	    ((fd = open(closed, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600)) < 0) ||
	    (write(fd, receipt, sizeof(receipt) - 1U) != (ssize_t)(sizeof(receipt) - 1U)) ||
	    (close(fd) != 0))
		goto fail;
	fd = -1;
	close(agent_listener);
	agent_listener = -1;
	if ((frdp_sesmand_pam_owner_reconcile_stale(dir) != 0) || (access(closed, F_OK) == 0) ||
	    (access(agent, F_OK) == 0) || (access(path, F_OK) == 0) ||
	    ((fd = open(failed, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600)) < 0) ||
	    (write(fd, failure, sizeof(failure) - 1U) != (ssize_t)(sizeof(failure) - 1U)) ||
	    (close(fd) != 0))
		goto fail;
	fd = -1;
	if ((frdp_sesmand_pam_owner_reconcile_stale(dir) == 0) || (access(failed, F_OK) != 0))
		goto fail;
	unlink(failed);
	if (rmdir(dir) != 0)
		goto fail;
	return 0;

fail:
	if (fd >= 0)
		close(fd);
	if (listener >= 0)
		close(listener);
	if (agent_listener >= 0)
		close(agent_listener);
	unlink(path);
	unlink(closed);
	unlink(agent);
	unlink(failed);
	rmdir(dir);
	return -1;
}
