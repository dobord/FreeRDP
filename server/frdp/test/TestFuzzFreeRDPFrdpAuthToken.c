#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "ipc/frdp-auth-token.h"

#define FRDP_AUTH_TOKEN_FUZZ_MAX_SIZE 1024U

static char g_fuzz_key_path[128] = { 0 };

static int write_all(int fd, const uint8_t* data, size_t size)
{
	size_t offset = 0;

	while (offset < size)
	{
		const ssize_t rc = write(fd, data + offset, size - offset);
		if (rc < 0)
			return -1;
		if (rc == 0)
			return -1;
		offset += (size_t)rc;
	}
	return 0;
}

static void cleanup_fuzz_key(void)
{
	if (g_fuzz_key_path[0])
		(void)unlink(g_fuzz_key_path);
}

static int ensure_fuzz_key(void)
{
	static int initialized = 0;
	char key_template[] = "/tmp/frdp-auth-token-fuzz-XXXXXX";
	const uint8_t key[32] = {
		0x46, 0x52, 0x44, 0x50, 0x2d, 0x61, 0x75, 0x74,
		0x68, 0x2d, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x2d,
		0x66, 0x75, 0x7a, 0x7a, 0x2d, 0x6b, 0x65, 0x79,
		0x2d, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31
	};
	int fd = -1;

	if (initialized)
		return g_fuzz_key_path[0] ? 0 : -1;
	fd = mkstemp(key_template);
	if (fd < 0)
		return -1;
	if (fchmod(fd, 0600) != 0)
	{
		(void)close(fd);
		(void)unlink(key_template);
		initialized = 1;
		return -1;
	}
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1)
	{
		(void)close(fd);
		(void)unlink(key_template);
		initialized = 1;
		return -1;
	}
	memcpy(g_fuzz_key_path, key_template, sizeof(key_template));
	if (write_all(fd, key, sizeof(key)) != 0)
	{
		(void)close(fd);
		(void)unlink(g_fuzz_key_path);
		g_fuzz_key_path[0] = '\0';
		initialized = 1;
		return -1;
	}
	if (close(fd) != 0)
	{
		(void)unlink(g_fuzz_key_path);
		g_fuzz_key_path[0] = '\0';
		initialized = 1;
		return -1;
	}
	if (setenv(FRDP_AUTH_TOKEN_KEY_ENV, g_fuzz_key_path, 1) != 0)
	{
		(void)unlink(g_fuzz_key_path);
		g_fuzz_key_path[0] = '\0';
		initialized = 1;
		return -1;
	}
	if (atexit(cleanup_fuzz_key) != 0)
	{
		(void)unlink(g_fuzz_key_path);
		g_fuzz_key_path[0] = '\0';
		initialized = 1;
		return -1;
	}
	initialized = 1;
	return 0;
}

static void fuzz_verify_token(const uint8_t* data, size_t size)
{
	char token[FRDP_AUTH_TOKEN_FUZZ_MAX_SIZE + 1U] = { 0 };
	char nonce[37];
	char cleared_nonce[sizeof(nonce)] = { 0 };
	unsigned long long expires_at = ULLONG_MAX;
	uint64_t groups[FRDP_AUTH_TOKEN_MAX_GROUPS] = { 1001, 1002 };
	uint32_t group_count = 2;
	size_t token_len = size;

	if (!data || (size == 0))
		return;
	if (token_len > FRDP_AUTH_TOKEN_FUZZ_MAX_SIZE)
		token_len = FRDP_AUTH_TOKEN_FUZZ_MAX_SIZE;
	memcpy(token, data, token_len);
	token[token_len] = '\0';
	group_count = (uint32_t)(data[0] % (FRDP_AUTH_TOKEN_MAX_GROUPS + 1U));
	for (uint32_t x = 0; x < group_count; x++)
		groups[x] = (uint64_t)(1000U + x + ((size > x) ? data[x] : 0U));

	memset(nonce, 0xa5, sizeof(nonce));
	if (frdp_auth_token_verify(token, "alice", "198.51.100.8", "corr-1", 1000, 1001, groups,
	                           group_count, 1, nonce, sizeof(nonce), &expires_at) == 0)
	{
		if ((nonce[0] == '\0') || (expires_at == 0))
			abort();
	}
	else if ((memcmp(nonce, cleared_nonce, sizeof(nonce)) != 0) || (expires_at != 0))
		abort();
}

static void fuzz_valid_token_path(const uint8_t* data, size_t size)
{
	char user[32] = "alice";
	char rhost[32] = "198.51.100.8";
	char correlation_id[32] = "corr-1";
	char token[192] = { 0 };
	char nonce[37] = { 0 };
	unsigned long long expires_at = 0;
	uint64_t groups[FRDP_AUTH_TOKEN_MAX_GROUPS] = { 1001, 1002 };
	uint32_t group_count = 2;
	size_t user_len = 0;

	if (!data || (size == 0))
		return;
	user_len = (size_t)(data[0] % (sizeof(user) - 1U));
	if (user_len > 0)
		memcpy(user, data, user_len);
	user[user_len] = '\0';
	group_count = (uint32_t)((size > 1U ? data[1] : 0U) % 4U);
	for (uint32_t x = 0; x < group_count; x++)
		groups[x] = (uint64_t)(2000U + x);
	if (frdp_auth_token_create(user, rhost, correlation_id, 1000, 1001, groups, group_count, 1,
	                           token, sizeof(token)) != 0)
		return;
	(void)frdp_auth_token_verify(token, user, rhost, correlation_id, 1000, 1001, groups,
	                             group_count, 1, nonce, sizeof(nonce), &expires_at);
}

int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
	if (!Data || (Size > FRDP_AUTH_TOKEN_FUZZ_MAX_SIZE))
		return 0;
	if (ensure_fuzz_key() != 0)
		return 0;
	fuzz_verify_token(Data, Size);
	if ((Size >= 4U) && (memcmp(Data, "FRDP", 4U) == 0))
		fuzz_valid_token_path(Data, Size);
	return 0;
}
