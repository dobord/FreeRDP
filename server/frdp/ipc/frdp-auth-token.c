#define _GNU_SOURCE

#include "frdp-auth-token.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include <winpr/crt.h>
#include <winpr/custom-crypto.h>

#define FRDP_AUTH_TOKEN_KEY_LEN 32U
#define FRDP_AUTH_TOKEN_HMAC_LEN WINPR_SHA256_DIGEST_LENGTH
#define FRDP_AUTH_TOKEN_HEX_LEN (FRDP_AUTH_TOKEN_HMAC_LEN * 2U)

static const char* frdp_auth_token_key_path(void)
{
	const char* path = getenv(FRDP_AUTH_TOKEN_KEY_ENV);

	if (path && (path[0] != '\0'))
		return path;
	return FRDP_AUTH_TOKEN_DEFAULT_KEY_PATH;
}

static int frdp_auth_token_read_key(const char* path, uint8_t* key, size_t key_len)
{
	int fd = -1;
	ssize_t total = 0;
	struct stat st = { 0 };

	if (!path || !key || (key_len != FRDP_AUTH_TOKEN_KEY_LEN))
		return -1;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if ((fstat(fd, &st) != 0) || !S_ISREG(st.st_mode) || ((st.st_mode & 0077) != 0))
		goto fail;
	while ((size_t)total < key_len)
	{
		const ssize_t rc = read(fd, &key[total], key_len - (size_t)total);

		if (rc < 0)
		{
			if (errno == EINTR)
				continue;
			goto fail;
		}
		if (rc == 0)
			goto fail;
		total += rc;
	}
	close(fd);
	return 0;

fail:
	close(fd);
	return -1;
}

static int frdp_auth_token_create_key(const char* path, uint8_t* key, size_t key_len)
{
	int fd = -1;
	ssize_t total = 0;

	if (!path || !key || (key_len != FRDP_AUTH_TOKEN_KEY_LEN))
		return -1;
	if (winpr_RAND(key, key_len) < 0)
		return -1;
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;
	while ((size_t)total < key_len)
	{
		const ssize_t rc = write(fd, &key[total], key_len - (size_t)total);

		if (rc < 0)
		{
			if (errno == EINTR)
				continue;
			goto fail;
		}
		total += rc;
	}
	if (close(fd) != 0)
		return -1;
	return 0;

fail:
	close(fd);
	unlink(path);
	return -1;
}

static int frdp_auth_token_load_key(uint8_t* key, size_t key_len)
{
	const char* path = frdp_auth_token_key_path();

	if (frdp_auth_token_read_key(path, key, key_len) == 0)
		return 0;
	if (errno != ENOENT)
		return -1;
	if (frdp_auth_token_create_key(path, key, key_len) == 0)
		return 0;
	if (errno == EEXIST)
		return frdp_auth_token_read_key(path, key, key_len);
	return -1;
}

static int frdp_auth_token_payload(char* dst, size_t dst_size, const char* nonce,
                                   unsigned long long expires_at, const char* user,
                                   const char* rhost, const char* correlation_id, uint64_t uid,
                                   uint64_t gid, const uint64_t* groups, uint32_t group_count,
                                   int account_ok)
{
	const char* token_nonce = nonce ? nonce : "";
	const char* token_user = user ? user : "";
	const char* token_rhost = rhost ? rhost : "";
	const char* token_correlation_id = correlation_id ? correlation_id : "";
	size_t used = 0;
	int rc = 0;

	if ((group_count > FRDP_AUTH_TOKEN_MAX_GROUPS) || ((group_count > 0U) && !groups))
		return -1;
	rc = snprintf(dst, dst_size, "n:%zu:%s|e:%llu|u:%zu:%s|r:%zu:%s|c:%zu:%s|uid:%" PRIu64
	                              "|gid:%" PRIu64 "|gc:%" PRIu32,
	              strlen(token_nonce), token_nonce, expires_at, strlen(token_user), token_user,
	              strlen(token_rhost), token_rhost, strlen(token_correlation_id),
	              token_correlation_id, uid, gid, group_count);
	if ((rc <= 0) || ((size_t)rc >= dst_size))
		return -1;
	used = (size_t)rc;
	for (uint32_t x = 0; x < group_count; x++)
	{
		rc = snprintf(&dst[used], dst_size - used, "|g%" PRIu32 ":%" PRIu64, x, groups[x]);
		if ((rc <= 0) || ((size_t)rc >= (dst_size - used)))
			return -1;
		used += (size_t)rc;
	}
	rc = snprintf(&dst[used], dst_size - used, "|a:%d", account_ok ? 1 : 0);
	return ((rc > 0) && ((size_t)rc < (dst_size - used))) ? 0 : -1;
}

static int frdp_auth_token_hmac_hex(const char* payload, char* hex, size_t hex_size)
{
	uint8_t key[FRDP_AUTH_TOKEN_KEY_LEN] = { 0 };
	uint8_t digest[FRDP_AUTH_TOKEN_HMAC_LEN] = { 0 };
	int rc = -1;

	if (!payload || !hex || (hex_size < FRDP_AUTH_TOKEN_HEX_LEN + 1U))
		return -1;
	SecureZeroMemory(hex, hex_size);
	if (frdp_auth_token_load_key(key, sizeof(key)) != 0)
		goto cleanup;
	if (!winpr_HMAC(WINPR_MD_SHA256, key, sizeof(key), payload, strlen(payload), digest,
	                sizeof(digest)))
		goto cleanup;
	for (size_t x = 0; x < sizeof(digest); x++)
		snprintf(&hex[x * 2U], hex_size - (x * 2U), "%02x", digest[x]);
	rc = 0;

cleanup:
	SecureZeroMemory(key, sizeof(key));
	SecureZeroMemory(digest, sizeof(digest));
	if (rc != 0)
		SecureZeroMemory(hex, hex_size);
	return rc;
}

static int frdp_auth_token_hex_equal(const char* a, const char* b)
{
	unsigned char diff = 0;

	if (!a || !b)
		return 0;
	for (size_t x = 0; x < FRDP_AUTH_TOKEN_HEX_LEN; x++)
		diff |= (unsigned char)(a[x] ^ b[x]);
	return diff == 0;
}

int frdp_auth_token_create(const char* user, const char* rhost, const char* correlation_id,
                           uint64_t uid, uint64_t gid, const uint64_t* groups,
                           uint32_t group_count, int account_ok, char* token, size_t token_size)
{
	uuid_t id;
	char nonce[37] = { 0 };
	char payload[2048] = { 0 };
	char hmac_hex[FRDP_AUTH_TOKEN_HEX_LEN + 1U] = { 0 };
	const unsigned long long expires_at =
	    (unsigned long long)time(NULL) + FRDP_AUTH_TOKEN_TTL_SECONDS;
	int rc = -1;
	int written = 0;

	if (!token || (token_size < 128))
		return -1;
	uuid_generate(id);
	uuid_unparse_lower(id, nonce);
	if (frdp_auth_token_payload(payload, sizeof(payload), nonce, expires_at, user, rhost,
	                            correlation_id, uid, gid, groups, group_count, account_ok) != 0)
		goto cleanup;
	if (frdp_auth_token_hmac_hex(payload, hmac_hex, sizeof(hmac_hex)) != 0)
		goto cleanup;
	SecureZeroMemory(token, token_size);
	written = snprintf(token, token_size, "%s:%llu:%s", nonce, expires_at, hmac_hex);
	if ((written < 0) || ((size_t)written >= token_size))
		goto cleanup;
	rc = 0;

cleanup:
	SecureZeroMemory(id, sizeof(id));
	SecureZeroMemory(nonce, sizeof(nonce));
	SecureZeroMemory(payload, sizeof(payload));
	SecureZeroMemory(hmac_hex, sizeof(hmac_hex));
	if (rc != 0)
		SecureZeroMemory(token, token_size);
	return rc;
}

int frdp_auth_token_verify(const char* token, const char* user, const char* rhost,
                           const char* correlation_id, uint64_t uid, uint64_t gid,
                           const uint64_t* groups, uint32_t group_count, int account_ok,
                           char* nonce, size_t nonce_size,
                           unsigned long long* expires_at)
{
	char parsed_nonce[37] = { 0 };
	char parsed_hmac[FRDP_AUTH_TOKEN_HEX_LEN + 1U] = { 0 };
	char expected_hmac[FRDP_AUTH_TOKEN_HEX_LEN + 1U] = { 0 };
	char payload[2048] = { 0 };
	unsigned long long parsed_expires_at = 0;
	int consumed = 0;
	int rc = -1;

	if (!token || !nonce || (nonce_size < sizeof(parsed_nonce)) || !expires_at)
	{
		if (nonce && (nonce_size > 0U))
			SecureZeroMemory(nonce, nonce_size);
		if (expires_at)
			*expires_at = 0;
		return -1;
	}
	if (sscanf(token, "%36[0-9a-f-]:%llu:%64[0-9a-f]%n", parsed_nonce, &parsed_expires_at,
	           parsed_hmac, &consumed) != 3)
		goto cleanup;
	if ((consumed <= 0) || (token[consumed] != '\0'))
		goto cleanup;
	if ((strlen(parsed_nonce) != 36U) || (strlen(parsed_hmac) != FRDP_AUTH_TOKEN_HEX_LEN))
		goto cleanup;
	if (parsed_expires_at < (unsigned long long)time(NULL))
		goto cleanup;
	if (frdp_auth_token_payload(payload, sizeof(payload), parsed_nonce, parsed_expires_at, user,
	                            rhost, correlation_id, uid, gid, groups, group_count,
	                            account_ok) != 0)
		goto cleanup;
	if (frdp_auth_token_hmac_hex(payload, expected_hmac, sizeof(expected_hmac)) != 0)
		goto cleanup;
	if (!frdp_auth_token_hex_equal(parsed_hmac, expected_hmac))
		goto cleanup;
	snprintf(nonce, nonce_size, "%s", parsed_nonce);
	*expires_at = parsed_expires_at;
	rc = 0;

cleanup:
	SecureZeroMemory(parsed_nonce, sizeof(parsed_nonce));
	SecureZeroMemory(parsed_hmac, sizeof(parsed_hmac));
	SecureZeroMemory(expected_hmac, sizeof(expected_hmac));
	SecureZeroMemory(payload, sizeof(payload));
	if (rc != 0)
	{
		SecureZeroMemory(nonce, nonce_size);
		*expires_at = 0;
	}
	return rc;
}
