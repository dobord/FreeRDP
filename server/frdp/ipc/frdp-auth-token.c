#define _GNU_SOURCE

#include "frdp-auth-token.h"

#include <errno.h>
#include <fcntl.h>
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
                                   const char* rhost, const char* correlation_id)
{
	const int rc = snprintf(dst, dst_size, "%s|%llu|%s|%s|%s", nonce ? nonce : "",
	                        expires_at, user ? user : "", rhost ? rhost : "",
	                        correlation_id ? correlation_id : "");

	return ((rc > 0) && ((size_t)rc < dst_size)) ? 0 : -1;
}

static int frdp_auth_token_hmac_hex(const char* payload, char* hex, size_t hex_size)
{
	uint8_t key[FRDP_AUTH_TOKEN_KEY_LEN] = { 0 };
	uint8_t digest[FRDP_AUTH_TOKEN_HMAC_LEN] = { 0 };

	if (!payload || !hex || (hex_size < FRDP_AUTH_TOKEN_HEX_LEN + 1U))
		return -1;
	if (frdp_auth_token_load_key(key, sizeof(key)) != 0)
		return -1;
	if (!winpr_HMAC(WINPR_MD_SHA256, key, sizeof(key), payload, strlen(payload), digest,
	                sizeof(digest)))
	{
		SecureZeroMemory(key, sizeof(key));
		return -1;
	}
	for (size_t x = 0; x < sizeof(digest); x++)
		snprintf(&hex[x * 2U], hex_size - (x * 2U), "%02x", digest[x]);
	SecureZeroMemory(key, sizeof(key));
	return 0;
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
                           char* token, size_t token_size)
{
	uuid_t id;
	char nonce[37] = { 0 };
	char payload[512] = { 0 };
	char hmac_hex[FRDP_AUTH_TOKEN_HEX_LEN + 1U] = { 0 };
	const unsigned long long expires_at =
	    (unsigned long long)time(NULL) + FRDP_AUTH_TOKEN_TTL_SECONDS;

	if (!token || (token_size < 128))
		return -1;
	uuid_generate(id);
	uuid_unparse_lower(id, nonce);
	if (frdp_auth_token_payload(payload, sizeof(payload), nonce, expires_at, user, rhost,
	                            correlation_id) != 0)
		return -1;
	if (frdp_auth_token_hmac_hex(payload, hmac_hex, sizeof(hmac_hex)) != 0)
		return -1;
	if (snprintf(token, token_size, "%s:%llu:%s", nonce, expires_at, hmac_hex) >=
	    (int)token_size)
		return -1;
	return 0;
}

int frdp_auth_token_verify(const char* token, const char* user, const char* rhost,
                           const char* correlation_id, char* nonce, size_t nonce_size,
                           unsigned long long* expires_at)
{
	char parsed_nonce[37] = { 0 };
	char parsed_hmac[FRDP_AUTH_TOKEN_HEX_LEN + 1U] = { 0 };
	char expected_hmac[FRDP_AUTH_TOKEN_HEX_LEN + 1U] = { 0 };
	char payload[512] = { 0 };
	unsigned long long parsed_expires_at = 0;
	int consumed = 0;

	if (!token || !nonce || (nonce_size < sizeof(parsed_nonce)) || !expires_at)
		return -1;
	if (sscanf(token, "%36[0-9a-f-]:%llu:%64[0-9a-f]%n", parsed_nonce, &parsed_expires_at,
	           parsed_hmac, &consumed) != 3)
		return -1;
	if ((consumed <= 0) || (token[consumed] != '\0'))
		return -1;
	if ((strlen(parsed_nonce) != 36U) || (strlen(parsed_hmac) != FRDP_AUTH_TOKEN_HEX_LEN))
		return -1;
	if (parsed_expires_at < (unsigned long long)time(NULL))
		return -1;
	if (frdp_auth_token_payload(payload, sizeof(payload), parsed_nonce, parsed_expires_at, user,
	                            rhost, correlation_id) != 0)
		return -1;
	if (frdp_auth_token_hmac_hex(payload, expected_hmac, sizeof(expected_hmac)) != 0)
		return -1;
	if (!frdp_auth_token_hex_equal(parsed_hmac, expected_hmac))
		return -1;
	snprintf(nonce, nonce_size, "%s", parsed_nonce);
	*expires_at = parsed_expires_at;
	return 0;
}
