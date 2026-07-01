#ifndef FRDP_AUTH_TOKEN_H
#define FRDP_AUTH_TOKEN_H

#include <stddef.h>
#include <stdint.h>

#define FRDP_AUTH_TOKEN_TTL_SECONDS 60
#define FRDP_AUTH_TOKEN_KEY_ENV "FRDP_AUTH_TOKEN_KEY"
#define FRDP_AUTH_TOKEN_DEFAULT_KEY_PATH "/run/frdp-auth-token/key"

int frdp_auth_token_create(const char* user, const char* rhost, const char* correlation_id,
                           uint64_t uid, uint64_t gid, int account_ok, char* token,
                           size_t token_size);
int frdp_auth_token_verify(const char* token, const char* user, const char* rhost,
                           const char* correlation_id, uint64_t uid, uint64_t gid,
                           int account_ok, char* nonce, size_t nonce_size,
                           unsigned long long* expires_at);

#endif /* FRDP_AUTH_TOKEN_H */
