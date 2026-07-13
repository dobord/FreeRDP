#ifndef FRDP_AUTH_FAILURE_LIMIT_H
#define FRDP_AUTH_FAILURE_LIMIT_H

#include <stddef.h>
#include <stdint.h>

#define FRDP_AUTH_FAILURE_LIMIT_MAX_ENTRIES 256U
#define FRDP_AUTH_FAILURE_LIMIT_KEY_SIZE 128U
#define FRDP_AUTH_FAILURE_LIMIT_DEFAULT_MAX_FAILURES 10U
#define FRDP_AUTH_FAILURE_LIMIT_DEFAULT_WINDOW_SECONDS 120U

typedef struct {
    char key[FRDP_AUTH_FAILURE_LIMIT_KEY_SIZE];
    uint64_t window_start;
    uint32_t failures;
    int in_use;
} frdpAuthFailureEntry;

typedef struct {
    frdpAuthFailureEntry entries[FRDP_AUTH_FAILURE_LIMIT_MAX_ENTRIES];
    uint32_t max_failures;
    uint32_t window_seconds;
} frdpAuthFailureLimiter;

void frdp_auth_failure_limiter_init(frdpAuthFailureLimiter *limiter, uint32_t max_failures,
                                    uint32_t window_seconds);
int frdp_auth_failure_limiter_account_key(const char *account, size_t account_size,
                                          const char *canonical_account, char *key,
                                          size_t key_size);
int frdp_auth_failure_limiter_allow(frdpAuthFailureLimiter *limiter, const char *key,
                                    uint64_t now_seconds);
int frdp_auth_failure_limiter_record(frdpAuthFailureLimiter *limiter, const char *key,
                                     uint64_t now_seconds);
void frdp_auth_failure_limiter_clear(frdpAuthFailureLimiter *limiter, const char *key);

#endif
