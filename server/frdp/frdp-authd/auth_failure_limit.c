#include "auth_failure_limit.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>

static int key_is_valid(const char *key)
{
    return key && key[0] && (strnlen(key, FRDP_AUTH_FAILURE_LIMIT_KEY_SIZE) <
                            FRDP_AUTH_FAILURE_LIMIT_KEY_SIZE);
}

static int entry_is_expired(const frdpAuthFailureLimiter *limiter,
                            const frdpAuthFailureEntry *entry, uint64_t now_seconds)
{
    if (!entry->in_use)
        return 0;
    if (now_seconds < entry->window_start)
        return 1;
    return (now_seconds - entry->window_start) >= limiter->window_seconds;
}

static void expire_entries(frdpAuthFailureLimiter *limiter, uint64_t now_seconds)
{
    for (size_t x = 0; x < FRDP_AUTH_FAILURE_LIMIT_MAX_ENTRIES; x++) {
        if (entry_is_expired(limiter, &limiter->entries[x], now_seconds))
            memset(&limiter->entries[x], 0, sizeof(limiter->entries[x]));
    }
}

void frdp_auth_failure_limiter_init(frdpAuthFailureLimiter *limiter, uint32_t max_failures,
                                    uint32_t window_seconds)
{
    if (!limiter)
        return;
    memset(limiter, 0, sizeof(*limiter));
    limiter->max_failures = max_failures;
    limiter->window_seconds = window_seconds;
}

int frdp_auth_failure_limiter_account_key(const char *account, size_t account_size,
                                          const char *canonical_account, char *key,
                                          size_t key_size)
{
    size_t length = 0;

    if (!account || account_size == 0 || !key || key_size == 0) {
        errno = EINVAL;
        return -1;
    }
    if (canonical_account && canonical_account[0]) {
        length = strnlen(canonical_account, key_size);
        if (length >= key_size) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(key, canonical_account, length + 1U);
        return 0;
    }
    length = strnlen(account, account_size);
    if ((length == 0) || (length >= account_size)) {
        errno = EINVAL;
        return -1;
    }
    if (length >= key_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    for (size_t x = 0; x <= length; x++) {
        const unsigned char c = (unsigned char)account[x];

        key[x] = (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : (char)c;
    }
    return 0;
}

int frdp_auth_failure_limiter_allow(frdpAuthFailureLimiter *limiter, const char *key,
                                    uint64_t now_seconds)
{
    int has_capacity = 0;

    if (!limiter || !key_is_valid(key) || limiter->max_failures == 0 ||
        limiter->window_seconds == 0) {
        errno = EINVAL;
        return 0;
    }
    expire_entries(limiter, now_seconds);
    for (size_t x = 0; x < FRDP_AUTH_FAILURE_LIMIT_MAX_ENTRIES; x++) {
        frdpAuthFailureEntry *entry = &limiter->entries[x];

        if (!entry->in_use) {
            has_capacity = 1;
            continue;
        }
        if (strcmp(entry->key, key) == 0)
            return entry->failures < limiter->max_failures;
    }
    if (!has_capacity)
        errno = ENOSPC;
    return has_capacity;
}

int frdp_auth_failure_limiter_record(frdpAuthFailureLimiter *limiter, const char *key,
                                     uint64_t now_seconds)
{
    frdpAuthFailureEntry *available = NULL;

    if (!limiter || !key_is_valid(key) || limiter->max_failures == 0 ||
        limiter->window_seconds == 0) {
        errno = EINVAL;
        return -1;
    }
    expire_entries(limiter, now_seconds);
    for (size_t x = 0; x < FRDP_AUTH_FAILURE_LIMIT_MAX_ENTRIES; x++) {
        frdpAuthFailureEntry *entry = &limiter->entries[x];

        if (!entry->in_use) {
            if (!available)
                available = entry;
            continue;
        }
        if (strcmp(entry->key, key) != 0)
            continue;
        if (entry->failures < UINT32_MAX)
            entry->failures++;
        return 0;
    }
    if (!available) {
        errno = ENOSPC;
        return -1;
    }
    memcpy(available->key, key, strlen(key) + 1U);
    available->window_start = now_seconds;
    available->failures = 1;
    available->in_use = 1;
    return 0;
}

void frdp_auth_failure_limiter_clear(frdpAuthFailureLimiter *limiter, const char *key)
{
    if (!limiter || !key_is_valid(key))
        return;
    for (size_t x = 0; x < FRDP_AUTH_FAILURE_LIMIT_MAX_ENTRIES; x++) {
        frdpAuthFailureEntry *entry = &limiter->entries[x];

        if (entry->in_use && (strcmp(entry->key, key) == 0)) {
            memset(entry, 0, sizeof(*entry));
            return;
        }
    }
}
