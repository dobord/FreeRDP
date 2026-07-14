#include "auth_failure_limit.h"

#include <errno.h>
#include <limits.h>
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

static void expire_aliases(frdpAuthFailureLimiter *limiter, uint64_t now_seconds)
{
    for (size_t x = 0; x < FRDP_AUTH_FAILURE_LIMIT_MAX_ENTRIES; x++) {
        frdpAuthFailureAlias *alias = &limiter->aliases[x];

        if (!alias->in_use)
            continue;
        if ((now_seconds < alias->bound_at) ||
            ((now_seconds - alias->bound_at) >= limiter->window_seconds))
            memset(alias, 0, sizeof(*alias));
    }
}

static const char *resolve_key(const frdpAuthFailureLimiter *limiter, const char *key)
{
    if (!limiter || !key_is_valid(key))
        return NULL;
    for (size_t x = 0; x < FRDP_AUTH_FAILURE_LIMIT_MAX_ENTRIES; x++) {
        const frdpAuthFailureAlias *alias = &limiter->aliases[x];

        if (alias->in_use && (strcmp(alias->alias, key) == 0))
            return alias->canonical;
    }
    return key;
}

static frdpAuthFailureEntry *find_entry(frdpAuthFailureLimiter *limiter, const char *key)
{
    for (size_t x = 0; x < FRDP_AUTH_FAILURE_LIMIT_MAX_ENTRIES; x++) {
        frdpAuthFailureEntry *entry = &limiter->entries[x];

        if (entry->in_use && (strcmp(entry->key, key) == 0))
            return entry;
    }
    return NULL;
}

static void merge_entries(frdpAuthFailureLimiter *limiter, const char *source_key,
                          const char *target_key)
{
    frdpAuthFailureEntry *source = NULL;
    frdpAuthFailureEntry *target = NULL;

    if (strcmp(source_key, target_key) == 0)
        return;
    source = find_entry(limiter, source_key);
    if (!source)
        return;
    target = find_entry(limiter, target_key);
    if (!target) {
        const size_t target_length = strlen(target_key);

        memset(source->key, 0, sizeof(source->key));
        memcpy(source->key, target_key, target_length + 1U);
        return;
    }
    if ((UINT32_MAX - target->failures) < source->failures)
        target->failures = UINT32_MAX;
    else
        target->failures += source->failures;
    if (source->window_start > target->window_start)
        target->window_start = source->window_start;
    memset(source, 0, sizeof(*source));
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
    const char *resolved = NULL;
    int has_capacity = 0;

    if (!limiter || !key_is_valid(key) || limiter->max_failures == 0 ||
        limiter->window_seconds == 0) {
        errno = EINVAL;
        return 0;
    }
    expire_entries(limiter, now_seconds);
    expire_aliases(limiter, now_seconds);
    resolved = resolve_key(limiter, key);
    if (!resolved)
        return 0;
    for (size_t x = 0; x < FRDP_AUTH_FAILURE_LIMIT_MAX_ENTRIES; x++) {
        frdpAuthFailureEntry *entry = &limiter->entries[x];

        if (!entry->in_use) {
            has_capacity = 1;
            continue;
        }
        if (strcmp(entry->key, resolved) == 0)
            return entry->failures < limiter->max_failures;
    }
    if (!has_capacity)
        errno = ENOSPC;
    return has_capacity;
}

int frdp_auth_failure_limiter_record(frdpAuthFailureLimiter *limiter, const char *key,
                                     uint64_t now_seconds)
{
    const char *resolved = NULL;
    frdpAuthFailureEntry *available = NULL;

    if (!limiter || !key_is_valid(key) || limiter->max_failures == 0 ||
        limiter->window_seconds == 0) {
        errno = EINVAL;
        return -1;
    }
    expire_entries(limiter, now_seconds);
    expire_aliases(limiter, now_seconds);
    resolved = resolve_key(limiter, key);
    if (!resolved)
        return -1;
    for (size_t x = 0; x < FRDP_AUTH_FAILURE_LIMIT_MAX_ENTRIES; x++) {
        frdpAuthFailureEntry *entry = &limiter->entries[x];

        if (!entry->in_use) {
            if (!available)
                available = entry;
            continue;
        }
        if (strcmp(entry->key, resolved) != 0)
            continue;
        if (entry->failures < UINT32_MAX)
            entry->failures++;
        return 0;
    }
    if (!available) {
        errno = ENOSPC;
        return -1;
    }
    memcpy(available->key, resolved, strlen(resolved) + 1U);
    available->window_start = now_seconds;
    available->failures = 1;
    available->in_use = 1;
    return 0;
}

int frdp_auth_failure_limiter_bind_alias(frdpAuthFailureLimiter *limiter, const char *alias,
                                         const char *canonical, uint64_t now_seconds)
{
    frdpAuthFailureAlias *binding = NULL;
    frdpAuthFailureAlias *available = NULL;
    const char *resolved_alias = NULL;
    const char *resolved_canonical = NULL;
    char source[FRDP_AUTH_FAILURE_LIMIT_KEY_SIZE] = {0};
    char target[FRDP_AUTH_FAILURE_LIMIT_KEY_SIZE] = {0};

    if (!limiter || !key_is_valid(alias) || !key_is_valid(canonical) ||
        (limiter->window_seconds == 0)) {
        errno = EINVAL;
        return -1;
    }
    expire_entries(limiter, now_seconds);
    expire_aliases(limiter, now_seconds);
    resolved_alias = resolve_key(limiter, alias);
    resolved_canonical = resolve_key(limiter, canonical);
    if (!resolved_alias || !resolved_canonical) {
        errno = EINVAL;
        return -1;
    }
    memcpy(source, resolved_alias, strlen(resolved_alias) + 1U);
    memcpy(target, resolved_canonical, strlen(resolved_canonical) + 1U);
    if (strcmp(alias, target) == 0) {
        merge_entries(limiter, source, target);
        return 0;
    }
    for (size_t x = 0; x < FRDP_AUTH_FAILURE_LIMIT_MAX_ENTRIES; x++) {
        frdpAuthFailureAlias *current = &limiter->aliases[x];

        if (!current->in_use) {
            if (!available)
                available = current;
            continue;
        }
        if (strcmp(current->alias, alias) == 0)
            binding = current;
    }
    if (binding && (strcmp(binding->canonical, target) != 0)) {
        errno = EEXIST;
        return -1;
    }
    if (!binding)
        binding = available;
    if (!binding) {
        errno = ENOSPC;
        return -1;
    }
    merge_entries(limiter, source, target);
    for (size_t x = 0; x < FRDP_AUTH_FAILURE_LIMIT_MAX_ENTRIES; x++) {
        frdpAuthFailureAlias *current = &limiter->aliases[x];

        if (current->in_use &&
            ((strcmp(current->canonical, source) == 0) || (strcmp(current->canonical, alias) == 0))) {
            memset(current->canonical, 0, sizeof(current->canonical));
            memcpy(current->canonical, target, strlen(target) + 1U);
            current->bound_at = now_seconds;
        }
    }
    memset(binding, 0, sizeof(*binding));
    memcpy(binding->alias, alias, strlen(alias) + 1U);
    memcpy(binding->canonical, target, strlen(target) + 1U);
    binding->bound_at = now_seconds;
    binding->in_use = 1;
    return 0;
}

void frdp_auth_failure_limiter_clear(frdpAuthFailureLimiter *limiter, const char *key)
{
    const char *resolved = NULL;

    if (!limiter || !key_is_valid(key))
        return;
    resolved = resolve_key(limiter, key);
    if (!resolved)
        return;
    for (size_t x = 0; x < FRDP_AUTH_FAILURE_LIMIT_MAX_ENTRIES; x++) {
        frdpAuthFailureEntry *entry = &limiter->entries[x];

        if (entry->in_use && (strcmp(entry->key, resolved) == 0)) {
            memset(entry, 0, sizeof(*entry));
            return;
        }
    }
}
