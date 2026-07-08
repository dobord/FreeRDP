/*
 * frdp-krb-authd - Kerberos acceptor for FreeRDP-based RDP server
 *
 * This prototype demonstrates how to accept a Kerberos GSSAPI security context
 * and map the resulting principal to a POSIX user. It is not integrated with
 * the RDP server but illustrates the sequence needed for phase 4 of the plan.
 */

#include <gssapi/gssapi.h>
#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <unistd.h>

#include <winpr/crt.h>

#include "../ipc/frdp-ipc.h"

extern void crypto_base64_decode(const char *enc_data, size_t length, unsigned char **dec_data,
                                 size_t *res_length);

#define FRDP_KRB_DEFAULT_KEYTAB "/etc/frdpd/frdpd.keytab"
#define FRDP_KRB_ACCEPTOR_NAME_ENV "FRDP_KRB_ACCEPTOR_NAME"

static void display_status(const char *msg, OM_uint32 code, int type)
{
    OM_uint32 maj_stat, min_stat;
    OM_uint32 msg_ctx = 0;
    gss_buffer_desc status_string;
    do {
        maj_stat = gss_display_status(&min_stat, code, type, GSS_C_NO_OID,
                                      &msg_ctx, &status_string);
        if (maj_stat != GSS_S_COMPLETE)
            break;
        fprintf(stderr, "%s: %.*s\n", msg, (int)status_string.length,
                (char *)status_string.value);
        gss_release_buffer(&min_stat, &status_string);
    } while (msg_ctx != 0);
}

static int disable_core_dumps(void)
{
    struct rlimit rl = { 0 };

    if (setrlimit(RLIMIT_CORE, &rl) != 0)
        return -1;
#ifdef __linux__
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
        return -1;
#endif
    return 0;
}

static int run_no_core_test(void)
{
    struct rlimit rl = { 0 };

    if (disable_core_dumps() != 0)
    {
        perror("disable_core_dumps");
        return 2;
    }
    if (getrlimit(RLIMIT_CORE, &rl) != 0)
    {
        perror("getrlimit(RLIMIT_CORE)");
        return 2;
    }
    if ((rl.rlim_cur != 0) || (rl.rlim_max != 0))
    {
        fprintf(stderr, "core dump limit is not disabled\n");
        return 2;
    }
#ifdef __linux__
    if (prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0)
    {
        fprintf(stderr, "process remains dumpable\n");
        return 2;
    }
#endif
    printf("ok\n");
    return 0;
}

static int normalize_user_principal(const char *principal, char *user, size_t user_size)
{
    const char *at = NULL;
    const char *extra_at = NULL;
    const char *realm = NULL;
    size_t user_len = 0;

    if (!principal || !user || (user_size == 0))
        return -1;
    user[0] = '\0';

    at = strchr(principal, '@');
    if (!at || (at == principal) || (at[1] == '\0'))
        return -1;
    extra_at = strchr(at + 1, '@');
    if (extra_at)
        return -1;
    realm = at + 1;

    user_len = (size_t)(at - principal);
    if ((user_len == 0) || (user_len >= user_size))
        return -1;
    if (memchr(principal, '/', user_len) || memchr(principal, '\\', user_len) ||
        memchr(principal, ':', user_len))
        return -1;
    if (!isalnum((unsigned char)principal[0]) && (principal[0] != '_'))
        return -1;
    if (!isalnum((unsigned char)realm[0]) && (realm[0] != '_'))
        return -1;

    for (size_t x = 0; x < user_len; x++)
    {
        const unsigned char c = (unsigned char)principal[x];
        if (!isalnum(c) && (c != '_') && (c != '-') && (c != '.'))
            return -1;
    }
    for (size_t x = 0; realm[x] != '\0'; x++)
    {
        const unsigned char c = (unsigned char)realm[x];
        if (!isalnum(c) && (c != '_') && (c != '-') && (c != '.'))
            return -1;
    }

    memcpy(user, principal, user_len);
    user[user_len] = '\0';
    return 0;
}

static int compare_uint64(const void *a, const void *b)
{
    const uint64_t left = *(const uint64_t *)a;
    const uint64_t right = *(const uint64_t *)b;

    return (left > right) - (left < right);
}

static int lookup_posix_groups(const char *user, gid_t primary_gid, uint64_t *groups,
                               uint32_t *group_count)
{
    gid_t native_groups[FRDP_IPC_MAX_AUTH_GROUPS] = { 0 };
    int count = (int)FRDP_IPC_MAX_AUTH_GROUPS;

    if (!user || !groups || !group_count)
        return -1;
    *group_count = 0;
    if (getgrouplist(user, primary_gid, native_groups, &count) < 0)
        return -1;
    if ((count < 0) || ((uint32_t)count > FRDP_IPC_MAX_AUTH_GROUPS))
        return -1;
    for (int x = 0; x < count; x++)
        groups[x] = (uint64_t)native_groups[x];
    qsort(groups, (size_t)count, sizeof(groups[0]), compare_uint64);
    *group_count = (uint32_t)count;
    return 0;
}

static struct passwd *lookup_principal_account(const char *principal, char *normalized,
                                               size_t normalized_size, const char **mapping)
{
    struct passwd *pwd = NULL;

    if (mapping)
        *mapping = NULL;
    if (normalized && (normalized_size > 0))
        normalized[0] = '\0';
    if (!principal)
        return NULL;

    if (normalize_user_principal(principal, normalized, normalized_size) != 0)
        return NULL;

    pwd = getpwnam(principal);
    if (pwd)
    {
        if (mapping)
            *mapping = "exact-principal";
        return pwd;
    }

    pwd = getpwnam(normalized);
    if (pwd && mapping)
        *mapping = "normalized-principal";
    return pwd;
}

static int run_normalize_principal_test(const char *principal)
{
    char user[64] = { 0 };

    if (normalize_user_principal(principal, user, sizeof(user)) != 0)
    {
        fprintf(stderr, "invalid Kerberos user principal\n");
        return 2;
    }
    printf("%s\n", user);
    return 0;
}

static int run_account_groups_test(const char *user)
{
    struct passwd *pwd = NULL;
    uint64_t groups[FRDP_IPC_MAX_AUTH_GROUPS] = { 0 };
    uint32_t group_count = 0;
    int rc = 0;

    if (!user || (user[0] == '\0'))
        return 2;

    pwd = getpwnam(user);
    if (!pwd)
    {
        fprintf(stderr, "POSIX account not found\n");
        return 2;
    }
    if (lookup_posix_groups(pwd->pw_name, pwd->pw_gid, groups, &group_count) != 0)
    {
        fprintf(stderr, "POSIX group lookup failed\n");
        rc = 3;
        goto cleanup;
    }

    printf("%s uid=%d gid=%d group_count=%u\n", pwd->pw_name, (int)pwd->pw_uid,
           (int)pwd->pw_gid, (unsigned int)group_count);

cleanup:
    SecureZeroMemory(groups, sizeof(groups));
    return rc;
}

static int decode_input_token(const char *token_b64, gss_buffer_desc *input_token)
{
    unsigned char *decoded = NULL;
    size_t decoded_len = 0;

    if (!token_b64 || !input_token)
        return -1;

    input_token->value = NULL;
    input_token->length = 0;

    crypto_base64_decode(token_b64, strlen(token_b64), &decoded, &decoded_len);
    if (!decoded || (decoded_len == 0))
    {
        free(decoded);
        return -1;
    }

    input_token->value = decoded;
    input_token->length = decoded_len;
    return 0;
}

static int run_decode_token_test(const char *token_b64)
{
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;

    if (decode_input_token(token_b64, &input_token) != 0)
    {
        fprintf(stderr, "invalid base64 Kerberos token\n");
        return 2;
    }

    printf("%zu ", input_token.length);
    for (size_t x = 0; x < input_token.length; x++)
        printf("%02x", ((const unsigned char *)input_token.value)[x]);
    printf("\n");
    SecureZeroMemory(input_token.value, input_token.length);
    free(input_token.value);
    return 0;
}

static int configure_keytab_env(void)
{
    const char *existing = NULL;
    const char *keytab = NULL;

    existing = getenv("KRB5_KTNAME");
    if (existing && (existing[0] != '\0'))
        return 0;

    keytab = getenv("FRDP_KRB_KEYTAB");
    if (!keytab || (keytab[0] == '\0'))
        keytab = FRDP_KRB_DEFAULT_KEYTAB;

    if (setenv("KRB5_KTNAME", keytab, 1) != 0)
    {
        perror("setenv(KRB5_KTNAME)");
        return -1;
    }
    return 0;
}

static int run_keytab_env_test(void)
{
    const char *keytab = NULL;

    if (configure_keytab_env() != 0)
        return 1;

    keytab = getenv("KRB5_KTNAME");
    if (!keytab)
    {
        fprintf(stderr, "KRB5_KTNAME is not set\n");
        return 2;
    }
    printf("%s\n", keytab);
    return 0;
}

static const char *select_acceptor_name(void)
{
    const char *name = getenv(FRDP_KRB_ACCEPTOR_NAME_ENV);

    return (name && (name[0] != '\0')) ? name : NULL;
}

static int import_acceptor_name(const char *name, gss_name_t *acceptor_name)
{
    OM_uint32 maj_stat = 0;
    OM_uint32 min_stat = 0;
    char name_copy[256] = { 0 };
    gss_buffer_desc name_buf = GSS_C_EMPTY_BUFFER;
    size_t name_len = 0;

    if (!name || (name[0] == '\0') || !acceptor_name)
        return -1;

    *acceptor_name = GSS_C_NO_NAME;
    name_len = strlen(name);
    if (name_len >= sizeof(name_copy))
        return -1;
    memcpy(name_copy, name, name_len);
    name_copy[name_len] = '\0';
    name_buf.value = name_copy;
    name_buf.length = name_len;

    maj_stat = gss_import_name(&min_stat, &name_buf, GSS_C_NT_HOSTBASED_SERVICE, acceptor_name);
    if (maj_stat != GSS_S_COMPLETE)
    {
        display_status("gss_import_name", maj_stat, GSS_C_GSS_CODE);
        display_status("gss_import_name", min_stat, GSS_C_MECH_CODE);
        return -1;
    }
    return 0;
}

static int acquire_acceptor_cred(gss_cred_id_t *acceptor_cred)
{
    OM_uint32 maj_stat = 0;
    OM_uint32 min_stat = 0;
    gss_name_t acceptor_name = GSS_C_NO_NAME;
    const char *name = NULL;

    if (!acceptor_cred)
        return -1;

    *acceptor_cred = GSS_C_NO_CREDENTIAL;
    name = select_acceptor_name();
    if (!name)
        return 0;

    if (import_acceptor_name(name, &acceptor_name) != 0)
        return -1;

    maj_stat = gss_acquire_cred(&min_stat, acceptor_name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                                GSS_C_ACCEPT, acceptor_cred, NULL, NULL);
    gss_release_name(&min_stat, &acceptor_name);
    if (maj_stat != GSS_S_COMPLETE)
    {
        display_status("gss_acquire_cred", maj_stat, GSS_C_GSS_CODE);
        display_status("gss_acquire_cred", min_stat, GSS_C_MECH_CODE);
        return -1;
    }
    return 0;
}

static int run_acceptor_env_test(void)
{
    const char *name = select_acceptor_name();

    printf("%s\n", name ? name : "(default)");
    return 0;
}

static int run_import_acceptor_name_test(const char *name)
{
    OM_uint32 min_stat = 0;
    gss_name_t acceptor_name = GSS_C_NO_NAME;

    if (import_acceptor_name(name, &acceptor_name) != 0)
    {
        fprintf(stderr, "invalid Kerberos acceptor name\n");
        return 2;
    }

    gss_release_name(&min_stat, &acceptor_name);
    printf("ok\n");
    return 0;
}

static int context_flags_allowed(OM_uint32 ret_flags)
{
    return ((ret_flags & GSS_C_DELEG_FLAG) == 0) ? 1 : 0;
}

static int run_context_flags_test(const char *flags)
{
    char *end = NULL;
    unsigned long parsed = 0;

    if (!flags || (flags[0] == '\0') || (flags[0] == '-'))
        return 2;

    errno = 0;
    parsed = strtoul(flags, &end, 0);
    if ((errno != 0) || !end || (end[0] != '\0') || (parsed > UINT_MAX))
        return 2;

    if (!context_flags_allowed((OM_uint32)parsed))
    {
        fprintf(stderr, "delegated Kerberos credentials are not accepted\n");
        return 3;
    }

    printf("ok\n");
    return 0;
}

int main(int argc, char **argv)
{
    int rc = 0;
    const char *token_b64 = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [--normalize-principal-test <principal> | "
                        "--account-groups-test <user> | "
                        "--decode-token-test <base64-token> | --keytab-env-test | "
                        "--acceptor-env-test | --import-acceptor-name-test <name> | "
                        "--context-flags-test <flags> | --no-core-test] "
                        "<base64-token>\n",
                argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "--normalize-principal-test") == 0)
    {
        if (argc != 3)
        {
            fprintf(stderr, "Usage: %s [--normalize-principal-test <principal> | "
                            "--account-groups-test <user> | "
                            "--decode-token-test <base64-token> | --keytab-env-test | "
                            "--acceptor-env-test | --import-acceptor-name-test <name> | "
                            "--context-flags-test <flags> | --no-core-test] "
                            "<base64-token>\n",
                    argv[0]);
            return 1;
        }
        return run_normalize_principal_test(argv[2]);
    }
    if (strcmp(argv[1], "--account-groups-test") == 0)
    {
        if (argc != 3)
        {
            fprintf(stderr, "Usage: %s [--normalize-principal-test <principal> | "
                            "--account-groups-test <user> | "
                            "--decode-token-test <base64-token> | --keytab-env-test | "
                            "--acceptor-env-test | --import-acceptor-name-test <name> | "
                            "--context-flags-test <flags> | --no-core-test] "
                            "<base64-token>\n",
                    argv[0]);
            return 1;
        }
        return run_account_groups_test(argv[2]);
    }
    if (strcmp(argv[1], "--decode-token-test") == 0)
    {
        if (argc != 3)
        {
            fprintf(stderr, "Usage: %s [--normalize-principal-test <principal> | "
                            "--account-groups-test <user> | "
                            "--decode-token-test <base64-token> | --keytab-env-test | "
                            "--acceptor-env-test | --import-acceptor-name-test <name> | "
                            "--context-flags-test <flags> | --no-core-test] "
                            "<base64-token>\n",
                    argv[0]);
            return 1;
        }
        return run_decode_token_test(argv[2]);
    }
    if (strcmp(argv[1], "--keytab-env-test") == 0)
    {
        if (argc != 2)
        {
            fprintf(stderr, "Usage: %s [--normalize-principal-test <principal> | "
                            "--account-groups-test <user> | "
                            "--decode-token-test <base64-token> | --keytab-env-test | "
                            "--acceptor-env-test | --import-acceptor-name-test <name> | "
                            "--context-flags-test <flags> | --no-core-test] "
                            "<base64-token>\n",
                    argv[0]);
            return 1;
        }
        return run_keytab_env_test();
    }
    if (strcmp(argv[1], "--acceptor-env-test") == 0)
    {
        if (argc != 2)
        {
            fprintf(stderr, "Usage: %s [--normalize-principal-test <principal> | "
                            "--account-groups-test <user> | "
                            "--decode-token-test <base64-token> | --keytab-env-test | "
                            "--acceptor-env-test | --import-acceptor-name-test <name> | "
                            "--context-flags-test <flags> | --no-core-test] "
                            "<base64-token>\n",
                    argv[0]);
            return 1;
        }
        return run_acceptor_env_test();
    }
    if (strcmp(argv[1], "--import-acceptor-name-test") == 0)
    {
        if (argc != 3)
        {
            fprintf(stderr, "Usage: %s [--normalize-principal-test <principal> | "
                            "--account-groups-test <user> | "
                            "--decode-token-test <base64-token> | --keytab-env-test | "
                            "--acceptor-env-test | --import-acceptor-name-test <name> | "
                            "--context-flags-test <flags> | --no-core-test] "
                            "<base64-token>\n",
                    argv[0]);
            return 1;
        }
        return run_import_acceptor_name_test(argv[2]);
    }
    if (strcmp(argv[1], "--context-flags-test") == 0)
    {
        if (argc != 3)
        {
            fprintf(stderr, "Usage: %s [--normalize-principal-test <principal> | "
                            "--account-groups-test <user> | "
                            "--decode-token-test <base64-token> | --keytab-env-test | "
                            "--acceptor-env-test | --import-acceptor-name-test <name> | "
                            "--context-flags-test <flags> | --no-core-test] "
                            "<base64-token>\n",
                    argv[0]);
            return 1;
        }
        return run_context_flags_test(argv[2]);
    }
    if (strcmp(argv[1], "--no-core-test") == 0)
    {
        if (argc != 2)
        {
            fprintf(stderr, "Usage: %s [--normalize-principal-test <principal> | "
                            "--account-groups-test <user> | "
                            "--decode-token-test <base64-token> | --keytab-env-test | "
                            "--acceptor-env-test | --import-acceptor-name-test <name> | "
                            "--context-flags-test <flags> | --no-core-test] "
                            "<base64-token>\n",
                    argv[0]);
            return 1;
        }
        return run_no_core_test();
    }
    token_b64 = argv[1];

    if (disable_core_dumps() != 0)
    {
        perror("disable_core_dumps");
        return 1;
    }

    /* Set keytab via environment. Adjust the path as needed. */
    if (configure_keytab_env() != 0)
        return 1;

    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_name_t client_name = GSS_C_NO_NAME;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    gss_cred_id_t acceptor_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t delegated_cred = GSS_C_NO_CREDENTIAL;
    OM_uint32 ret_flags = 0;
    OM_uint32 maj_stat = 0, min_stat = 0;

    if (decode_input_token(token_b64, &input_token) != 0)
    {
        fprintf(stderr, "invalid base64 Kerberos token\n");
        return 1;
    }

    if (acquire_acceptor_cred(&acceptor_cred) != 0)
    {
        rc = 1;
        goto cleanup;
    }

    fprintf(stderr, "frdp-krb-authd: skeleton - accepting decoded SPNEGO token.\n");

    /* Accept the security context. On success, client_name will hold the principal. */
    maj_stat = gss_accept_sec_context(&min_stat, &context, acceptor_cred,
                                      &input_token, GSS_C_NO_CHANNEL_BINDINGS,
                                      &client_name, NULL, &output_token,
                                      &ret_flags, NULL, &delegated_cred);
    if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
        display_status("gss_accept_sec_context", maj_stat, GSS_C_GSS_CODE);
        display_status("gss_accept_sec_context", min_stat, GSS_C_MECH_CODE);
        rc = 1;
        goto cleanup;
    }
    if (!context_flags_allowed(ret_flags))
    {
        fprintf(stderr, "delegated Kerberos credentials are not accepted\n");
        rc = 1;
        goto cleanup;
    }

    /* Display the authenticated principal and map to a POSIX user. */
    gss_buffer_desc name_buf = GSS_C_EMPTY_BUFFER;
    maj_stat = gss_display_name(&min_stat, client_name, &name_buf, NULL);
    if (maj_stat == GSS_S_COMPLETE) {
        char principal[256] = { 0 };
        char normalized_user[64] = { 0 };
        const char *mapping = NULL;
        if (name_buf.length >= sizeof(principal))
        {
            printf("No POSIX account found for principal; principal too long\n");
            gss_release_buffer(&min_stat, &name_buf);
            goto cleanup;
        }
        memcpy(principal, name_buf.value, name_buf.length);
        principal[name_buf.length] = '\0';
        printf("Kerberos principal: %s\n", principal);

        struct passwd *pwd = lookup_principal_account(principal, normalized_user,
                                                      sizeof(normalized_user), &mapping);
        if (pwd) {
            uint64_t groups[FRDP_IPC_MAX_AUTH_GROUPS] = { 0 };
            uint32_t group_count = 0;

            if (lookup_posix_groups(pwd->pw_name, pwd->pw_gid, groups, &group_count) != 0)
            {
                printf("POSIX group lookup failed for mapped user: %s\n", pwd->pw_name);
                rc = 1;
                SecureZeroMemory(groups, sizeof(groups));
                gss_release_buffer(&min_stat, &name_buf);
                goto cleanup;
            }
            printf("Mapped user: %s uid=%d gid=%d group_count=%u mapping=%s\n",
                   pwd->pw_name, (int)pwd->pw_uid, (int)pwd->pw_gid,
                   (unsigned int)group_count,
                   mapping ? mapping : "unknown");
            SecureZeroMemory(groups, sizeof(groups));
        } else if (normalized_user[0] != '\0') {
            printf("No POSIX account found for normalized user: %s\n", normalized_user);
        } else {
            printf("No POSIX account found for principal; mapping rejected\n");
        }
        gss_release_buffer(&min_stat, &name_buf);
    }

cleanup:
    if (client_name != GSS_C_NO_NAME)
        gss_release_name(&min_stat, &client_name);
    if (context != GSS_C_NO_CONTEXT)
        gss_delete_sec_context(&min_stat, &context, GSS_C_NO_BUFFER);
    if (acceptor_cred != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&min_stat, &acceptor_cred);
    if (delegated_cred != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&min_stat, &delegated_cred);
    if (output_token.length > 0)
        gss_release_buffer(&min_stat, &output_token);
    if (input_token.value && (input_token.length > 0))
        SecureZeroMemory(input_token.value, input_token.length);
    free(input_token.value);
    return rc;
}
