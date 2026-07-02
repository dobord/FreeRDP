/*
 * frdp-krb-authd - Kerberos acceptor for FreeRDP-based RDP server
 *
 * This prototype demonstrates how to accept a Kerberos GSSAPI security context
 * and map the resulting principal to a POSIX user. It is not integrated with
 * the RDP server but illustrates the sequence needed for phase 4 of the plan.
 */

#include <gssapi/gssapi.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>

extern void crypto_base64_decode(const char *enc_data, size_t length, unsigned char **dec_data,
                                 size_t *res_length);

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
    free(input_token.value);
    return 0;
}

int main(int argc, char **argv)
{
    int rc = 0;
    const char *token_b64 = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [--normalize-principal-test <principal> | "
                        "--decode-token-test <base64-token>] <base64-token>\n",
                argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "--normalize-principal-test") == 0)
    {
        if (argc != 3)
        {
            fprintf(stderr, "Usage: %s [--normalize-principal-test <principal> | "
                            "--decode-token-test <base64-token>] <base64-token>\n",
                    argv[0]);
            return 1;
        }
        return run_normalize_principal_test(argv[2]);
    }
    if (strcmp(argv[1], "--decode-token-test") == 0)
    {
        if (argc != 3)
        {
            fprintf(stderr, "Usage: %s [--normalize-principal-test <principal> | "
                            "--decode-token-test <base64-token>] <base64-token>\n",
                    argv[0]);
            return 1;
        }
        return run_decode_token_test(argv[2]);
    }
    token_b64 = argv[1];

    /* Set keytab via environment. Adjust the path as needed. */
    if (!getenv("KRB5_KTNAME"))
    {
        const char *keytab = getenv("FRDP_KRB_KEYTAB");
        if (!keytab)
            keytab = "/etc/frdpd/frdpd.keytab";
        if (setenv("KRB5_KTNAME", keytab, 1) != 0)
        {
            perror("setenv(KRB5_KTNAME)");
            return 1;
        }
    }

    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_name_t client_name = GSS_C_NO_NAME;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    OM_uint32 maj_stat = 0, min_stat = 0;

    if (decode_input_token(token_b64, &input_token) != 0)
    {
        fprintf(stderr, "invalid base64 Kerberos token\n");
        return 1;
    }

    fprintf(stderr, "frdp-krb-authd: skeleton - accepting decoded SPNEGO token.\n");

    /* Accept the security context. On success, client_name will hold the principal. */
    maj_stat = gss_accept_sec_context(&min_stat, &context, GSS_C_NO_CREDENTIAL,
                                      &input_token, GSS_C_NO_CHANNEL_BINDINGS,
                                      &client_name, NULL, &output_token,
                                      NULL, NULL, NULL);
    if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
        display_status("gss_accept_sec_context", maj_stat, GSS_C_GSS_CODE);
        display_status("gss_accept_sec_context", min_stat, GSS_C_MECH_CODE);
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
            printf("Mapped user: %s uid=%d gid=%d mapping=%s\n",
                   pwd->pw_name, (int)pwd->pw_uid, (int)pwd->pw_gid,
                   mapping ? mapping : "unknown");
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
    if (output_token.length > 0)
        gss_release_buffer(&min_stat, &output_token);
    free(input_token.value);
    return rc;
}
