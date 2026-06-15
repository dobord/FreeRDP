/*
 * frdp-krb-authd - Kerberos acceptor for FreeRDP-based RDP server
 *
 * This prototype demonstrates how to accept a Kerberos GSSAPI security context
 * and map the resulting principal to a POSIX user. It is not integrated with
 * the RDP server but illustrates the sequence needed for phase 4 of the plan.
 */

#include <gssapi/gssapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>

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

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <base64-token>\n", argv[0]);
        return 1;
    }
    const char *token_b64 = argv[1];
    (void)token_b64;

    /* Set keytab via environment. Adjust the path as needed. */
    setenv("KRB5_KTNAME", "/etc/frdpd/frdpd.keytab", 1);

    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_name_t client_name = GSS_C_NO_NAME;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    OM_uint32 maj_stat = 0, min_stat = 0;

    /* For demonstration, we skip base64 decoding. In production, decode
     * token_b64 into input_token.value/length here. */
    fprintf(stderr, "frdp-krb-authd: skeleton – implement SPNEGO token handling.\n");

    /* Accept the security context. On success, client_name will hold the principal. */
    maj_stat = gss_accept_sec_context(&min_stat, &context, GSS_C_NO_CREDENTIAL,
                                      &input_token, GSS_C_NO_CHANNEL_BINDINGS,
                                      &client_name, NULL, &output_token,
                                      NULL, NULL, NULL);
    if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
        display_status("gss_accept_sec_context", maj_stat, GSS_C_GSS_CODE);
        display_status("gss_accept_sec_context", min_stat, GSS_C_MECH_CODE);
        return 1;
    }

    /* Display the authenticated principal and map to a POSIX user. */
    gss_buffer_desc name_buf = GSS_C_EMPTY_BUFFER;
    maj_stat = gss_display_name(&min_stat, client_name, &name_buf, NULL);
    if (maj_stat == GSS_S_COMPLETE) {
        printf("Kerberos principal: %.*s\n", (int)name_buf.length,
               (char *)name_buf.value);
        struct passwd *pwd = getpwnam((char *)name_buf.value);
        if (pwd) {
            printf("Mapped user: %s uid=%d gid=%d\n",
                   pwd->pw_name, (int)pwd->pw_uid, (int)pwd->pw_gid);
        } else {
            printf("No POSIX account found for principal\n");
        }
        gss_release_buffer(&min_stat, &name_buf);
    }

    if (client_name != GSS_C_NO_NAME)
        gss_release_name(&min_stat, &client_name);
    if (context != GSS_C_NO_CONTEXT)
        gss_delete_sec_context(&min_stat, &context, GSS_C_NO_BUFFER);
    if (output_token.length > 0)
        gss_release_buffer(&min_stat, &output_token);
    return 0;
}
