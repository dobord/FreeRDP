#include "frdp-config.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

static int copy_string(char *dst, size_t dst_size, const char *src)
{
    if (!dst || dst_size == 0)
        return -1;

    if (!src)
        src = "";
    int rc = snprintf(dst, dst_size, "%s", src);
    return (rc >= 0 && (size_t)rc < dst_size) ? 0 : -1;
}

/* Helper to trim whitespace from both ends of a string */
static void trim(char *s)
{
    char *p = s;
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1]))
        s[--len] = '\0';
    while (*p && isspace((unsigned char)*p))
        p++;
    if (p != s)
        memmove(s, p, strlen(p) + 1);
}

static int unquote_value(char *value)
{
    size_t len = 0;

    if (!value)
        return -1;

    len = strlen(value);
    if (len < 2)
        return -1;
    if (!((value[0] == '"' && value[len - 1] == '"') ||
          (value[0] == '\'' && value[len - 1] == '\'')))
        return -1;

    value[len - 1] = '\0';
    memmove(value, value + 1, len - 1);
    return 0;
}

/* Load key/value pairs from a simple TOML-like file. This parser ignores unknown sections and keys. */
int frdp_config_load(const char *path, frdpConfig *config)
{
    if (!path || !config)
        return -1;

    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char line[512];
    char current_section[32] = "";
    int seen_server_section = 0;
    int seen_auth_section = 0;
    int seen_listen = 0;
    int seen_security = 0;
    int seen_tls_cert = 0;
    int seen_tls_key = 0;
    int seen_auth_mode = 0;
    int seen_pam_service = 0;
    int seen_auth_socket = 0;
    /* Set defaults */
    memset(config, 0, sizeof(*config));
    if (copy_string(config->listen, sizeof(config->listen), "0.0.0.0:3389") != 0 ||
        copy_string(config->security, sizeof(config->security), "nla") != 0 ||
        copy_string(config->auth_mode, sizeof(config->auth_mode), "pam-sssd") != 0 ||
        copy_string(config->pam_service, sizeof(config->pam_service), "frdpd") != 0) {
        fclose(f);
        return -1;
    }
    while (fgets(line, sizeof(line), f)) {
        size_t raw_len = strlen(line);
        if (raw_len > 0 && line[raw_len - 1] != '\n' && !feof(f)) {
            fclose(f);
            return -1;
        }
        trim(line);
        if (line[0] == '#' || line[0] == '\0')
            continue;
        if (line[0] == '[') {
            char *end = strchr(line, ']');
            char *tail = NULL;
            if (!end) {
                fclose(f);
                return -1;
            }
            tail = end + 1;
            while (*tail && isspace((unsigned char)*tail))
                tail++;
            if (*tail != '\0' && *tail != '#') {
                fclose(f);
                return -1;
            }
            *end = '\0';
            if (copy_string(current_section, sizeof(current_section), line + 1) != 0) {
                fclose(f);
                return -1;
            }
            if ((strcmp(current_section, "server") != 0) &&
                (strcmp(current_section, "auth") != 0)) {
                fclose(f);
                return -1;
            }
            if (strcmp(current_section, "server") == 0) {
                if (seen_server_section) {
                    fclose(f);
                    return -1;
                }
                seen_server_section = 1;
            } else if (strcmp(current_section, "auth") == 0) {
                if (seen_auth_section) {
                    fclose(f);
                    return -1;
                }
                seen_auth_section = 1;
            }
            continue;
        }
        char *eq = strchr(line, '=');
        if (!eq) {
            fclose(f);
            return -1;
        }
        *eq = '\0';
        char key[64] = {0};
        char val[256] = {0};
        if (copy_string(key, sizeof(key), line) != 0 ||
            copy_string(val, sizeof(val), eq + 1) != 0) {
            fclose(f);
            return -1;
        }
        trim(key);
        trim(val);
        if (unquote_value(val) != 0) {
            fclose(f);
            return -1;
        }
        if (val[0] == '\0') {
            fclose(f);
            return -1;
        }
        if (strcmp(current_section, "server") == 0) {
            if (strcmp(key, "listen") == 0)
            {
                if (seen_listen) {
                    fclose(f);
                    return -1;
                }
                seen_listen = 1;
                if (copy_string(config->listen, sizeof(config->listen), val) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "security") == 0)
            {
                if (seen_security) {
                    fclose(f);
                    return -1;
                }
                seen_security = 1;
                if (copy_string(config->security, sizeof(config->security), val) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "tls_cert") == 0)
            {
                if (seen_tls_cert) {
                    fclose(f);
                    return -1;
                }
                seen_tls_cert = 1;
                if (copy_string(config->tls_cert, sizeof(config->tls_cert), val) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "tls_key") == 0)
            {
                if (seen_tls_key) {
                    fclose(f);
                    return -1;
                }
                seen_tls_key = 1;
                if (copy_string(config->tls_key, sizeof(config->tls_key), val) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "max_connections") == 0)
            {
                fclose(f);
                return -1;
            }
            else {
                fclose(f);
                return -1;
            }
        } else if (strcmp(current_section, "auth") == 0) {
            if (strcmp(key, "mode") == 0)
            {
                if (seen_auth_mode) {
                    fclose(f);
                    return -1;
                }
                seen_auth_mode = 1;
                if (copy_string(config->auth_mode, sizeof(config->auth_mode), val) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "pam_service") == 0)
            {
                if (seen_pam_service) {
                    fclose(f);
                    return -1;
                }
                seen_pam_service = 1;
                if (copy_string(config->pam_service, sizeof(config->pam_service), val) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "auth_socket") == 0)
            {
                if (seen_auth_socket) {
                    fclose(f);
                    return -1;
                }
                seen_auth_socket = 1;
                if (copy_string(config->auth_socket, sizeof(config->auth_socket), val) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "kerberos") == 0)
            {
                fclose(f);
                return -1;
            }
            else if (strcmp(key, "ntlm_fallback") == 0)
            {
                fclose(f);
                return -1;
            }
            else if (strcmp(key, "keytab") == 0)
            {
                fclose(f);
                return -1;
            }
            else if (strcmp(key, "accepted_spn") == 0)
            {
                fclose(f);
                return -1;
            }
            else {
                fclose(f);
                return -1;
            }
        } else if ((strcmp(current_section, "session") == 0) ||
                   (strcmp(current_section, "channels") == 0) ||
                   (strcmp(current_section, "audit") == 0)) {
            fclose(f);
            return -1;
        } else if (current_section[0] != '\0') {
            fclose(f);
            return -1;
        } else {
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    return 0;
}
