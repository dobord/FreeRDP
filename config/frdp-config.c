#include "frdp-config.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

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

/* Load key/value pairs from a simple TOML-like file. This parser ignores unknown sections and keys. */
int frdp_config_load(const char *path, frdpConfig *config)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char line[512];
    char current_section[32] = "";
    /* Set defaults */
    memset(config, 0, sizeof(*config));
    strcpy(config->listen, "0.0.0.0:3389");
    strcpy(config->security, "nla");
    strcpy(config->auth_mode, "pam-sssd");
    strcpy(config->pam_service, "frdpd");
    strcpy(config->kerberos_policy, "preferred");
    config->max_connections = 64;
    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (line[0] == '#' || line[0] == '\0')
            continue;
        if (line[0] == '[') {
            char *end = strchr(line, ']');
            if (end) {
                *end = '\0';
                strncpy(current_section, line + 1, sizeof(current_section) - 1);
            }
            continue;
        }
        char *eq = strchr(line, '=');
        if (!eq)
            continue;
        *eq = '\0';
        char key[64], val[256];
        strncpy(key, line, sizeof(key) - 1);
        strncpy(val, eq + 1, sizeof(val) - 1);
        trim(key);
        trim(val);
        size_t vlen = strlen(val);
        if (vlen >= 2 && ((val[0] == '"' && val[vlen - 1] == '"') || (val[0] == '\'' && val[vlen - 1] == '\''))) {
            val[vlen - 1] = '\0';
            memmove(val, val + 1, vlen - 1);
        }
        if (strcmp(current_section, "server") == 0) {
            if (strcmp(key, "listen") == 0)
                strncpy(config->listen, val, sizeof(config->listen) - 1);
            else if (strcmp(key, "security") == 0)
                strncpy(config->security, val, sizeof(config->security) - 1);
            else if (strcmp(key, "tls_cert") == 0)
                strncpy(config->tls_cert, val, sizeof(config->tls_cert) - 1);
            else if (strcmp(key, "tls_key") == 0)
                strncpy(config->tls_key, val, sizeof(config->tls_key) - 1);
            else if (strcmp(key, "max_connections") == 0)
                config->max_connections = atoi(val);
        } else if (strcmp(current_section, "auth") == 0) {
            if (strcmp(key, "mode") == 0)
                strncpy(config->auth_mode, val, sizeof(config->auth_mode) - 1);
            else if (strcmp(key, "pam_service") == 0)
                strncpy(config->pam_service, val, sizeof(config->pam_service) - 1);
            else if (strcmp(key, "kerberos") == 0)
                strncpy(config->kerberos_policy, val, sizeof(config->kerberos_policy) - 1);
            else if (strcmp(key, "ntlm_fallback") == 0)
                config->ntlm_fallback = (val[0] == 't' || val[0] == 'T' || val[0] == '1');
            else if (strcmp(key, "keytab") == 0)
                strncpy(config->keytab, val, sizeof(config->keytab) - 1);
        }
        /* session and channels sections could be parsed here in future */
    }
    fclose(f);
    return 0;
}
