#ifndef FRDP_CONFIG_H
#define FRDP_CONFIG_H
#include <stdint.h>

/* Structure representing configuration parsed from frdpd.toml */
typedef struct {
    char listen[64];
    char security[16];
    char tls_cert[256];
    char tls_key[256];
    int max_connections;
    char auth_mode[32];
    char pam_service[64];
    char kerberos_policy[16];
    int ntlm_fallback;
    char keytab[256];
} frdpConfig;

/* Load configuration from a TOML file into the provided struct. Returns 0 on success. */
int frdp_config_load(const char *path, frdpConfig *config);

#endif /* FRDP_CONFIG_H */
