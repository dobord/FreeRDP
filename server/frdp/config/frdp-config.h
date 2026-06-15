#ifndef FRDP_CONFIG_H
#define FRDP_CONFIG_H
#include <stdint.h>

/* Structure representing configuration parsed from frdpd.toml */
typedef struct {
    char listen[64];
    char security[16];
    char tls_cert[256];
    char tls_key[256];
    char auth_mode[32];
    char pam_service[64];
    char auth_socket[108];
    char session_socket[108];
} frdpConfig;

/* Load configuration from a TOML file into the provided struct. Returns 0 on success. */
int frdp_config_load(const char *path, frdpConfig *config);

#endif /* FRDP_CONFIG_H */
