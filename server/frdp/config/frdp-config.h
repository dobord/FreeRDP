#ifndef FRDP_CONFIG_H
#define FRDP_CONFIG_H
#include <stdint.h>

#define FRDP_CONFIG_MAX_CHANNELS 31
#define FRDP_CONFIG_CHANNEL_NAME_SIZE 9

typedef struct {
    uint32_t static_allow_count;
    char static_allow[FRDP_CONFIG_MAX_CHANNELS][FRDP_CONFIG_CHANNEL_NAME_SIZE];
    uint32_t dynamic_allow_count;
    char dynamic_allow[FRDP_CONFIG_MAX_CHANNELS][FRDP_CONFIG_CHANNEL_NAME_SIZE];
} frdpChannelPolicy;

/* Structure representing configuration parsed from frdpd.toml */
typedef struct {
    char listen[64];
    uint32_t max_connections;
    char security[16];
    char tls_cert[256];
    char tls_key[256];
    char auth_mode[32];
    char pam_service[64];
    char auth_socket[108];
    char session_socket[108];
    frdpChannelPolicy channels;
} frdpConfig;

/* Load configuration from a TOML file into the provided struct. Returns 0 on success. */
int frdp_config_load(const char *path, frdpConfig *config);

#endif /* FRDP_CONFIG_H */
