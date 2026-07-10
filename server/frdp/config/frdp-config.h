#ifndef FRDP_CONFIG_H
#define FRDP_CONFIG_H
#include <stdint.h>

#define FRDP_CONFIG_MAX_CHANNELS 31
#define FRDP_CONFIG_CHANNEL_NAME_SIZE 9
#define FRDP_SESSION_HEARTBEAT_DEFAULT_INTERVAL_MS 5000U
#define FRDP_SESSION_HEARTBEAT_DEFAULT_TIMEOUT_MS 500U
#define FRDP_SESSION_HEARTBEAT_DEFAULT_FAILURES 3U
#define FRDP_SESSION_HEARTBEAT_MIN_INTERVAL_MS 1000U
#define FRDP_SESSION_HEARTBEAT_MAX_INTERVAL_MS 60000U
#define FRDP_SESSION_HEARTBEAT_MIN_TIMEOUT_MS 500U
#define FRDP_SESSION_HEARTBEAT_MAX_TIMEOUT_MS 5000U
#define FRDP_SESSION_HEARTBEAT_MAX_FAILURES 10U
#define FRDP_SESSION_HEARTBEAT_MIN_FAILURES 3U

typedef enum {
    FRDP_CHANNEL_FILTER_BLOCKLIST = 0,
    FRDP_CHANNEL_FILTER_ALLOWLIST = 1
} frdpChannelFilterMode;

typedef enum {
    FRDP_CLIPBOARD_MODE_DISABLED = 0,
    FRDP_CLIPBOARD_MODE_TEXT = 1
} frdpClipboardMode;

typedef enum {
    FRDP_CLIPBOARD_DIRECTION_DISABLED = 0,
    FRDP_CLIPBOARD_DIRECTION_CLIENT_TO_SERVER = 1,
    FRDP_CLIPBOARD_DIRECTION_SERVER_TO_CLIENT = 2,
    FRDP_CLIPBOARD_DIRECTION_BIDIRECTIONAL = 3
} frdpClipboardDirection;

typedef struct {
    frdpChannelFilterMode static_mode;
    uint32_t static_allow_count;
    char static_allow[FRDP_CONFIG_MAX_CHANNELS][FRDP_CONFIG_CHANNEL_NAME_SIZE];
    uint32_t static_deny_count;
    char static_deny[FRDP_CONFIG_MAX_CHANNELS][FRDP_CONFIG_CHANNEL_NAME_SIZE];
    frdpChannelFilterMode dynamic_mode;
    uint32_t dynamic_allow_count;
    char dynamic_allow[FRDP_CONFIG_MAX_CHANNELS][FRDP_CONFIG_CHANNEL_NAME_SIZE];
    uint32_t dynamic_deny_count;
    char dynamic_deny[FRDP_CONFIG_MAX_CHANNELS][FRDP_CONFIG_CHANNEL_NAME_SIZE];
} frdpChannelPolicy;

typedef struct {
    frdpClipboardMode mode;
    frdpClipboardDirection direction;
    uint32_t max_text_bytes;
} frdpClipboardPolicy;

typedef struct {
    uint32_t max_processes;
    uint32_t memory_max_mb;
} frdpSessionResourcePolicy;

typedef struct {
    uint32_t interval_ms;
    uint32_t timeout_ms;
    uint32_t failure_threshold;
} frdpSessionHeartbeatPolicy;

typedef struct {
    int enabled;
} frdpAuditPolicy;

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
    int ntlm_fallback;
    int kerberos;
    char keytab[256];
    char accepted_spn[256];
    char session_socket[108];
    frdpSessionResourcePolicy session_resources;
    frdpSessionHeartbeatPolicy session_heartbeat;
    frdpChannelPolicy channels;
    frdpClipboardPolicy clipboard;
    frdpAuditPolicy audit;
} frdpConfig;

/* Load configuration from a TOML file into the provided struct. Returns 0 on success. */
int frdp_config_load(const char *path, frdpConfig *config);

#endif /* FRDP_CONFIG_H */
