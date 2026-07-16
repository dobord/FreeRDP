#include "frdp-config.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#define FRDP_CLIPBOARD_DEFAULT_MAX_TEXT_BYTES 65536U
#define FRDP_CLIPBOARD_MAX_TEXT_BYTES_LIMIT 1048576U
#define FRDP_SESSION_MAX_PROCESSES_LIMIT 1048576U
#define FRDP_SESSION_MEMORY_MAX_MB_LIMIT 1048576U

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

static int parse_uint32_limit(const char *value, uint32_t *out)
{
    char *end = NULL;
    unsigned long tmp = 0;

    if (!value || !out || value[0] == '\0' || value[0] == '-')
        return -1;

    errno = 0;
    tmp = strtoul(value, &end, 10);
    if ((errno != 0) || !end || (end[0] != '\0') || (tmp > INT_MAX))
        return -1;
    *out = (uint32_t)tmp;
    return 0;
}

static int parse_bool_value(const char *value, int *out)
{
    if (!value || !out)
        return -1;
    if (strcmp(value, "true") == 0) {
        *out = 1;
        return 0;
    }
    if (strcmp(value, "false") == 0) {
        *out = 0;
        return 0;
    }
    return -1;
}

static int parse_channel_filter_mode(const char *value, frdpChannelFilterMode *mode)
{
    if (!value || !mode)
        return -1;
    if (strcmp(value, "allowlist") == 0 || strcmp(value, "whitelist") == 0) {
        *mode = FRDP_CHANNEL_FILTER_ALLOWLIST;
        return 0;
    }
    if (strcmp(value, "blocklist") == 0 || strcmp(value, "blacklist") == 0) {
        *mode = FRDP_CHANNEL_FILTER_BLOCKLIST;
        return 0;
    }
    return -1;
}

static int parse_clipboard_mode(const char *value, frdpClipboardMode *mode)
{
    if (!value || !mode)
        return -1;
    if (strcmp(value, "disabled") == 0) {
        *mode = FRDP_CLIPBOARD_MODE_DISABLED;
        return 0;
    }
    if (strcmp(value, "text") == 0) {
        *mode = FRDP_CLIPBOARD_MODE_TEXT;
        return 0;
    }
    return -1;
}

static int parse_clipboard_direction(const char *value, frdpClipboardDirection *direction)
{
    if (!value || !direction)
        return -1;
    if (strcmp(value, "disabled") == 0) {
        *direction = FRDP_CLIPBOARD_DIRECTION_DISABLED;
        return 0;
    }
    if (strcmp(value, "client-to-server") == 0) {
        *direction = FRDP_CLIPBOARD_DIRECTION_CLIENT_TO_SERVER;
        return 0;
    }
    if (strcmp(value, "server-to-client") == 0) {
        *direction = FRDP_CLIPBOARD_DIRECTION_SERVER_TO_CLIENT;
        return 0;
    }
    if (strcmp(value, "bidirectional") == 0) {
        *direction = FRDP_CLIPBOARD_DIRECTION_BIDIRECTIONAL;
        return 0;
    }
    return -1;
}

static int is_absolute_path(const char *path)
{
    if (!path || path[0] != '/')
        return 0;
    for (size_t i = 0; path[i] != '\0'; i++) {
        const unsigned char c = (unsigned char)path[i];
        if (iscntrl(c))
            return 0;
    }
    return 1;
}

static int is_accepted_spn_valid(const char *spn)
{
    const char prefix[] = "TERMSRV/";
    const size_t prefix_len = sizeof(prefix) - 1U;
    const char *host = NULL;
    size_t host_len = 0;
    char previous = '\0';
    int has_dot = 0;

    if (!spn || strncmp(spn, prefix, prefix_len) != 0)
        return 0;
    host = spn + prefix_len;
    host_len = strlen(host);
    if (host_len == 0 || host[0] == '.' || host[0] == '-' ||
        host[host_len - 1U] == '.' || host[host_len - 1U] == '-')
        return 0;
    for (size_t i = 0; i < host_len; i++) {
        const unsigned char c = (unsigned char)host[i];
        if (!(isalnum(c) || c == '.' || c == '-'))
            return 0;
        if ((c == '.') && (previous == '.' || previous == '-'))
            return 0;
        if ((c == '-') && (previous == '.'))
            return 0;
        if (c == '.')
            has_dot = 1;
        previous = (char)c;
    }
    return has_dot;
}

static int is_channel_name_valid(const char *name)
{
    size_t len = 0;

    if (!name)
        return 0;
    len = strlen(name);
    if (len == 0 || len >= FRDP_CONFIG_CHANNEL_NAME_SIZE)
        return 0;
    for (size_t i = 0; i < len; i++) {
        const unsigned char c = (unsigned char)name[i];
        if (!isalnum(c) && c != '_')
            return 0;
    }
    return 1;
}

static int add_channel_name(char channels[FRDP_CONFIG_MAX_CHANNELS][FRDP_CONFIG_CHANNEL_NAME_SIZE],
                            uint32_t *count, const char *name)
{
    if (!channels || !count || !is_channel_name_valid(name))
        return -1;
    for (uint32_t i = 0; i < *count; i++) {
        if (strcmp(channels[i], name) == 0)
            return -1;
    }
    if (*count >= FRDP_CONFIG_MAX_CHANNELS)
        return -1;
    if (copy_string(channels[*count], FRDP_CONFIG_CHANNEL_NAME_SIZE, name) != 0)
        return -1;
    (*count)++;
    return 0;
}

static int add_static_channel_allow(frdpConfig *config, const char *name)
{
    if (!config)
        return -1;
    return add_channel_name(config->channels.static_allow, &config->channels.static_allow_count,
                            name);
}

static int add_static_channel_deny(frdpConfig *config, const char *name)
{
    if (!config)
        return -1;
    return add_channel_name(config->channels.static_deny, &config->channels.static_deny_count,
                            name);
}

static int add_dynamic_channel_allow(frdpConfig *config, const char *name)
{
    if (!config)
        return -1;
    return add_channel_name(config->channels.dynamic_allow, &config->channels.dynamic_allow_count,
                            name);
}

static int add_dynamic_channel_deny(frdpConfig *config, const char *name)
{
    if (!config)
        return -1;
    return add_channel_name(config->channels.dynamic_deny, &config->channels.dynamic_deny_count,
                            name);
}

static int parse_channel_list(frdpConfig *config, char *value, int dynamic, int deny)
{
    char *cursor = value;

    if (!config || !value)
        return -1;
    if (value[0] == '\0')
        return 0;
    while (cursor) {
        char *next = strchr(cursor, ',');

        if (next) {
            *next = '\0';
            next++;
        }
        trim(cursor);
        if (dynamic) {
            if (deny) {
                if (add_dynamic_channel_deny(config, cursor) != 0)
                    return -1;
            }
            else if (add_dynamic_channel_allow(config, cursor) != 0)
                return -1;
        }
        else if (deny) {
            if (add_static_channel_deny(config, cursor) != 0)
                return -1;
        }
        else if (add_static_channel_allow(config, cursor) != 0)
            return -1;
        cursor = next;
    }
    return 0;
}

static int parse_static_channel_allow(frdpConfig *config, char *value)
{
    return parse_channel_list(config, value, 0, 0);
}

static int parse_static_channel_deny(frdpConfig *config, char *value)
{
    return parse_channel_list(config, value, 0, 1);
}

static int parse_dynamic_channel_allow(frdpConfig *config, char *value)
{
    return parse_channel_list(config, value, 1, 0);
}

static int parse_dynamic_channel_deny(frdpConfig *config, char *value)
{
    return parse_channel_list(config, value, 1, 1);
}

static int channel_list_contains(
    const char channels[FRDP_CONFIG_MAX_CHANNELS][FRDP_CONFIG_CHANNEL_NAME_SIZE], uint32_t count,
    const char *name)
{
    for (uint32_t i = 0; i < count; i++) {
        if (strcmp(channels[i], name) == 0)
            return 1;
    }
    return 0;
}

static int validate_channel_filter_lists(const frdpConfig *config, int seen_static_allow,
                                         int seen_static_deny, int seen_dynamic_allow,
                                         int seen_dynamic_deny)
{
    if (!config)
        return -1;
    if (config->channels.static_mode == FRDP_CHANNEL_FILTER_ALLOWLIST) {
        if (seen_static_deny)
            return -1;
    }
    else if (config->channels.static_mode == FRDP_CHANNEL_FILTER_BLOCKLIST) {
        if (seen_static_allow)
            return -1;
    }
    else
        return -1;

    if (config->channels.dynamic_mode == FRDP_CHANNEL_FILTER_ALLOWLIST) {
        if (seen_dynamic_deny)
            return -1;
        if (channel_list_contains(config->channels.dynamic_allow,
                                  config->channels.dynamic_allow_count, "drdynvc"))
            return -1;
    }
    else if (config->channels.dynamic_mode == FRDP_CHANNEL_FILTER_BLOCKLIST) {
        if (seen_dynamic_allow)
            return -1;
    }
    else
        return -1;
    return 0;
}

static int validate_clipboard_policy(const frdpConfig *config, int seen_direction)
{
    if (!config)
        return -1;
    if ((config->clipboard.max_text_bytes == 0) ||
        (config->clipboard.max_text_bytes > FRDP_CLIPBOARD_MAX_TEXT_BYTES_LIMIT))
        return -1;

    if (config->clipboard.mode == FRDP_CLIPBOARD_MODE_DISABLED)
        return (config->clipboard.direction == FRDP_CLIPBOARD_DIRECTION_DISABLED) ? 0 : -1;

    if (config->clipboard.mode == FRDP_CLIPBOARD_MODE_TEXT) {
        if (!seen_direction)
            return -1;
        return (config->clipboard.direction != FRDP_CLIPBOARD_DIRECTION_DISABLED) ? 0 : -1;
    }

    return -1;
}

static int validate_audit_policy(const frdpConfig *config)
{
    if (!config)
        return -1;
    return (config->audit.enabled == 0) ? 0 : -1;
}

static int validate_session_resource_policy(const frdpConfig *config)
{
    if (!config)
        return -1;
    if (config->session_resources.max_processes > FRDP_SESSION_MAX_PROCESSES_LIMIT)
        return -1;
    if (config->session_resources.memory_max_mb > FRDP_SESSION_MEMORY_MAX_MB_LIMIT)
        return -1;
    return 0;
}

static int validate_session_heartbeat_policy(const frdpConfig *config)
{
    if (!config)
        return -1;
    if ((config->session_heartbeat.interval_ms < FRDP_SESSION_HEARTBEAT_MIN_INTERVAL_MS) ||
        (config->session_heartbeat.interval_ms > FRDP_SESSION_HEARTBEAT_MAX_INTERVAL_MS))
        return -1;
    if ((config->session_heartbeat.timeout_ms < FRDP_SESSION_HEARTBEAT_MIN_TIMEOUT_MS) ||
        (config->session_heartbeat.timeout_ms > FRDP_SESSION_HEARTBEAT_MAX_TIMEOUT_MS) ||
        (config->session_heartbeat.timeout_ms > config->session_heartbeat.interval_ms))
        return -1;
    if ((config->session_heartbeat.failure_threshold < FRDP_SESSION_HEARTBEAT_MIN_FAILURES) ||
        (config->session_heartbeat.failure_threshold > FRDP_SESSION_HEARTBEAT_MAX_FAILURES))
        return -1;
    return 0;
}

static int validate_session_display_policy(const frdpConfig* config)
{
    if (!config)
        return -1;
    if (config->session_display.backend == FRDP_SESSION_DISPLAY_XVFB)
        return (config->session_display.xorg_path[0] == '\0' &&
                config->session_display.xorg_config[0] == '\0')
                   ? 0
                   : -1;
    if (config->session_display.backend != FRDP_SESSION_DISPLAY_XORG_DUMMY)
        return -1;
    return (is_absolute_path(config->session_display.xorg_path) &&
            is_absolute_path(config->session_display.xorg_config))
               ? 0
               : -1;
}

/* Load key/value pairs from a small fail-closed TOML subset. */
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
    int seen_session_section = 0;
    int seen_channels_section = 0;
    int seen_clipboard_section = 0;
    int seen_audit_section = 0;
    int seen_listen = 0;
    int seen_max_connections = 0;
    int seen_security = 0;
    int seen_tls_cert = 0;
    int seen_tls_key = 0;
    int seen_auth_mode = 0;
    int seen_pam_service = 0;
    int seen_auth_socket = 0;
    int seen_ntlm_fallback = 0;
    int seen_ntlm_sam_file = 0;
    int seen_kerberos = 0;
    int seen_keytab = 0;
    int seen_accepted_spn = 0;
    int seen_session_socket = 0;
    int seen_session_max_processes = 0;
    int seen_session_memory_max_mb = 0;
    int seen_session_heartbeat_interval_ms = 0;
    int seen_session_heartbeat_timeout_ms = 0;
    int seen_session_heartbeat_failures = 0;
    int seen_session_display_backend = 0;
    int seen_session_xorg_path = 0;
    int seen_session_xorg_config = 0;
    int seen_channel_static_mode = 0;
    int seen_channel_static_allow = 0;
    int seen_channel_static_deny = 0;
    int seen_channel_dynamic_mode = 0;
    int seen_channel_dynamic_allow = 0;
    int seen_channel_dynamic_deny = 0;
    int seen_clipboard_mode = 0;
    int seen_clipboard_direction = 0;
    int seen_clipboard_max_text_bytes = 0;
    int seen_audit_enabled = 0;
    /* Set defaults */
    memset(config, 0, sizeof(*config));
    config->ntlm_fallback = 0;
    config->session_heartbeat.interval_ms = FRDP_SESSION_HEARTBEAT_DEFAULT_INTERVAL_MS;
    config->session_heartbeat.timeout_ms = FRDP_SESSION_HEARTBEAT_DEFAULT_TIMEOUT_MS;
    config->session_heartbeat.failure_threshold = FRDP_SESSION_HEARTBEAT_DEFAULT_FAILURES;
    config->clipboard.max_text_bytes = FRDP_CLIPBOARD_DEFAULT_MAX_TEXT_BYTES;
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
                (strcmp(current_section, "auth") != 0) &&
                (strcmp(current_section, "session") != 0) &&
                (strcmp(current_section, "channels") != 0) &&
                (strcmp(current_section, "clipboard") != 0) &&
                (strcmp(current_section, "audit") != 0)) {
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
            } else if (strcmp(current_section, "session") == 0) {
                if (seen_session_section) {
                    fclose(f);
                    return -1;
                }
                seen_session_section = 1;
            } else if (strcmp(current_section, "channels") == 0) {
                if (seen_channels_section) {
                    fclose(f);
                    return -1;
                }
                seen_channels_section = 1;
            } else if (strcmp(current_section, "clipboard") == 0) {
                if (seen_clipboard_section) {
                    fclose(f);
                    return -1;
                }
                seen_clipboard_section = 1;
            } else if (strcmp(current_section, "audit") == 0) {
                if (seen_audit_section) {
                    fclose(f);
                    return -1;
                }
                seen_audit_section = 1;
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
        const int allow_empty_value = (strcmp(current_section, "channels") == 0) &&
                                      ((strcmp(key, "static_allow") == 0) ||
                                       (strcmp(key, "static_deny") == 0) ||
                                       (strcmp(key, "dynamic_allow") == 0) ||
                                       (strcmp(key, "dynamic_deny") == 0));
        const int allow_bare_value = ((strcmp(current_section, "server") == 0) &&
                                      (strcmp(key, "max_connections") == 0)) ||
                                     ((strcmp(current_section, "auth") == 0) &&
                                     (strcmp(key, "ntlm_fallback") == 0)) ||
                                     ((strcmp(current_section, "auth") == 0) &&
                                      (strcmp(key, "kerberos") == 0)) ||
                                     ((strcmp(current_section, "clipboard") == 0) &&
                                      (strcmp(key, "max_text_bytes") == 0)) ||
                                     ((strcmp(current_section, "session") == 0) &&
                                      ((strcmp(key, "max_processes") == 0) ||
                                       (strcmp(key, "memory_max_mb") == 0) ||
                                       (strcmp(key, "agent_heartbeat_interval_ms") == 0) ||
                                       (strcmp(key, "agent_heartbeat_timeout_ms") == 0) ||
                                       (strcmp(key, "agent_heartbeat_failures") == 0))) ||
                                     ((strcmp(current_section, "audit") == 0) &&
                                      (strcmp(key, "enabled") == 0));
        if (allow_bare_value) {
            /* Bare values are accepted for TOML-like integer and boolean fields. */
        }
        else {
            if (unquote_value(val) != 0) {
                fclose(f);
                return -1;
            }
        }
        if (val[0] == '\0' && !allow_empty_value) {
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
                if (strcmp(val, "nla") != 0) {
                    fclose(f);
                    return -1;
                }
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
                if (seen_max_connections) {
                    fclose(f);
                    return -1;
                }
                seen_max_connections = 1;
                if (parse_uint32_limit(val, &config->max_connections) != 0) {
                    fclose(f);
                    return -1;
                }
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
                if (strcmp(val, "pam-sssd") != 0) {
                    fclose(f);
                    return -1;
                }
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
                if (!is_absolute_path(val) ||
                    copy_string(config->auth_socket, sizeof(config->auth_socket), val) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "kerberos") == 0)
            {
                if (seen_kerberos) {
                    fclose(f);
                    return -1;
                }
                seen_kerberos = 1;
                if (parse_bool_value(val, &config->kerberos) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "ntlm_fallback") == 0)
            {
                if (seen_ntlm_fallback) {
                    fclose(f);
                    return -1;
                }
                seen_ntlm_fallback = 1;
                if (parse_bool_value(val, &config->ntlm_fallback) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "ntlm_sam_file") == 0)
            {
                if (seen_ntlm_sam_file) {
                    fclose(f);
                    return -1;
                }
                seen_ntlm_sam_file = 1;
                if (!is_absolute_path(val) ||
                    copy_string(config->ntlm_sam_file, sizeof(config->ntlm_sam_file), val) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "keytab") == 0)
            {
                if (seen_keytab) {
                    fclose(f);
                    return -1;
                }
                seen_keytab = 1;
                if (!is_absolute_path(val) ||
                    copy_string(config->keytab, sizeof(config->keytab), val) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "accepted_spn") == 0)
            {
                if (seen_accepted_spn) {
                    fclose(f);
                    return -1;
                }
                seen_accepted_spn = 1;
                if (!is_accepted_spn_valid(val) ||
                    copy_string(config->accepted_spn, sizeof(config->accepted_spn), val) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else {
                fclose(f);
                return -1;
            }
        } else if (strcmp(current_section, "session") == 0) {
            if (strcmp(key, "session_socket") == 0)
            {
                if (seen_session_socket) {
                    fclose(f);
                    return -1;
                }
                seen_session_socket = 1;
                if (!is_absolute_path(val) ||
                    copy_string(config->session_socket, sizeof(config->session_socket), val) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "max_processes") == 0)
            {
                if (seen_session_max_processes) {
                    fclose(f);
                    return -1;
                }
                seen_session_max_processes = 1;
                if (parse_uint32_limit(val, &config->session_resources.max_processes) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "memory_max_mb") == 0)
            {
                if (seen_session_memory_max_mb) {
                    fclose(f);
                    return -1;
                }
                seen_session_memory_max_mb = 1;
                if (parse_uint32_limit(val, &config->session_resources.memory_max_mb) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "agent_heartbeat_interval_ms") == 0)
            {
                if (seen_session_heartbeat_interval_ms) {
                    fclose(f);
                    return -1;
                }
                seen_session_heartbeat_interval_ms = 1;
                if (parse_uint32_limit(val, &config->session_heartbeat.interval_ms) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "agent_heartbeat_timeout_ms") == 0)
            {
                if (seen_session_heartbeat_timeout_ms) {
                    fclose(f);
                    return -1;
                }
                seen_session_heartbeat_timeout_ms = 1;
                if (parse_uint32_limit(val, &config->session_heartbeat.timeout_ms) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "agent_heartbeat_failures") == 0)
            {
                if (seen_session_heartbeat_failures) {
                    fclose(f);
                    return -1;
                }
                seen_session_heartbeat_failures = 1;
                if (parse_uint32_limit(val, &config->session_heartbeat.failure_threshold) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "display_backend") == 0)
            {
                if (seen_session_display_backend) {
                    fclose(f);
                    return -1;
                }
                seen_session_display_backend = 1;
                if (strcmp(val, "xvfb") == 0)
                    config->session_display.backend = FRDP_SESSION_DISPLAY_XVFB;
                else if (strcmp(val, "xorg-dummy") == 0)
                    config->session_display.backend = FRDP_SESSION_DISPLAY_XORG_DUMMY;
                else {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "xorg_path") == 0)
            {
                if (seen_session_xorg_path || !is_absolute_path(val) ||
                    copy_string(config->session_display.xorg_path,
                                sizeof(config->session_display.xorg_path), val) != 0) {
                    fclose(f);
                    return -1;
                }
                seen_session_xorg_path = 1;
            }
            else if (strcmp(key, "xorg_config") == 0)
            {
                if (seen_session_xorg_config || !is_absolute_path(val) ||
                    copy_string(config->session_display.xorg_config,
                                sizeof(config->session_display.xorg_config), val) != 0) {
                    fclose(f);
                    return -1;
                }
                seen_session_xorg_config = 1;
            }
            else {
                fclose(f);
                return -1;
            }
        } else if (strcmp(current_section, "channels") == 0) {
            if (strcmp(key, "static_mode") == 0) {
                if (seen_channel_static_mode) {
                    fclose(f);
                    return -1;
                }
                seen_channel_static_mode = 1;
                if (parse_channel_filter_mode(val, &config->channels.static_mode) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "static_allow") == 0) {
                if (seen_channel_static_allow) {
                    fclose(f);
                    return -1;
                }
                seen_channel_static_allow = 1;
                if (parse_static_channel_allow(config, val) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "static_deny") == 0) {
                if (seen_channel_static_deny) {
                    fclose(f);
                    return -1;
                }
                seen_channel_static_deny = 1;
                if (parse_static_channel_deny(config, val) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "dynamic_mode") == 0) {
                if (seen_channel_dynamic_mode) {
                    fclose(f);
                    return -1;
                }
                seen_channel_dynamic_mode = 1;
                if (parse_channel_filter_mode(val, &config->channels.dynamic_mode) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "dynamic_allow") == 0) {
                if (seen_channel_dynamic_allow) {
                    fclose(f);
                    return -1;
                }
                seen_channel_dynamic_allow = 1;
                if (parse_dynamic_channel_allow(config, val) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "dynamic_deny") == 0) {
                if (seen_channel_dynamic_deny) {
                    fclose(f);
                    return -1;
                }
                seen_channel_dynamic_deny = 1;
                if (parse_dynamic_channel_deny(config, val) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else {
                fclose(f);
                return -1;
            }
        } else if (strcmp(current_section, "clipboard") == 0) {
            if (strcmp(key, "mode") == 0) {
                if (seen_clipboard_mode) {
                    fclose(f);
                    return -1;
                }
                seen_clipboard_mode = 1;
                if (parse_clipboard_mode(val, &config->clipboard.mode) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "direction") == 0) {
                if (seen_clipboard_direction) {
                    fclose(f);
                    return -1;
                }
                seen_clipboard_direction = 1;
                if (parse_clipboard_direction(val, &config->clipboard.direction) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else if (strcmp(key, "max_text_bytes") == 0) {
                if (seen_clipboard_max_text_bytes) {
                    fclose(f);
                    return -1;
                }
                seen_clipboard_max_text_bytes = 1;
                if (parse_uint32_limit(val, &config->clipboard.max_text_bytes) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else {
                fclose(f);
                return -1;
            }
        } else if (strcmp(current_section, "audit") == 0) {
            if (strcmp(key, "enabled") == 0) {
                if (seen_audit_enabled) {
                    fclose(f);
                    return -1;
                }
                seen_audit_enabled = 1;
                if (parse_bool_value(val, &config->audit.enabled) != 0) {
                    fclose(f);
                    return -1;
                }
            }
            else {
                fclose(f);
                return -1;
            }
        } else if (current_section[0] != '\0') {
            fclose(f);
            return -1;
        } else {
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    if (validate_channel_filter_lists(config, seen_channel_static_allow, seen_channel_static_deny,
                                      seen_channel_dynamic_allow,
                                      seen_channel_dynamic_deny) != 0)
        return -1;
    if (validate_clipboard_policy(config, seen_clipboard_direction) != 0)
        return -1;
    if (validate_session_resource_policy(config) != 0)
        return -1;
    if (validate_session_heartbeat_policy(config) != 0)
        return -1;
    if (validate_session_display_policy(config) != 0)
        return -1;
    if (validate_audit_policy(config) != 0)
        return -1;
    if (!config->kerberos && (seen_keytab || seen_accepted_spn))
        return -1;
    if (config->kerberos &&
        (!seen_ntlm_fallback || !seen_keytab || !seen_accepted_spn || config->ntlm_fallback))
        return -1;
    if (seen_ntlm_sam_file && !config->ntlm_fallback)
        return -1;
    return 0;
}
