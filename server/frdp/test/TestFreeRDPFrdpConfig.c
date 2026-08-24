#include "config/frdp-config.h"
#include "frdpd/channel_policy.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int write_config(const char* name, const char* body, char* path, size_t path_size)
{
	FILE* fp = NULL;
	const int rc = snprintf(path, path_size, "%s/%s", CMAKE_CURRENT_BINARY_DIR, name);

	if ((rc < 0) || ((size_t)rc >= path_size))
		return -1;

	fp = fopen(path, "w");
	if (!fp)
		return -1;
	if (fputs(body, fp) < 0)
	{
		fclose(fp);
		return -1;
	}
	if (fclose(fp) != 0)
		return -1;
	return 0;
}

static int load_config_body(const char* name, const char* body, frdpConfig* config)
{
	char path[1024] = { 0 };
	int rc = -1;

	if (write_config(name, body, path, sizeof(path)) != 0)
		return -1;
	rc = frdp_config_load(path, config);
	(void)unlink(path);
	return rc;
}

static int expect_load_failure(const char* name, const char* body)
{
	frdpConfig config = { 0 };

	if (load_config_body(name, body, &config) == 0)
	{
		printf("config unexpectedly loaded: %s\n", name);
		return -1;
	}
	return 0;
}

static int test_default_blocklist(void)
{
	frdpConfig config = { 0 };
	CHANNEL_DEF channel = { 0 };
	char name[CHANNEL_NAME_LEN + 2] = { 0 };

	if (load_config_body("frdp-default-blocklist.toml", "", &config) != 0)
		return -1;
	if (config.max_connections != 0)
		return -1;
	if (config.session_resources.max_sessions != 0)
		return -1;
	if (config.session_resources.max_processes != 0)
		return -1;
	if (config.session_resources.memory_max_mb != 0)
		return -1;
	if (config.session_resources.cpu_quota_percent != 0)
		return -1;
	if (config.session_resources.systemd_scope != 0)
		return -1;
	if (config.session_resources.logind_session != 0)
		return -1;
	if (config.session_heartbeat.interval_ms != FRDP_SESSION_HEARTBEAT_DEFAULT_INTERVAL_MS)
		return -1;
	if (config.session_heartbeat.timeout_ms != FRDP_SESSION_HEARTBEAT_DEFAULT_TIMEOUT_MS)
		return -1;
	if (config.session_heartbeat.failure_threshold != FRDP_SESSION_HEARTBEAT_DEFAULT_FAILURES)
		return -1;
	if (config.session_display.backend != FRDP_SESSION_DISPLAY_XVFB)
		return -1;
	if (config.session_display.xorg_path[0] != '\0' ||
	    config.session_display.xorg_config[0] != '\0')
		return -1;
	if (config.channels.static_mode != FRDP_CHANNEL_FILTER_BLOCKLIST)
		return -1;
	if (config.channels.dynamic_mode != FRDP_CHANNEL_FILTER_BLOCKLIST)
		return -1;
	if (config.channels.static_allow_count != 0)
		return -1;
	if (config.channels.static_deny_count != 0)
		return -1;
	if (config.channels.dynamic_allow_count != 0)
		return -1;
	if (config.channels.dynamic_deny_count != 0)
		return -1;
	if (config.clipboard.mode != FRDP_CLIPBOARD_MODE_DISABLED)
		return -1;
	if (config.clipboard.direction != FRDP_CLIPBOARD_DIRECTION_DISABLED)
		return -1;
	if (config.clipboard.max_text_bytes != 65536)
		return -1;
	if (config.audit.enabled != 0)
		return -1;
	if (strcmp(config.audit.sink, "journald") != 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "cliprdr") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed_for_runtime(&config.channels, &config.clipboard,
	                                                   "cliprdr") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "rdpsnd") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed_for_runtime(&config.channels, &config.clipboard,
	                                                   "rdpsnd") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "rdpdr") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed_for_runtime(&config.channels, &config.clipboard,
	                                                   "rdpdr") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "rail") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed_for_runtime(&config.channels, &config.clipboard,
	                                                   "rail") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "drdynvc") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed_for_runtime(&config.channels, &config.clipboard,
	                                                   "drdynvc") == 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed(&config.channels, "rdpgfx") == 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed(&config.channels, "drdynvc") != 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed_for_runtime(
	        &config.channels, "Microsoft::Windows::RDS::DisplayControl") == 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed_for_runtime(&config.channels, "rdpgfx") == 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed_for_runtime(
	        &config.channels, "Microsoft::Windows::RDS::Graphics") == 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed_for_runtime(&config.channels, "bad\nchannel") != 0)
		return -1;
	if (frdp_channel_policy_static_allowed(NULL, "cliprdr") != 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "") != 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed(NULL, "rdpgfx") != 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed(&config.channels, "") != 0)
		return -1;
	memcpy(channel.name, "bad-name", sizeof(channel.name));
	if (frdp_channel_policy_static_channel_allowed(&config.channels, &channel, name,
	                                               sizeof(name)) != 0)
		return -1;
	memcpy(channel.name, "cliprdr", sizeof("cliprdr"));
	if (frdp_channel_policy_static_channel_allowed_for_runtime(&config.channels, &config.clipboard,
	                                                           &channel, name, sizeof(name)) == 0)
		return -1;
	if (strcmp(name, "cliprdr") != 0)
		return -1;
	return 0;
}

static int test_server_max_connections(void)
{
	frdpConfig config = { 0 };

	if (load_config_body("frdp-max-connections-bare.toml", "[server]\nmax_connections = 64\n",
	                     &config) != 0)
		return -1;
	if (config.max_connections != 64)
		return -1;
	if (load_config_body("frdp-max-connections-zero.toml", "[server]\nmax_connections = 0\n",
	                     &config) != 0)
		return -1;
	if (config.max_connections != 0)
		return -1;
	return 0;
}

static int test_server_auth_session_fields(void)
{
	frdpConfig config = { 0 };
	const char* body = "[server]\n"
	                   "listen = \"127.0.0.1:3390\"\n"
	                   "security = \"nla\"\n"
	                   "tls_cert = \"/etc/frdpd/tls/server.crt\"\n"
	                   "tls_key = \"/etc/frdpd/tls/server.key\"\n"
	                   "max_connections = 9\n"
	                   "[auth]\n"
	                   "mode = \"pam-sssd\"\n"
	                   "pam_service = \"frdpd-test\"\n"
	                   "auth_socket = \"/run/frdp-authd/authd.sock\"\n"
	                   "[session]\n"
	                   "session_socket = \"/run/frdp-sesmand/sesmand.sock\"\n"
	                   "max_sessions = 32\n"
	                   "max_processes = 128\n"
	                   "memory_max_mb = 2048\n"
	                   "cpu_quota_percent = 250\n"
	                   "systemd_scope = true\n";

	if (load_config_body("frdp-server-auth-session.toml", body, &config) != 0)
		return -1;
	if (strcmp(config.listen, "127.0.0.1:3390") != 0)
		return -1;
	if (config.max_connections != 9)
		return -1;
	if (strcmp(config.security, "nla") != 0)
		return -1;
	if (strcmp(config.tls_cert, "/etc/frdpd/tls/server.crt") != 0)
		return -1;
	if (strcmp(config.tls_key, "/etc/frdpd/tls/server.key") != 0)
		return -1;
	if (strcmp(config.auth_mode, "pam-sssd") != 0)
		return -1;
	if (strcmp(config.pam_service, "frdpd-test") != 0)
		return -1;
	if (strcmp(config.auth_socket, "/run/frdp-authd/authd.sock") != 0)
		return -1;
	if (config.ntlm_fallback != 0)
		return -1;
	if (config.ntlm_sam_file[0] != '\0')
		return -1;
	if (config.kerberos != 0)
		return -1;
	if (config.keytab[0] != '\0')
		return -1;
	if (config.accepted_spn[0] != '\0')
		return -1;
	if (strcmp(config.session_socket, "/run/frdp-sesmand/sesmand.sock") != 0)
		return -1;
	if (config.session_resources.max_sessions != 32)
		return -1;
	if (config.session_resources.max_processes != 128)
		return -1;
	if (config.session_resources.memory_max_mb != 2048)
		return -1;
	if (config.session_resources.cpu_quota_percent != 250)
		return -1;
	if (config.session_resources.systemd_scope != 1)
		return -1;
	if (config.session_resources.logind_session != 0)
		return -1;
	return 0;
}

static int test_session_resource_policy(void)
{
	frdpConfig config = { 0 };

	if (load_config_body("frdp-session-resource-limits.toml",
	                     "[session]\nmax_sessions = 16\nmax_processes = 64\nmemory_max_mb = 1024\n",
	                     &config) != 0)
		return -1;
	if (config.session_resources.max_sessions != 16)
		return -1;
	if (config.session_resources.max_processes != 64)
		return -1;
	if (config.session_resources.memory_max_mb != 1024)
		return -1;
	if (config.session_resources.systemd_scope != 0)
		return -1;
	if (load_config_body("frdp-session-systemd-scope.toml",
	                     "[session]\nsystemd_scope = true\ncpu_quota_percent = 250\n",
	                     &config) != 0)
		return -1;
	if ((config.session_resources.systemd_scope != 1) ||
	    (config.session_resources.cpu_quota_percent != 250))
		return -1;
	if (load_config_body("frdp-session-logind.toml", "[session]\nlogind_session = true\n",
	                     &config) != 0 ||
	    config.session_resources.logind_session != 1 ||
	    config.session_resources.systemd_scope != 0)
		return -1;
	if (load_config_body("frdp-session-systemd-scope-max-cpu.toml",
	                     "[session]\nsystemd_scope = true\ncpu_quota_percent = 10000\n",
	                     &config) != 0 ||
	    config.session_resources.cpu_quota_percent != 10000)
		return -1;
	if (load_config_body("frdp-session-resource-unlimited.toml",
	                     "[session]\nmax_sessions = 0\nmax_processes = 0\nmemory_max_mb = 0\n"
	                     "cpu_quota_percent = 0\nsystemd_scope = false\n",
	                     &config) != 0)
		return -1;
	if (config.session_resources.max_sessions != 0)
		return -1;
	if (config.session_resources.max_processes != 0)
		return -1;
	if (config.session_resources.memory_max_mb != 0)
		return -1;
	if (config.session_resources.cpu_quota_percent != 0)
		return -1;
	if (config.session_resources.systemd_scope != 0)
		return -1;
	return 0;
}

static int test_session_heartbeat_policy(void)
{
	frdpConfig config = { 0 };

	if (load_config_body("frdp-session-heartbeat.toml",
	                     "[session]\nagent_heartbeat_interval_ms = 2500\n"
	                     "agent_heartbeat_timeout_ms = 750\n"
	                     "agent_heartbeat_failures = 4\n",
	                     &config) != 0)
		return -1;
	if ((config.session_heartbeat.interval_ms != 2500) ||
	    (config.session_heartbeat.timeout_ms != 750) ||
	    (config.session_heartbeat.failure_threshold != 4))
		return -1;
	return 0;
}

static int test_session_display_policy(void)
{
	frdpConfig config = { 0 };

	if (load_config_body("frdp-session-display-xvfb.toml",
	                     "[session]\ndisplay_backend = \"xvfb\"\n", &config) != 0)
		return -1;
	if (config.session_display.backend != FRDP_SESSION_DISPLAY_XVFB)
		return -1;
	if (load_config_body("frdp-session-display-xorg.toml",
	                     "[session]\ndisplay_backend = \"xorg-dummy\"\n"
	                     "xorg_path = \"/usr/lib/xorg/Xorg\"\n"
	                     "xorg_config = \"/usr/share/frdpd/xorg-dummy.conf\"\n",
	                     &config) != 0)
		return -1;
	if (config.session_display.backend != FRDP_SESSION_DISPLAY_XORG_DUMMY)
		return -1;
	if (strcmp(config.session_display.xorg_path, "/usr/lib/xorg/Xorg") != 0 ||
	    strcmp(config.session_display.xorg_config, "/usr/share/frdpd/xorg-dummy.conf") != 0)
		return -1;
	return 0;
}

static int test_sample_config(void)
{
	frdpConfig config = { 0 };

	if (frdp_config_load(FRDP_SAMPLE_CONFIG_PATH, &config) != 0)
		return -1;
	if (strcmp(config.listen, "0.0.0.0:3389") != 0)
		return -1;
	if (strcmp(config.security, "nla") != 0)
		return -1;
	if (strcmp(config.tls_cert, "/etc/frdpd/tls.crt") != 0)
		return -1;
	if (strcmp(config.tls_key, "/etc/frdpd/tls.key") != 0)
		return -1;
	if (strcmp(config.auth_mode, "pam-sssd") != 0)
		return -1;
	if (strcmp(config.pam_service, "frdpd") != 0)
		return -1;
	if (strcmp(config.auth_socket, "/run/frdp-authd/authd.sock") != 0)
		return -1;
	if (strcmp(config.session_socket, "/run/frdp-sesmand/sesmand.sock") != 0)
		return -1;
	if (config.session_display.backend != FRDP_SESSION_DISPLAY_XVFB)
		return -1;
#if FRDPD_NTLM_ENABLED
	if ((config.ntlm_fallback != 1) || (strcmp(config.ntlm_sam_file, "/etc/frdpd/ntlm.sam") != 0))
		return -1;
#else
	if ((config.ntlm_fallback != 0) || (config.ntlm_sam_file[0] != '\0'))
		return -1;
#endif
	if (config.kerberos != 0)
		return -1;
	if (config.max_connections != 0)
		return -1;
	if (config.channels.static_mode != FRDP_CHANNEL_FILTER_BLOCKLIST)
		return -1;
	if (config.channels.dynamic_mode != FRDP_CHANNEL_FILTER_BLOCKLIST)
		return -1;
	if (config.clipboard.mode != FRDP_CLIPBOARD_MODE_DISABLED)
		return -1;
	if (config.clipboard.direction != FRDP_CLIPBOARD_DIRECTION_DISABLED)
		return -1;
	if (config.clipboard.max_text_bytes != 65536)
		return -1;
	if (config.audit.enabled != 0)
		return -1;
	if (strcmp(config.audit.sink, "journald") != 0)
		return -1;
	return 0;
}

static int test_auth_ntlm_fallback_policy(void)
{
	frdpConfig config = { 0 };

	if (load_config_body("frdp-auth-ntlm-fallback-false.toml", "[auth]\nntlm_fallback = false\n",
	                     &config) != 0)
		return -1;
	if (config.ntlm_fallback != 0)
		return -1;
	if (load_config_body("frdp-auth-ntlm-fallback-true.toml",
	                     "[auth]\nntlm_fallback = true\n"
	                     "ntlm_sam_file = \"/etc/frdpd/ntlm.sam\"\n",
	                     &config) != 0)
		return -1;
	if (config.ntlm_fallback != 1)
		return -1;
	if (strcmp(config.ntlm_sam_file, "/etc/frdpd/ntlm.sam") != 0)
		return -1;
	return 0;
}

static int test_empty_filter_lists(void)
{
	frdpConfig config = { 0 };
	const char* body = "[channels]\nstatic_mode = \"blacklist\"\nstatic_deny = \"\"\n"
	                   "dynamic_mode = \"blocklist\"\ndynamic_deny = \"\"\n";

	if (load_config_body("frdp-empty-channels.toml", body, &config) != 0)
		return -1;
	if (config.channels.static_mode != FRDP_CHANNEL_FILTER_BLOCKLIST)
		return -1;
	if (config.channels.dynamic_mode != FRDP_CHANNEL_FILTER_BLOCKLIST)
		return -1;
	if (config.channels.static_allow_count != 0)
		return -1;
	if (config.channels.static_deny_count != 0)
		return -1;
	if (config.channels.dynamic_allow_count != 0)
		return -1;
	if (config.channels.dynamic_deny_count != 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "cliprdr") == 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed(&config.channels, "rdpgfx") == 0)
		return -1;
	return 0;
}

static int test_static_allowlist(void)
{
	frdpConfig config = { 0 };
	frdpChannelPolicy direct_policy = { 0 };
	const char* body = "[channels]\nstatic_mode = \"allowlist\"\n"
	                   "static_allow = \"cliprdr, rdpsnd,rdpdr,rail,drdynvc\"\n";
	CHANNEL_DEF channel = { 0 };
	char name[CHANNEL_NAME_LEN + 2] = { 0 };

	if (load_config_body("frdp-static-channels.toml", body, &config) != 0)
		return -1;
	if (config.channels.static_mode != FRDP_CHANNEL_FILTER_ALLOWLIST)
		return -1;
	if (config.channels.static_allow_count != 5)
		return -1;
	if (config.channels.static_deny_count != 0)
		return -1;
	if (strcmp(config.channels.static_allow[0], "cliprdr") != 0)
		return -1;
	if (strcmp(config.channels.static_allow[1], "rdpsnd") != 0)
		return -1;
	if (strcmp(config.channels.static_allow[2], "rdpdr") != 0)
		return -1;
	if (strcmp(config.channels.static_allow[3], "rail") != 0)
		return -1;
	if (strcmp(config.channels.static_allow[4], "drdynvc") != 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "cliprdr") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "rdpsnd") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed_for_runtime(&config.channels, &config.clipboard,
	                                                   "rdpsnd") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "rdpdr") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed_for_runtime(&config.channels, &config.clipboard,
	                                                   "rdpdr") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "rail") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed_for_runtime(&config.channels, &config.clipboard,
	                                                   "rail") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "drdynvc") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "CLIPRDR") != 0)
		return -1;
	memcpy(channel.name, "cliprdr", sizeof("cliprdr"));
	if (frdp_channel_policy_static_channel_allowed(&config.channels, &channel, name,
	                                               sizeof(name)) == 0)
		return -1;
	if (strcmp(name, "cliprdr") != 0)
		return -1;
	memset(&channel, 0, sizeof(channel));
	memset(name, 0, sizeof(name));
	memcpy(channel.name, "drdynvc", sizeof("drdynvc"));
	if (frdp_channel_policy_static_channel_allowed(&config.channels, &channel, name,
	                                               sizeof(name)) == 0)
		return -1;
	if (strcmp(name, "drdynvc") != 0)
		return -1;
	direct_policy.static_mode = FRDP_CHANNEL_FILTER_ALLOWLIST;
	direct_policy.static_allow_count = 1;
	memcpy(direct_policy.static_allow[0], "drdynvc", sizeof("drdynvc"));
	if (frdp_channel_policy_static_allowed(&direct_policy, "drdynvc") == 0)
		return -1;
	if (frdp_channel_policy_static_channel_allowed(&direct_policy, &channel, name, sizeof(name)) ==
	    0)
		return -1;
	memset(&channel, 0, sizeof(channel));
	memset(name, 0xff, sizeof(name));
	if (frdp_channel_policy_static_channel_allowed(&config.channels, &channel, name,
	                                               sizeof(name)) != 0)
		return -1;
	if (name[0] != '\0')
		return -1;
	if (frdp_channel_policy_static_channel_allowed(&config.channels, NULL, name, sizeof(name)) != 0)
		return -1;
	return 0;
}

static int test_static_blocklist(void)
{
	frdpConfig config = { 0 };
	const char* body = "[channels]\nstatic_mode = \"blocklist\"\n"
	                   "static_deny = \"cliprdr, drdynvc\"\n";
	CHANNEL_DEF channel = { 0 };
	char name[CHANNEL_NAME_LEN + 2] = { 0 };

	if (load_config_body("frdp-static-blocklist.toml", body, &config) != 0)
		return -1;
	if (config.channels.static_mode != FRDP_CHANNEL_FILTER_BLOCKLIST)
		return -1;
	if (config.channels.static_deny_count != 2)
		return -1;
	if (strcmp(config.channels.static_deny[0], "cliprdr") != 0)
		return -1;
	if (strcmp(config.channels.static_deny[1], "drdynvc") != 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "cliprdr") != 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "drdynvc") != 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "rdpsnd") == 0)
		return -1;
	memcpy(channel.name, "rdpsnd", sizeof("rdpsnd"));
	if (frdp_channel_policy_static_channel_allowed(&config.channels, &channel, name,
	                                               sizeof(name)) == 0)
		return -1;
	if (strcmp(name, "rdpsnd") != 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "rdpdr") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed_for_runtime(&config.channels, &config.clipboard,
	                                                   "rdpdr") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "rail") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed_for_runtime(&config.channels, &config.clipboard,
	                                                   "rail") == 0)
		return -1;
	return 0;
}

static int test_dynamic_allowlist(void)
{
	frdpConfig config = { 0 };
	const char* body = "[channels]\ndynamic_mode = \"whitelist\"\n"
	                   "dynamic_allow = \"rdpgfx, disp,geometry\"\n";
	CHANNEL_DEF channel = { 0 };
	char name[CHANNEL_NAME_LEN + 2] = { 0 };

	if (load_config_body("frdp-dynamic-channels.toml", body, &config) != 0)
		return -1;
	if (config.channels.dynamic_mode != FRDP_CHANNEL_FILTER_ALLOWLIST)
		return -1;
	if (config.channels.static_allow_count != 0)
		return -1;
	if (config.channels.dynamic_allow_count != 3)
		return -1;
	if (strcmp(config.channels.dynamic_allow[0], "rdpgfx") != 0)
		return -1;
	if (strcmp(config.channels.dynamic_allow[1], "disp") != 0)
		return -1;
	if (strcmp(config.channels.dynamic_allow[2], "geometry") != 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed(&config.channels, "rdpgfx") == 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed(&config.channels, "disp") == 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed(&config.channels, "geometry") == 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed(&config.channels, "RDPGFX") != 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed(&config.channels, "drdynvc") != 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed_for_runtime(
	        &config.channels, "Microsoft::Windows::RDS::DisplayControl") == 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed_for_runtime(&config.channels, "rdpgfx") == 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed_for_runtime(
	        &config.channels, "Microsoft::Windows::RDS::Graphics") == 0)
		return -1;
	memcpy(channel.name, "drdynvc", sizeof("drdynvc"));
	if (frdp_channel_policy_static_channel_allowed(&config.channels, &channel, name,
	                                               sizeof(name)) == 0)
		return -1;
	if (strcmp(name, "drdynvc") != 0)
		return -1;
	return 0;
}

static int test_dynamic_blocklist(void)
{
	frdpConfig config = { 0 };
	const char* body = "[channels]\ndynamic_deny = \"rdpgfx, disp\"\n";

	if (load_config_body("frdp-dynamic-blocklist.toml", body, &config) != 0)
		return -1;
	if (config.channels.dynamic_mode != FRDP_CHANNEL_FILTER_BLOCKLIST)
		return -1;
	if (config.channels.dynamic_deny_count != 2)
		return -1;
	if (strcmp(config.channels.dynamic_deny[0], "rdpgfx") != 0)
		return -1;
	if (strcmp(config.channels.dynamic_deny[1], "disp") != 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed(&config.channels, "rdpgfx") != 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed(&config.channels, "disp") != 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed(&config.channels, "geometry") == 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed_for_runtime(
	        &config.channels, "Microsoft::Windows::RDS::DisplayControl") != 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed_for_runtime(
	        &config.channels, "Microsoft::Windows::RDS::Graphics") != 0)
		return -1;
	return 0;
}

static int test_clipboard_policy(void)
{
	frdpConfig config = { 0 };
	frdpClipboardPolicy invalid_clipboard = { .mode = (frdpClipboardMode)99,
		                                      .direction = FRDP_CLIPBOARD_DIRECTION_BIDIRECTIONAL,
		                                      .max_text_bytes = 4096 };
	const char* body = "[clipboard]\nmode = \"text\"\n"
	                   "direction = \"client-to-server\"\nmax_text_bytes = 4096\n";

	if (load_config_body("frdp-clipboard-client-to-server.toml", body, &config) != 0)
		return -1;
	if (config.clipboard.mode != FRDP_CLIPBOARD_MODE_TEXT)
		return -1;
	if (config.clipboard.direction != FRDP_CLIPBOARD_DIRECTION_CLIENT_TO_SERVER)
		return -1;
	if (config.clipboard.max_text_bytes != 4096)
		return -1;
	if (frdp_channel_policy_static_allowed_for_runtime(&config.channels, &config.clipboard,
	                                                   "cliprdr") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed_for_runtime(&config.channels, &invalid_clipboard,
	                                                   "cliprdr") == 0)
		return -1;

	body = "[clipboard]\nmode = \"text\"\ndirection = \"server-to-client\"\n";
	if (load_config_body("frdp-clipboard-server-to-client.toml", body, &config) != 0)
		return -1;
	if (config.clipboard.direction != FRDP_CLIPBOARD_DIRECTION_SERVER_TO_CLIENT)
		return -1;
	if (config.clipboard.max_text_bytes != 65536)
		return -1;

	body =
	    "[clipboard]\nmode = \"text\"\ndirection = \"bidirectional\"\nmax_text_bytes = 1048576\n";
	if (load_config_body("frdp-clipboard-bidirectional.toml", body, &config) != 0)
		return -1;
	if (config.clipboard.direction != FRDP_CLIPBOARD_DIRECTION_BIDIRECTIONAL)
		return -1;
	if (config.clipboard.max_text_bytes != 1048576)
		return -1;

	body = "[clipboard]\nmode = \"disabled\"\nmax_text_bytes = 1024\n";
	if (load_config_body("frdp-clipboard-disabled.toml", body, &config) != 0)
		return -1;
	if (config.clipboard.mode != FRDP_CLIPBOARD_MODE_DISABLED)
		return -1;
	if (config.clipboard.direction != FRDP_CLIPBOARD_DIRECTION_DISABLED)
		return -1;
	if (config.clipboard.max_text_bytes != 1024)
		return -1;

	return 0;
}

static int test_audit_policy(void)
{
	frdpConfig config = { 0 };

	if (load_config_body("frdp-audit-empty.toml", "[audit]\n", &config) != 0)
		return -1;
	if (config.audit.enabled != 0)
		return -1;
	if (strcmp(config.audit.sink, "journald") != 0)
		return -1;
	if (load_config_body("frdp-audit-disabled.toml", "[audit]\nenabled = false\n", &config) != 0)
		return -1;
	if (config.audit.enabled != 0)
		return -1;
	if (strcmp(config.audit.sink, "journald") != 0)
		return -1;
	if (load_config_body("frdp-audit-enabled.toml", "[audit]\nenabled = true\n", &config) != 0)
		return -1;
	if ((config.audit.enabled != 1) || (strcmp(config.audit.sink, "journald") != 0))
		return -1;
	if (load_config_body("frdp-audit-explicit-sink.toml",
	                     "[audit]\nenabled = true\nsink = \"journald\"\n", &config) != 0)
		return -1;
	if ((config.audit.enabled != 1) || (strcmp(config.audit.sink, "journald") != 0))
		return -1;
	return 0;
}

static int test_auth_kerberos_policy(void)
{
	frdpConfig config = { 0 };
	const char* body = "[auth]\n"
	                   "ntlm_fallback = false\n"
	                   "kerberos = true\n"
	                   "keytab = \"/etc/frdpd/frdpd.keytab\"\n"
	                   "accepted_spn = \"TERMSRV/rdp01.example.com\"\n";

	if (load_config_body("frdp-auth-kerberos-policy.toml", body, &config) != 0)
		return -1;
	if (config.ntlm_fallback != 0)
		return -1;
	if (config.kerberos != 1)
		return -1;
	if (strcmp(config.keytab, "/etc/frdpd/frdpd.keytab") != 0)
		return -1;
	if (strcmp(config.accepted_spn, "TERMSRV/rdp01.example.com") != 0)
		return -1;
	if (load_config_body("frdp-auth-kerberos-false.toml", "[auth]\nkerberos = false\n", &config) !=
	    0)
		return -1;
	if (config.kerberos != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-auth-kerberos-needs-ntlm-disabled.toml",
	        "[auth]\nkerberos = true\nkeytab = \"/etc/frdpd/frdpd.keytab\"\naccepted_spn = "
	        "\"TERMSRV/host.example.com\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-auth-kerberos-needs-keytab.toml",
	                        "[auth]\nntlm_fallback = false\nkerberos = true\naccepted_spn = "
	                        "\"TERMSRV/host.example.com\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-auth-kerberos-needs-spn.toml",
	                        "[auth]\nntlm_fallback = false\nkerberos = true\nkeytab = "
	                        "\"/etc/frdpd/frdpd.keytab\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-auth-keytab-without-kerberos.toml",
	                        "[auth]\nkeytab = \"/etc/krb5.keytab\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-auth-spn-without-kerberos.toml",
	                        "[auth]\naccepted_spn = \"TERMSRV/host.example.com\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-auth-relative-keytab.toml",
	                        "[auth]\nntlm_fallback = false\nkerberos = true\nkeytab = "
	                        "\"frdpd.keytab\"\naccepted_spn = \"TERMSRV/host.example.com\"\n") != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-auth-control-keytab.toml",
	        "[auth]\nntlm_fallback = false\nkerberos = true\nkeytab = "
	        "\"/etc/frdpd/\001.keytab\"\naccepted_spn = \"TERMSRV/host.example.com\"\n") != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-auth-invalid-spn.toml",
	        "[auth]\nntlm_fallback = false\nkerberos = true\nkeytab = "
	        "\"/etc/frdpd/frdpd.keytab\"\naccepted_spn = \"host/rdp01.example.com\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-auth-short-spn.toml",
	                        "[auth]\nntlm_fallback = false\nkerberos = true\nkeytab = "
	                        "\"/etc/frdpd/frdpd.keytab\"\naccepted_spn = \"TERMSRV/host\"\n") != 0)
		return -1;
	return 0;
}

static int test_invalid_channel_config(void)
{
	char long_line[640] = { 0 };

	memset(long_line, 'a', sizeof(long_line) - 1);
	if (expect_load_failure("frdp-long-line.toml", long_line) != 0)
		return -1;
	if (expect_load_failure("frdp-top-level-key.toml", "listen = \"127.0.0.1:3389\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-unknown-section.toml", "[logging]\nlevel = \"debug\"\n") != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-duplicate-server-section.toml",
	        "[server]\nlisten = \"127.0.0.1:3389\"\n[server]\nsecurity = \"nla\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-auth-section.toml",
	                        "[auth]\nmode = \"pam-sssd\"\n[auth]\npam_service = \"frdpd\"\n") != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-duplicate-session-section.toml",
	        "[session]\nsession_socket = \"/tmp/a\"\n[session]\nsession_socket = \"/tmp/b\"\n") !=
	    0)
		return -1;
	if (expect_load_failure("frdp-unknown-server-key.toml", "[server]\nport = \"3389\"\n") != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-duplicate-listen.toml",
	        "[server]\nlisten = \"127.0.0.1:3389\"\nlisten = \"127.0.0.1:3390\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-security.toml",
	                        "[server]\nsecurity = \"nla\"\nsecurity = \"nla\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-unsupported-security.toml", "[server]\nsecurity = \"tls\"\n") !=
	    0)
		return -1;
	if (expect_load_failure("frdp-duplicate-tls-cert.toml",
	                        "[server]\ntls_cert = \"/tmp/a.crt\"\ntls_cert = \"/tmp/b.crt\"\n") !=
	    0)
		return -1;
	if (expect_load_failure("frdp-duplicate-tls-key.toml",
	                        "[server]\ntls_key = \"/tmp/a.key\"\ntls_key = \"/tmp/b.key\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-auth-mode.toml",
	                        "[auth]\nmode = \"pam-sssd\"\nmode = \"pam-sssd\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-unsupported-auth-mode.toml", "[auth]\nmode = \"local\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-pam-service.toml",
	                        "[auth]\npam_service = \"frdpd\"\npam_service = \"other\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-auth-socket.toml",
	                        "[auth]\nauth_socket = \"/tmp/a\"\nauth_socket = \"/tmp/b\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-relative-auth-socket.toml",
	                        "[auth]\nauth_socket = \"relative/authd.sock\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-relative-session-socket.toml",
	                        "[session]\nsession_socket = \"relative/sesmand.sock\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-control-auth-socket.toml",
	                        "[auth]\nauth_socket = \"/tmp/frdp-\001-auth.sock\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-control-session-socket.toml",
	                        "[session]\nsession_socket = \"/tmp/frdp-\001-session.sock\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-unknown-display-backend.toml",
	                        "[session]\ndisplay_backend = \"wayland\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-display-backend.toml",
	                        "[session]\ndisplay_backend = \"xvfb\"\n"
	                        "display_backend = \"xorg-dummy\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-xorg-missing-path.toml",
	                        "[session]\ndisplay_backend = \"xorg-dummy\"\n"
	                        "xorg_config = \"/usr/share/frdpd/xorg-dummy.conf\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-xorg-missing-config.toml",
	                        "[session]\ndisplay_backend = \"xorg-dummy\"\n"
	                        "xorg_path = \"/usr/lib/xorg/Xorg\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-xorg-path-with-xvfb.toml",
	                        "[session]\ndisplay_backend = \"xvfb\"\n"
	                        "xorg_path = \"/usr/lib/xorg/Xorg\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-relative-xorg-path.toml",
	                        "[session]\ndisplay_backend = \"xorg-dummy\"\n"
	                        "xorg_path = \"Xorg\"\n"
	                        "xorg_config = \"/usr/share/frdpd/xorg-dummy.conf\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-relative-xorg-config.toml",
	                        "[session]\ndisplay_backend = \"xorg-dummy\"\n"
	                        "xorg_path = \"/usr/lib/xorg/Xorg\"\n"
	                        "xorg_config = \"xorg-dummy.conf\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-ntlm-fallback.toml",
	                        "[auth]\nntlm_fallback = false\nntlm_fallback = true\n") != 0)
		return -1;
	if (expect_load_failure("frdp-quoted-ntlm-fallback.toml",
	                        "[auth]\nntlm_fallback = \"false\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-invalid-ntlm-fallback.toml", "[auth]\nntlm_fallback = maybe\n") !=
	    0)
		return -1;
	if (expect_load_failure("frdp-duplicate-ntlm-sam-file.toml",
	                        "[auth]\nntlm_sam_file = \"/a\"\nntlm_sam_file = \"/b\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-relative-ntlm-sam-file.toml",
	                        "[auth]\nntlm_sam_file = \"ntlm.sam\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-ntlm-sam-file-without-fallback.toml",
	                        "[auth]\nntlm_fallback = false\n"
	                        "ntlm_sam_file = \"/etc/frdpd/ntlm.sam\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-kerberos.toml",
	                        "[auth]\nkerberos = false\nkerberos = true\n") != 0)
		return -1;
	if (expect_load_failure("frdp-quoted-kerberos.toml", "[auth]\nkerberos = \"true\"\n") != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-duplicate-keytab.toml",
	        "[auth]\nntlm_fallback = false\nkerberos = true\nkeytab = \"/a\"\nkeytab = "
	        "\"/b\"\naccepted_spn = \"TERMSRV/host.example.com\"\n") != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-duplicate-accepted-spn.toml",
	        "[auth]\nntlm_fallback = false\nkerberos = true\nkeytab = \"/a\"\naccepted_spn = "
	        "\"TERMSRV/host.example.com\"\naccepted_spn = \"TERMSRV/other.example.com\"\n") != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-duplicate-session-socket.toml",
	        "[session]\nsession_socket = \"/tmp/a\"\nsession_socket = \"/tmp/b\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-session-max-processes.toml",
	                        "[session]\nmax_processes = 8\nmax_processes = 9\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-session-max-sessions.toml",
	                        "[session]\nmax_sessions = 8\nmax_sessions = 9\n") != 0)
		return -1;
	if (expect_load_failure("frdp-negative-session-max-sessions.toml",
	                        "[session]\nmax_sessions = -1\n") != 0)
		return -1;
	if (expect_load_failure("frdp-quoted-session-max-sessions.toml",
	                        "[session]\nmax_sessions = \"8\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-too-large-session-max-sessions.toml",
	                        "[session]\nmax_sessions = 65\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-session-memory-max.toml",
	                        "[session]\nmemory_max_mb = 512\nmemory_max_mb = 1024\n") != 0)
		return -1;
	if (expect_load_failure("frdp-negative-session-max-processes.toml",
	                        "[session]\nmax_processes = -1\n") != 0)
		return -1;
	if (expect_load_failure("frdp-quoted-session-max-processes.toml",
	                        "[session]\nmax_processes = \"8\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-too-large-session-max-processes.toml",
	                        "[session]\nmax_processes = 1048577\n") != 0)
		return -1;
	if (expect_load_failure("frdp-negative-session-memory-max.toml",
	                        "[session]\nmemory_max_mb = -1\n") != 0)
		return -1;
	if (expect_load_failure("frdp-quoted-session-memory-max.toml",
	                        "[session]\nmemory_max_mb = \"1024\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-too-large-session-memory-max.toml",
	                        "[session]\nmemory_max_mb = 1048577\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-session-cpu-quota.toml",
	                        "[session]\ncpu_quota_percent = 100\ncpu_quota_percent = 200\n"
	                        "systemd_scope = true\n") != 0)
		return -1;
	if (expect_load_failure("frdp-negative-session-cpu-quota.toml",
	                        "[session]\ncpu_quota_percent = -1\nsystemd_scope = true\n") != 0)
		return -1;
	if (expect_load_failure("frdp-quoted-session-cpu-quota.toml",
	                        "[session]\ncpu_quota_percent = \"100\"\nsystemd_scope = true\n") != 0)
		return -1;
	if (expect_load_failure("frdp-too-large-session-cpu-quota.toml",
	                        "[session]\ncpu_quota_percent = 10001\nsystemd_scope = true\n") != 0)
		return -1;
	if (expect_load_failure("frdp-session-cpu-quota-without-scope.toml",
	                        "[session]\ncpu_quota_percent = 100\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-session-systemd-scope.toml",
	                        "[session]\nsystemd_scope = true\nsystemd_scope = false\n") != 0)
		return -1;
	if (expect_load_failure("frdp-quoted-session-systemd-scope.toml",
	                        "[session]\nsystemd_scope = \"true\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-invalid-session-systemd-scope.toml",
	                        "[session]\nsystemd_scope = required\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-session-logind.toml",
	                        "[session]\nlogind_session = true\nlogind_session = false\n") != 0)
		return -1;
	if (expect_load_failure("frdp-quoted-session-logind.toml",
	                        "[session]\nlogind_session = \"true\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-invalid-session-logind.toml",
	                        "[session]\nlogind_session = required\n") != 0)
		return -1;
	if (expect_load_failure("frdp-conflicting-systemd-ownership.toml",
	                        "[session]\nsystemd_scope = true\nlogind_session = true\n") != 0)
		return -1;
	if (expect_load_failure("frdp-small-heartbeat-interval.toml",
	                        "[session]\nagent_heartbeat_interval_ms = 999\n") != 0)
		return -1;
	if (expect_load_failure("frdp-large-heartbeat-interval.toml",
	                        "[session]\nagent_heartbeat_interval_ms = 60001\n") != 0)
		return -1;
	if (expect_load_failure("frdp-small-heartbeat-timeout.toml",
	                        "[session]\nagent_heartbeat_timeout_ms = 499\n") != 0)
		return -1;
	if (expect_load_failure("frdp-large-heartbeat-timeout.toml",
	                        "[session]\nagent_heartbeat_timeout_ms = 5001\n") != 0)
		return -1;
	if (expect_load_failure("frdp-heartbeat-timeout-over-interval.toml",
	                        "[session]\nagent_heartbeat_interval_ms = 1000\n"
	                        "agent_heartbeat_timeout_ms = 1001\n") != 0)
		return -1;
	if (expect_load_failure("frdp-zero-heartbeat-failures.toml",
	                        "[session]\nagent_heartbeat_failures = 2\n") != 0)
		return -1;
	if (expect_load_failure("frdp-large-heartbeat-failures.toml",
	                        "[session]\nagent_heartbeat_failures = 11\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-heartbeat-interval.toml",
	                        "[session]\nagent_heartbeat_interval_ms = 1000\n"
	                        "agent_heartbeat_interval_ms = 2000\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-heartbeat-timeout.toml",
	                        "[session]\nagent_heartbeat_timeout_ms = 500\n"
	                        "agent_heartbeat_timeout_ms = 600\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-heartbeat-failures.toml",
	                        "[session]\nagent_heartbeat_failures = 3\n"
	                        "agent_heartbeat_failures = 4\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-max-connections.toml",
	                        "[server]\nmax_connections = 1\nmax_connections = 2\n") != 0)
		return -1;
	if (expect_load_failure("frdp-negative-max-connections.toml",
	                        "[server]\nmax_connections = -1\n") != 0)
		return -1;
	if (expect_load_failure("frdp-invalid-max-connections.toml",
	                        "[server]\nmax_connections = \"many\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-quoted-max-connections.toml",
	                        "[server]\nmax_connections = \"7\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-too-large-max-connections.toml",
	                        "[server]\nmax_connections = 2147483648\n") != 0)
		return -1;
	if (expect_load_failure("frdp-bad-static-mode.toml", "[channels]\nstatic_mode = \"maybe\"\n") !=
	    0)
		return -1;
	if (expect_load_failure("frdp-bad-dynamic-mode.toml",
	                        "[channels]\ndynamic_mode = \"maybe\"\n") != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-duplicate-static-mode.toml",
	        "[channels]\nstatic_mode = \"blocklist\"\nstatic_mode = \"allowlist\"\n") != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-duplicate-dynamic-mode.toml",
	        "[channels]\ndynamic_mode = \"blocklist\"\ndynamic_mode = \"allowlist\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-static-allow-with-default-blocklist.toml",
	                        "[channels]\nstatic_allow = \"cliprdr\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-empty-static-allow-with-default-blocklist.toml",
	                        "[channels]\nstatic_allow = \"\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-dynamic-allow-with-default-blocklist.toml",
	                        "[channels]\ndynamic_allow = \"rdpgfx\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-empty-dynamic-allow-with-default-blocklist.toml",
	                        "[channels]\ndynamic_allow = \"\"\n") != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-static-deny-with-allowlist.toml",
	        "[channels]\nstatic_mode = \"allowlist\"\nstatic_deny = \"cliprdr\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-empty-static-deny-with-allowlist.toml",
	                        "[channels]\nstatic_mode = \"allowlist\"\nstatic_deny = \"\"\n") != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-dynamic-deny-with-allowlist.toml",
	        "[channels]\ndynamic_mode = \"allowlist\"\ndynamic_deny = \"rdpgfx\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-empty-dynamic-deny-with-allowlist.toml",
	                        "[channels]\ndynamic_mode = \"allowlist\"\ndynamic_deny = \"\"\n") != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-static-allow-with-blocklist.toml",
	        "[channels]\nstatic_mode = \"blocklist\"\nstatic_allow = \"cliprdr\"\n") != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-dynamic-allow-with-blocklist.toml",
	        "[channels]\ndynamic_mode = \"blocklist\"\ndynamic_allow = \"rdpgfx\"\n") != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-drdynvc-dynamic-allow.toml",
	        "[channels]\ndynamic_mode = \"allowlist\"\ndynamic_allow = \"drdynvc\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-channel.toml",
	                        "[channels]\nstatic_mode = \"allowlist\"\n"
	                        "static_allow = \"cliprdr,cliprdr\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-dynamic-channel.toml",
	                        "[channels]\ndynamic_mode = \"allowlist\"\n"
	                        "dynamic_allow = \"rdpgfx,rdpgfx\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-static-deny-channel.toml",
	                        "[channels]\nstatic_deny = \"cliprdr,cliprdr\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-dynamic-deny-channel.toml",
	                        "[channels]\ndynamic_deny = \"rdpgfx,rdpgfx\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-empty-channel-token.toml",
	                        "[channels]\nstatic_mode = \"allowlist\"\n"
	                        "static_allow = \"cliprdr,,rdpsnd\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-empty-dynamic-channel-token.toml",
	                        "[channels]\ndynamic_mode = \"allowlist\"\n"
	                        "dynamic_allow = \"rdpgfx,,disp\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-bad-channel-char.toml",
	                        "[channels]\nstatic_deny = \"clip-rdr\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-bad-dynamic-channel-char.toml",
	                        "[channels]\ndynamic_deny = \"rdp-gfx\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-long-channel-name.toml",
	                        "[channels]\nstatic_deny = \"abcdefghi\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-long-dynamic-channel-name.toml",
	                        "[channels]\ndynamic_deny = \"abcdefghi\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-static-deny-key.toml",
	                        "[channels]\nstatic_deny = \"cliprdr\"\nstatic_deny = \"rdpsnd\"\n") !=
	    0)
		return -1;
	if (expect_load_failure("frdp-duplicate-dynamic-channel-key.toml",
	                        "[channels]\ndynamic_allow = \"\"\ndynamic_allow = \"\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-unknown-channel-key.toml",
	                        "[channels]\nclipboard = \"true\"\n") != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-duplicate-channel-section.toml",
	        "[channels]\nstatic_deny = \"cliprdr\"\n[channels]\nstatic_deny = \"rdpsnd\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-bad-clipboard-mode.toml", "[clipboard]\nmode = \"files\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-bad-clipboard-direction.toml",
	                        "[clipboard]\ndirection = \"up\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-clipboard-direction-without-mode.toml",
	                        "[clipboard]\ndirection = \"client-to-server\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-clipboard-text-without-direction.toml",
	                        "[clipboard]\nmode = \"text\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-clipboard-text-disabled-direction.toml",
	                        "[clipboard]\nmode = \"text\"\ndirection = \"disabled\"\n") != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-clipboard-disabled-with-direction.toml",
	        "[clipboard]\nmode = \"disabled\"\ndirection = \"server-to-client\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-clipboard-zero-limit.toml",
	                        "[clipboard]\nmax_text_bytes = 0\n") != 0)
		return -1;
	if (expect_load_failure("frdp-clipboard-large-limit.toml",
	                        "[clipboard]\nmax_text_bytes = 1048577\n") != 0)
		return -1;
	if (expect_load_failure("frdp-clipboard-quoted-limit.toml",
	                        "[clipboard]\nmax_text_bytes = \"4096\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-clipboard-duplicate-mode.toml",
	                        "[clipboard]\nmode = \"disabled\"\nmode = \"text\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-clipboard-duplicate-direction.toml",
	                        "[clipboard]\nmode = \"text\"\ndirection = "
	                        "\"client-to-server\"\ndirection = \"server-to-client\"\n") != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-clipboard-duplicate-limit.toml",
	        "[clipboard]\nmode = \"text\"\ndirection = \"client-to-server\"\nmax_text_bytes = "
	        "1024\nmax_text_bytes = 2048\n") != 0)
		return -1;
	if (expect_load_failure(
	        "frdp-duplicate-clipboard-section.toml",
	        "[clipboard]\nmode = \"disabled\"\n[clipboard]\nmode = \"disabled\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-unknown-clipboard-key.toml", "[clipboard]\nfiles = \"true\"\n") !=
	    0)
		return -1;
	if (expect_load_failure("frdp-audit-quoted-enabled.toml", "[audit]\nenabled = \"false\"\n") !=
	    0)
		return -1;
	if (expect_load_failure("frdp-audit-invalid-enabled.toml", "[audit]\nenabled = maybe\n") != 0)
		return -1;
	if (expect_load_failure("frdp-audit-duplicate-enabled.toml",
	                        "[audit]\nenabled = false\nenabled = false\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-audit-section.toml",
	                        "[audit]\nenabled = false\n[audit]\nenabled = false\n") != 0)
		return -1;
	if (expect_load_failure("frdp-audit-bare-sink.toml", "[audit]\nsink = journald\n") != 0)
		return -1;
	if (expect_load_failure("frdp-audit-unknown-sink.toml", "[audit]\nsink = \"syslog\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-audit-duplicate-sink.toml",
	                        "[audit]\nsink = \"journald\"\nsink = \"journald\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-unknown-audit-key.toml", "[audit]\nformat = \"json\"\n") != 0)
		return -1;
	return 0;
}

int TestFreeRDPFrdpConfig(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_default_blocklist() != 0)
		return -1;
	if (test_empty_filter_lists() != 0)
		return -1;
	if (test_server_max_connections() != 0)
		return -1;
	if (test_server_auth_session_fields() != 0)
		return -1;
	if (test_session_resource_policy() != 0)
		return -1;
	if (test_session_heartbeat_policy() != 0)
		return -1;
	if (test_session_display_policy() != 0)
		return -1;
	if (test_sample_config() != 0)
		return -1;
	if (test_auth_ntlm_fallback_policy() != 0)
		return -1;
	if (test_static_allowlist() != 0)
		return -1;
	if (test_static_blocklist() != 0)
		return -1;
	if (test_dynamic_allowlist() != 0)
		return -1;
	if (test_dynamic_blocklist() != 0)
		return -1;
	if (test_clipboard_policy() != 0)
		return -1;
	if (test_audit_policy() != 0)
		return -1;
	if (test_auth_kerberos_policy() != 0)
		return -1;
	if (test_invalid_channel_config() != 0)
		return -1;
	return 0;
}
