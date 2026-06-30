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
	if (frdp_channel_policy_static_allowed(&config.channels, "cliprdr") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "drdynvc") != 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed(&config.channels, "rdpgfx") == 0)
		return -1;
	if (frdp_channel_policy_dynamic_allowed(&config.channels, "drdynvc") != 0)
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
	                   "static_allow = \"cliprdr, rdpsnd,rdpdr\"\n";
	CHANNEL_DEF channel = { 0 };
	char name[CHANNEL_NAME_LEN + 2] = { 0 };

	if (load_config_body("frdp-static-channels.toml", body, &config) != 0)
		return -1;
	if (config.channels.static_mode != FRDP_CHANNEL_FILTER_ALLOWLIST)
		return -1;
	if (config.channels.static_allow_count != 3)
		return -1;
	if (config.channels.static_deny_count != 0)
		return -1;
	if (strcmp(config.channels.static_allow[0], "cliprdr") != 0)
		return -1;
	if (strcmp(config.channels.static_allow[1], "rdpsnd") != 0)
		return -1;
	if (strcmp(config.channels.static_allow[2], "rdpdr") != 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "cliprdr") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "rdpsnd") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "rdpdr") == 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "drdynvc") != 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "CLIPRDR") != 0)
		return -1;
	memcpy(channel.name, "cliprdr", sizeof("cliprdr"));
	if (frdp_channel_policy_static_channel_allowed(&config.channels, &channel, name, sizeof(name)) == 0)
		return -1;
	if (strcmp(name, "cliprdr") != 0)
		return -1;
	memset(&channel, 0, sizeof(channel));
	memset(name, 0, sizeof(name));
	memcpy(channel.name, "drdynvc", sizeof("drdynvc"));
	if (frdp_channel_policy_static_channel_allowed(&config.channels, &channel, name, sizeof(name)) != 0)
		return -1;
	if (strcmp(name, "drdynvc") != 0)
		return -1;
	direct_policy.static_mode = FRDP_CHANNEL_FILTER_ALLOWLIST;
	direct_policy.static_allow_count = 1;
	memcpy(direct_policy.static_allow[0], "drdynvc", sizeof("drdynvc"));
	if (frdp_channel_policy_static_allowed(&direct_policy, "drdynvc") != 0)
		return -1;
	if (frdp_channel_policy_static_channel_allowed(&direct_policy, &channel, name,
	                                               sizeof(name)) != 0)
		return -1;
	memset(&channel, 0, sizeof(channel));
	memset(name, 0xff, sizeof(name));
	if (frdp_channel_policy_static_channel_allowed(&config.channels, &channel, name, sizeof(name)) != 0)
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
	memcpy(channel.name, "drdynvc", sizeof("drdynvc"));
	if (frdp_channel_policy_static_channel_allowed(&config.channels, &channel, name,
	                                               sizeof(name)) != 0)
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
	return 0;
}

static int test_clipboard_policy(void)
{
	frdpConfig config = { 0 };
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

	body = "[clipboard]\nmode = \"text\"\ndirection = \"server-to-client\"\n";
	if (load_config_body("frdp-clipboard-server-to-client.toml", body, &config) != 0)
		return -1;
	if (config.clipboard.direction != FRDP_CLIPBOARD_DIRECTION_SERVER_TO_CLIENT)
		return -1;
	if (config.clipboard.max_text_bytes != 65536)
		return -1;

	body = "[clipboard]\nmode = \"text\"\ndirection = \"bidirectional\"\nmax_text_bytes = 1048576\n";
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

static int test_invalid_channel_config(void)
{
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
	if (expect_load_failure("frdp-bad-static-mode.toml",
	                        "[channels]\nstatic_mode = \"maybe\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-bad-dynamic-mode.toml",
	                        "[channels]\ndynamic_mode = \"maybe\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-static-mode.toml",
	                        "[channels]\nstatic_mode = \"blocklist\"\nstatic_mode = \"allowlist\"\n") !=
	    0)
		return -1;
	if (expect_load_failure("frdp-duplicate-dynamic-mode.toml",
	                        "[channels]\ndynamic_mode = \"blocklist\"\ndynamic_mode = \"allowlist\"\n") !=
	    0)
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
	if (expect_load_failure("frdp-static-deny-with-allowlist.toml",
	                        "[channels]\nstatic_mode = \"allowlist\"\nstatic_deny = \"cliprdr\"\n") !=
	    0)
		return -1;
	if (expect_load_failure("frdp-empty-static-deny-with-allowlist.toml",
	                        "[channels]\nstatic_mode = \"allowlist\"\nstatic_deny = \"\"\n") !=
	    0)
		return -1;
	if (expect_load_failure("frdp-dynamic-deny-with-allowlist.toml",
	                        "[channels]\ndynamic_mode = \"allowlist\"\ndynamic_deny = \"rdpgfx\"\n") !=
	    0)
		return -1;
	if (expect_load_failure("frdp-empty-dynamic-deny-with-allowlist.toml",
	                        "[channels]\ndynamic_mode = \"allowlist\"\ndynamic_deny = \"\"\n") !=
	    0)
		return -1;
	if (expect_load_failure("frdp-static-allow-with-blocklist.toml",
	                        "[channels]\nstatic_mode = \"blocklist\"\nstatic_allow = \"cliprdr\"\n") !=
	    0)
		return -1;
	if (expect_load_failure("frdp-dynamic-allow-with-blocklist.toml",
	                        "[channels]\ndynamic_mode = \"blocklist\"\ndynamic_allow = \"rdpgfx\"\n") !=
	    0)
		return -1;
	if (expect_load_failure("frdp-drdynvc-static-allow.toml",
	                        "[channels]\nstatic_mode = \"allowlist\"\nstatic_allow = \"drdynvc\"\n") !=
	    0)
		return -1;
	if (expect_load_failure("frdp-drdynvc-dynamic-allow.toml",
	                        "[channels]\ndynamic_mode = \"allowlist\"\ndynamic_allow = \"drdynvc\"\n") !=
	    0)
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
	                        "[channels]\ndynamic_allow = \"\"\ndynamic_allow = \"\"\n") !=
	    0)
		return -1;
	if (expect_load_failure("frdp-unknown-channel-key.toml", "[channels]\nclipboard = \"true\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-channel-section.toml",
	                        "[channels]\nstatic_deny = \"cliprdr\"\n[channels]\nstatic_deny = \"rdpsnd\"\n") !=
	    0)
		return -1;
	if (expect_load_failure("frdp-bad-clipboard-mode.toml",
	                        "[clipboard]\nmode = \"files\"\n") != 0)
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
	if (expect_load_failure("frdp-clipboard-disabled-with-direction.toml",
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
	if (expect_load_failure("frdp-duplicate-clipboard-section.toml",
	                        "[clipboard]\nmode = \"disabled\"\n[clipboard]\nmode = \"disabled\"\n") !=
	    0)
		return -1;
	if (expect_load_failure("frdp-unknown-clipboard-key.toml",
	                        "[clipboard]\nfiles = \"true\"\n") != 0)
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
	if (test_invalid_channel_config() != 0)
		return -1;
	return 0;
}
