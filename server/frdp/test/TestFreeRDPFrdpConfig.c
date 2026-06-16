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

static int test_default_deny(void)
{
	frdpConfig config = { 0 };

	if (load_config_body("frdp-default-deny.toml", "", &config) != 0)
		return -1;
	if (config.max_connections != 0)
		return -1;
	if (config.channels.static_allow_count != 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "cliprdr") != 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "rdpsnd") != 0)
		return -1;
	if (frdp_channel_policy_static_allowed(NULL, "cliprdr") != 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "") != 0)
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

static int test_empty_allow_list(void)
{
	frdpConfig config = { 0 };
	const char* body = "[channels]\nstatic_allow = \"\"\n";

	if (load_config_body("frdp-empty-channels.toml", body, &config) != 0)
		return -1;
	if (config.channels.static_allow_count != 0)
		return -1;
	if (frdp_channel_policy_static_allowed(&config.channels, "cliprdr") != 0)
		return -1;
	return 0;
}

static int test_static_allow_list(void)
{
	frdpConfig config = { 0 };
	const char* body = "[channels]\nstatic_allow = \"cliprdr, rdpsnd,rdpdr\"\n";
	CHANNEL_DEF channel = { 0 };
	char name[CHANNEL_NAME_LEN + 2] = { 0 };

	if (load_config_body("frdp-static-channels.toml", body, &config) != 0)
		return -1;
	if (config.channels.static_allow_count != 3)
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
	if (expect_load_failure("frdp-duplicate-channel.toml",
	                        "[channels]\nstatic_allow = \"cliprdr,cliprdr\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-empty-channel-token.toml",
	                        "[channels]\nstatic_allow = \"cliprdr,,rdpsnd\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-bad-channel-char.toml",
	                        "[channels]\nstatic_allow = \"clip-rdr\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-long-channel-name.toml",
	                        "[channels]\nstatic_allow = \"abcdefghi\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-unknown-channel-key.toml", "[channels]\nclipboard = \"true\"\n") != 0)
		return -1;
	if (expect_load_failure("frdp-duplicate-channel-section.toml",
	                        "[channels]\nstatic_allow = \"cliprdr\"\n[channels]\nstatic_allow = \"rdpsnd\"\n") !=
	    0)
		return -1;
	return 0;
}

int TestFreeRDPFrdpConfig(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_default_deny() != 0)
		return -1;
	if (test_empty_allow_list() != 0)
		return -1;
	if (test_server_max_connections() != 0)
		return -1;
	if (test_static_allow_list() != 0)
		return -1;
	if (test_invalid_channel_config() != 0)
		return -1;
	return 0;
}
