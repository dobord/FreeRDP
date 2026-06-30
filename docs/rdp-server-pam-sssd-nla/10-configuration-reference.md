# 10. Configuration reference

This document describes the configuration options available in `frdpd.toml` (see `server/frdp/config/frdpd.toml`).

## [server]

- `listen` (string): IP address and port to bind. Default `0.0.0.0:3389`.
- `security` (string): Acceptable security layer. Currently implemented value: `nla` (CredSSP/Kerberos). Default `nla`. TLS fallback remains a separate compatibility path and must not be treated as the production default.
- `tls_cert`, `tls_key` (path): Paths to the TLS certificate and private key.
- `max_connections` (integer): Optional cap on concurrently accepted peer workers, in the range `0..2147483647`. `0` or omission means unlimited. The CLI override is `--max-connections=<n>`. When the cap is reached, `frdpd` rejects new peers before authentication, channel checks, or managed-session creation.

## [auth]

- `mode` (string): Authentication backend. Currently implemented value: `pam-sssd`. Default `pam-sssd`.
- `pam_service` (string): Name of PAM service file for the legacy in-process PAM path and PAM auth smoke test. Default `frdpd`. The tree installs a non-interactive example as `/etc/pam.d/frdpd` through the `server` component. In the normal `auth_socket` path, the broker-side `frdp-authd --pam-service` setting selects the PAM service.
- `auth_socket` (path): Absolute Unix socket path for the `frdp-authd` IPC broker in normal server startup. Relative paths and unsafe socket locations are rejected. The installed helper unit listens on `/run/frdp-authd/authd.sock`. Pair it with `[session].session_socket`; configuring only one helper socket is rejected. When omitted, `frdpd` starts only with the explicit `--allow-in-process-pam` legacy/development flag.
- `kerberos`, `ntlm_fallback`, `keytab`, `accepted_spn`: planned Kerberos-first production fields. The current parser rejects them until the daemon can enforce the corresponding policy.

## [session]

- `session_socket` (path): Absolute Unix socket path for the `frdp-sesmand` IPC service in normal server startup. Relative paths and unsafe socket locations are rejected. The installed helper unit listens on `/run/frdp-sesmand/sesmand.sock`. After authentication and static-channel policy checks pass, `frdpd` sends session open and close requests to `frdp-sesmand` and fails the login closed if session creation fails.
- Other session lifecycle fields remain planned. Unknown `[session]` keys are rejected until the daemon enforces them.

## [channels]

- `static_mode` (string): `blocklist`/`blacklist` or `allowlist`/`whitelist`. Default is `blocklist`. In blocklist mode, `static_deny` names are rejected and all other valid non-empty static channel names pass the filter, except `drdynvc`, which remains guard-denied until DVC transport and handlers are explicitly enabled. In allowlist mode, only `static_allow` names pass.
- `static_deny` (string): Optional comma-separated exact RDP static virtual channel names to reject in `blocklist` mode, for example `"drdynvc,rdpdr"`. Default empty. The key is rejected unless `static_mode = "blocklist"`, even when the value is empty.
- `static_allow` (string): Optional comma-separated exact RDP static virtual channel names to allow in `allowlist` mode, for example `"cliprdr,rdpsnd"`. Default empty. The key is rejected unless `static_mode = "allowlist"`, even when the value is empty.
- `dynamic_mode` (string): `blocklist`/`blacklist` or `allowlist`/`whitelist`. Default is `blocklist`. This feeds the DVC authorization callback for server-created dynamic channels, but remains operationally preparatory while `drdynvc` and useful dynamic handlers stay disabled.
- `dynamic_deny` (string): Optional comma-separated exact dynamic virtual channel names to reject in `blocklist` mode, for example `"rdpgfx,disp"`. Default empty. The key is rejected unless `dynamic_mode = "blocklist"`, even when the value is empty.
- `dynamic_allow` (string): Optional comma-separated exact dynamic virtual channel names to allow in `allowlist` mode, for example `"rdpgfx,disp"`. Default empty. The key is rejected unless `dynamic_mode = "allowlist"`, even when the value is empty.
- Allowing a name only permits negotiation/filter passage; clipboard/audio/device channel handlers are not implemented yet.

## [audit]

Planned audit fields. The current parser rejects `[audit]` until structured audit configuration and channel correlation are implemented; auth/session/agent correlation ids already exist on the optional IPC paths.
