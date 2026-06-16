# 10. Configuration reference

This document describes the configuration options available in `frdpd.toml` (see `server/frdp/config/frdpd.toml`).

## [server]

- `listen` (string): IP address and port to bind. Default `0.0.0.0:3389`.
- `security` (string): Acceptable security layer. Currently implemented value: `nla` (CredSSP/Kerberos). Default `nla`. TLS fallback remains a separate compatibility path and must not be treated as the production default.
- `tls_cert`, `tls_key` (path): Paths to the TLS certificate and private key.
- `max_connections` (integer): Optional cap on concurrently accepted peer workers, in the range `0..2147483647`. `0` or omission means unlimited. When the cap is reached, `frdpd` rejects new peers before authentication, channel checks, or managed-session creation.

## [auth]

- `mode` (string): Authentication backend. Currently implemented value: `pam-sssd`. Default `pam-sssd`.
- `pam_service` (string): Name of PAM service file for the in-process PAM path. Default `frdpd`. The tree installs a non-interactive example as `/etc/pam.d/frdpd` through the `server` component. In `auth_socket` mode, the broker-side `frdp-authd --pam-service` setting selects the PAM service.
- `auth_socket` (path): Optional absolute Unix socket path for the `frdp-authd` IPC broker. Relative paths and unsafe socket locations are rejected. The installed helper unit listens on `/run/frdp-authd/authd.sock`. This auth/account path requires `--no-pam-session`; with `frdpd.service`, set `FRDPD_ARGS=--no-pam-session` in `/etc/frdpd/frdpd.env`. Pair it with `[session].session_socket` when `frdp-sesmand` owns sessions. When omitted, `frdpd` uses the current in-process PAM auth/account path.
- `kerberos`, `ntlm_fallback`, `keytab`, `accepted_spn`: planned Kerberos-first production fields. The current parser rejects them until the daemon can enforce the corresponding policy.

## [session]

- `session_socket` (path): Optional absolute Unix socket path for the `frdp-sesmand` IPC service. Relative paths and unsafe socket locations are rejected. The installed helper unit listens on `/run/frdp-sesmand/sesmand.sock`. This path requires `--no-pam-session`; after authentication and static-channel policy checks pass, `frdpd` sends session open and close requests to `frdp-sesmand` and fails the login closed if session creation fails.
- Other session lifecycle fields remain planned. Unknown `[session]` keys are rejected until the daemon enforces them.

## [channels]

- `static_allow` (string): Optional comma-separated exact RDP static virtual channel names to allow during client capability processing, for example `"cliprdr,rdpsnd"`. Default deny-all. Allowing a name only permits negotiation; clipboard/audio/device channel handlers are not implemented yet. Dynamic channel policy is not implemented, so do not allow `drdynvc` for production use.

## [audit]

Planned audit fields. The current parser rejects `[audit]` until structured audit configuration and channel correlation are implemented; auth/session/agent correlation ids already exist on the optional IPC paths.
