# 10. Configuration reference

This document describes the configuration options available in `frdpd.toml` (see `server/frdp/config/frdpd.toml`).

## [server]

- `listen` (string): IP address and port to bind. Default `0.0.0.0:3389`.
- `security` (string): Acceptable security layer. Currently implemented value: `nla` (CredSSP/Kerberos). Default `nla`. TLS fallback remains a separate compatibility path and must not be treated as the production default.
- `tls_cert`, `tls_key` (path): Paths to the TLS certificate and private key.
- `max_connections`: planned connection-limit field. The current parser rejects it until the daemon enforces connection caps.

## [auth]

- `mode` (string): Authentication backend. Currently implemented value: `pam-sssd`. Default `pam-sssd`.
- `pam_service` (string): Name of PAM service file for the in-process PAM path. Default `frdpd`. In `auth_socket` mode, the broker-side `frdp-authd --pam-service` setting selects the PAM service.
- `auth_socket` (path): Optional absolute Unix socket path for the `frdp-authd` IPC broker. Relative paths and unsafe socket locations are rejected. Because session-manager IPC is not wired yet, this auth/account-only path currently requires `--no-pam-session`; when omitted, `frdpd` uses the current in-process PAM path.
- `kerberos`, `ntlm_fallback`, `keytab`, `accepted_spn`: planned Kerberos-first production fields. The current parser rejects them until the daemon can enforce the corresponding policy.

## [session]

Planned session lifecycle fields. The current parser rejects `[session]` until the session manager enforces these settings.

## [channels]

Planned channel policy fields. The current parser rejects `[channels]` until channel policy is enforced in the daemon and channel-open path.

## [audit]

Planned audit fields. The current parser rejects `[audit]` until structured audit and correlation-id propagation are implemented.
