# 10. Configuration reference

This document describes the configuration options available in `frdpd.toml` (see `config/frdpd.toml`).

## [server]

- `listen` (string): IP address and port to bind. Default `0.0.0.0:3389`.
- `security` (string): Acceptable security layers. Allowed values: `nla` (CredSSP/Kerberos), `tls` (TLS only). Default `nla`.
- `tls_cert`, `tls_key` (path): Paths to the TLS certificate and private key.
- `max_connections` (int): Maximum concurrent connections.

## [auth]

- `mode` (string): Authentication backend. Allowed values: `pam-sssd`, `pam-krb5`. Default `pam-sssd`.
- `pam_service` (string): Name of PAM service file. Default `frdpd`.
- `kerberos` (string): Kerberos usage policy: `required`, `preferred`, or `disabled`. Default `preferred`.
- `ntlm_fallback` (bool): Whether to fall back to NTLM if Kerberos fails. Default `false`.
- `keytab` (path): Path to the server’s keytab for Kerberos.
- `accepted_spn` (list of strings): SPN aliases accepted for incoming Kerberos logins.

## [session]

- `backend` (string): Desktop backend. Allowed: `xorg`, `xvfb`, `wayland`. Default `xorg`.
- `default_desktop` (string): Default desktop environment, e.g. `xfce`.
- `idle_timeout` (duration): Session idle timeout. Default `60m`.
- `absolute_timeout` (duration): Maximum session lifetime. Default `12h`.
- `reconnect` (bool): Allow reconnecting to existing sessions.

## [channels]

Each key controls policy for a virtual channel. Values: `allow`, `deny`. Unknown channels are denied by default. Example:

```toml
[channels]
clipboard_text = "allow"
audio_output = "allow"
drive = "deny"
```

## [audit]

- `structured` (bool): Emit structured log events.
- `correlation_id` (bool): Include a unique identifier per connection to correlate audit events across components.
