# 10. Configuration reference

This document describes the configuration options available in `frdpd.toml` (see `server/frdp/config/frdpd.toml`).

## [server]

- `listen` (string): IP address and port to bind. Default `0.0.0.0:3389`.
- `security` (string): Acceptable security layer. Currently implemented value: `nla` (CredSSP/Kerberos). Default `nla`. TLS fallback remains a separate compatibility path and must not be treated as the production default.
- `tls_cert`, `tls_key` (path): Paths to the TLS certificate and private key.
- `max_connections` (integer): Optional cap on concurrently accepted peer workers, in the range `0..2147483647`. `0` or omission means unlimited. The CLI override is `--max-connections=<n>`. When the cap is reached, `frdpd` rejects new peers before authentication, channel checks, or managed-session creation.

## [auth]

- `mode` (string): Authentication backend. Currently implemented value: `pam-sssd`. Default `pam-sssd`.
- `pam_service` (string): Name of PAM service file. Default `frdpd`. The tree installs a non-interactive example as `/etc/pam.d/frdpd` through the `server` component. The installed `frdp-authd.service` and `frdp-sesmand.service` launch their helpers with `--config /etc/frdpd/frdpd.toml`; `frdp-authd --config <path>` reads this field for broker-side authentication in the normal `auth_socket` path, while `--pam-service` remains a direct CLI override for standalone helper launches. `frdp-sesmand --config <path>` reads the same field for future PAM session opens, and `frdpctl reload` asks `frdp-sesmand` to reread it without changing existing PAM handles. On success, that reload reports a compact applied-policy summary containing `pam_service`, `max_processes`, and `memory_max_mb`. The field is also used by the `frdpd --pam-auth-test` smoke command.
- `auth_socket` (path): Absolute Unix socket path for the `frdp-authd` IPC broker in normal server startup. Relative paths and unsafe socket locations are rejected. The installed helper unit listens on `/run/frdp-authd/authd.sock`. Pair it with `[session].session_socket`; configuring only one helper socket is rejected. Before listening, `frdpd` requires bounded health responses identifying the paths as `frdp-authd` and `frdp-sesmand`, so stale or swapped sockets fail closed. Installed units restart failures; requests fail closed during the restart window.
- `ntlm_fallback` (boolean): Runtime default `false`; the installed sample enables it explicitly. NTLM support is included in the build by default and can be removed with `-DWITH_FRDPD_NTLM=OFF`; a binary built that way rejects `ntlm_fallback = true` before listening. Set `false` to configure server-side CredSSP/Negotiate with package list `kerberos,u2u,!ntlm`, causing NTLM mechanisms to be skipped, and to reject the NLA login before PAM if the selected SSPI package cannot be confirmed as Kerberos. This requires a working Kerberos path in the deployment; it does not by itself provision a keytab, accepted SPN, SSSD mapping, or PAM account/session policy.
- `ntlm_sam_file` (path): Required when `ntlm_fallback = true`. Absolute path to a WinPR SAM file containing NT hashes. `frdpd` opens it with no symlink following, requires an owner-only regular file with mode `0600`, one hard link, and ownership matching the daemon's effective UID, then pins that open inode for all NTLM checks. NT hashes are password-equivalent secrets. The SAM verifies the NTLMv2 challenge response; the NTLM proof user/domain must match the decrypted CredSSP password identity, after which `frdp-authd` still performs mandatory PAM authentication and account management, including SSSD policy. PAM/SSSD cannot supply the NT hash needed to verify an NTLM challenge response, so the SAM and PAM/SSSD checks are distinct mandatory gates and must be provisioned consistently.
- `kerberos` (boolean): Default `false`. When set to `true`, the config must also set `ntlm_fallback = false`, `keytab`, and `accepted_spn`. Current `frdpd` startup still fails closed because the integrated CredSSP/SPNEGO acceptor path is not implemented.
- `keytab` (path): Absolute path to the Kerberos service keytab; relative paths and control characters are rejected. Accepted only together with `kerberos = true`.
- `accepted_spn` (string): Accepted RDP service principal in `TERMSRV/fqdn` form. Accepted only together with `kerberos = true`.

## [session]

- `session_socket` (path): Absolute Unix socket path for the `frdp-sesmand` IPC service in normal server startup. Relative paths and unsafe socket locations are rejected. The installed helper unit listens on `/run/frdp-sesmand/sesmand.sock`. After authentication and static-channel policy checks pass, `frdpd` sends session open and close requests to `frdp-sesmand` and fails the login closed if session creation fails.
- `max_processes` (integer): Optional POSIX `RLIMIT_NPROC` guard applied by `frdp-sesmand` to newly launched `frdp-session-agent` children before `exec`. Valid range `0..1048576`; `0` or omission means unlimited. This is a process-count guard, not a replacement for per-session systemd cgroup ownership.
- `memory_max_mb` (integer): Optional POSIX `RLIMIT_AS` address-space guard, in MiB, applied by `frdp-sesmand` to newly launched `frdp-session-agent` children before `exec`. Valid range `0..1048576`; `0` or omission means unlimited. Production CPU/memory accounting through logind/systemd scopes remains open.
- `agent_heartbeat_interval_ms` (integer): Interval between agent supervision probes. Default `5000`; valid range `1000..60000`.
- `agent_heartbeat_timeout_ms` (integer): Absolute connect/send/receive deadline for one probe. Default `500`; valid range `500..5000` and it must not exceed `agent_heartbeat_interval_ms`.
- `agent_heartbeat_failures` (integer): Consecutive failed probes before `frdp-sesmand` cleans the managed process group and session artifacts. Default `3`; valid range `3..10`. A successful probe resets the counter; the lower bound allows a transient control-path operation to finish without destroying a healthy session.
- Unknown `[session]` keys are rejected until the daemon enforces them.

## [channels]

- `static_mode` (string): `blocklist`/`blacklist` or `allowlist`/`whitelist`. Default is `blocklist`. In blocklist mode, `static_deny` names are rejected and all other valid non-empty static channel names pass the filter, except `drdynvc`, which remains guard-denied until DVC transport and handlers are explicitly enabled. In allowlist mode, only `static_allow` names pass.
- `static_deny` (string): Optional comma-separated exact RDP static virtual channel names to reject in `blocklist` mode, for example `"drdynvc,rdpdr"`. Default empty. The key is rejected unless `static_mode = "blocklist"`, even when the value is empty.
- `static_allow` (string): Optional comma-separated exact RDP static virtual channel names to allow in `allowlist` mode, for example `"cliprdr"`. Default empty. The key is rejected unless `static_mode = "allowlist"`, even when the value is empty.
- `dynamic_mode` (string): `blocklist`/`blacklist` or `allowlist`/`whitelist`. Default is `blocklist`. This feeds the DVC authorization callback for server-created dynamic channels; the implemented `disp` alias controls Display Control over `drdynvc`.
- `dynamic_deny` (string): Optional comma-separated exact dynamic virtual channel names to reject in `blocklist` mode, for example `"rdpgfx,disp"`. Default empty. The key is rejected unless `dynamic_mode = "blocklist"`, even when the value is empty.
- `dynamic_allow` (string): Optional comma-separated exact dynamic virtual channel names to allow in `allowlist` mode, for example `"rdpgfx,disp"`. Default empty. The key is rejected unless `dynamic_mode = "allowlist"`, even when the value is empty.
- Allowing a name only permits negotiation/filter passage; runtime gates still deny arbitrary static channels and named handlers that are not implemented yet, including `rdpsnd` audio output and `rdpdr` device redirection.

## [clipboard]

- `mode` (string): `disabled` or `text`. Default `disabled`. `text` enables the server-side `cliprdr` handler for `CF_UNICODETEXT` and the bounded session-agent X11 selection bridge.
- `direction` (string): `disabled`, `client-to-server`, `server-to-client`, or `bidirectional`. Default `disabled`. `mode = "text"` requires an explicit non-disabled direction; any non-disabled direction is rejected while clipboard mode is disabled.
- `max_text_bytes` (integer): Maximum UTF/text payload size accepted by the text clipboard policy. Default `65536`; valid range is `1..1048576`. The value must be an unquoted integer.
- The effective X11 payload limit is additionally capped below the display server's ordinary maximum request size. Oversized transfers and the X11 `INCR` protocol fail closed; configure `max_text_bytes` below that backend limit for interoperable transfers.
- File clipboard, paths, images, and arbitrary formats remain unsupported and must stay denied until separate policy and runtime tests exist.
- Clipboard policy is applied when a peer starts; `frdpctl reload` does not yet change existing peer/channel instances.

## [audit]

- `enabled` (boolean): Default `false`. The parser accepts omitted or explicit `false` so deployments can carry a disabled audit stanza, but rejects `true` until structured audit sinks and runtime enforcement are implemented. Unknown `[audit]` keys are rejected.
- Auth/session/agent correlation ids already exist on the optional IPC paths; structured audit configuration and useful channel correlation remain planned.
