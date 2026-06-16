# 02. Solution architecture

## Goal

The goal is to implement a Linux RDP server on top of the FreeRDP server-side API, not to fork xrdp. The server must support NLA/CredSSP, Kerberos-first authentication, PAM/SSSD as the system identity/account/session policy boundary, a managed user desktop-session lifecycle, and an extensible channel model.

## High-level principles

1. **The RDP protocol layer is isolated from the session layer.** FreeRDP handles transport, security negotiation, peer callbacks, codecs, and virtual channels. Project code handles authentication, policy, lifecycle, and the display backend.
2. **Pre-authentication happens before desktop resources are allocated.** Xorg/Wayland processes, runtime directories, and user agents are not created until NLA/PAM authentication succeeds.
3. **PAM is the source of the login/account/session decision.** SSSD acts as the backend for AD/LDAP/Kerberos/NSS/cache, but the allow/deny decision passes through the PAM service.
4. **Privilege separation is mandatory.** The listener, authentication broker, session manager, and user agent run with different privileges and communicate over UDS or gRPC-like IPC.
5. **Redirection is denied by default.** Clipboard, drive, printer, smartcard, microphone, camera, and USB redirection are enabled only by policy.

## Components

```text
RDP client
  -> frdpd listener
      -> FreeRDP peer worker
          -> frdp-authd
              -> CredSSP/SPNEGO/Kerberos/NTLM
              -> PAM service frdpd
              -> SSSD/NSS/Kerberos
          -> frdp-sesmand
              -> logind/cgroups/PAM session
              -> frdp-session-agent
                  -> Xorg/Xvfb/Wayland backend
                  -> RDP channels and encoders
```

## frdpd listener

`frdpd` listens on TCP 3389 or a systemd socket, creates the FreeRDP peer, applies TLS policy, enables mandatory NLA, and passes the peer to a worker. This process must not contain user credentials, keytab handling, or desktop lifecycle logic. After binding to the privileged port, it should drop unnecessary capabilities.

Main responsibilities:

- accepting and rate-limiting connections;
- TLS certificate selection;
- security negotiation and client capability discovery;
- creating a per-connection correlation id;
- dispatching work into a worker pool;
- first-pass filtering by IP, TLS profile, and client build.

## frdp-authd

The authentication broker isolates the sensitive path. It accepts only minimal data from the peer worker: connection id, client address, normalized username, domain, negotiated mechanism, and a protected credential reference. Passwords are not logged, are not serialized in clear text, and must remain in locked memory only for the duration of the PAM transaction.

Responsibilities:

- processing the CredSSP/SPNEGO result;
- Kerberos acceptor context through a keytab;
- PAM transaction for the password-backed flow;
- `pam_acct_mgmt` for account restrictions;
- NSS lookup through SSSD;
- principal-to-POSIX account normalization;
- returning `AuthResult` to the session manager.

## frdp-sesmand

The session manager is similar in role to xrdp-sesman, but it is more tightly bound to PAM/logind/cgroups. It decides whether to create a new session or reconnect to an existing one, opens the PAM session, creates runtime state, starts the desktop agent, and controls cleanup.

Responsibilities:

- session registry;
- `pam_open_session` / `pam_close_session`;
- systemd-logind integration;
- cgroup slices and resource limits;
- reconnect by user/session id;
- idle and absolute timeouts;
- cleanup of Xorg/DBus/PulseAudio/PipeWire/temporary mounts.

## frdp-session-agent

The user agent runs as the target user and serves the desktop backend and RDP channels. It does not make authentication or policy decisions; it only enforces the policy profile received from the session manager.

Responsibilities:

- starting Xorg/Xvfb/Xorg dummy or a future Wayland backend;
- handling input events;
- capturing framebuffer/damage regions;
- clipboard, audio, and display resize handling;
- channel filter policy enforcement;
- health metrics and watchdog heartbeat.

## Display backend

The MVP should use headless Xorg/Xvfb/Xorg dummy because this lowers risk and quickly provides compatibility with existing Linux desktop environments. A Wayland/wlroots backend should be a separate milestone after the RDP, security, and session layers are stable.

## IPC

IPC channels should be local Unix domain sockets with `SO_PEERCRED`, short timeouts, schema versioning, and a strict method allowlist. memfd/shared memory is acceptable for large frame buffers, but ownership and lifecycle must be controlled by the session agent.

## Observability

Every login flow receives a correlation id that travels through the listener, authd, PAM, sesmand, agent, and channel logs. Minimum events: connection accepted, TLS negotiated, NLA started, authentication success/failure, PAM account denied, session created/reconnected/closed, channel opened/denied, and policy changed.
