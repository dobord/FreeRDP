# 01. Executive summary

## Objective

The project proposes building an xrdp-like Linux RDP server on top of FreeRDP. The focus is not only remote desktop login, but an enterprise RDP server with NLA/CredSSP, Kerberos-first authentication, PAM/SSSD policy enforcement, and a controlled user-session lifecycle.

## Key conclusion

The solution is technically feasible, but it should not be implemented as a thin wrapper around `freerdp-shadow-cli`. It needs a complete server stack:

- the FreeRDP listener/peer API for the RDP protocol layer;
- a dedicated authentication broker for CredSSP/SPNEGO/Kerberos/PAM;
- a session manager with a role similar to xrdp-sesman, but with a stricter security model;
- a per-user session agent for the desktop backend and channels;
- deny-by-default policy for redirection.

## Why FreeRDP

FreeRDP provides mature building blocks for the RDP protocol, security negotiation, codecs, virtual channels, and server/proxy/shadow primitives. This makes it possible to focus on the missing layer: PAM/SSSD, desktop lifecycle, policy, packaging, and operations.

## Why not just xrdp

xrdp is mature, widely available, and a practical baseline. However, when NLA/CredSSP/Kerberos-first authentication, strict channel policy, centralized audit, and a managed enterprise authentication/session layer are required, a FreeRDP-based architecture gives more control at the cost of greater complexity and a longer implementation schedule.

## MVP scope

The MVP should include:

1. A TCP listener on 3389 with TLS and mandatory NLA.
2. A password-backed CredSSP flow into the `frdpd` PAM service through SSSD.
3. SSSD/NSS lookup for uid/gid/groups and account restrictions.
4. A session manager with `pam_open_session`, logind/cgroups, and reconnect support.
5. A headless Xorg/Xvfb/Xorg dummy backend.
6. Keyboard/mouse input, resize, text clipboard, and baseline audio output.
7. Structured journald audit events.
8. deb/rpm packaging and systemd units.

## Deferred scope

Do not include in the first MVP:

- production Kerberos-only passwordless mode without a separate security review;
- arbitrary interactive PAM/MFA prompts inside NLA;
- full drive/printer/smartcard/USB redirection;
- a Wayland-only backend;
- GPU hardware encoding;
- session recording and proxy gateway mode.

## Main risks

| Risk | Level | Control |
|---|---:|---|
| The FreeRDP server API is less stable than the client API | High | pin version, compatibility layer, upstream tracking |
| CredSSP/Kerberos interoperability with Windows clients | High | client matrix and regression suite |
| PAM prompts do not match the NLA UX | Medium | constrain the MVP to a password-backed flow |
| Desktop lifecycle is more complex than the RDP layer | High | dedicated sesmand and Xorg MVP |
| Redirection can become an exfiltration channel | High | deny-by-default and group policy |
| Performance under browser/video workloads | Medium | load tests, codec tuning, resource limits |

## Recommendation

Start with a lab proof and MVP on the FreeRDP 3.26.0 release branch. Keep xrdp as the production fallback and benchmark. The project branch should be based on the release commit to reduce upstream noise and make builds reproducible.
