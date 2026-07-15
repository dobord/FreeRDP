# 14. Support matrix

This matrix is a pilot validation target, not a GA support promise. A row moves
from "candidate" to "supported" only after package install, authentication,
session lifecycle, rollback, and client interoperability evidence is attached to
the release record.

## Status legend

| Status | Meaning |
|---|---|
| Candidate | Intended target for pilot validation. |
| Prototype | Code or documentation exists, but production behavior is incomplete. |
| Not supported | Must stay disabled or documented as unavailable for GA. |

## Operating systems

| Platform | Status | Required evidence before GA |
|---|---|---|
| Debian 12 | Candidate | Dependency-checked package build, clean install/uninstall, systemd start/stop, PAM/SSSD login, rollback test. |
| Ubuntu 24.04 LTS | Candidate | Dependency-checked package build, clean install/uninstall, systemd start/stop, PAM/SSSD login, rollback test. |
| RHEL 9 compatible distributions | Candidate | Dependency-checked RPM build on target distro macros, SELinux review, systemd and PAM/SSSD login tests. |
| Ubuntu 22.04 LTS | Candidate | Separate dependency review because the prototype currently builds and tests primarily on newer toolchains. |
| Non-systemd Linux | Not supported | Helper units, tmpfiles, PAM/session lifecycle, and runbooks assume systemd. |

## Identity and authentication

| Capability | Status | Required evidence before GA |
|---|---|---|
| PAM password authentication through SSSD | Candidate | Accepted, denied, expired/disabled account, group lookup, and PAM account/session tests against local, Samba AD, and FreeIPA profiles. |
| NTLM-enabled NLA fallback | Prototype | Explicit deployment decision, audit trail, and client matrix evidence; default guidance remains Kerberos-preferred. |
| NTLM-disabled Kerberos-only mode | Prototype | Integrated CredSSP/SPNEGO acceptor, keytab/SPN handling, SSSD principal mapping, and Windows client evidence. |
| Remote Credential Guard ticket handoff | Not supported | Current integrated path rejects unsupported ticket handoff. |
| Interactive PAM prompts/MFA inside NLA | Not supported | Requires separate UX and protocol design; interactive and extra password PAM prompts fail closed. |

## Clients

| Client | Status | Required evidence before GA |
|---|---|---|
| FreeRDP 3.x client built independently from the server tree | Candidate | Auth success/failure, graphical session lifecycle, resize, reconnect, clipboard, and log capture. |
| Windows 11 `mstsc.exe` | Candidate | Auth success/failure, graphical session lifecycle, resize, reconnect, clipboard, and log capture. |
| Windows 10 `mstsc.exe` | Candidate | Same scenario set as Windows 11 or explicit de-scope decision. |
| Microsoft Remote Desktop for macOS | Candidate | Same scenario set or explicit de-scope decision. |
| Browser or HTML5 RDP gateways | Not supported | Out of scope for the initial GA matrix. |

## Desktop and channels

| Capability | Status | Required evidence before GA |
|---|---|---|
| Xvfb-backed desktop session | Prototype | Replace or augment the fixed-mode Xvfb backend to apply the now-negotiated Display Control geometry changes, then attach resize churn and load/soak evidence. |
| Wayland backend | Not supported | No production backend is implemented. |
| Text clipboard | Prototype | Runtime `cliprdr` handler, direction/size policy enforcement, client interoperability, and audit evidence. |
| Audio output | Not supported | Baseline audio handler and policy tests are not implemented. |
| Drive, printer, smart card, arbitrary file clipboard | Not supported | Must remain denied until separate policy, audit, and runtime tests exist. |
| Dynamic virtual channels | Prototype | Policy-gated `drdynvc` and Display Control have focused/live-client evidence; other handlers remain disabled until explicit policy and interoperability coverage exists. |

## Packaging and operations

| Capability | Status | Required evidence before GA |
|---|---|---|
| Debian package | Prototype | Accumulated dependency-checked CI, complete source copyright review, equivalent SSSD-provider active-session evidence across package upgrade/rollback, and review of remaining non-error lintian findings. Local-PAM login/reconnect plus active-session cleanup are covered independently at each transition. |
| RPM package | Prototype | Target distro CI with real BuildRequires, systemd scriptlets, SELinux review, install/upgrade/uninstall. |
| systemd units and tmpfiles | Candidate | Distro verification, restart behavior, hardening review, runtime directory ownership checks. |
| AppArmor and SELinux examples | Prototype | Enforcing policy review and target-distro validation. |
| Monitoring examples | Prototype | Pilot thresholds, native auth/session/frame metrics, dashboard import evidence, alert tuning. |

## Release rule

Do not mark a cell "supported" for GA until the evidence is reproducible from a
clean install of the release artifact. If evidence is partial or comes only from
developer worktrees, leave the cell as "candidate" or "prototype".
