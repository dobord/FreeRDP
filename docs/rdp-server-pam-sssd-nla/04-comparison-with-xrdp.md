# 04. Comparison with xrdp

## Short conclusion

xrdp remains a mature and practical Linux RDP server. Its strengths are readiness, broad distribution packaging, the understandable `xrdp + xrdp-sesman + xorgxrdp` model, and a rich set of baseline RDP features. A new FreeRDP-based server makes sense when the main goal is a more modern security/authentication stack, control over NLA/CredSSP/Kerberos, custom session policy, and a more flexible architecture for enterprise use cases.

## Advantages of the FreeRDP-based approach

- Use of the FreeRDP server-side peer/listener API and existing protocol/security/channel stack.
- Ability to design NLA/CredSSP/Kerberos-first authentication without historical xrdp constraints.
- Clear privilege separation: listener, authentication broker, session manager, user agent.
- Policy-driven redirection: deny-by-default and a centralized channel model.
- Ability to build session registry, audit, metrics, tracing, and zero-trust controls from the start.
- Shared library base with the FreeRDP client/proxy/shadow ecosystem.

## Disadvantages of the FreeRDP-based approach

- The FreeRDP server side is less ready as a full Linux terminal server than xrdp.
- Session lifecycle, desktop backend, reconnect, packaging, and operations tooling must be implemented.
- Significant protocol interoperability risk with Windows clients.
- Fuzzing, regression suites, and security review are required around NLA/CredSSP/PAM boundaries.
- Cost of ownership is likely higher during the first 12-18 months.

## Advantages of xrdp

- Proven solution available in Debian/Ubuntu/RHEL-like distributions.
- xorgxrdp backend and working desktop login scenarios.
- Common channels such as clipboard, audio, and drive/printer redirection are supported in different configurations.
- Community knowledge base and known operational patterns.
- The 0.10.x branch improved unprivileged daemon mode, security fixes, and graphics capabilities.

## Disadvantages of xrdp relative to the target architecture

- NLA/CredSSP/Kerberos-first is traditionally not xrdp's primary strength.
- The architecture historically grew around its own protocol/session components, not around the FreeRDP security stack.
- Some PAM scenarios and additional prompts are hard to reconcile with the RDP NLA UX.
- Strict enterprise policy can be harder to add when deep authentication/session/redirection customization is required.

## Matrix

| Criterion | xrdp | FreeRDP-based server |
|---|---|---|
| Readiness | High | Low at the start, improves by milestone |
| NLA/CredSSP/Kerberos-first | Limited / not the primary profile | Target profile |
| PAM/SSSD | Works through the session/auth stack | Designed as a core boundary |
| Session lifecycle | Existing sesman | Must be implemented |
| Desktop backend | Mature xorgxrdp | MVP Xorg/Xvfb, Wayland later |
| Redirection policy | Features exist, policy depends on config | Deny-by-default, centralized policy |
| Security isolation | Improving | Designed from the start |
| Time to MVP | Faster | Longer |
| Long-term customization | Medium | High |

## Recommendation

Use xrdp as the baseline and production fallback while the FreeRDP-based server goes through MVP and interoperability testing. The new project is justified if NLA/CredSSP/Kerberos, PAM/SSSD policy, audit, and managed redirection are mandatory requirements that are difficult or expensive to implement on top of xrdp without a deep fork.
