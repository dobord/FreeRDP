# frdpd prototype

`frdpd` is an experimental FreeRDP server daemon prototype for the PAM/SSSD/NLA work described in
`docs/rdp-server-pam-sssd-nla`.

The target provides an experimental RDP listener and a PAM authentication smoke path:

```bash
frdpd --bind=0.0.0.0 --port=3389 --cert=server.crt --key=server.key --pam-service=frdpd
```

The listener enables NLA/CredSSP and requires the normal `frdp-authd` and `frdp-sesmand` helper sockets
for authentication, PAM session ownership, and desktop agent launch. The old in-process PAM fallback has
been removed; use the explicit PAM smoke command below for local PAM checks.

```bash
frdpd --pam-auth-test USER [--domain DOMAIN] [--service SERVICE] [--rhost HOST]
```

The PAM flow is intentionally non-interactive. The helper sets `PAM_AUTHTOK` before
`pam_authenticate()` and answers password prompts with the CredSSP/NLA password, matching the
constraint that there is no arbitrary PAM conversation UI. Configure `/etc/pam.d/frdpd` to consume the
existing token (`pam_sss.so use_first_pass` or an equivalent site policy).

`frdpd_authenticate_identity()` adapts a FreeRDP `SEC_WINNT_AUTH_IDENTITY` from the peer `Logon`
callback into this PAM request and clears temporary password copies after authentication.
