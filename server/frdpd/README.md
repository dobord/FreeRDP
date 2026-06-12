# frdpd prototype

`frdpd` is an experimental FreeRDP server daemon prototype for the PAM/SSSD/NLA work described in
`docs/rdp-server-pam-sssd-nla`.

The current target provides a PAM authentication smoke path:

```bash
frdpd --pam-auth-test USER [--domain DOMAIN] [--service SERVICE] [--rhost HOST]
```

The PAM flow is intentionally non-interactive. The helper sets `PAM_AUTHTOK` before
`pam_authenticate()` and rejects `PAM_PROMPT_*` requests, matching the CredSSP/NLA constraint that
there is no arbitrary PAM conversation UI. Configure `/etc/pam.d/frdpd` to consume the existing token
(`pam_sss.so use_first_pass` or an equivalent site policy).

`frdpd_authenticate_identity()` adapts a FreeRDP `SEC_WINNT_AUTH_IDENTITY` from the peer `Logon`
callback into this PAM request and clears temporary password copies after authentication.
