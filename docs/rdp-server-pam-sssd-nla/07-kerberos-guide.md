# 07. Kerberos-first authentication

This document describes how to enable Kerberos-first authentication for the FreeRDP-based server, as described in Phase 4 of the implementation plan【196565104317886†L61-L72】.

## SPN and keytab provisioning

1. Create a service principal name (SPN) in Active Directory for each RDP server instance:
   
   ```
   setspn -S TERMSRV/rdp01.example.com <AD-account>
   ```
   
   Use the host FQDN and ensure the short SPN alias is also mapped.
2. Generate a Kerberos keytab containing the service principal’s credentials and install it on the server at `/etc/frdpd/frdpd.keytab`. Use `ktutil` or `ktpass` to export the keytab.
3. Restrict file permissions on the keytab (`chmod 600`). The current `frdpd.toml` parser rejects `keytab` until the integrated daemon can enforce the Kerberos acceptor policy; keep keytab wiring in the Kerberos milestone implementation rather than in current production config.

## GSSAPI acceptor path

The `frdp-krb-authd` component (see `server/frdp/frdp-krb-authd/frdp-krb-authd.c`) demonstrates how to accept a GSSAPI security context. It:

- Sets the keytab through `KRB5_KTNAME`, preserving an existing non-empty value,
  otherwise using `FRDP_KRB_KEYTAB` or `/etc/frdpd/frdpd.keytab`.
- Optionally imports `FRDP_KRB_ACCEPTOR_NAME` as a GSS host-based service name
  such as `TERMSRV@host.example.com` and acquires acceptor credentials for that
  name before accepting a context.
- Base64-decodes the standalone token argument and calls `gss_accept_sec_context()`
  on the resulting token bytes. Production `frdpd` still needs to extract the
  SPNEGO token from the RDP CredSSP handshake and pass it to the acceptor path.
- Extracts the authenticated principal using `gss_display_name()`.
- Maps the principal to a POSIX account (`getpwnam()`). The build-only
  prototype first tries the displayed principal exactly, then fail-closed
  normalizes simple `user@REALM` names to a local account candidate and rejects
  service/instance principals such as `host/server@REALM`.
- Optionally opens a PAM session for the user (reusing the logic from `frdp-authd`).

In a production server, the RDP daemon must decode the SPNEGO token from the CredSSP handshake, invoke the GSSAPI acceptor to obtain the client’s principal, and use that identity for PAM/SSSD account checks. NTLM fallback must be disabled by an enforced daemon policy. The current parser rejects `ntlm_fallback` until that policy is implemented, so do not add it to `frdpd.toml` yet.

## Principal to POSIX mapping

Name mapping is handled by SSSD and PAM. Ensure that `sssd.conf` has:

```
[sssd]
services = nss, pam
domains = your.domain.example.com

[domain/your.domain.example.com]
id_provider = ad
override_homedir = /home/%u
```

This maps UPN or down-level logon names to UNIX users. The service should call `getpwnam()` on the normalized username to validate that the account exists before launching a session.

## Passwordless PAM session

If the Kerberos context is accepted, the server should open a PAM session without requiring a password. The PAM service file (`/etc/pam.d/frdpd`) can use `pam_sss.so try_cert_auth` or `pam_krb5.so` in `sufficient` mode to permit ticket-based authentication.

## Security review

Kerberos credential delegation must be disabled unless explicit delegation is required. The RDP server should verify the `GSS_C_DELEG_FLAG` on the incoming context and ignore or wipe delegated tickets. Audit logs should record the client principal, target SPN, result of account checks, and correlation ID for each connection.
