# 07. Kerberos-first authentication

This document describes how to enable Kerberos-first authentication for the FreeRDP-based server, as described in Phase 4 of the implementation plan【196565104317886†L61-L72】.

## SPN and keytab provisioning

1. Create a service principal name (SPN) in Active Directory for each RDP server instance:
   
   ```
   setspn -S TERMSRV/rdp01.example.com <AD-account>
   ```
   
   Use the host FQDN and ensure the short SPN alias is also mapped.
2. Generate a Kerberos keytab containing the service principal’s credentials and install it on the server at `/etc/frdpd/frdpd.keytab`. Use `ktutil` or `ktpass` to export the keytab.
3. Restrict file permissions on the keytab (`chmod 600`) and configure `frdpd` to load it via the `keytab` option in `frdpd.toml`.

## GSSAPI acceptor path

The `frdp-krb-authd` component (see `frdp-krb-authd/frdp-krb-authd.c`) demonstrates how to accept a GSSAPI security context. It:

- Sets the keytab via the environment variable `KRB5_KTNAME`.
- Calls `gss_accept_sec_context()` on an incoming token provided by the RDP CredSSP client.
- Extracts the authenticated principal using `gss_display_name()`.
- Maps the principal to a POSIX account (`getpwnam()`).
- Optionally opens a PAM session for the user (reusing the logic from `frdp-authd`).

In a production server, the RDP daemon must decode the SPNEGO token from the CredSSP handshake, invoke the GSSAPI acceptor to obtain the client’s principal, and use that identity for PAM/SSSD account checks. NTLM fallback should be disabled via configuration (`ntlm_fallback = false`) to enforce Kerberos-only mode.

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
