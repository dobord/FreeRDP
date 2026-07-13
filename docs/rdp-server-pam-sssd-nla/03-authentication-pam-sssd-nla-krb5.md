# 03. Authentication: PAM, SSSD, NLA/CredSSP, and Kerberos

## Security goals

- Mandatory NLA for the production profile.
- Kerberos-first model for domain clients.
- NTLM fallback only behind an explicit feature flag and only for compatibility.
- PAM/SSSD as the single account/session policy boundary.
- Passwords and delegated credentials must not enter logs, core dumps, crash reports, or long-lived storage.

## Password-backed NLA flow

```text
Client -> TLS -> CredSSP -> SPNEGO -> password credentials
  -> frdp-authd
      -> pam_start(service=frdpd)
      -> pam_set_item(PAM_USER)
      -> pam_authenticate
      -> pam_acct_mgmt
      -> NSS/SSSD lookup
      -> AuthResult
  -> frdp-sesmand
      -> pam_setcred
      -> pam_open_session
      -> user session
```

This mode is the most compatible path for regular Windows RDP clients. An important limitation is that RDP NLA is not an arbitrary interactive PAM conversation. MFA through additional PAM prompts therefore works only with a deliberately designed UX or through non-interactive OTP/password concatenation, which should be treated as a temporary workaround.

## Kerberos service principal

AD integration requires SPNs:

```text
TERMSRV/host.example.com
TERMSRV/host
```

The keytab must be readable only by root or by the dedicated authentication broker user. In production, prefer a dedicated service account or machine account with only the required SPNs and no unnecessary delegation.

## Kerberos acceptor mode

Kerberos-only prevalidated login is possible with a strict design:

1. CredSSP/SPNEGO provides a Kerberos service ticket for `TERMSRV/fqdn`.
2. The server validates the ticket through the keytab.
3. The principal is normalized to a canonical user name.
4. SSSD/NSS maps the principal to a POSIX uid/gid/groups.
5. PAM account/session hooks run without rechecking the password.

In practice, this should be a separate milestone because the standard PAM password flow usually expects a password. Possible approaches include a custom PAM helper, a GSSAPI-aware PAM module, or a `pam_acct_mgmt` + `pam_open_session` mode after the Kerberos acceptor decision. This mode requires a security review.

## SSSD

SSSD is responsible for:

- AD/LDAP realm discovery;
- Kerberos configuration and cache policy;
- NSS user/group lookup;
- access provider rules;
- offline credentials policy;
- home directory, shell, and ID mapping.

Example minimum expectations for `sssd.conf`:

```ini
[sssd]
services = nss, pam
config_file_version = 2
domains = corp.example.com

[domain/corp.example.com]
id_provider = ad
auth_provider = ad
access_provider = ad
cache_credentials = true
krb5_realm = CORP.EXAMPLE.COM
fallback_homedir = /home/%u@%d
default_shell = /bin/bash
```

## PAM service

`/etc/pam.d/frdpd` should be a dedicated service, not a reused `login` or `sshd` stack without review.

Example:

```text
auth      required   pam_env.so
auth      sufficient pam_sss.so forward_pass
auth      required   pam_deny.so
account   required   pam_sss.so
session   required   pam_limits.so
session   optional   pam_systemd.so
session   required   pam_sss.so
password  sufficient pam_sss.so use_authtok
```

## Name normalization

Supported input forms:

- `user@REALM`;
- `user@domain.example.com`;
- `DOMAIN/user` as a UI alias;
- a local user for break-glass mode, if policy allows it.

The result must be a canonical principal and POSIX account. Ambiguous mappings must fail closed instead of guessing the user.

## Hardening

- `mlock`/secure allocator for password buffers.
- `PR_SET_DUMPABLE=0` for authd.
- Zeroization after the PAM transaction.
- journald redaction for username/domain where privacy requires it.
- Rate limiting by remote source and normalized account (`frdp-authd` now keeps independent,
  process-local fixed-window failure budgets: 10 credential/account denials in 120 seconds, with
  backend-canonical account keys (ASCII case-fold fallback for unresolved names) and bounded
  tables that fail closed when capacity is exhausted; distributed enforcement remains an
  operational follow-up).
- Audit events for authentication success/failure with reason codes and no sensitive data.
- Keytab rotation procedure.

## Policy decisions

The authentication broker returns not only `ok/deny`, but also a policy profile: allowed channels, idle timeout, reconnect permission, session class, logging level, and watermark/session-recording flags. This ties AD/SSSD groups to RDP behavior.
