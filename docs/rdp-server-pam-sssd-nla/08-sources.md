# 08. Sources

Source review date: 2026-06-11.

## FreeRDP

1. FreeRDP Documentation - Introduction.
   https://pub.freerdp.com/api/index.html

2. FreeRDP GitHub repository.
   https://github.com/FreeRDP/FreeRDP

3. FreeRDP Server/Proxy Documentation - overview of sample server, shadow server, proxy server and server APIs.
   https://pub.freerdp.com/api/md_doc_2server_2Server.html

4. FreeRDP Peer API documentation - custom server with `freerdp_peer`, callbacks and settings.
   https://pub.freerdp.com/api/md_doc_2server_2Peer.html

5. FreeRDP Shadow Server documentation.
   https://pub.freerdp.com/api/md_doc_2server_2Shadow.html

6. FreeRDP Proxy Server documentation.
   https://pub.freerdp.com/api/md_doc_2server_2Proxy.html

7. FreeRDP Virtual Channels documentation.
   https://pub.freerdp.com/api/md_doc_2channels_2Channels.html

8. FreeRDP Codecs documentation.
   https://pub.freerdp.com/api/md_doc_2Codecs.html

9. FreeRDP Security documentation - RDP/TLS/NLA, CredSSP, Kerberos/GSSAPI.
   https://pub.freerdp.com/api/md_doc_2Security.html

10. FreeRDP Certificates documentation.
    https://pub.freerdp.com/api/md_doc_2Certificates.html

11. FreeRDP 3.26.0 release note, 2026-05-06.
    https://www.freerdp.com/2026/05/06/3_26_0-release

12. FreeRDP GitHub releases.
    https://github.com/FreeRDP/FreeRDP/releases

## Microsoft RDP / CredSSP / SPN

13. Microsoft Open Specifications - [MS-CSSP]: Credential Security Support Provider Protocol.
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/

14. Microsoft Open Specifications - CredSSP usage in RDP negotiation.
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/8a3a5c53-bd22-4e2e-9b1b-8eeefc9b043b

15. Microsoft Open Specifications - CredSSP relationship to TLS/SPNEGO/Kerberos/NTLM.
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/f381294e-1b7f-4771-864e-7a97fefd6e0e

16. Microsoft Learn - `setspn` command and examples including `TERMSRV`.
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/setspn

17. Microsoft Learn - Policy CSP / Credentials Delegation, Remote Desktop Session Host examples.
    https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-credentialdelegation

## PAM / SSSD / Kerberos

18. Linux man-pages - PAM application API.
    https://man7.org/linux/man-pages/man3/pam.3.html

19. Linux man-pages - `pam_authenticate`.
    https://man7.org/linux/man-pages/man3/pam_authenticate.3.html

20. Ubuntu Server documentation - SSSD with Active Directory.
    https://documentation.ubuntu.com/server/how-to/sssd/with-active-directory/

21. Ubuntu Server documentation - Introduction to SSSD.
    https://documentation.ubuntu.com/server/explanation/intro-to/sssd/

22. SSSD project documentation - migration from pam_krb5.
    https://sssd.io/docs/ad/ad-provider.html

23. Red Hat documentation - configuring SSSD domains, LDAP/Kerberos examples.
    https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/system-level_authentication_guide/configuring_domains

24. Red Hat documentation - restricting PAM services to selected SSSD domains.
    https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/restricting-domains-for-pam-services-using-sssd

25. Red Hat documentation - SSSD offline credentials caching.
    https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/deployment_guide/sssd-cache-cred

26. Red Hat documentation - directly integrating RHEL systems with AD using SSSD.
    https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/connecting-rhel-systems-directly-to-ad-using-sssd

27. SSSD man page - `sssd-ad`.
    https://www.mankier.com/5/sssd-ad

28. MIT Kerberos documentation - keytab definition.
    https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html

29. MIT Kerberos documentation - GSSAPI application server behavior.
    https://web.mit.edu/kerberos/krb5-latest/doc/appdev/gssapi.html

30. MIT Kerberos documentation - environment variables including `KRB5_KTNAME`.
    https://web.mit.edu/kerberos/krb5-latest/doc/user/user_config/kerberos.html

31. MIT Kerberos documentation - application servers and keytab protection.
    https://web.mit.edu/kerberos/krb5-latest/doc/admin/appl_servers.html

## xrdp

32. xrdp official website.
    https://www.xrdp.org/

33. xrdp GitHub repository.
    https://github.com/neutrinolabs/xrdp

34. xorgxrdp GitHub repository.
    https://github.com/neutrinolabs/xorgxrdp

35. xrdp v0.10 release notes - GFX/H.264, unprivileged daemon, security fixes.
    https://raw.githubusercontent.com/wiki/neutrinolabs/xrdp/NEWS-v0.10.md

36. xrdp GitHub issue #1083 - historical note on CredSSP/NLA support.
    https://github.com/neutrinolabs/xrdp/issues/1083

37. xrdp GitHub issue #2770 - NLA support request.
    https://github.com/neutrinolabs/xrdp/issues/2770

38. xrdp discussion #2604 - PAM additional prompt limitation discussion.
    https://github.com/neutrinolabs/xrdp/discussions/2604

## Important notes about sources

- FreeRDP server-side APIs evolve; before implementation, pin the exact FreeRDP version and verify headers/APIs on target distributions.
- Public xrdp GitHub issues are used as indicators of historical/practical NLA/CredSSP concerns, but migration decisions must verify the exact xrdp version available on the target operating system.
- PAM/SSSD behavior depends on the distribution and local PAM stack; configuration examples in these documents are templates, not universal ready-to-use policies.
- Kerberos/SPN/keytab operations must follow the rules of the specific AD/IdM environment.
