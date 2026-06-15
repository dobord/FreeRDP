Name: frdpd
Version: 0.1.0
Release: 1%{?dist}
Summary: FreeRDP PAM/SSSD/NLA RDP server
License: BSD
URL: https://example.com/frdpd
Source0: %{name}-%{version}.tar.gz

# Build requirements
BuildRequires: cmake, gcc, pam-devel, krb5-devel, openssl-devel, systemd-devel
BuildRequires: libX11-devel, libXv-devel, libXtst-devel, sssd-client, libuuid-devel, systemd-rpm-macros

# Runtime dependencies
Requires: pam, sssd, xorg-x11-server-Xvfb
%{?systemd_requires}

%description
frdpd provides an RDP server based on the FreeRDP library.  It supports
Network Level Authentication (CredSSP) using PAM/SSSD.  frdpd includes a
listener daemon, an authentication broker, a session manager, per-user session
agents, and administrative helper tools.  Kerberos-first authentication remains
a non-installed prototype in the current package.

%prep
%setup -q

%build
# Configure and build using CMake
%cmake -DWITH_FRDPD=ON -DWITH_SERVER=ON -DWITH_SAMPLE=OFF -DWITH_SHADOW=OFF -DWITH_PROXY=OFF -DFRDP_SYSTEMD_SYSTEM_UNIT_DIR=%{_unitdir} .
%cmake_build

%install
# Install built binaries and configuration
%cmake_install

%post
%systemd_post frdpd.service frdp-authd.service frdp-sesmand.service

%preun
%systemd_preun frdpd.service frdp-authd.service frdp-sesmand.service

%postun
%systemd_postun_with_restart frdpd.service frdp-authd.service frdp-sesmand.service

%files
%license LICENSE
%doc docs/rdp-server-pam-sssd-nla
/usr/bin/frdpd
/usr/bin/frdp-authd
/usr/bin/frdp-sesmand
/usr/bin/frdp-session-agent
/usr/bin/frdpctl
%dir %{_sysconfdir}/frdpd
%config(noreplace) %{_sysconfdir}/frdpd/frdpd.toml
%config(noreplace) %{_sysconfdir}/frdpd/frdpd.env
%config(noreplace) %{_sysconfdir}/pam.d/frdpd
%{_unitdir}/frdpd.service
%{_unitdir}/frdp-authd.service
%{_unitdir}/frdp-sesmand.service
%dir %{_datadir}/frdpd
%dir %{_datadir}/frdpd/security
%dir %{_datadir}/frdpd/security/selinux
%dir %{_datadir}/frdpd/security/apparmor
%{_datadir}/frdpd/security/selinux/frdpd.te
%{_datadir}/frdpd/security/apparmor/frdpd

%changelog
* Mon Jun 15 2026 Example Maintainer <maintainer@example.com> - 0.1.0-1
- Initial RPM package
