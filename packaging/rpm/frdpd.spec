Name: frdpd
Version: 0.1.0
Release: 1%{?dist}
Summary: FreeRDP PAM/SSSD/NLA RDP server
License: BSD
URL: https://example.com/frdpd
Source0: %{name}-%{version}.tar.gz

# Build requirements
BuildRequires: cmake, gcc, pam-devel, krb5-devel, openssl-devel, systemd-devel
BuildRequires: libX11-devel, libXv-devel, sssd-client, libuuid-devel

# Runtime dependencies
Requires: pam, sssd

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
%cmake -DWITH_FRDPD=ON -DWITH_SERVER=ON -DWITH_SAMPLE=OFF -DWITH_SHADOW=OFF -DWITH_PROXY=OFF .
%cmake_build

%install
# Install built binaries and configuration
%cmake_install

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
%config(noreplace) %{_sysconfdir}/pam.d/frdpd

%changelog
* Mon Jun 15 2026 Example Maintainer <maintainer@example.com> - 0.1.0-1
- Initial RPM package
