Name: frdpd
Version: 0.1.0
Release: 1%{?dist}
Summary: FreeRDP PAM/SSSD/NLA RDP server
License: BSD
URL: https://example.com/frdpd
Source0: %{name}-%{version}.tar.gz

# Keep bundled ABI-private libraries out of the global RPM dependency namespace.
%global __provides_exclude_from ^%{_libdir}/frdpd/.*$
%global __requires_exclude ^(libfreerdp3|libfreerdp-server3|libwinpr3|libwinpr-tools3)[.]so[.]3.*$

# Build requirements
BuildRequires: cmake, gcc, pam-devel, krb5-devel, openssl-devel, systemd-devel
BuildRequires: pkgconf-pkg-config, zlib-devel, cjson-devel, libicu-devel
BuildRequires: libjpeg-turbo-devel, libpng-devel
BuildRequires: libX11-devel, libXv-devel, libXtst-devel, libXdamage-devel, libXrandr-devel, sssd-client, libuuid-devel, systemd-rpm-macros

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
%cmake \
    -DWITH_FRDPD=ON \
    -DWITH_SERVER=ON \
    -DWITH_CLIENT=OFF \
    -DWITH_CLIENT_COMMON=OFF \
    -DWITH_CLIENT_CHANNELS=OFF \
    -DWITH_CLIENT_SDL=OFF \
    -DWITH_SAMPLE=OFF \
    -DWITH_SHADOW=OFF \
    -DWITH_PROXY=OFF \
    -DWITH_MANPAGES=OFF \
    -DWITH_WAYLAND=OFF \
    -DWITH_SDL=OFF \
    -DWITH_PULSE=OFF \
    -DWITH_ALSA=OFF \
    -DWITH_CUPS=OFF \
    -DWITH_PCSC=OFF \
    -DWITH_PKCS11=OFF \
    -DWITH_SMARTCARD_EMULATE=OFF \
    -DWITH_SMARTCARD_PCSC=OFF \
    -DWITH_VAAPI_H264_ENCODING=OFF \
    -DWITH_FFMPEG=OFF \
    -DWITH_SWSCALE=OFF \
    -DWITH_FUSE=OFF \
    -DWITH_OPENCL=OFF \
    -DCHANNEL_URBDRC=OFF \
    -DCMAKE_INSTALL_SYSCONFDIR=%{_sysconfdir} \
    -DCMAKE_INSTALL_LIBDIR=%{_lib}/frdpd \
    -DFRDP_SYSTEMD_SYSTEM_UNIT_DIR=%{_unitdir} \
    .
%cmake_build --target winpr-tools winpr-hash frdpd frdp-authd frdp-sesmand frdp-session-agent frdpctl

%install
# Install built binaries and configuration
%cmake_install --component libraries
%cmake_install --component server

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
/usr/bin/winpr-hash
%dir %{_libdir}/frdpd
%{_libdir}/frdpd/lib*.so*
%dir %{_sysconfdir}/frdpd
%config(noreplace) %{_sysconfdir}/frdpd/frdpd.toml
%config(noreplace) %{_sysconfdir}/frdpd/frdpd.env
%config(noreplace) %{_sysconfdir}/pam.d/frdpd
%{_unitdir}/frdpd.service
%{_unitdir}/frdp-authd.service
%{_unitdir}/frdp-sesmand.service
%{_tmpfilesdir}/frdpd.conf
%dir %{_datadir}/frdpd
%dir %{_datadir}/frdpd/security
%dir %{_datadir}/frdpd/security/selinux
%dir %{_datadir}/frdpd/security/apparmor
%{_datadir}/frdpd/security/selinux/frdpd.te
%{_datadir}/frdpd/security/selinux/frdpd.fc
%{_datadir}/frdpd/security/apparmor/frdpd
%dir %{_datadir}/frdpd/monitoring
%{_datadir}/frdpd/monitoring/frdpd-node-exporter-textfile.sh
%{_datadir}/frdpd/monitoring/frdpd-prometheus-alerts.yml
%{_datadir}/frdpd/monitoring/frdpd-grafana-dashboard.json

%changelog
* Mon Jun 15 2026 Example Maintainer <maintainer@example.com> - 0.1.0-1
- Initial RPM package
