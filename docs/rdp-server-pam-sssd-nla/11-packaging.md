# 11. Packaging and distribution

This document provides guidance on building and distributing the FreeRDP-based RDP server as Debian and RPM packages. These instructions complement the packaging files in this tree and address the deliverables for phase 6.

## Debian packaging

The root `debian/` directory contains minimal preview packaging for the server-only `frdpd` runtime path. It builds the daemon, local helper tools, and the runtime libraries they need, installs the CMake `libraries` and `server` components, and intentionally disables unrelated client, sample, shadow, proxy, smart-card, Wayland, CUPS, and VAAPI targets during package configuration.

- Build depends list the toolchain and libraries required at build time, including debhelper compat 13, CMake/Ninja, PAM, Kerberos/GSSAPI, OpenSSL, systemd, JSON, FFmpeg codec libraries, Cairo, and the X11/XTest/XDamage/XRandR headers used by the server prototype.
- The resulting binary package declares runtime dependencies through `${shlibs:Depends}` / `${misc:Depends}` plus `libpam0g`, `sssd`, and `xvfb` for the PAM/SSSD session-agent prototype.
- Run `DEB_BUILD_OPTIONS='nocheck parallel=1' dpkg-buildpackage -uc -us -b -j1` from the project root for a local binary package smoke build. The serial build option avoids noisy local resource races while this preview package is still being hardened. `packaging/scripts/create_deb.sh -uc -us -b -j1` is a wrapper around the same root `debian/control` metadata.
- The local smoke build has been verified to produce `frdpd_0.1.0-1_amd64.deb` with the `frdpd`, `frdp-authd`, `frdp-sesmand`, `frdp-session-agent`, and `frdpctl` binaries, FreeRDP/WinPR shared libraries, `/etc/frdpd` configuration, `/etc/pam.d/frdpd`, service unit examples under `/lib/systemd/system`, and inactive SELinux/AppArmor examples under `/usr/share/frdpd/security`. The current CMake `server` component install emits baseline-hardened versions of those service unit examples, and the focused CTest suite verifies the generated units with `systemd-analyze` when it is available.
- This preview package currently installs its bundled FreeRDP/WinPR shared libraries into the public multiarch library directory. Production packaging must either split those libraries into policy-compliant packages or add appropriate conflict/replacement/private-libdir handling before coexisting with distro FreeRDP packages.
- Sign the resulting packages with the project’s GPG key and publish them to an APT repository.
- Remaining Debian work includes copyright metadata, maintainer script policy checks, systemd enablement policy, lintian/distro CI, package signing, upgrade/rollback tests, and validation of installed SELinux/AppArmor draft examples.

## RPM packaging

The `packaging/rpm/frdpd.spec` file is a starting point for building an RPM. It defines the package name, summary, license, build requirements and installation scripts. To build an RPM:

1. Create a source archive (`frdpd-0.1.0.tar.gz`) containing the project source tree.
2. Place the spec file in your `~/rpmbuild/SPECS` directory and the source archive in `~/rpmbuild/SOURCES`.
3. Run `rpmbuild -ba frdpd.spec` to produce binary and source RPMs.
4. Import the project’s RPM signing key and sign the packages using `rpm --addsign`.

The `%files` section installs the daemons (`frdpd`, `frdp-authd`, `frdp-sesmand`, `frdp-session-agent`), the administrative tool `frdpctl`, configuration files under `/etc/frdpd`, and documentation. `frdp-krb-authd` remains a build-only prototype until the Kerberos acceptor path is implemented.

## Reproducible builds and signing

To ensure supply-chain integrity and reproducibility:

- Pin compiler and toolchain versions in CI and use environment variables such as `SOURCE_DATE_EPOCH` for deterministic timestamps.
- Strip build paths from debug information (e.g. use `-ffile-prefix-map` with GCC/Clang).
- Sign binary packages using the project’s dedicated signing key. Provide the public key via the project’s web site or repository so that users can verify signatures.

## Repository structure

```
packaging/
  rpm/
    frdpd.spec   # RPM spec file
  selinux/
    frdpd.te     # SELinux policy (draft)
    frdpd.fc     # SELinux file contexts (draft)
  apparmor/
    frdpd        # AppArmor profile (draft)
debian/
  control        # Debian package metadata
  rules          # server-only CMake/Ninja package build
  changelog
  source/
```

Future work includes production Debian policy validation, RPM build verification, validated SELinux and AppArmor policies, and automated package builds in CI. The packaging guidelines above keep pilot and GA packaging work tied to executable package builds instead of draft-only metadata.
