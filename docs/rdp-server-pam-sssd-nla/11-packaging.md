# 11. Packaging and distribution

This document provides guidance on building and distributing the FreeRDP-based RDP server as Debian and RPM packages. These instructions complement the packaging files in this tree and address the deliverables for phase 6.

## Debian packaging

The root `debian/` directory contains minimal preview packaging for the server-only `frdpd` runtime path. It builds the daemon, local helper tools, and the runtime libraries they need, installs the CMake `libraries` and `server` components, and intentionally disables unrelated client, sample, shadow, proxy, smart-card, Wayland, CUPS, and VAAPI targets during package configuration.

- Build depends list the toolchain and libraries required at build time, including debhelper compat 13, CMake/Ninja, PAM, Kerberos/GSSAPI, OpenSSL, systemd, JSON, FFmpeg codec libraries, Cairo, and the X11/XTest/XDamage/XRandR headers used by the server prototype.
- The resulting binary package declares runtime dependencies through `${shlibs:Depends}` / `${misc:Depends}` plus `libpam0g`, `sssd`, and `xvfb` for the PAM/SSSD session-agent prototype.
- Run `SOURCE_DATE_EPOCH=<commit-time> DEB_BUILD_OPTIONS='nocheck parallel=1' dpkg-buildpackage -uc -us -b -j1` from the project root for a local binary package smoke build. The serial build option avoids noisy local resource races while this preview package is still being hardened. `packaging/scripts/create_deb.sh -uc -us -b -j1` is a wrapper around the same root `debian/control` metadata.
- The local smoke build has been verified to produce `frdpd_0.1.0-1_amd64.deb` with the `frdpd`, `frdp-authd`, `frdp-sesmand`, `frdp-session-agent`, and `frdpctl` binaries, FreeRDP/WinPR shared libraries, `/etc/frdpd` configuration, `/etc/pam.d/frdpd`, service unit examples under `/lib/systemd/system`, and inactive SELinux/AppArmor examples under `/usr/share/frdpd/security`. The current CMake `server` component install emits baseline-hardened versions of those service unit examples, and the focused CTest suite verifies the generated units with `systemd-analyze`, the tmpfiles rule with `systemd-tmpfiles`, SELinux draft packaging with `checkmodule`/`semodule_package`, and AppArmor parsing with `apparmor_parser` when those tools are available.
- This preview package currently installs its bundled FreeRDP/WinPR shared libraries into the public multiarch library directory. Production packaging must either split those libraries into policy-compliant packages or add appropriate conflict/replacement/private-libdir handling before coexisting with distro FreeRDP packages.
- Sign the resulting packages with the project’s GPG key and publish them to an APT repository.
- Remaining Debian work includes copyright metadata, maintainer script policy checks, systemd enablement policy, lintian/distro CI, package signing, upgrade/rollback tests, and validation of installed SELinux/AppArmor draft examples.

## RPM packaging

The `packaging/rpm/frdpd.spec` file is a starting point for building a server-only RPM. It defines the package name, summary, license, build requirements and installation scripts, builds only the FRDP server/helper targets, and installs the CMake `server` component. To build an RPM:

1. Create a source archive (`frdpd-0.1.0.tar.gz`) containing the project source tree.
2. Place the spec file in your `~/rpmbuild/SPECS` directory and the source archive in `~/rpmbuild/SOURCES`.
3. Run `rpmbuild -ba frdpd.spec` to produce binary and source RPMs.
4. Import the project’s RPM signing key and sign the packages using `rpm --addsign`.

The `%files` section installs the daemons (`frdpd`, `frdp-authd`, `frdp-sesmand`, `frdp-session-agent`), the administrative tool `frdpctl`, configuration files under `/etc/frdpd`, and documentation. `frdp-krb-authd` remains a build-only prototype until the Kerberos acceptor path is implemented.

A local Ubuntu smoke build was verified with `rpmbuild -bb --nodeps` plus a temporary macro overlay for Fedora-style `%cmake`, `%cmake_build`, `%cmake_install`, `%_unitdir`, `%_tmpfilesdir`, and systemd scriptlet macros. That smoke produced `frdpd-0.1.0-1.x86_64.rpm` containing the FRDP daemons/helpers, `/etc/frdpd`, `/etc/pam.d/frdpd`, systemd units, the tmpfiles rule, monitoring examples, and inactive SELinux/AppArmor examples. Target RPM distro CI still needs to run with real BuildRequires resolution and distro-provided macros.

## Reproducible builds and signing

The preview package is not yet a release artifact, but release builds should
already use a repeatable contract:

- Build from a signed Git tag or an immutable commit id. Record the commit,
  package version, builder image digest, compiler versions, CMake version,
  Ninja version, dependency repository snapshots, and enabled CMake flags.
- Set `SOURCE_DATE_EPOCH` to the signed tag time or the commit time used for the
  source archive. FreeRDP's CMake date helper consumes this value, and Debian
  tooling uses it for deterministic archive metadata.
- Keep CMake `WITH_REPRODUCIBLE_BUILD_FLAGS=ON` for package builds so
  `-fdebug-prefix-map`, `-fmacro-prefix-map`, and `-ffile-prefix-map` normalize
  source and build directory paths. The Debian preview package also uses
  `dpkg-buildflags` hardening flags and disables LTO for predictable local smoke
  builds.
- Use a sanitized build environment: fixed locale (`LC_ALL=C.UTF-8`), fixed
  timezone (`TZ=UTC`), no writable network dependency during the build step, and
  no untracked source-tree files included in generated source archives.
- Produce unsigned artifacts first with `dpkg-buildpackage -uc -us -b` or
  `rpmbuild -ba`, then sign only after package validation succeeds.
- Sign Debian `.changes` / `.buildinfo` / `.deb` artifacts with the project
  release key (`debsign` or repository-signing tooling). Sign RPM artifacts with
  the RPM release key (`rpm --addsign`) after importing the key into the builder
  macro configuration.
- Publish the public signing keys, fingerprints, revocation plan, package
  checksums, `.buildinfo` files, and source archive checksums beside the package
  repository metadata.

Minimum release validation before signing:

1. Run two clean builds from the same source in separate build directories or
   builder containers with identical `SOURCE_DATE_EPOCH`.
2. Compare package file lists, maintainer scripts, unit files, PAM files,
   security draft files, ELF dependency metadata, and checksums. Use
   `diffoscope` when byte-for-byte output differs.
3. Install the unsigned package into a fresh target image and verify ownership
   and permissions for `/etc/frdpd`, `/etc/pam.d/frdpd`, helper binaries,
   systemd units, runtime directories, and inactive MAC policy examples.
4. Run the focused FRDP CTest set or the component container profile against
   the installed binaries.
5. Sign only the artifacts that passed the install and component checks.

Open reproducibility gaps:

- RPM builds still need dependency-checked CI verification on target distros with distro macros available.
- Debian maintainer scripts, copyright metadata, and lintian policy checks are
  still incomplete.
- Installed package validation does not yet prove PAM login, AD/SSSD policy,
  real-client sessions, upgrade/rollback, or enforcing SELinux/AppArmor mode.
- The preview package bundles FreeRDP/WinPR shared libraries in the public
  library directory; production packaging needs a policy-compliant library split
  or private-libdir/conflict handling.

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

Future work includes production Debian policy validation, dependency-checked RPM CI, production-reviewed enforcing SELinux and AppArmor policies, and automated package builds in CI. The packaging guidelines above keep pilot and GA packaging work tied to executable package builds instead of draft-only metadata.
