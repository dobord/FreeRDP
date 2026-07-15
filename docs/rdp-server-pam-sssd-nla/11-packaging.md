# 11. Packaging and distribution

This document provides guidance on building and distributing the FreeRDP-based RDP server as Debian and RPM packages. These instructions complement the packaging files in this tree and address the deliverables for phase 6.

## Debian packaging

The root `debian/` directory contains minimal preview packaging for the server-only `frdpd` runtime path. It builds the daemon, local helper tools, and the runtime libraries they need, installs the CMake `libraries` and `server` components, and intentionally disables unrelated client, sample, shadow, proxy, smart-card, Wayland, CUPS, and VAAPI targets during package configuration.

- Build depends list the toolchain and libraries required at build time, including debhelper compat 13, CMake/Ninja, PAM, Kerberos/GSSAPI, OpenSSL, systemd, JSON, ICU, and the X11/XTest/XDamage/XRandR headers used by the server prototype. Unrelated FFmpeg, Cairo, URI-parser, JPEG/PNG image conversion, client, multimedia, smart-card, and device-redirection features are disabled by the package build policy.
- The resulting binary package declares runtime dependencies through `${shlibs:Depends}` / `${misc:Depends}` plus `libpam0g`, `sssd`, and `xvfb` for the PAM/SSSD session-agent prototype.
- Run `SOURCE_DATE_EPOCH=<commit-time> DEB_BUILD_OPTIONS='nocheck parallel=1' dpkg-buildpackage -uc -us -b -j1` from the project root for a local binary package smoke build. The serial build option avoids noisy local resource races while this preview package is still being hardened. `packaging/scripts/create_deb.sh -uc -us -b -j1` is a wrapper around the same root `debian/control` metadata.
- A clean Ubuntu 24.04 build using only the declared build dependencies produces `frdpd_0.1.0-1_amd64.deb` with the `frdpd`, `frdp-authd`, `frdp-sesmand`, `frdp-session-agent`, `frdpctl`, and default-on NTLM `winpr-hash` binaries, configuration, PAM service, systemd units, monitoring examples, and inactive MAC policy examples. Its exact FreeRDP/WinPR libraries are ABI-private under `/usr/lib/x86_64-linux-gnu/frdpd`; `dh_makeshlibs` excludes that directory, so the package emits no public `shlibs` file or `ldconfig` trigger. A second clean Ubuntu 24.04 container passed APT installation, `dpkg -V`, private-library linkage checks over all six binaries, installed `winpr-hash` provisioning, and package purge through the generated maintainer scripts.
- The binary package carries scoped DEP-5 metadata for the Apache-2.0 runtime sources plus the BSD, Boost, Expat, HPND, Zlib, and public-domain exceptions in its build closure. This does not replace a complete source-package copyright audit. The clean builder runs pedantic `lintian`, writes the complete report directly into the retained artifact directory even when the policy check fails, and rejects error-level violations.
- The FRDP workflow repeats the dependency-resolved build, checks package metadata and the private multiarch layout, installs the package in a clean target container, and uploads the `.deb`, control archive, lintian report, and manifests. Successful CI history still needs to accumulate.
- Sign the resulting packages with the project’s GPG key and publish them to an APT repository.
- Remaining Debian work includes a complete source-package copyright audit, resolving or formally reviewing non-error lintian findings, systemd enablement policy, package signing, upgrade/rollback tests, PAM/SSSD real-login validation against the installed package, and validation of installed SELinux/AppArmor draft examples.

## RPM packaging

The `packaging/rpm/frdpd.spec` file is a starting point for building a server-only RPM. It defines the package name, summary, license, build requirements and installation scripts, builds only the FRDP server/helper targets, and installs the CMake `server` component. To build an RPM:

1. Create a source archive (`frdpd-0.1.0.tar.gz`) containing the project source tree.
2. Place the spec file in your `~/rpmbuild/SPECS` directory and the source archive in `~/rpmbuild/SOURCES`.
3. Run `rpmbuild -ba frdpd.spec` to produce binary and source RPMs.
4. Import the project’s RPM signing key and sign the packages using `rpm --addsign`.

The `%files` section installs the daemons (`frdpd`, `frdp-authd`, `frdp-sesmand`, `frdp-session-agent`), the administrative tool `frdpctl`, the default-on NTLM provisioning tool `winpr-hash`, configuration files under `/etc/frdpd`, and documentation. `frdp-krb-authd` remains a build-only prototype until the Kerberos acceptor path is implemented.

A clean Fedora 42 container build was verified with `dnf builddep` followed by
`rpmbuild -ba`, using only the dependencies and feature policy declared by the
spec. The resulting source, binary, debuginfo, and debugsource RPMs were
created with distro-provided macros. The binary RPM carries its exact in-tree
FreeRDP/WinPR libraries in a private `/usr/lib64/frdpd` directory. Installing
it through DNF in a separate clean Fedora 42 container resolved the remaining
system dependencies; `rpm -V` and private-library `ldd` checks over all six
packaged binaries passed.
The FRDP workflow now performs the same dependency-checked build, package
install, manifest and linkage checks and uploads the resulting RPM artifacts.
Successful target-distro CI history and additional RPM distro coverage still
need to accumulate.

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

- The Fedora dependency-checked RPM job still needs successful CI history and
  coverage on any additional target RPM distributions.
- A complete source-package copyright audit, non-error lintian findings,
  service enablement policy, and upgrade/rollback validation remain open.
- Installed package validation does not yet prove PAM login, AD/SSSD policy,
  real-client sessions, upgrade/rollback, or enforcing SELinux/AppArmor mode.
- Successful Debian and Fedora package-job history still needs to accumulate,
  and the current private-library approach still needs multi-architecture and
  upgrade compatibility evidence.

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
  monitoring/
    frdpd-node-exporter-textfile.sh
    frdpd-prometheus-alerts.yml
    frdpd-grafana-dashboard.json
debian/
  control        # Debian package metadata
  rules          # server-only CMake/Ninja package build
  changelog
  source/
```

Future work includes production Debian policy validation, accumulated and
broader target-distro RPM CI evidence, production-reviewed enforcing SELinux
and AppArmor policies, signing, and repository publication. The packaging
guidelines above keep pilot and GA packaging work tied to executable package
builds instead of draft-only metadata.
