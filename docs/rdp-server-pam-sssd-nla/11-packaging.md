# 11. Packaging and distribution

This document provides guidance on building and distributing the FreeRDP‑based RDP server as Debian and RPM packages. These instructions complement the packaging stubs under `packaging/` and address the deliverables for phase 6.

## Debian packaging

The `packaging/debian` directory contains a sample `control` file and can be extended with the rest of the Debian packaging infrastructure (`rules`, `copyright`, `changelog`, etc.). Key points:

- Build depends list the toolchain and libraries required at build time (debhelper, cmake, GCC, PAM, GSSAPI and OpenSSL headers).
- The resulting binary package declares dependencies on `pam` and `sssd` so that authentication back ends are present.
- Use `dpkg-buildpackage -uc -us` from the project root to build a `.deb` after the remaining packaging files are added.
- Sign the resulting packages with the project’s GPG key and publish them to an APT repository.

## RPM packaging

The `packaging/rpm/frdpd.spec` file is a starting point for building an RPM. It defines the package name, summary, license, build requirements and installation scripts. To build an RPM:

1. Create a source archive (`frdpd-0.1.0.tar.gz`) containing the project source tree.
2. Place the spec file in your `~/rpmbuild/SPECS` directory and the source archive in `~/rpmbuild/SOURCES`.
3. Run `rpmbuild -ba frdpd.spec` to produce binary and source RPMs.
4. Import the project’s RPM signing key and sign the packages using `rpm --addsign`.

The `%files` section installs the daemons (`frdpd`, `frdp-authd`, `frdp-sesmand`, `frdp-session-agent`, `frdp-krb-authd`), the administrative tool `frdpctl`, configuration files under `/etc/frdpd`, and documentation.

## Reproducible builds and signing

To ensure supply‑chain integrity and reproducibility:

- Pin compiler and toolchain versions in CI and use environment variables such as `SOURCE_DATE_EPOCH` for deterministic timestamps.
- Strip build paths from debug information (e.g. use `-ffile-prefix-map` with GCC/Clang).
- Sign binary packages using the project’s dedicated signing key. Provide the public key via the project’s web site or repository so that users can verify signatures.

## Repository structure

```
packaging/
  debian/
    control      # Debian package metadata
    …            # other debhelper files (rules, changelog, copyright)
  rpm/
    frdpd.spec   # RPM spec file
  selinux/
    frdpd.te     # SELinux policy (draft)
    frdpd.fc     # SELinux file contexts (draft)
  apparmor/
    frdpd        # AppArmor profile (draft)
```

Future work includes completing the Debian `rules` file, providing SELinux and AppArmor policies, and automating package builds in CI. The packaging guidelines above ensure that pilot and GA users can install and manage the RDP server on supported distributions.
