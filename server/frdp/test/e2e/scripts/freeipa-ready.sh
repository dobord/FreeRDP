#!/usr/bin/env bash
set -Eeuo pipefail

marker=/data/frdp-e2e-seeded
lock=/data/frdp-e2e-seed.lock
admin_password=${PASSWORD:?PASSWORD is required by the FreeIPA container}
user=${FRDP_TEST_USER:-rdpuser}
password=${FRDP_TEST_PASSWORD:-RdpPassw0rd!}
deny_user=${FRDP_DENY_USER:-rdpdisabled}
deny_password=${FRDP_DENY_PASSWORD:-DeniedPassw0rd!}

ipactl status >/dev/null 2>&1 || exit 1
[[ -f $marker ]] && exit 0

if ! mkdir "$lock" 2>/dev/null; then
	exit 1
fi
trap 'rmdir "$lock" 2>/dev/null || true' EXIT

[[ -f $marker ]] && exit 0

printf '%s\n' "$admin_password" | kinit admin >/dev/null

if ! ipa user-show "$user" >/dev/null 2>&1; then
	ipa user-add "$user" --first=RDP --last=User --shell=/bin/bash >/dev/null
fi
printf '%s\n%s\n' "$password" "$password" | ipa passwd "$user" >/dev/null
ipa user-enable "$user" >/dev/null 2>&1 || true
# Passwords assigned by an administrator are initially expired. The isolated
# E2E principal must be immediately usable by a non-interactive CredSSP flow.
ipa user-mod "$user" --setattr=krbPasswordExpiration=20380101000000Z >/dev/null

if ! ipa user-show "$deny_user" >/dev/null 2>&1; then
	ipa user-add "$deny_user" --first=Denied --last=User --shell=/bin/bash >/dev/null
fi
printf '%s\n%s\n' "$deny_password" "$deny_password" | ipa passwd "$deny_user" >/dev/null
ipa user-disable "$deny_user" >/dev/null

# Register the PAM service name even though the default allow_all HBAC rule is
# intentionally retained for this authentication/lifecycle baseline profile.
ipa hbacsvc-show frdpd >/dev/null 2>&1 || \
	ipa hbacsvc-add frdpd --desc='FreeRDP E2E PAM service' >/dev/null

kdestroy || true
touch "$marker"
