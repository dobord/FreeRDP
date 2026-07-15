#!/usr/bin/env bash
set -Eeuo pipefail

marker=/data/frdp-e2e-seeded
lock=/data/frdp-e2e-seed.lock
admin_password=${PASSWORD:?PASSWORD is required by the FreeIPA container}
user=${FRDP_TEST_USER:-rdpuser}
password=${FRDP_TEST_PASSWORD:-RdpPassw0rd!}
deny_user=${FRDP_DENY_USER:-rdpdisabled}
deny_password=${FRDP_DENY_PASSWORD:-DeniedPassw0rd!}
host=${FRDP_FREEIPA_HOST:-frdpd.ipa.test}
enroll_password=${FRDP_FREEIPA_ENROLL_PASSWORD:-IpaEnrollPassw0rd!}

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
ipa user-enable "$deny_user" >/dev/null 2>&1 || true
ipa user-mod "$deny_user" --setattr=krbPasswordExpiration=20380101000000Z >/dev/null

if ipa host-show "$host" >/dev/null 2>&1; then
	ipa host-del "$host" >/dev/null
fi
ipa host-add "$host" --force --password="$enroll_password" >/dev/null

ipa hbacsvc-show frdpd >/dev/null 2>&1 || \
	ipa hbacsvc-add frdpd --desc='FreeRDP E2E PAM service' >/dev/null
ipa hbacrule-show frdpd-allow >/dev/null 2>&1 || \
	ipa hbacrule-add frdpd-allow --desc='Allow RDP only for the E2E account' >/dev/null
ipa hbacrule-add-user frdpd-allow --users="$user" >/dev/null 2>&1 || true
ipa hbacrule-add-host frdpd-allow --hosts="$host" >/dev/null 2>&1 || true
ipa hbacrule-add-service frdpd-allow --hbacsvcs=frdpd >/dev/null 2>&1 || true
ipa hbacrule-enable frdpd-allow >/dev/null 2>&1 || true
ipa hbacrule-disable allow_all >/dev/null

kdestroy || true
touch "$marker"
