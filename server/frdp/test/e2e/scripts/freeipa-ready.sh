#!/usr/bin/env bash
set -Eeuo pipefail

data_dir=${FRDP_E2E_DATA_DIR:-/data}
marker=$data_dir/frdp-e2e-seeded
lock=$data_dir/frdp-e2e-seed.lock
keytab_dir=${FRDP_E2E_KEYTAB_DIR:-/frdp-e2e-keytab}
admin_password=${PASSWORD:?PASSWORD is required by the FreeIPA container}
user=${FRDP_TEST_USER:-rdpuser}
password=${FRDP_TEST_PASSWORD:-RdpPassw0rd!}
deny_user=${FRDP_DENY_USER:-rdpdisabled}
deny_password=${FRDP_DENY_PASSWORD:-DeniedPassw0rd!}
host=${FRDP_FREEIPA_HOST:-frdpd.ipa.test}
realm=${FRDP_FREEIPA_REALM:-IPA.TEST}
enroll_password=${FRDP_FREEIPA_ENROLL_PASSWORD:-IpaEnrollPassw0rd!}

ipactl status >/dev/null 2>&1 || exit 1
command -v flock >/dev/null 2>&1 || exit 1

seed_directory()
(
	[[ -f $marker ]] && return 0
	exec 8>"$lock"
	flock -n 8 || return 1
	[[ -f $marker ]] && return 0

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
)

rotate_host_keytab()
(
	local expected_principal="host/$host@$realm"
	local new_keytab="$keytab_dir/freeipa-keytab.next"
	local new_kvno=
	local old_kvno=
	local principal=
	local request="$keytab_dir/keytab-rollover-request"
	local temporary="$keytab_dir/.freeipa-keytab.$$"
	local metadata="$keytab_dir/.keytab-rollover-ready.$$"
	local in_progress="$keytab_dir/keytab-rollover-in-progress"
	local status=0

	[[ -f $request ]] || return 0
	[[ ! -f $keytab_dir/keytab-rollover-ready ]] || return 0
	[[ ! -f $keytab_dir/keytab-rollover-failed ]] || return 1
	exec 9>"$keytab_dir/keytab-rollover.lock"
	flock -n 9 || return 0
	if [[ -f $in_progress ]]; then
		: >"$keytab_dir/keytab-rollover-failed"
		return 1
	fi
	: >"$in_progress"
	trap 'status=$?; rm -f "$temporary" "$metadata"; kdestroy >/dev/null 2>&1 || true; if ((status != 0)) && [[ ! -f $keytab_dir/keytab-rollover-ready ]]; then : >"$keytab_dir/keytab-rollover-failed"; fi; exit "$status"' EXIT

	principal=$(sed -n 's/^principal=//p' "$request")
	old_kvno=$(sed -n 's/^old_kvno=//p' "$request")
	if [[ $principal != "$expected_principal" || ! $old_kvno =~ ^[1-9][0-9]*$ ]] ||
		! printf '%s\n' "$admin_password" | kinit admin >/dev/null ||
		! ipa-getkeytab -p "$principal" -k "$temporary" >/dev/null 2>&1; then
		: >"$keytab_dir/keytab-rollover-failed"
		return 1
	fi
	chmod 0600 "$temporary"
	new_kvno=$(klist -k "$temporary" | awk -v principal="$principal" \
		'$1 ~ /^[0-9]+$/ && $2 == principal { if ($1 > max) max = $1; found = 1 }
		 END { if (found) print max; else exit 1 }') || true
	if [[ ! $new_kvno =~ ^[1-9][0-9]*$ ]] || ((new_kvno <= old_kvno)); then
		: >"$keytab_dir/keytab-rollover-failed"
		return 1
	fi
	mv -f "$temporary" "$new_keytab"
	printf 'principal=%s\nold_kvno=%s\nnew_kvno=%s\n' \
		"$principal" "$old_kvno" "$new_kvno" >"$metadata"
	mv -f "$metadata" "$keytab_dir/keytab-rollover-ready"
	rm -f "$in_progress"
)

seed_directory
rotate_host_keytab
