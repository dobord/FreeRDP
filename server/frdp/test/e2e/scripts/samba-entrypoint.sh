#!/usr/bin/env bash
set -Eeuo pipefail

realm=${FRDP_AD_REALM:-AD.TEST}
domain=${FRDP_AD_NETBIOS_DOMAIN:-AD}
admin_password=${FRDP_AD_ADMIN_PASSWORD:?FRDP_AD_ADMIN_PASSWORD is required}
user=${FRDP_TEST_USER:-rdpuser}
password=${FRDP_TEST_PASSWORD:-RdpPassw0rd!}
deny_user=${FRDP_DENY_USER:-rdpdisabled}
deny_password=${FRDP_DENY_PASSWORD:-DeniedPassw0rd!}
test_group=${FRDP_TEST_GROUP:-rdp-users}

if [[ ! -s /var/lib/samba/private/sam.ldb ]]; then
	rm -f /etc/samba/smb.conf
	samba-tool domain provision \
		--server-role=dc \
		--realm="$realm" \
		--domain="$domain" \
		--dns-backend=SAMBA_INTERNAL \
		--adminpass="$admin_password" \
		--use-rfc2307 \
		--option='interfaces = lo eth0' \
		--option='bind interfaces only = yes'
fi

install -m 0644 /var/lib/samba/private/krb5.conf /etc/krb5.conf
samba-tool domain passwordsettings set --min-pwd-age=0 >/dev/null
samba-tool domain passwordsettings set --max-pwd-age=0 >/dev/null

if samba-tool user show "$user" >/dev/null 2>&1; then
	samba-tool user setpassword "$user" --newpassword="$password" >/dev/null
else
	samba-tool user add "$user" "$password" >/dev/null
fi
samba-tool user enable "$user" >/dev/null 2>&1 || true
samba-tool user setexpiry "$user" --noexpiry >/dev/null

if ! samba-tool group show "$test_group" >/dev/null 2>&1; then
	samba-tool group add "$test_group" >/dev/null
fi
if ! samba-tool group listmembers "$test_group" | grep -Fxq -- "$user"; then
	samba-tool group addmembers "$test_group" "$user" >/dev/null
fi

if samba-tool user show "$deny_user" >/dev/null 2>&1; then
	samba-tool user setpassword "$deny_user" --newpassword="$deny_password" >/dev/null
else
	samba-tool user add "$deny_user" "$deny_password" >/dev/null
fi
samba-tool user disable "$deny_user" >/dev/null
samba-tool user setexpiry "$deny_user" --noexpiry >/dev/null

exec samba -i --debug-stdout --no-process-group
