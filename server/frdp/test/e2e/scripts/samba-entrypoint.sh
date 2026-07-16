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
deny_uac=

object_sid()
{
	local kind=$1
	local name=$2
	local sid

	sid=$(samba-tool "$kind" show "$name" --attributes=objectSid |
		sed -n 's/^objectSid: //p')
	[[ $sid =~ ^S-1-5-[0-9-]+$ ]] || {
		printf 'invalid SID for %s %s: %s\n' "$kind" "$name" "$sid" >&2
		return 1
	}
	printf '%s\n' "$sid"
}

provision_rdp_gpo()
{
	local allow_group_sid deny_user_sid domain_admins_sid
	local auth_file=/run/frdp-gpo-auth
	local create_output domain_dn gpo_dir gpo_guid policy_dir

	allow_group_sid=$(object_sid group "$test_group")
	deny_user_sid=$(object_sid user "$deny_user")
	domain_admins_sid=$(object_sid group "Domain Admins")
	domain_dn="DC=${realm//./,DC=}"
	install -m 0600 /dev/null "$auth_file"
	printf 'username = Administrator\npassword = %s\n' "$admin_password" >"$auth_file"
	create_output=$(samba-tool gpo create "FRDP Remote Desktop Access" \
		-H ldap://127.0.0.1 --authentication-file="$auth_file")
	gpo_guid=$(grep -o '{[0-9A-Fa-f-]\{36\}}' <<<"$create_output" | head -n 1)
	[[ $gpo_guid =~ ^\{[0-9A-F-]{36}\}$ ]] || {
		printf 'failed to obtain the FRDP GPO GUID from: %s\n' "$create_output" >&2
		return 1
	}

	gpo_dir="/var/lib/samba/sysvol/${realm,,}/Policies/$gpo_guid"
	policy_dir="$gpo_dir/Machine/Microsoft/Windows NT/SecEdit"
	install -d -m 0750 -o root -g users "$policy_dir"
	cat >"$policy_dir/GptTmpl.inf" <<EOF
[Unicode]
Unicode=yes
[Version]
signature="\$CHICAGO\$"
Revision=1
[Privilege Rights]
SeInteractiveLogonRight = *${allow_group_sid},*${domain_admins_sid}
SeRemoteInteractiveLogonRight = *${allow_group_sid},*${domain_admins_sid}
SeDenyInteractiveLogonRight = *${deny_user_sid}
SeDenyRemoteInteractiveLogonRight = *${deny_user_sid}
EOF
	chown root:users "$policy_dir/GptTmpl.inf"
	chmod 0640 "$policy_dir/GptTmpl.inf"
	printf '[General]\r\nVersion=1\r\n' >"$gpo_dir/GPT.INI"

	python3 - "$gpo_guid" "$domain_dn" "$auth_file" <<'PY'
import ldb
import sys

from samba.auth import system_session
from samba.credentials import Credentials
from samba.param import LoadParm
from samba.samdb import SamDB

guid, domain_dn, auth_file = sys.argv[1:]
with open(auth_file, encoding="utf-8") as stream:
    credentials = {}
    for line in stream:
        if "=" in line:
            key, value = line.split("=", 1)
            credentials[key.strip()] = value.strip()
lp = LoadParm()
lp.load_default()
creds = Credentials()
creds.guess(lp)
creds.set_username(credentials["username"])
creds.set_password(credentials["password"])
samdb = SamDB(
    url="ldap://127.0.0.1",
    session_info=system_session(),
    credentials=creds,
    lp=lp,
)
message = ldb.Message()
message.dn = ldb.Dn(samdb, f"CN={guid},CN=Policies,CN=System,{domain_dn}")
message["extensions"] = ldb.MessageElement(
    "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"
    "{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]",
    ldb.FLAG_MOD_REPLACE,
    "gPCMachineExtensionNames",
)
message["version"] = ldb.MessageElement(
    "1", ldb.FLAG_MOD_REPLACE, "versionNumber"
)
samdb.modify(message)
PY

	samba-tool gpo setlink "$domain_dn" "$gpo_guid" --enforce \
		-H ldap://127.0.0.1 --authentication-file="$auth_file"
	samba-tool gpo show "$gpo_guid" -H ldap://127.0.0.1 \
		--authentication-file="$auth_file" | grep -Fq \
		'Machine Exts : [{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
	rm -f "$auth_file"
	grep -Fq "SeRemoteInteractiveLogonRight = *${allow_group_sid},*${domain_admins_sid}" \
		"$policy_dir/GptTmpl.inf"
	printf 'Samba AD enforcing GPO %s allows %s and denies enabled user %s for frdpd\n' \
		"$gpo_guid" "$test_group" "$deny_user"
}

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
samba-tool user enable "$deny_user" >/dev/null
samba-tool user setexpiry "$deny_user" --noexpiry >/dev/null
deny_uac=$(samba-tool user show "$deny_user" --attributes=userAccountControl |
	sed -n 's/^userAccountControl: //p')
if [[ ! $deny_uac =~ ^[0-9]+$ ]] || ((deny_uac & 2)); then
	printf 'Samba AD GPO deny account %s is not enabled (UAC=%s)\n' \
		"$deny_user" "$deny_uac" >&2
	exit 1
fi

samba -i --debug-stdout --no-process-group &
samba_pid=$!
# shellcheck disable=SC2317 # Called indirectly by the signal/exit trap.
stop_samba()
{
	rm -f /run/frdp-gpo-auth
	kill -TERM "$samba_pid" 2>/dev/null || true
	wait "$samba_pid" 2>/dev/null || true
}
trap stop_samba EXIT TERM INT
for _ in $(seq 1 120); do
	if smbclient -L //127.0.0.1 -U "Administrator%$admin_password" -m SMB3 \
		>/dev/null 2>&1; then
		break
	fi
	kill -0 "$samba_pid"
	sleep 1
done
kill -0 "$samba_pid"
smbclient -L //127.0.0.1 -U "Administrator%$admin_password" -m SMB3 >/dev/null
provision_rdp_gpo
: >/run/frdp-gpo-ready
set +e
wait "$samba_pid"
status=$?
set -e
trap - EXIT TERM INT
exit "$status"
