#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

FRDP_IDENTITY_PROVIDER=${FRDP_IDENTITY_PROVIDER:-local}
FRDP_TEST_USER=${FRDP_TEST_USER:-rdpuser}
FRDP_TEST_PASSWORD=${FRDP_TEST_PASSWORD:-RdpPassw0rd!}
FRDP_DENY_USER=${FRDP_DENY_USER:-rdpdisabled}
FRDP_DENY_PASSWORD=${FRDP_DENY_PASSWORD:-DeniedPassw0rd!}
FRDP_SSSD_DEBUG_LEVEL=${FRDP_SSSD_DEBUG_LEVEL:-3}
FRDP_AUTH_SOCKET=${FRDP_AUTH_SOCKET:-/run/frdp-authd/authd.sock}
FRDP_SESSION_SOCKET=${FRDP_SESSION_SOCKET:-/run/frdp-sesmand/sesmand.sock}
FRDP_CONFIG=${FRDP_CONFIG:-/etc/frdpd/frdpd.toml}

children=()
stopping=0

log()
{
	printf '[frdp-e2e-server] %s\n' "$*" >&2
}

fail()
{
	log "ERROR: $*"
	exit 1
}

validate_local_name()
{
	[[ $1 =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
}

wait_tcp()
{
	local host=$1
	local port=$2
	local attempts=${3:-120}

	for ((i = 0; i < attempts; i++)); do
		if nc -z -w 1 "$host" "$port" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	return 1
}

wait_socket()
{
	local path=$1
	local attempts=${2:-100}

	for ((i = 0; i < attempts; i++)); do
		[[ -S $path ]] && return 0
		sleep 0.1
	done
	return 1
}

ensure_sss_nsswitch()
{
	for database in passwd group; do
		if ! awk -v db="$database" '$1 == db ":" { for (i = 2; i <= NF; i++) if ($i == "sss") found = 1 } END { exit found ? 0 : 1 }' /etc/nsswitch.conf; then
			sed -ri "s/^(${database}:[^#]*)$/\\1 sss/" /etc/nsswitch.conf
		fi
	done
}

install_pam_profile()
{
	local profile=$1
	install -m 0644 "/opt/frdp-e2e/pam/${profile}" /etc/pam.d/frdpd
}

start_sssd()
{
	mkdir -p /var/lib/sss/db /var/lib/sss/mc /var/log/sssd /run/sssd
	chmod 0700 /etc/sssd
	chmod 0600 /etc/sssd/sssd.conf
	rm -f /run/sssd.pid /var/run/sssd.pid
	sssctl config-check
	/usr/sbin/sssd -i -d "$FRDP_SSSD_DEBUG_LEVEL" &
	children+=("$!")

	for ((i = 0; i < 120; i++)); do
		if getent passwd "$FRDP_TEST_USER" >/dev/null; then
			getent passwd "$FRDP_DENY_USER" >/dev/null || true
			return 0
		fi
		if ! kill -0 "${children[-1]}" 2>/dev/null; then
			wait "${children[-1]}" || true
			return 1
		fi
		sleep 1
	done
	return 1
}

wait_supplementary_group()
{
	local user=$1
	local group=$2
	local attempts=${3:-120}

	for ((i = 0; i < attempts; i++)); do
		local gid
		gid=$(getent group "$group" 2>/dev/null |
			awk -F: 'NR == 1 && $3 ~ /^[0-9]+$/ { print $3 }' || true)
		if [[ -n $gid ]] && id -G "$user" | tr ' ' '\n' | grep -Fxq -- "$gid"; then
			return 0
		fi
		sleep 1
	done
	return 1
}

configure_local_identity()
{
	validate_local_name "$FRDP_TEST_USER" || fail "invalid local test user name"
	validate_local_name "$FRDP_DENY_USER" || fail "invalid local denied user name"

	if ! id "$FRDP_TEST_USER" >/dev/null 2>&1; then
		useradd --create-home --shell /bin/bash "$FRDP_TEST_USER"
	fi
	printf '%s:%s\n' "$FRDP_TEST_USER" "$FRDP_TEST_PASSWORD" | chpasswd
	usermod --unlock "$FRDP_TEST_USER" 2>/dev/null || true

	if ! id "$FRDP_DENY_USER" >/dev/null 2>&1; then
		useradd --create-home --shell /bin/bash "$FRDP_DENY_USER"
	fi
	printf '%s:%s\n' "$FRDP_DENY_USER" "$FRDP_DENY_PASSWORD" | chpasswd
	usermod --lock "$FRDP_DENY_USER"
	install_pam_profile frdpd-local
}

configure_freeipa_identity()
{
	local server=${FRDP_FREEIPA_SERVER:-ipa.ipa.test}
	local domain=${FRDP_FREEIPA_DOMAIN:-ipa.test}
	local realm=${FRDP_FREEIPA_REALM:-IPA.TEST}
	local host=${FRDP_FREEIPA_HOST:-$(hostname -f)}
	local enroll_password=${FRDP_FREEIPA_ENROLL_PASSWORD:?FRDP_FREEIPA_ENROLL_PASSWORD is required}

	wait_tcp "$server" 389 || fail "FreeIPA LDAP did not become reachable"
	wait_tcp "$server" 88 || fail "FreeIPA Kerberos did not become reachable"

	ipa-client-install \
		--unattended \
		--domain="$domain" \
		--realm="$realm" \
		--server="$server" \
		--password="$enroll_password" \
		--no-ntp \
		--no-sudo \
		--no-ssh \
		--no-sshd \
		--no-dns-sshfp
	[[ -s /etc/krb5.keytab ]] || fail "FreeIPA enrollment did not create a host keytab"
	[[ $(stat -c '%U:%G:%a' /etc/krb5.keytab) == root:root:600 ]] ||
		fail "FreeIPA host keytab permissions are not root:root 0600"
	klist -k /etc/krb5.keytab | grep -Fq "host/$host@$realm" ||
		fail "FreeIPA host keytab does not contain the expected host principal"

	mkdir -p /etc/sssd
	cat > /etc/sssd/sssd.conf <<EOF
[sssd]
config_file_version = 2
services = nss, pam
domains = ${domain}

[nss]

[pam]

[domain/${domain}]
id_provider = ipa
auth_provider = ipa
access_provider = ipa
chpass_provider = ipa
ipa_domain = ${domain}
ipa_server = ${server}
ipa_hostname = ${host}
krb5_realm = ${realm}
krb5_validate = true
krb5_store_password_if_offline = false
krb5_ccname_template = FILE:/tmp/krb5cc_%U
cache_credentials = false
enumerate = false
use_fully_qualified_names = false
fallback_homedir = /home/%u
default_shell = /bin/bash
EOF

	ensure_sss_nsswitch
	install_pam_profile frdpd-sssd
	start_sssd || fail "SSSD did not resolve the FreeIPA test user"
	local allowed_checks denied_checks
	allowed_checks=$(LC_ALL=C sssctl user-checks -a acct -s frdpd "$FRDP_TEST_USER" 2>&1) ||
		fail "FreeIPA HBAC allowed-user check failed"
	grep -Fq 'pam_acct_mgmt: Success' <<<"$allowed_checks" ||
		fail "FreeIPA HBAC did not allow the test user"
	denied_checks=$(LC_ALL=C sssctl user-checks -a acct -s frdpd "$FRDP_DENY_USER" 2>&1) || true
	grep -Fq 'pam_acct_mgmt: Permission denied' <<<"$denied_checks" ||
		fail "FreeIPA HBAC did not deny the policy-test user"
	log "FreeIPA host enrollment, keytab validation, and HBAC allow/deny checks passed"
}

configure_samba_identity()
{
	local dc=${FRDP_AD_DC:-dc.ad.test}
	local domain=${FRDP_AD_DOMAIN:-ad.test}
	local realm=${FRDP_AD_REALM:-AD.TEST}
	local admin_user=${FRDP_AD_ADMIN_USER:-Administrator}
	local admin_password=${FRDP_AD_ADMIN_PASSWORD:?FRDP_AD_ADMIN_PASSWORD is required}
	local host_fqdn=${FRDP_AD_HOST_FQDN:-$(hostname -f)}
	local computer_name=${FRDP_AD_COMPUTER_NAME:-FRDPD}
	local test_group=${FRDP_TEST_GROUP:-rdp-users}

	validate_local_name "$test_group" || fail "invalid Samba AD test group name"

	wait_tcp "$dc" 389 || fail "Samba AD LDAP did not become reachable"
	wait_tcp "$dc" 88 || fail "Samba AD Kerberos did not become reachable"

	cat > /etc/krb5.conf <<EOF
[libdefaults]
 default_realm = ${realm}
 dns_lookup_realm = false
 dns_lookup_kdc = true
 rdns = false
 udp_preference_limit = 0

[domain_realm]
 .${domain} = ${realm}
 ${domain} = ${realm}
EOF
	chmod 0644 /etc/krb5.conf

	if ! adcli testjoin --domain="$domain" --domain-controller="$dc" >/dev/null 2>&1; then
		printf '%s\n' "$admin_password" | adcli join "$domain" \
			--domain-controller="$dc" \
			--host-fqdn="$host_fqdn" \
			--computer-name="$computer_name" \
			--login-user="$admin_user" \
			--stdin-password \
			--verbose
	fi
	adcli testjoin --domain="$domain" --domain-controller="$dc"

	mkdir -p /etc/sssd
	cat > /etc/sssd/sssd.conf <<EOF
[sssd]
config_file_version = 2
services = nss, pam
domains = ${domain}

[nss]

[pam]

[domain/${domain}]
id_provider = ad
auth_provider = ad
access_provider = ad
ad_domain = ${domain}
ad_server = ${dc}
krb5_realm = ${realm}
krb5_ccname_template = FILE:/tmp/krb5cc_%U
ldap_id_mapping = true
cache_credentials = false
krb5_store_password_if_offline = false
use_fully_qualified_names = false
fallback_homedir = /home/%u
default_shell = /bin/bash
dyndns_update = false
ad_gpo_access_control = permissive
EOF

	ensure_sss_nsswitch
	install_pam_profile frdpd-sssd
	start_sssd || fail "SSSD did not resolve the Samba AD test user"
	wait_supplementary_group "$FRDP_TEST_USER" "$test_group" ||
		fail "SSSD did not resolve supplementary group $test_group for $FRDP_TEST_USER"
	log "SSSD resolved supplementary group $test_group for $FRDP_TEST_USER"
}

configure_identity()
{
	case "$FRDP_IDENTITY_PROVIDER" in
		local)
			configure_local_identity
			;;
		freeipa)
			configure_freeipa_identity
			;;
		samba)
			configure_samba_identity
			;;
		*)
			fail "unsupported identity provider: $FRDP_IDENTITY_PROVIDER"
			;;
	esac
}

generate_tls_identity()
{
	local fqdn
	fqdn=$(hostname -f)
	mkdir -p /etc/frdpd
	if [[ ! -s /etc/frdpd/tls.crt || ! -s /etc/frdpd/tls.key ]]; then
		openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 \
			-subj "/CN=${fqdn}" \
			-addext "subjectAltName=DNS:${fqdn},DNS:localhost,IP:127.0.0.1" \
			-keyout /etc/frdpd/tls.key \
			-out /etc/frdpd/tls.crt >/dev/null 2>&1
	fi
	chmod 0600 /etc/frdpd/tls.key
	chmod 0644 /etc/frdpd/tls.crt
	install -m 0600 /opt/frdp-e2e/frdpd.toml "$FRDP_CONFIG"
}

nt_hash()
{
	printf '%s' "$1" | iconv -f UTF-8 -t UTF-16LE |
		openssl dgst -md4 -provider legacy | awk '{ print $NF }'
}

generate_ntlm_test_sam()
{
	local user_hash deny_hash
	user_hash=$(nt_hash "$FRDP_TEST_PASSWORD")
	deny_hash=$(nt_hash "$FRDP_DENY_PASSWORD")
	[[ $user_hash =~ ^[0-9a-f]{32}$ ]] || fail "failed to derive test-user NT hash"
	[[ $deny_hash =~ ^[0-9a-f]{32}$ ]] || fail "failed to derive denied-user NT hash"
	printf '%s:::%s:::\n%s:::%s:::\n' \
		"$FRDP_TEST_USER" "$user_hash" "$FRDP_DENY_USER" "$deny_hash" \
		> /etc/frdpd/ntlm.sam
	chmod 0600 /etc/frdpd/ntlm.sam
}

shutdown_children()
{
	local pid

	if ((stopping)); then
		return
	fi
	stopping=1
	trap - TERM INT EXIT
	for pid in "${children[@]}"; do
		kill -TERM "$pid" 2>/dev/null || true
	done
	for pid in "${children[@]}"; do
		wait "$pid" 2>/dev/null || true
	done
}

trap 'shutdown_children; exit 143' TERM INT
trap shutdown_children EXIT

mkdir -p /run/frdp-authd /run/frdp-sesmand /run/frdp-auth-token /tmp/.X11-unix /artifacts
chmod 0700 /run/frdp-authd /run/frdp-sesmand /run/frdp-auth-token
chmod 1777 /tmp /tmp/.X11-unix
rm -f "$FRDP_AUTH_SOCKET" "$FRDP_SESSION_SOCKET"

log "configuring identity provider: $FRDP_IDENTITY_PROVIDER"
configure_identity
generate_tls_identity
generate_ntlm_test_sam

frdp-authd --config "$FRDP_CONFIG" --socket "$FRDP_AUTH_SOCKET" &
children+=("$!")
frdp-sesmand --config "$FRDP_CONFIG" --socket "$FRDP_SESSION_SOCKET" &
children+=("$!")

wait_socket "$FRDP_AUTH_SOCKET" || fail "frdp-authd socket was not created"
wait_socket "$FRDP_SESSION_SOCKET" || fail "frdp-sesmand socket was not created"

frdpd --config "$FRDP_CONFIG" --domain-mode=plain &
children+=("$!")

log "FRDP stack started for provider=$FRDP_IDENTITY_PROVIDER user=$FRDP_TEST_USER"
set +e
wait -n "${children[@]}"
status=$?
set -e
log "a managed process exited with status $status"
shutdown_children
exit "$status"
