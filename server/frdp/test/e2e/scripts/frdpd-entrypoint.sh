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
FRDP_E2E_SESMAND_CRASH_RECOVERY=${FRDP_E2E_SESMAND_CRASH_RECOVERY:-0}
FRDP_E2E_FREEIPA_KEYTAB_ROLLOVER=${FRDP_E2E_FREEIPA_KEYTAB_ROLLOVER:-0}
FRDP_E2E_POLICY_RELOAD=${FRDP_E2E_POLICY_RELOAD:-0}
FRDP_E2E_CONTROL_DIR=${FRDP_E2E_CONTROL_DIR:-/run/frdp-e2e-control}
FRDP_E2E_KEYTAB_DIR=${FRDP_E2E_KEYTAB_DIR:-/run/frdp-e2e-keytab}

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

wait_replaced_socket()
{
	local path=$1
	local pid=$2
	local previous_inode=${3:-}
	local inode

	for ((i = 0; i < 100; i++)); do
		kill -0 "$pid" 2>/dev/null || return 1
		if [[ -S $path ]]; then
			inode=$(stat -c %i "$path")
			if [[ -z $previous_inode || $inode != "$previous_inode" ]]; then
				printf '%s\n' "$inode"
				return 0
			fi
		fi
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

keytab_max_kvno()
{
	local keytab=$1
	local principal=$2

	klist -k "$keytab" | awk -v principal="$principal" \
		'$1 ~ /^[0-9]+$/ && $2 == principal { if ($1 > max) max = $1; found = 1 }
		 END { if (found) print max; else exit 1 }'
}

rotate_freeipa_keytab()
{
	local realm=$1
	local host=$2
	local principal="host/$host@$realm"
	local old_kvno=
	local new_kvno=
	local request="$FRDP_E2E_KEYTAB_DIR/.keytab-rollover-request.$$"
	local ready="$FRDP_E2E_KEYTAB_DIR/keytab-rollover-ready"
	local next="$FRDP_E2E_KEYTAB_DIR/freeipa-keytab.next"
	local ccache="FILE:/tmp/frdp-e2e-keytab-rollover.ccache"
	local installed=/etc/krb5.keytab.rollover

	old_kvno=$(keytab_max_kvno /etc/krb5.keytab "$principal") ||
		fail "could not read the enrolled FreeIPA host key KVNO"
	KRB5CCNAME=$ccache kinit -k -t /etc/krb5.keytab "$principal" ||
		fail "enrolled FreeIPA host keytab could not obtain a ticket before rollover"
	KRB5CCNAME=$ccache kdestroy >/dev/null 2>&1 || true
	printf 'principal=%s\nold_kvno=%s\n' "$principal" "$old_kvno" >"$request"
	mv -f "$request" "$FRDP_E2E_KEYTAB_DIR/keytab-rollover-request"

	for ((i = 0; i < 180; i++)); do
		[[ ! -f $FRDP_E2E_KEYTAB_DIR/keytab-rollover-failed ]] ||
			fail "FreeIPA server rejected the host keytab rollover request"
		[[ -f $ready && -s $next ]] && break
		sleep 1
	done
	[[ -f $ready && -s $next ]] || fail "FreeIPA host keytab rollover timed out"
	grep -Fxq "principal=$principal" "$ready" ||
		fail "FreeIPA keytab rollover returned the wrong principal"
	grep -Fxq "old_kvno=$old_kvno" "$ready" ||
		fail "FreeIPA keytab rollover returned the wrong prior KVNO"
	new_kvno=$(sed -n 's/^new_kvno=//p' "$ready")
	if [[ ! $new_kvno =~ ^[1-9][0-9]*$ ]] || ((new_kvno <= old_kvno)); then
		fail "FreeIPA keytab rollover did not increase the host key KVNO"
	fi
	[[ $(keytab_max_kvno "$next" "$principal") == "$new_kvno" ]] ||
		fail "FreeIPA rollover keytab does not contain the announced KVNO"
	if KRB5CCNAME=$ccache kinit -k -t /etc/krb5.keytab "$principal" >/dev/null 2>&1; then
		KRB5CCNAME=$ccache kdestroy >/dev/null 2>&1 || true
		fail "FreeIPA accepted the old host key after rollover"
	fi
	install -o root -g root -m 0600 "$next" "$installed"
	mv -f "$installed" /etc/krb5.keytab
	KRB5CCNAME=$ccache kinit -k -t /etc/krb5.keytab "$principal" ||
		fail "FreeIPA rejected the rotated host keytab"
	KRB5CCNAME=$ccache kdestroy >/dev/null 2>&1 || true
	printf 'principal=%s\nold_kvno=%s\nnew_kvno=%s\nold_key_rejected=pass\nnew_key_accepted=pass\n' \
		"$principal" "$old_kvno" "$new_kvno" \
		>"$FRDP_E2E_CONTROL_DIR/keytab-rollover-result"
	log "FreeIPA host keytab rollover passed for $principal KVNO $old_kvno -> $new_kvno"
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
	if [[ $FRDP_E2E_FREEIPA_KEYTAB_ROLLOVER == 1 ]]; then
		rotate_freeipa_keytab "$realm" "$host"
	fi
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
	local allowed_checks denied_checks

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
ad_gpo_access_control = enforcing
ad_gpo_map_remote_interactive = +frdpd
EOF

	ensure_sss_nsswitch
	install_pam_profile frdpd-sssd
	start_sssd || fail "SSSD did not resolve the Samba AD test user"
	wait_supplementary_group "$FRDP_TEST_USER" "$test_group" ||
		fail "SSSD did not resolve supplementary group $test_group for $FRDP_TEST_USER"
	log "SSSD resolved supplementary group $test_group for $FRDP_TEST_USER"
	allowed_checks=$(LC_ALL=C sssctl user-checks -a acct -s frdpd "$FRDP_TEST_USER" 2>&1) ||
		fail "Samba AD enforcing GPO allowed-user check failed"
	grep -Fq 'pam_acct_mgmt: Success' <<<"$allowed_checks" ||
		fail "Samba AD enforcing GPO did not allow the RDP test user"
	denied_checks=$(LC_ALL=C sssctl user-checks -a acct -s frdpd "$FRDP_DENY_USER" 2>&1) || true
	grep -Fq 'pam_acct_mgmt: Permission denied' <<<"$denied_checks" ||
		fail "Samba AD enforcing GPO did not deny the RDP policy-test user"
	log "Samba AD enforcing GPO allow/deny checks passed for PAM service frdpd"
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

publish_sesmand_state()
{
	local pid=$1
	local inode=$2
	local generation=$3
	local temporary="$FRDP_E2E_CONTROL_DIR/.sesmand-state.$$"

	printf 'pid=%s\ninode=%s\ngeneration=%s\n' "$pid" "$inode" "$generation" >"$temporary"
	mv -f "$temporary" "$FRDP_E2E_CONTROL_DIR/sesmand-state"
}

run_sesmand_supervisor()
{
	local generation=0
	local inode=
	local old_inode=
	local pid=
	local status=0

	trap '[[ -z ${pid:-} ]] || kill -TERM "$pid" 2>/dev/null || true; [[ -z ${pid:-} ]] || wait "$pid" 2>/dev/null || true; exit 143' TERM INT
	while ((generation < 2)); do
		frdp-sesmand --config "$FRDP_CONFIG" --socket "$FRDP_SESSION_SOCKET" &
		pid=$!
		inode=$(wait_replaced_socket "$FRDP_SESSION_SOCKET" "$pid" "$old_inode") || {
			kill -TERM "$pid" 2>/dev/null || true
			wait "$pid" 2>/dev/null || true
			return 1
		}
		publish_sesmand_state "$pid" "$inode" "$generation"
		if ((generation == 1)); then
			: >"$FRDP_E2E_CONTROL_DIR/sesmand-restarted"
		fi

		set +e
		wait "$pid"
		status=$?
		set -e
		pid=
		if ((generation == 0)) && [[ -f $FRDP_E2E_CONTROL_DIR/sesmand-crash-triggered ]] &&
			((status != 0)); then
			old_inode=$inode
			generation=1
			continue
		fi
		return "$status"
	done
	return 1
}

run_policy_reload_supervisor()
{
	local frdpd_pid=$1
	local mode=
	local next="${FRDP_CONFIG}.next"
	local original="${FRDP_CONFIG}.e2e-original"
	local ready=
	local request=
	local temporary=

	cp -p "$FRDP_CONFIG" "$original"
	trap 'exit 0' TERM INT
	while kill -0 "$frdpd_pid" 2>/dev/null; do
		for mode in deny malformed restore; do
			request="$FRDP_E2E_CONTROL_DIR/policy-reload-${mode}-request"
			[[ -f $request ]] || continue
			ready="$FRDP_E2E_CONTROL_DIR/policy-reload-${mode}-ready"
			temporary="$FRDP_E2E_CONTROL_DIR/.policy-reload-${mode}-ready.$$"
			case "$mode" in
				deny)
					awk '
						$0 == "static_mode = \"blocklist\"" {
							print "static_mode = \"allowlist\""; next
						}
						$0 == "static_deny = \"\"" {
							print "static_allow = \"\""; next
						}
						{ print }
					' "$original" >"$next"
					grep -Fxq 'static_mode = "allowlist"' "$next"
					grep -Fxq 'static_allow = ""' "$next"
					;;
				malformed)
					printf '[channels\n' >"$next"
					;;
				restore)
					cp "$original" "$next"
					;;
			esac
			chmod 0600 "$next"
			mv -f "$next" "$FRDP_CONFIG"
			kill -HUP "$frdpd_pid"
			sleep 1
			kill -0 "$frdpd_pid"
			printf 'mode=%s\nresult=pass\n' "$mode" >"$temporary"
			mv -f "$temporary" "$ready"
			rm -f "$request"
		done
		sleep 0.1
	done
	return 1
}

inject_sesmand_crash()
{
	local agent_pid=
	local generation=
	local i
	local new_inode=
	local new_pid=
	local old_inode=
	local old_pid=
	local session_id=
	local observed_agent_pid=
	local observed_session_id=
	local socket_pin
	local state
	local temporary="$FRDP_E2E_CONTROL_DIR/.sesmand-recovery.$$"
	socket_pin="$(dirname "$FRDP_SESSION_SOCKET")/.e2e-old-sesmand-socket"
	trap 'exit 0' TERM INT

	while [[ ! -f $FRDP_E2E_CONTROL_DIR/arm-sesmand-crash ]]; do
		sleep 0.1
	done
	while [[ ! -f $FRDP_E2E_CONTROL_DIR/client-session-observed ]]; do
		sleep 0.1
	done
	observed_session_id=$(sed -n 's/^session_id=//p' "$FRDP_E2E_CONTROL_DIR/client-session-observed")
	observed_agent_pid=$(sed -n 's/^agent_pid=//p' "$FRDP_E2E_CONTROL_DIR/client-session-observed")
	[[ -n $observed_session_id && $observed_agent_pid =~ ^[0-9]+$ ]]

	for ((i = 0; i < 600; i++)); do
		if [[ -f $FRDP_E2E_CONTROL_DIR/sesmand-state ]]; then
			old_pid=$(sed -n 's/^pid=//p' "$FRDP_E2E_CONTROL_DIR/sesmand-state")
			old_inode=$(sed -n 's/^inode=//p' "$FRDP_E2E_CONTROL_DIR/sesmand-state")
			generation=$(sed -n 's/^generation=//p' "$FRDP_E2E_CONTROL_DIR/sesmand-state")
		fi
		frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" >"$FRDP_E2E_CONTROL_DIR/session-before-crash" 2>/dev/null || true
		read -r session_id agent_pid < <(
			awk -v user="$FRDP_TEST_USER" 'NR > 1 && $2 == user && $4 == "active" { print $1, $5; exit }' \
				"$FRDP_E2E_CONTROL_DIR/session-before-crash") || true
		if [[ $old_pid =~ ^[0-9]+$ && $old_inode =~ ^[0-9]+$ && $generation == 0 &&
			$agent_pid == "$observed_agent_pid" && $session_id == "$observed_session_id" ]]; then
			break
		fi
		sleep 0.1
	done
	[[ $old_pid =~ ^[0-9]+$ && $old_inode =~ ^[0-9]+$ && $generation == 0 ]]
	[[ $agent_pid =~ ^[0-9]+$ && -n $session_id ]]
	kill -0 "$old_pid"
	kill -0 "$agent_pid"
	rm -f "$socket_pin"
	ln "$FRDP_SESSION_SOCKET" "$socket_pin"
	[[ $(stat -c %i "$socket_pin") == "$old_inode" ]]
	: >"$FRDP_E2E_CONTROL_DIR/sesmand-crash-triggered"
	kill -KILL "$old_pid"

	for ((i = 0; i < 600; i++)); do
		if [[ -f $FRDP_E2E_CONTROL_DIR/sesmand-restarted ]]; then
			new_pid=$(sed -n 's/^pid=//p' "$FRDP_E2E_CONTROL_DIR/sesmand-state")
			new_inode=$(sed -n 's/^inode=//p' "$FRDP_E2E_CONTROL_DIR/sesmand-state")
			generation=$(sed -n 's/^generation=//p' "$FRDP_E2E_CONTROL_DIR/sesmand-state")
			if [[ $new_pid =~ ^[0-9]+$ && $new_inode =~ ^[0-9]+$ && $generation == 1 &&
				$new_pid != "$old_pid" && $new_inode != "$old_inode" ]]; then
				break
			fi
		fi
		sleep 0.1
	done
	[[ $new_pid =~ ^[0-9]+$ && $new_inode =~ ^[0-9]+$ && $generation == 1 ]]
	[[ $new_pid != "$old_pid" && $new_inode != "$old_inode" ]]
	frdpctl status --socket "$FRDP_SESSION_SOCKET" | grep -Fxq 'Session manager: reachable'
	rm -f "$socket_pin"

	for ((i = 0; i < 600; i++)); do
		state=$(ps -o stat= -p "$agent_pid" 2>/dev/null | tr -d '[:space:]' || true)
		frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" >"$FRDP_E2E_CONTROL_DIR/session-after-crash" 2>/dev/null || true
		if [[ -z $state || $state == Z* ]] &&
			grep -Fxq 'No active sessions' "$FRDP_E2E_CONTROL_DIR/session-after-crash" &&
			[[ -z $(find "$(dirname "$FRDP_SESSION_SOCKET")" -mindepth 1 ! -name "$(basename "$FRDP_SESSION_SOCKET")" -print -quit) ]]; then
			break
		fi
		sleep 0.1
	done
	[[ -z $state || $state == Z* ]]
	grep -Fxq 'No active sessions' "$FRDP_E2E_CONTROL_DIR/session-after-crash"
	[[ -z $(find "$(dirname "$FRDP_SESSION_SOCKET")" -mindepth 1 ! -name "$(basename "$FRDP_SESSION_SOCKET")" -print -quit) ]]

	printf 'session_id=%s\nagent_pid=%s\nold_pid=%s\nnew_pid=%s\nold_inode=%s\nnew_inode=%s\nresult=pass\n' \
		"$session_id" "$agent_pid" "$old_pid" "$new_pid" "$old_inode" "$new_inode" >"$temporary"
	mv -f "$temporary" "$FRDP_E2E_CONTROL_DIR/sesmand-recovery"
	log "provider-backed frdp-sesmand recovery passed for provider=$FRDP_IDENTITY_PROVIDER session=$session_id"
	while :; do
		sleep 1
	done
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

if [[ $FRDP_E2E_SESMAND_CRASH_RECOVERY != 0 && $FRDP_E2E_SESMAND_CRASH_RECOVERY != 1 ]]; then
	fail "FRDP_E2E_SESMAND_CRASH_RECOVERY must be 0 or 1"
fi
if [[ $FRDP_E2E_FREEIPA_KEYTAB_ROLLOVER != 0 && $FRDP_E2E_FREEIPA_KEYTAB_ROLLOVER != 1 ]]; then
	fail "FRDP_E2E_FREEIPA_KEYTAB_ROLLOVER must be 0 or 1"
fi
if [[ $FRDP_E2E_POLICY_RELOAD != 0 && $FRDP_E2E_POLICY_RELOAD != 1 ]]; then
	fail "FRDP_E2E_POLICY_RELOAD must be 0 or 1"
fi
if [[ $FRDP_E2E_FREEIPA_KEYTAB_ROLLOVER == 1 && $FRDP_IDENTITY_PROVIDER != freeipa ]]; then
	fail "keytab rollover requires the FreeIPA provider profile"
fi
if [[ $FRDP_E2E_SESMAND_CRASH_RECOVERY == 1 && $FRDP_IDENTITY_PROVIDER != samba &&
	$FRDP_IDENTITY_PROVIDER != freeipa ]]; then
	fail "frdp-sesmand crash recovery injection requires a Samba or FreeIPA provider profile"
fi
if [[ $FRDP_E2E_POLICY_RELOAD == 1 && $FRDP_IDENTITY_PROVIDER != local ]]; then
	fail "frdpd policy reload injection requires the local provider profile"
fi
if [[ $FRDP_E2E_SESMAND_CRASH_RECOVERY == 1 || $FRDP_E2E_FREEIPA_KEYTAB_ROLLOVER == 1 ||
	$FRDP_E2E_POLICY_RELOAD == 1 ]]; then
	mkdir -p "$FRDP_E2E_CONTROL_DIR"
	rm -f "$FRDP_E2E_CONTROL_DIR"/*
fi
if [[ $FRDP_E2E_FREEIPA_KEYTAB_ROLLOVER == 1 ]]; then
	mkdir -p "$FRDP_E2E_KEYTAB_DIR"
	chmod 0700 "$FRDP_E2E_KEYTAB_DIR"
	rm -f "$FRDP_E2E_KEYTAB_DIR"/*
fi

log "configuring identity provider: $FRDP_IDENTITY_PROVIDER"
configure_identity
generate_tls_identity
generate_ntlm_test_sam

frdp-authd --config "$FRDP_CONFIG" --socket "$FRDP_AUTH_SOCKET" &
children+=("$!")
if [[ $FRDP_E2E_SESMAND_CRASH_RECOVERY == 1 ]]; then
	run_sesmand_supervisor &
	children+=("$!")
else
	frdp-sesmand --config "$FRDP_CONFIG" --socket "$FRDP_SESSION_SOCKET" &
	children+=("$!")
fi

wait_socket "$FRDP_AUTH_SOCKET" || fail "frdp-authd socket was not created"
wait_socket "$FRDP_SESSION_SOCKET" || fail "frdp-sesmand socket was not created"

frdpd --config "$FRDP_CONFIG" --domain-mode=plain &
frdpd_pid=$!
children+=("$frdpd_pid")

if [[ $FRDP_E2E_POLICY_RELOAD == 1 ]]; then
	run_policy_reload_supervisor "$frdpd_pid" &
	children+=("$!")
fi

if [[ $FRDP_E2E_SESMAND_CRASH_RECOVERY == 1 ]]; then
	inject_sesmand_crash &
	children+=("$!")
fi

log "FRDP stack started for provider=$FRDP_IDENTITY_PROVIDER user=$FRDP_TEST_USER"
set +e
wait -n "${children[@]}"
status=$?
set -e
log "a managed process exited with status $status"
shutdown_children
exit "$status"
