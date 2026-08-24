#!/usr/bin/env bash
set -Eeuo pipefail

user=${FRDP_TEST_USER:-rdpuser}
provider=${FRDP_IDENTITY_PROVIDER:-local}
socket=${FRDP_SESSION_SOCKET:-/run/frdp-sesmand/sesmand.sock}

[[ -S ${FRDP_AUTH_SOCKET:-/run/frdp-authd/authd.sock} ]]
[[ -S $socket ]]
getent passwd "$user" >/dev/null
frdpctl status --socket "$socket" >/dev/null
ss -H -ltn 'sport = :3389' | grep -q .

if [[ $provider != local ]]; then
	pgrep -x sssd >/dev/null
fi
