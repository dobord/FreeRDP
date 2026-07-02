#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$root/../../../.." && pwd)
compose_file="$root/compose.yaml"
artifacts=${FRDP_E2E_ARTIFACTS:-$root/artifacts}
keep=${FRDP_E2E_KEEP:-0}

export FRDP_E2E_ARTIFACTS="$artifacts"
mkdir -p "$artifacts"

git -C "$repo_root" rev-parse 'HEAD^{tree}' >"$artifacts/base-tree-sha.txt"
tar -C "$repo_root" -czf "$artifacts/frdp-source.tar.gz" \
	server/frdp tools/frdpctl include/freerdp/channels/wtsvc.h \
	libfreerdp/core/server.c libfreerdp/core/server.h \
	.github/workflows/frdpd-compose.yml

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 2; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required" >&2; exit 2; }

compose=(docker compose -f "$compose_file")

cleanup()
{
	if [[ $keep != 1 ]]; then
		"${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
	fi
}

run_profile()
{
	local profile=$1
	local exit_service=$2
	local status=0
	local output="$artifacts/$profile/compose-up.log"
	local container_ids="$artifacts/$profile/container-ids.txt"

	mkdir -p "$artifacts/$profile"
	: >"$output"
	"${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
	"${compose[@]}" --profile "$profile" config >"$artifacts/$profile/compose-config.yaml" 2>&1 || true

	set +e
	"${compose[@]}" --profile "$profile" up --build \
		--abort-on-container-exit \
		--exit-code-from "$exit_service" \
		"$exit_service" 2>&1 | tee "$output"
	status=${PIPESTATUS[0]}
	set -e

	"${compose[@]}" --profile "$profile" logs --no-color --timestamps >"$artifacts/$profile/compose.log" 2>&1 || true
	"${compose[@]}" --profile "$profile" ps -a >"$artifacts/$profile/compose-ps.txt" 2>&1 || true
	"${compose[@]}" --profile "$profile" ps -a -q >"$container_ids" 2>/dev/null || true
	mkdir -p "$artifacts/$profile/container-logs" "$artifacts/$profile/container-inspect"
	while IFS= read -r container_id; do
		[[ -n $container_id ]] || continue
		local container_name
		container_name=$(docker inspect --format '{{.Name}}' "$container_id" 2>/dev/null || true)
		container_name=${container_name#/}
		container_name=${container_name//[^A-Za-z0-9_.-]/_}
		if [[ -z $container_name ]]; then
			container_name=$container_id
		fi
		docker logs --timestamps "$container_id" >"$artifacts/$profile/container-logs/$container_name.log" 2>&1 || true
		docker inspect "$container_id" >"$artifacts/$profile/container-inspect/$container_name.json" 2>&1 || true
	done <"$container_ids"
	printf '%s\n' "$status" >"$artifacts/$profile/exit-code.txt"
	cleanup
	return "$status"
}

usage()
{
	cat >&2 <<EOF
Usage: bash $0 component|local|samba|freeipa|all

  component  Build and run focused CTest/component coverage.
  local      Real TLS/NLA/CredSSP, local PAM and managed-session lifecycle.
  samba      Samba AD DC + adcli + SSSD AD + PAM + real RDP lifecycle.
  freeipa    Official FreeIPA server + SSSD LDAP/Kerberos + PAM + real RDP lifecycle.
  all        Run all profiles sequentially.

Set FRDP_E2E_KEEP=1 to leave failed containers and volumes running for diagnosis.
EOF
}

profile=${1:-}
case "$profile" in
	component)
		run_profile component component-tests
		;;
	local)
		run_profile local rdp-client-local
		;;
	samba)
		run_profile samba rdp-client-samba
		;;
	freeipa)
		if [[ ! -e /sys/fs/cgroup/cgroup.controllers ]]; then
			echo "warning: the FreeIPA profile is designed for a cgroups-v2 Docker host" >&2
		fi
		run_profile freeipa rdp-client-freeipa
		;;
	all)
		run_profile component component-tests
		run_profile local rdp-client-local
		run_profile samba rdp-client-samba
		run_profile freeipa rdp-client-freeipa
		;;
	*)
		usage
		exit 2
		;;
esac
