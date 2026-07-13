#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$root/../../../.." && pwd)
compose_file="$root/compose.yaml"
artifacts=${FRDP_E2E_ARTIFACTS:-$root/artifacts}
keep=${FRDP_E2E_KEEP:-0}
profile_timeout=${FRDP_E2E_PROFILE_TIMEOUT:-1800}

mkdir -p "$artifacts"
artifacts=$(cd "$artifacts" && pwd -P)
[[ $artifacts != "$repo_root" ]] || { echo "FRDP_E2E_ARTIFACTS must not be the repository root" >&2; exit 2; }
export FRDP_E2E_ARTIFACTS="$artifacts"

positive_integer()
{
	[[ $1 =~ ^[1-9][0-9]*$ ]]
}

positive_integer "$profile_timeout" || { echo "FRDP_E2E_PROFILE_TIMEOUT must be positive" >&2; exit 2; }
command -v git >/dev/null 2>&1 || { echo "git is required" >&2; exit 2; }
command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 2; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required" >&2; exit 2; }
command -v timeout >/dev/null 2>&1 || { echo "timeout is required" >&2; exit 2; }

snapshot_excluded_paths=("${root#"$repo_root/"}/artifacts")
if [[ $artifacts == "$repo_root/"* &&
	${artifacts#"$repo_root/"} != "${snapshot_excluded_paths[0]}" ]]; then
	snapshot_excluded_paths+=("${artifacts#"$repo_root/"}")
fi
snapshot_excludes=()
for excluded_path in "${snapshot_excluded_paths[@]}"; do
	snapshot_excludes+=("--exclude=$excluded_path")
done
source_archive=$(mktemp "${TMPDIR:-/tmp}/frdp-source.XXXXXX.tar.gz")
cleanup_source_archive()
{
	[[ -z ${source_archive:-} ]] || rm -f "$source_archive"
}
trap cleanup_source_archive EXIT

git -C "$repo_root" rev-parse 'HEAD^{tree}' >"$artifacts/base-tree-sha.txt"
tar -C "$repo_root" -czf "$source_archive" "${snapshot_excludes[@]}" \
	server/frdp tools/frdpctl include/freerdp/channels/wtsvc.h \
	libfreerdp/core/server.c libfreerdp/core/server.h \
	.github/workflows/frdpd-compose.yml
for excluded_path in "${snapshot_excluded_paths[@]}"; do
	while IFS= read -r archive_entry; do
		if [[ $archive_entry == "$excluded_path" || $archive_entry == "$excluded_path/"* ]]; then
			echo "source snapshot contains excluded path: $excluded_path" >&2
			exit 2
		fi
	done < <(tar -tzf "$source_archive")
done
mv "$source_archive" "$artifacts/frdp-source.tar.gz"
source_archive=

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
	timeout "${profile_timeout}s" "${compose[@]}" --profile "$profile" up --build \
		--abort-on-container-exit \
		--exit-code-from "$exit_service" \
		"$exit_service" 2>&1 | tee "$output"
	status=${PIPESTATUS[0]}
	set -e
	if [[ $status -eq 124 ]]; then
		printf 'profile %s exceeded FRDP_E2E_PROFILE_TIMEOUT=%s seconds\n' \
			"$profile" "$profile_timeout" | tee -a "$output" >&2
	fi

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
Set FRDP_E2E_PROFILE_TIMEOUT=<seconds> to bound each Compose profile run.
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
