#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
artifact_root=${FRDP_DESKTOP_MATRIX_ARTIFACTS:-$root/desktop-matrix}
image_prefix=${FRDP_DESKTOP_IMAGE_PREFIX:-frdpd-e2e}
supported=(openbox xfce mate lxqt plasma gnome)

if (($# > 0)); then
	desktops=("$@")
else
	desktops=("${supported[@]}")
fi

is_supported()
{
	local requested=$1
	local candidate=
	for candidate in "${supported[@]}"; do
		[[ $requested == "$candidate" ]] && return 0
	done
	return 1
}

for desktop in "${desktops[@]}"; do
	is_supported "$desktop" || {
		printf 'unsupported desktop %s (expected one of: %s)\n' \
			"$desktop" "${supported[*]}" >&2
		exit 2
	}
	desktop_artifacts=$artifact_root/$desktop/artifacts
	mkdir -p "$desktop_artifacts"
	printf '\n[frdp-desktop-matrix] testing %s\n' "$desktop" >&2
	FRDP_DESKTOP_TYPE=$desktop \
	FRDP_E2E_IMAGE=$image_prefix:$desktop \
	FRDP_E2E_ARTIFACTS=$desktop_artifacts \
		bash "$root/run.sh" local
done

printf '\n[frdp-desktop-matrix] passed: %s\n' "${desktops[*]}" >&2
